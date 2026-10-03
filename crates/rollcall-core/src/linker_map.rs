//! A panic-free parser for GNU ld map files (`ld -Map`, e.g. Zephyr's `zephyr/zephyr.map`).
//!
//! [`parse`] reads the parts of a map that say which object files ended up in the image:
//!
//! | Map section | Read into |
//! |-------------|-----------|
//! | `Archive member included to satisfy reference by file (symbol)` | [`LinkerMap::archive_members`]: each archive member the link pulled in, and why |
//! | `Discarded input sections` | [`ObjectUsage::discarded`] of each object (sections `--gc-sections` dropped) |
//! | `Linker script and memory map` | [`LinkerMap::loads`] (`LOAD` lines) and [`ObjectUsage::linked`]: every input section placed in an output section; sections under `/DISCARD/` go to [`ObjectUsage::discarded`] |
//!
//! Everything else (`Memory Configuration`, `Allocating common symbols`, `Cross Reference
//! Table`, symbol and assignment lines, `*fill*`, `FILL`, input-section patterns such as
//! `*(SORT_BY_ALIGNMENT(.text.*))`, `PROVIDE`) is skipped.
//!
//! # GNU ld quirks handled
//!
//! - An input-section name too long for its column is printed alone, and its address, size
//!   and file follow on the next line.
//! - An archive member is written `path/libx.a(member.c.obj)` ([`ObjectId`]); a loose object
//!   is a plain path; the linker's own sections come from the two-word file `linker stubs`.
//! - Paths are normalised: `\` becomes `/` and `.` and `..` segments are collapsed
//!   (`zephyr/CMakeFiles/offsets.dir/./arch/x.c.obj`, `/sdk/bin/../lib/libc.a`).
//! - Non-allocated sections (`.debug_*`, `.comment`, `.ARM.attributes`, …, see
//!   [`is_non_allocated`]) list input sections from every object at address 0; they do not
//!   make an object linked. Neither do zero-size sections.
//! - CRLF line endings are accepted; addresses may be 32- or 64-bit.
//!
//! An object is *linked* ([`ObjectUsage::is_linked`]) when at least one of its input
//! sections with a non-zero size was placed in an allocated output section. An object that
//! appears only among the discarded sections, only with empty sections, or only in the
//! archive-member list was not linked: the linker garbage-collected it.
//!
//! # Errors
//!
//! A map with no `Linker script and memory map` header is not a GNU ld map
//! ([`LinkerMapError::NotGnuLd`]; LLVM lld and vendor linkers write other formats). An
//! input-section line whose address or size starts with `0x` but is not a 64-bit hex number
//! is [`LinkerMapError::BadNumber`], with its line. Nothing panics: unknown lines are
//! skipped, and a map cut short yields what was read before the cut.
//!
//! # Determinism
//!
//! Objects are kept in a sorted map keyed by [`ObjectId`]; sections, members and loads keep
//! file order.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The header of the archive-member section.
const ARCHIVE_MEMBERS: &str = "Archive member included to satisfy reference by file (symbol)";
/// The header of the as-needed section (same layout as the archive-member one).
const AS_NEEDED: &str = "As-needed library included to satisfy reference by file (symbol)";
/// The header of the common-symbol section.
const COMMON_SYMBOLS: &str = "Allocating common symbols";
/// The header of the discarded-sections section.
const DISCARDED: &str = "Discarded input sections";
/// The header of the memory-configuration section.
const MEMORY_CONFIGURATION: &str = "Memory Configuration";
/// The header of the memory map proper.
const MEMORY_MAP: &str = "Linker script and memory map";
/// The header of the `--cref` table.
const CROSS_REFERENCE: &str = "Cross Reference Table";
/// The output section the linker script discards into.
const DISCARD_SECTION: &str = "/DISCARD/";

/// A parsed GNU ld map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkerMap {
    objects: BTreeMap<ObjectId, ObjectUsage>,
    archive_members: Vec<ArchiveMember>,
    loads: Vec<Load>,
    /// The first line showing link-time optimisation, if any.
    lto: Option<u32>,
    /// The line of the `OUTPUT(<file> <bfd-target>)` line GNU ld writes near the end of the
    /// memory map, if the map has one (a map cut short does not).
    output_line: Option<u32>,
}

/// An object file: an archive member (`archive(member)`) or a loose object (`member` only).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId {
    /// The archive, normalised, when the object is an archive member.
    pub archive: Option<String>,
    /// The member name, or the loose object's normalised path.
    pub member: String,
}

impl ObjectId {
    /// Parses a map file field: `path/libx.a(member.o)`, or a plain path.
    pub fn parse(field: &str) -> Self {
        let field = field.trim();
        if let Some(inner) = field.strip_suffix(')')
            && let Some(open) = inner.rfind('(')
        {
            let archive = inner.get(..open).unwrap_or_default();
            let member = inner.get(open.saturating_add(1)..).unwrap_or_default();
            if !archive.is_empty() && !member.is_empty() {
                return Self {
                    archive: Some(normalise_path(archive)),
                    member: member.to_owned(),
                };
            }
        }
        Self {
            archive: None,
            member: normalise_path(field),
        }
    }

    /// The member name without its object suffix (`hci_core.c.obj` → `hci_core.c`,
    /// `crt0.o` → `crt0`): the source file name under CMake's object naming.
    pub fn source_name(&self) -> &str {
        let name = match self.member.rsplit_once('/') {
            Some((_, name)) => name,
            None => &self.member,
        };
        name.strip_suffix(".obj")
            .or_else(|| name.strip_suffix(".o"))
            .unwrap_or(name)
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.archive {
            Some(archive) => write!(f, "{archive}({})", self.member),
            None => f.write_str(&self.member),
        }
    }
}

/// One input section: a section of an object file as the map lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSection {
    /// The input section name, e.g. `.text.bt_enable`.
    pub name: String,
    /// The output section it was placed in (empty in `Discarded input sections`).
    pub output_section: String,
    /// The address.
    pub address: u64,
    /// The size in bytes.
    pub size: u64,
    /// The 1-based line of the address and size.
    pub line: u32,
}

impl InputSection {
    /// Whether this section occupies space in the image: non-zero size, in an allocated
    /// output section.
    pub fn occupies_image(&self) -> bool {
        self.size > 0
            && !is_non_allocated(&self.name)
            && !is_non_allocated(&self.output_section)
            && self.output_section != DISCARD_SECTION
    }
}

/// What the map says about one object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectUsage {
    /// Input sections placed in allocated output sections, in file order (including empty
    /// ones).
    pub linked: Vec<InputSection>,
    /// Input sections the linker discarded (garbage-collected or matched by `/DISCARD/`), in
    /// file order.
    pub discarded: Vec<InputSection>,
    /// How many of its sections the map lists in non-allocated sections ([`is_non_allocated`]:
    /// debug information, comments, attributes). They are counted, not kept: every object has
    /// them and they say nothing about what is in the image.
    pub non_allocated: usize,
    /// The symbols the map lists under its linked input sections (`0x… name` lines), in file
    /// order. ld lists global symbols only, not `static` ones.
    pub symbols: Vec<String>,
}

impl ObjectUsage {
    /// Whether any of the object's code or data is in the image.
    pub fn is_linked(&self) -> bool {
        self.linked.iter().any(InputSection::occupies_image)
    }

    /// The first section that makes the object linked, if any.
    pub fn first_linked(&self) -> Option<&InputSection> {
        self.linked.iter().find(|s| s.occupies_image())
    }
}

/// An `Archive member included …` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveMember {
    /// The member.
    pub object: ObjectId,
    /// The file whose reference pulled it in, if one is named.
    pub referrer: Option<String>,
    /// The symbol that was referenced, if one is named.
    pub symbol: Option<String>,
    /// Whether it was included by `--whole-archive` rather than a reference.
    pub whole_archive: bool,
    /// The 1-based line of the member.
    pub line: u32,
}

/// A `LOAD` line: a file given to the linker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Load {
    /// The normalised path (or `linker stubs`).
    pub path: String,
    /// The 1-based line.
    pub line: u32,
}

/// Why a map could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LinkerMapError {
    /// The text has no `Linker script and memory map` header.
    #[error("not a GNU ld map file (no \"{MEMORY_MAP}\" header)")]
    NotGnuLd,
    /// An address or size is not a 64-bit hex number.
    #[error("line {line}: {token:?} is not a 64-bit hex number")]
    BadNumber {
        /// The 1-based line.
        line: u32,
        /// The token.
        token: String,
    },
}

impl LinkerMap {
    /// Every object the map mentions, in [`ObjectId`] order.
    pub fn objects(&self) -> impl Iterator<Item = (&ObjectId, &ObjectUsage)> {
        self.objects.iter()
    }

    /// The objects that are linked ([`ObjectUsage::is_linked`]), in [`ObjectId`] order.
    pub fn linked_objects(&self) -> impl Iterator<Item = (&ObjectId, &ObjectUsage)> {
        self.objects.iter().filter(|(_, usage)| usage.is_linked())
    }

    /// What the map says about `object`, if it mentions it in a section list.
    pub fn usage(&self, object: &ObjectId) -> Option<&ObjectUsage> {
        self.objects.get(object)
    }

    /// The archive members the link included, in file order.
    pub fn archive_members(&self) -> &[ArchiveMember] {
        &self.archive_members
    }

    /// The `LOAD` lines, in file order.
    pub fn loads(&self) -> &[Load] {
        &self.loads
    }

    /// The first line that shows the image was linked with link-time optimisation (an
    /// `ltrans` object, or a `.gnu.lto_` section), if any.
    pub fn lto_line(&self) -> Option<u32> {
        self.lto
    }

    /// The line of GNU ld's `OUTPUT(<file> <bfd-target>)` line, near the end of the memory
    /// map; `None` when the map has none, as when it was cut short.
    pub fn output_line(&self) -> Option<u32> {
        self.output_line
    }
}

/// Whether a section name is one GNU toolchains never allocate in the image (debug
/// information, comments, attributes).
pub fn is_non_allocated(name: &str) -> bool {
    const PREFIXES: [&str; 6] = [
        ".debug",
        ".zdebug",
        ".stab",
        ".gnu.build.attributes",
        ".mdebug",
        ".xt.",
    ];
    const NAMES: [&str; 8] = [
        ".comment",
        ".line",
        ".ARM.attributes",
        ".riscv.attributes",
        ".gnu.attributes",
        ".xtensa.info",
        ".pdr",
        ".note.GNU-stack",
    ];
    PREFIXES.iter().any(|p| name.starts_with(p)) || NAMES.contains(&name)
}

/// `\` → `/`, and `.` and `..` segments collapsed (a leading `..` of a relative path stays).
pub fn normalise_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let absolute = path.starts_with('/');
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => match segments.last() {
                Some(&last) if last != ".." => {
                    segments.pop();
                }
                _ if absolute => {}
                _ => segments.push(".."),
            },
            other => segments.push(other),
        }
    }
    let joined = segments.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Which part of the map a line is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Preamble,
    ArchiveMembers,
    Skipped,
    Discarded,
    MemoryMap,
}

/// Parser state.
struct Parser {
    map: LinkerMap,
    part: Part,
    /// The output section the memory map is in.
    output: String,
    /// A wrapped input-section name awaiting its address line.
    pending_section: Option<String>,
    /// An archive member awaiting its referrer line.
    pending_member: Option<ArchiveMember>,
    /// The object of the last input section placed in an allocated output section, which the
    /// symbol lines that follow belong to.
    last_linked: Option<ObjectId>,
    seen_memory_map: bool,
}

/// Whether `text` names link-time-optimisation output: GCC's `….ltrans0.ltrans.o`, or the
/// `(symbol from plugin)` marker GNU ld writes for objects an LTO plugin (GCC's or Clang's
/// LLVMgold) produced.
fn is_lto_object(text: &str) -> bool {
    text.contains(".ltrans") || text.contains("(symbol from plugin)")
}

/// Whether `token` can be a symbol name on a `0x… name` line. Accepting a leading `$` is
/// harmless: ld does not print ARM mapping symbols (`$t`, `$d`), and any name it prints is a
/// symbol in the image.
fn is_symbol_token(token: &str) -> bool {
    let mut chars = token.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '.'))
}

fn parse_hex(token: &str, line: u32) -> Result<u64, LinkerMapError> {
    let digits = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
        .unwrap_or(token);
    u64::from_str_radix(digits, 16).map_err(|_| LinkerMapError::BadNumber {
        line,
        token: token.to_owned(),
    })
}

fn is_hex_token(token: &str) -> bool {
    token.starts_with("0x") || token.starts_with("0X")
}

/// `(--whole-archive)`, `file.o (symbol)` or `file.o` → (referrer, symbol, whole_archive).
fn parse_referrer(text: &str) -> (Option<String>, Option<String>, bool) {
    let text = text.trim();
    if text.is_empty() {
        return (None, None, false);
    }
    if text == "(--whole-archive)" {
        return (None, None, true);
    }
    if let Some(inner) = text.strip_suffix(')')
        && let Some(open) = inner.rfind(" (")
    {
        let referrer = inner.get(..open).unwrap_or_default().trim();
        let symbol = inner.get(open.saturating_add(2)..).unwrap_or_default();
        return (
            (!referrer.is_empty()).then(|| normalise_path(referrer)),
            (!symbol.is_empty()).then(|| symbol.to_owned()),
            false,
        );
    }
    (Some(normalise_path(text)), None, false)
}

impl Parser {
    fn new() -> Self {
        Self {
            map: LinkerMap::default(),
            part: Part::Preamble,
            output: String::new(),
            pending_section: None,
            pending_member: None,
            last_linked: None,
            seen_memory_map: false,
        }
    }

    fn flush_member(&mut self) {
        if let Some(member) = self.pending_member.take() {
            self.map.archive_members.push(member);
        }
    }

    /// Switches part when `line` is a section header; returns whether it was one.
    fn header(&mut self, line: &str) -> bool {
        let part = match line.trim_end() {
            ARCHIVE_MEMBERS | AS_NEEDED => Part::ArchiveMembers,
            DISCARDED => Part::Discarded,
            COMMON_SYMBOLS | MEMORY_CONFIGURATION | CROSS_REFERENCE => Part::Skipped,
            MEMORY_MAP => {
                self.seen_memory_map = true;
                Part::MemoryMap
            }
            _ => return false,
        };
        self.flush_member();
        self.pending_section = None;
        self.last_linked = None;
        self.output.clear();
        self.part = part;
        true
    }

    fn line(&mut self, line: &str, number: u32) -> Result<(), LinkerMapError> {
        if self.header(line) {
            return Ok(());
        }
        if self.map.lto.is_none() && line.contains("(symbol from plugin)") {
            self.map.lto = Some(number);
        }
        match self.part {
            Part::Preamble | Part::Skipped => Ok(()),
            Part::ArchiveMembers => {
                self.archive_member_line(line, number);
                Ok(())
            }
            Part::Discarded | Part::MemoryMap => self.section_line(line, number),
        }
    }

    fn archive_member_line(&mut self, line: &str, number: u32) {
        if line.trim().is_empty() {
            self.flush_member();
            return;
        }
        if line.starts_with(char::is_whitespace) {
            // The referrer of a member whose name filled the first column.
            if let Some(member) = self.pending_member.as_mut()
                && member.referrer.is_none()
                && member.symbol.is_none()
                && !member.whole_archive
            {
                let (referrer, symbol, whole) = parse_referrer(line);
                member.referrer = referrer;
                member.symbol = symbol;
                member.whole_archive = whole;
            }
            self.flush_member();
            return;
        }
        self.flush_member();
        // `member` then, after a run of spaces, the referrer; or `member` alone.
        let (object, rest) = match line.find("  ") {
            Some(at) => (
                line.get(..at).unwrap_or_default(),
                line.get(at..).unwrap_or_default(),
            ),
            None => (line, ""),
        };
        let (referrer, symbol, whole_archive) = parse_referrer(rest);
        self.pending_member = Some(ArchiveMember {
            object: ObjectId::parse(object),
            referrer,
            symbol,
            whole_archive,
            line: number,
        });
    }

    fn record(&mut self, name: String, tokens: &[&str], number: u32) -> Result<(), LinkerMapError> {
        let (Some(address), Some(size)) = (tokens.first(), tokens.get(1)) else {
            return Ok(());
        };
        let address = parse_hex(address, number)?;
        let size = parse_hex(size, number)?;
        let Some(file_tokens) = tokens.get(2..).filter(|t| !t.is_empty()) else {
            // An address and size with no file: nothing to attribute.
            return Ok(());
        };
        let object = ObjectId::parse(&file_tokens.join(" "));
        if self.map.lto.is_none()
            && (name.starts_with(".gnu.lto_") || is_lto_object(&object.member))
        {
            self.map.lto = Some(number);
        }
        let output_section = if self.part == Part::Discarded {
            String::new()
        } else {
            self.output.clone()
        };
        let discarded = self.part == Part::Discarded || output_section == DISCARD_SECTION;
        let section = InputSection {
            name,
            output_section,
            address,
            size,
            line: number,
        };
        self.last_linked = None;
        let usage = self.map.objects.entry(object.clone()).or_default();
        if is_non_allocated(&section.name) || is_non_allocated(&section.output_section) {
            usage.non_allocated = usage.non_allocated.saturating_add(1);
        } else if discarded {
            usage.discarded.push(section);
        } else {
            usage.linked.push(section);
            self.last_linked = Some(object);
        }
        Ok(())
    }

    fn section_line(&mut self, line: &str, number: u32) -> Result<(), LinkerMapError> {
        let pending = self.pending_section.take();
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(&first) = tokens.first() else {
            return Ok(());
        };
        if !line.starts_with(char::is_whitespace) {
            // Column 0: a LOAD line, an output section header, or linker directives.
            if self.part == Part::MemoryMap {
                if first == "LOAD" {
                    let path = line.get(4..).unwrap_or_default().trim();
                    if self.map.lto.is_none() && is_lto_object(path) {
                        self.map.lto = Some(number);
                    }
                    if !path.is_empty() {
                        self.map.loads.push(Load {
                            path: normalise_path(path),
                            line: number,
                        });
                    }
                } else if line.starts_with("START GROUP") || line.starts_with("END GROUP") {
                    // `--start-group`/`--end-group` markers around LOAD lines: not sections.
                } else if line.starts_with("OUTPUT(") && line.trim_end().ends_with(')') {
                    self.map.output_line = Some(number);
                } else if !first.contains('(') {
                    self.output = first.to_owned();
                    self.last_linked = None;
                }
            }
            return Ok(());
        }
        let one_space = line.starts_with(' ')
            && !line
                .get(1..)
                .unwrap_or_default()
                .starts_with(char::is_whitespace);
        if one_space {
            // ` name addr size file`, or ` name` alone when the name is long.
            self.last_linked = None;
            if first.starts_with('*') {
                return Ok(());
            }
            match tokens.get(1) {
                None => self.pending_section = Some(first.to_owned()),
                Some(second) if is_hex_token(second) => {
                    let rest = tokens.get(1..).unwrap_or_default();
                    // `FILL mask 0x..`, `LONG 0x..` and the like have no size token.
                    if rest.get(1).is_some_and(|t| is_hex_token(t)) {
                        self.record(first.to_owned(), rest, number)?;
                    }
                }
                Some(_) => {}
            }
            return Ok(());
        }
        // Deeper indentation: the address line of a wrapped name, or a symbol/assignment.
        if let Some(name) = pending
            && tokens.len() >= 3
            && is_hex_token(first)
            && tokens.get(1).is_some_and(|t| is_hex_token(t))
        {
            self.record(name, &tokens, number)?;
            return Ok(());
        }
        // `0x… name`: a symbol defined in the input section just listed.
        if self.part == Part::MemoryMap
            && let [address, symbol] = tokens.as_slice()
            && is_hex_token(address)
            && is_symbol_token(symbol)
            && let Some(object) = &self.last_linked
            && let Some(usage) = self.map.objects.get_mut(object)
        {
            usage.symbols.push((*symbol).to_owned());
        }
        Ok(())
    }
}

/// Parses a GNU ld map. See the [module docs](self).
pub fn parse(text: &str) -> Result<LinkerMap, LinkerMapError> {
    let mut parser = Parser::new();
    for (index, raw) in text.split('\n').enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let number = u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX);
        parser.line(line, number)?;
    }
    parser.flush_member();
    if !parser.seen_memory_map {
        return Err(LinkerMapError::NotGnuLd);
    }
    Ok(parser.map)
}

/// Why a map gives no evidence about which functions are linked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NoLinkEvidence {
    /// The image was linked with link-time optimisation: functions may be inlined into, or
    /// moved to, `ltrans` objects whose sections do not name them.
    #[error("line {line}: the image was linked with link-time optimisation")]
    Lto {
        /// The first line showing it.
        line: u32,
    },
    /// The map is incomplete: it has no `OUTPUT(…)` line near the end of the memory map (it
    /// was cut short), or it places no input section in the image.
    #[error("the map is incomplete: {reason}")]
    Incomplete {
        /// What is missing.
        reason: &'static str,
    },
    /// An object outside the C runtime libraries has code in a section that names no
    /// function (`.text`, or `.text.unlikely` and the like): it was built without
    /// `-ffunction-sections`, so the map does not say which functions it holds.
    #[error("line {line}: {object} has code in {section}, which names no function")]
    UnsplitText {
        /// The object.
        object: String,
        /// The section, e.g. `.text`.
        section: String,
        /// The section's line.
        line: u32,
    },
}

/// The toolchain's C and compiler runtime archives, whose objects are built without
/// `-ffunction-sections` (plain `.text`; the fixtures link `memchr.S.o`, `strlen.S.o` and the
/// like from `libc.a`, and the 64-bit division helpers from `libgcc.a`). They cannot define an
/// application's or a library's functions, so they do not make [`linked_functions`] give up;
/// but which of their functions are linked is not known.
const RUNTIME_ARCHIVES: [&str; 2] = ["libc.a", "libgcc.a"];

/// GCC's prefixes for functions it places by profile: `.text.unlikely.foo` is `foo`.
const TEXT_PREFIXES: [&str; 4] = ["unlikely.", "startup.", "hot.", "exit."];

/// The function a `.text.…` section name holds: `.text.foo` → `foo`, also for GCC's
/// placement prefixes (`.text.unlikely.foo`) and clones (`.text.foo.constprop.0`,
/// `.text.foo.isra.0`, `.text.foo.part.0`, `.text.foo.cold`). A bare placement prefix
/// (`.text.exit`) gives the prefix's word: with `-ffunction-sections` it is a function of
/// that name (C's `exit`, say); [`is_ambiguous_text`] covers the other reading. `None` for
/// `.text` and anything not under `.text.`.
fn text_section_function(name: &str) -> Option<&str> {
    let rest = name.strip_prefix(".text.")?;
    let rest = TEXT_PREFIXES
        .iter()
        .find_map(|p| rest.strip_prefix(p))
        .unwrap_or(rest);
    let function = rest.split('.').next().unwrap_or_default();
    (!function.is_empty()).then_some(function)
}

/// Whether a code section might name no function: `.text`, or a bare placement prefix
/// (`.text.unlikely`, `.text.exit`, …), which is what GCC emits without
/// `-ffunction-sections` (and also the section of a function named `exit` with it).
fn is_ambiguous_text(name: &str) -> bool {
    name == ".text"
        || name.strip_prefix(".text.").is_some_and(|rest| {
            TEXT_PREFIXES
                .iter()
                .any(|p| p.strip_suffix('.') == Some(rest))
        })
}

/// Whether the object was compiled with `-ffunction-sections`: some section of it, linked or
/// discarded, is `.text.<name>` other than a bare placement prefix.
fn has_function_sections(usage: &ObjectUsage) -> bool {
    usage
        .linked
        .iter()
        .chain(&usage.discarded)
        .any(|s| s.name.starts_with(".text.") && !is_ambiguous_text(&s.name))
}

/// Whether the object is a member of the toolchain's `libc.a` or `libgcc.a`: the archive's
/// file name is one of [`RUNTIME_ARCHIVES`] and its path is an absolute one with a `/lib/`
/// directory, as a toolchain's sysroot is (`/opt/zephyr-sdk/…/arm-zephyr-eabi/lib/…/libc.a`).
/// Archives the build made are relative to the build directory (a C library built as a
/// Zephyr module, say), so they are not exempt. The match is by name and location only: an
/// unrelated absolute `…/lib/…/libc.a` would be exempt too.
fn is_runtime_archive(object: &ObjectId) -> bool {
    object.archive.as_deref().is_some_and(|archive| {
        let file = archive.rsplit('/').next().unwrap_or(archive);
        let absolute = archive.starts_with('/')
            || matches!(archive.as_bytes(), [drive, b':', b'/', ..] if drive.is_ascii_alphabetic());
        RUNTIME_ARCHIVES.contains(&file) && absolute && archive.contains("/lib/")
    })
}

/// The functions in the image, as evidence for VEX `symbol_not_linked` conditions
/// ([`crate::vex::BuildEvidence::with_linked_symbols`]). Sorted, each name once.
///
/// A name is linked when the map shows it in the image either way:
///
/// - an input section `.text.<name>` that occupies the image ([`InputSection::occupies_image`]),
///   including GCC's placement prefixes and clones (see `.text.unlikely.foo`,
///   `.text.foo.constprop.0`): Zephyr compiles with `-ffunction-sections`, so each function
///   is its own section, and one the linker garbage-collected is not there;
/// - a symbol line (`0x… name`) under any section placed in the image (global symbols only).
///
/// The answer is conservative: a name that is not in the set must really be absent. So
/// rather than a set that could miss a function, it returns [`NoLinkEvidence`] when:
///
/// - the map is incomplete: it has no `OUTPUT(<file> <bfd-target>)` line near the end of
///   the memory map (GNU ld always writes one, so a map without it was cut short), or no
///   input section in the image at all;
/// - the map shows link-time optimisation (an `ltrans` object, a `.gnu.lto_` section, or
///   ld's `(symbol from plugin)` marker): functions may be inlined or moved into objects
///   whose sections do not name them;
/// - an object outside the toolchain's `libc.a` and `libgcc.a` has non-empty code in plain
///   `.text`, or in a bare placement section (`.text.unlikely`, `.text.hot`,
///   `.text.startup`; `.text.exit` too unless the object was built with
///   `-ffunction-sections`, where it is the C function `exit`): built without
///   `-ffunction-sections`, such as a prebuilt library or assembly.
///
/// Limits, so what `symbol_not_linked` can prove:
///
/// - only the absence of a function that is non-`static`, built with `-ffunction-sections`,
///   not placed in a custom section (`.ramfunc`, `.itcm`, …), and called only from other
///   source files. GCC may inline any function, `static` or not, into a caller in its own
///   file, and `--gc-sections` then drops the out-of-line copy; code in a section that names
///   no function is not seen either;
/// - never the absence of a C-runtime function: which functions of `libc.a` and `libgcc.a`
///   are linked is not known (their plain `.text` is not counted against the answer).
///
/// `docs/vex-rules.md` ("Using `symbol_not_linked`") gives the same rules to rule authors.
pub fn linked_functions(map: &LinkerMap) -> Result<BTreeSet<String>, NoLinkEvidence> {
    if map.output_line.is_none() {
        return Err(NoLinkEvidence::Incomplete {
            reason: "no OUTPUT(…) line near the end of the memory map (cut short?)",
        });
    }
    if !map.objects.values().any(ObjectUsage::is_linked) {
        return Err(NoLinkEvidence::Incomplete {
            reason: "no input section is placed in the image",
        });
    }
    if let Some(line) = map.lto {
        return Err(NoLinkEvidence::Lto { line });
    }
    let mut functions = BTreeSet::new();
    for (object, usage) in &map.objects {
        let split = has_function_sections(usage);
        for section in usage.linked.iter().filter(|s| s.occupies_image()) {
            // In a -ffunction-sections object, `.text.exit` is the C function `exit`; the
            // other bare placement sections are never a function's own section.
            let unsplit = section.name == ".text"
                || (is_ambiguous_text(&section.name) && (section.name != ".text.exit" || !split));
            if unsplit && !is_runtime_archive(object) {
                return Err(NoLinkEvidence::UnsplitText {
                    object: object.to_string(),
                    section: section.name.clone(),
                    line: section.line,
                });
            }
            if !unsplit && let Some(function) = text_section_function(&section.name) {
                functions.insert(function.to_owned());
            }
        }
        if usage.is_linked() {
            functions.extend(usage.symbols.iter().cloned());
        }
    }
    Ok(functions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A small map in GNU ld's layout, exercising every quirk the parser handles.
    const MAP: &str = "\
Archive member included to satisfy reference by file (symbol)

app/libapp.a(main.c.obj)      (--whole-archive)
zephyr/subsys/bluetooth/host/libsubsys__bluetooth__host.a(hci_core.c.obj)
                              app/libapp.a(main.c.obj) (bt_enable)
zephyr/libzephyr.a(log_core.c.obj)
                              (--whole-archive)
zephyr/subsys/net/libsubsys__net.a(gc.c.obj)
                              zephyr/libzephyr.a(log_core.c.obj) (net_gc)

Discarded input sections

 .text          0x00000000        0x0 app/libapp.a(main.c.obj)
 .text.net_gc_unused
                0x00000000       0x24 zephyr/subsys/net/libsubsys__net.a(gc.c.obj)
 .debug_info    0x00000000       0x80 zephyr/subsys/net/libsubsys__net.a(gc.c.obj)

Memory Configuration

Name             Origin             Length             Attributes
FLASH            0x00000000         0x00100000         xr

Linker script and memory map

                0x00000020                        _region_min_align = 0x20
LOAD zephyr/CMakeFiles/offsets.dir/./arch/arm/core/offsets/offsets.c.obj
LOAD app/libapp.a
LOAD /sdk/bin/../lib/libc.a
LOAD linker stubs

text            0x00001000      0x400
 *(SORT_BY_ALIGNMENT(.text.*))
 .text.main     0x00001000       0x28 app/libapp.a(main.c.obj)
                0x00001000                main
 .text.bt_hci_cmd_send_sync_with_a_long_name
                0x00001028      0x1c8 zephyr/subsys/bluetooth/host/libsubsys__bluetooth__host.a(hci_core.c.obj)
                0x00001028                bt_hci_cmd_send_sync_with_a_long_name
 *fill*         0x000011f0        0x4
 .text.strlen   0x000011f4       0x10 /sdk/bin/../lib/libc.a(strlen.o)
 FILL mask 0x00
 .glue_7        0x00001204        0x0 linker stubs
 .text.empty    0x00001204        0x0 zephyr/CMakeFiles/offsets.dir/./arch/arm/core/offsets/offsets.c.obj
                [!provide]                        PROVIDE (__end = .)

/DISCARD/
 *(SORT_BY_ALIGNMENT(.plt))
 .plt           0x00000000        0x8 zephyr/libzephyr.a(log_core.c.obj)

.debug_info     0x00000000     0x2000
 .debug_info    0x00000000      0x100 zephyr/libzephyr.a(log_core.c.obj)
 .debug_info    0x00000100      0x100 zephyr/subsys/net/libsubsys__net.a(gc.c.obj)

.comment        0x00000000       0x20
 .comment       0x00000000       0x20 zephyr/libzephyr.a(log_core.c.obj)
OUTPUT(zephyr/zephyr.elf elf32-littlearm)
LOAD linker stubs
";

    fn id(archive: &str, member: &str) -> ObjectId {
        ObjectId {
            archive: Some(archive.to_owned()),
            member: member.to_owned(),
        }
    }

    fn linked_names(map: &LinkerMap) -> Vec<String> {
        map.linked_objects().map(|(o, _)| o.to_string()).collect()
    }

    #[test]
    fn parses_input_sections_with_archive_members() {
        let map = parse(MAP).unwrap();
        let main = map.usage(&id("app/libapp.a", "main.c.obj")).unwrap();
        assert!(main.is_linked());
        let first = main.first_linked().unwrap();
        assert_eq!(first.name, ".text.main");
        assert_eq!(first.output_section, "text");
        assert_eq!((first.address, first.size), (0x1000, 0x28));
        assert_eq!(first.line, 33);
        // `main.c.obj`'s empty `.text` was discarded too.
        assert_eq!(main.discarded.len(), 1);
        assert_eq!(
            linked_names(&map),
            [
                "/sdk/lib/libc.a(strlen.o)",
                "app/libapp.a(main.c.obj)",
                "zephyr/subsys/bluetooth/host/libsubsys__bluetooth__host.a(hci_core.c.obj)",
            ]
        );
    }

    #[test]
    fn linked_functions_are_the_linked_text_sections_and_symbols() {
        let map = parse(MAP).unwrap();
        // `strlen.o` is in libc.a, whose plain sections do not count against the answer.
        let functions: Vec<String> = linked_functions(&map).unwrap().into_iter().collect();
        // Not `.text.empty` (size 0), `.text.net_gc_unused` (discarded) or `.glue_7`; `main`
        // is also a symbol line, `bt_hci_cmd_send_sync_with_a_long_name` too.
        assert_eq!(
            functions,
            ["bt_hci_cmd_send_sync_with_a_long_name", "main", "strlen"]
        );
        assert!(matches!(
            linked_functions(&LinkerMap::default()),
            Err(NoLinkEvidence::Incomplete { .. })
        ));
        let main = map.usage(&id("app/libapp.a", "main.c.obj")).unwrap();
        assert_eq!(main.symbols, ["main"]);
    }

    /// A map with one input section and its symbol lines, from `file`.
    fn one_section(section: &str, file: &str, symbols: &[&str]) -> String {
        let mut text = format!(
            "Linker script and memory map\n\ntext            0x00001000      0x400\n {section}\n                0x00001000       0x28 {file}\n"
        );
        for symbol in symbols {
            text.push_str(&format!(
                "                0x00001000                {symbol}\n"
            ));
        }
        text.push_str(OUTPUT);
        text
    }

    const OUTPUT: &str = "OUTPUT(zephyr/zephyr.elf elf32-littlearm)\n";

    #[test]
    fn incomplete_maps_give_no_evidence() {
        // The header alone: every symbol_not_linked would otherwise be true.
        for text in [
            "Linker script and memory map\n",
            "Linker script and memory map\n\nOUTPUT(zephyr/zephyr.elf elf32-littlearm)\n",
        ] {
            assert!(
                matches!(
                    linked_functions(&parse(text).unwrap()),
                    Err(NoLinkEvidence::Incomplete { .. })
                ),
                "{text:?}"
            );
        }
        // MAP cut anywhere inside its memory map, before the OUTPUT line.
        let memory_map = MAP.find("Linker script and memory map").unwrap();
        let output = MAP.find("OUTPUT(").unwrap();
        for cut in (memory_map + 30..output).step_by(7) {
            let Ok(map) = parse(&MAP[..cut]) else {
                continue;
            };
            assert!(
                matches!(
                    linked_functions(&map),
                    Err(NoLinkEvidence::Incomplete { .. })
                ),
                "cut at {cut}"
            );
        }
        assert!(linked_functions(&parse(MAP).unwrap()).is_ok());
    }

    #[test]
    fn plugin_lto_gives_no_evidence() {
        // Clang (LLVMgold) or GCC's plugin through GNU ld: objects marked `(symbol from plugin)`.
        let text = format!(
            "Archive member included to satisfy reference by file (symbol)\n\napp/libapp.a(main.c.o)\n                              (symbol from plugin) (main)\n\n{}",
            one_section(".text.main", "app/libapp.a(main.c.o)", &[])
        );
        assert_eq!(
            linked_functions(&parse(&text).unwrap()),
            Err(NoLinkEvidence::Lto { line: 4 })
        );
    }

    #[test]
    fn only_the_toolchains_libc_and_libgcc_are_exempt() {
        for (file, exempt) in [
            (
                "/opt/zephyr-sdk/arm-zephyr-eabi/lib/thumb/libc.a(strlen.S.o)",
                true,
            ),
            (
                "C:/zephyr-sdk/lib/gcc/arm-zephyr-eabi/14.3.0/libgcc.a(_udivmoddi4.o)",
                true,
            ),
            // Another runtime archive, a C library the build made, and a vendor libc.a.
            (
                "/opt/zephyr-sdk/arm-zephyr-eabi/lib/thumb/libm.a(s_sin.o)",
                false,
            ),
            ("modules/picolibc/libc.a(strlen.c.obj)", false),
            ("/opt/vendor/blobs/libc.a(x.o)", false),
        ] {
            let result = linked_functions(&parse(&one_section(".text", file, &[])).unwrap());
            assert_eq!(result.is_ok(), exempt, "{file}: {result:?}");
        }
    }

    #[test]
    fn bare_placement_sections_in_split_objects_are_refused_except_exit() {
        for (bare, ok) in [
            (".text.unlikely", false),
            (".text.hot", false),
            (".text.startup", false),
            (".text.exit", true),
        ] {
            let text = format!(
                "{}{}",
                one_section(bare, "lib/libmbedtls.a(platform.c.obj)", &[]),
                " .text.mbedtls_free\n                0x00001028        0x4 lib/libmbedtls.a(platform.c.obj)\n"
            );
            let result = linked_functions(&parse(&text).unwrap());
            assert_eq!(result.is_ok(), ok, "{bare}: {result:?}");
        }
    }

    #[test]
    fn gcc_clones_and_placement_prefixes_count_as_linked() {
        for (section, function) in [
            (
                ".text.mbedtls_ssl_handshake_client_step.constprop.0",
                "mbedtls_ssl_handshake_client_step",
            ),
            (".text.foo.isra.0", "foo"),
            (".text.foo.part.0", "foo"),
            (".text.foo.cold", "foo"),
            (".text.unlikely.foo", "foo"),
            (".text.startup.main", "main"),
            (".text.hot.foo.constprop.1", "foo"),
        ] {
            let map = parse(&one_section(section, "lib/libx.a(x.c.obj)", &[])).unwrap();
            let functions = linked_functions(&map).unwrap();
            assert!(functions.contains(function), "{section}: {functions:?}");
        }
    }

    #[test]
    fn unsplit_text_outside_the_runtime_gives_no_evidence() {
        // A prebuilt library's plain `.text`, even when ld names a symbol in it: a `static`
        // function there would not be listed.
        let map = parse(&one_section(
            ".text",
            "vendor/libblob.a(blob.o)",
            &["blob_init"],
        ))
        .unwrap();
        assert_eq!(
            linked_functions(&map),
            Err(NoLinkEvidence::UnsplitText {
                object: "vendor/libblob.a(blob.o)".to_owned(),
                section: ".text".to_owned(),
                line: 5,
            })
        );
        let map = parse(&one_section(".text.unlikely", "app/libapp.a(a.c.obj)", &[])).unwrap();
        assert!(matches!(
            linked_functions(&map),
            Err(NoLinkEvidence::UnsplitText { .. })
        ));
        // In an object built with -ffunction-sections, `.text.exit` is the function `exit`
        // (Mbed TLS's platform.c in the old-mbedTLS fixture has one).
        let split = format!(
            "{}{}",
            one_section(".text.exit", "lib/libmbedtls.a(platform.c.obj)", &[]),
            " .text.mbedtls_free\n                0x00001028        0x4 lib/libmbedtls.a(platform.c.obj)\n"
        );
        let functions = linked_functions(&parse(&split).unwrap()).unwrap();
        assert!(
            functions.contains("exit") && functions.contains("mbedtls_free"),
            "{functions:?}"
        );
        // The C runtime's plain `.text` is fine; its global symbols are reported.
        let map = parse(&one_section(
            ".text",
            "/sdk/lib/thumb/libgcc.a(_udivmoddi4.o)",
            &["__udivmoddi4"],
        ))
        .unwrap();
        assert_eq!(
            linked_functions(&map)
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            ["__udivmoddi4"]
        );
    }

    #[test]
    fn lto_map_gives_no_evidence() {
        let ltrans = one_section(
            ".text",
            "/tmp/ccA1b2C3.ltrans0.ltrans.o",
            &["mbedtls_ssl_handshake_server_step"],
        );
        assert_eq!(
            linked_functions(&parse(&ltrans).unwrap()),
            Err(NoLinkEvidence::Lto { line: 5 })
        );
        let load = format!(
            "Linker script and memory map\n\nLOAD /tmp/ccX.ltrans0.ltrans.o\n{}",
            one_section(".text.main", "app/libapp.a(main.c.obj)", &[])
                .replace("Linker script and memory map\n\n", "")
        );
        assert_eq!(
            linked_functions(&parse(&load).unwrap()),
            Err(NoLinkEvidence::Lto { line: 3 })
        );
        let lto_section = one_section(".gnu.lto_main.0", "app/libapp.a(main.c.obj)", &[]);
        assert!(matches!(
            linked_functions(&parse(&lto_section).unwrap()),
            Err(NoLinkEvidence::Lto { .. })
        ));
    }

    #[test]
    fn wrapped_long_section_names_attach_to_next_line() {
        let map = parse(MAP).unwrap();
        let hci = map
            .usage(&id(
                "zephyr/subsys/bluetooth/host/libsubsys__bluetooth__host.a",
                "hci_core.c.obj",
            ))
            .unwrap();
        let [section] = hci.linked.as_slice() else {
            panic!("{hci:?}")
        };
        assert_eq!(section.name, ".text.bt_hci_cmd_send_sync_with_a_long_name");
        assert_eq!(
            (section.address, section.size, section.line),
            (0x1028, 0x1c8, 36)
        );
        // The wrapped discarded section too.
        let gc = map
            .usage(&id("zephyr/subsys/net/libsubsys__net.a", "gc.c.obj"))
            .unwrap();
        assert_eq!(
            gc.discarded.first().map(|s| s.name.as_str()),
            Some(".text.net_gc_unused")
        );
        assert_eq!(gc.discarded.first().map(|s| s.size), Some(0x24));
    }

    #[test]
    fn archive_member_list_parses_wrapped_referrers() {
        let map = parse(MAP).unwrap();
        let members = map.archive_members();
        assert_eq!(members.len(), 4, "{members:#?}");
        let [app, hci, log, gc] = members else {
            panic!("{members:#?}")
        };
        assert_eq!(app.object, id("app/libapp.a", "main.c.obj"));
        assert!(app.whole_archive && app.referrer.is_none() && app.symbol.is_none());
        assert_eq!(app.line, 3);
        assert_eq!(hci.referrer.as_deref(), Some("app/libapp.a(main.c.obj)"));
        assert_eq!(hci.symbol.as_deref(), Some("bt_enable"));
        assert!(!hci.whole_archive);
        assert!(log.whole_archive);
        assert_eq!(gc.symbol.as_deref(), Some("net_gc"));
        assert_eq!(gc.line, 8);
    }

    #[test]
    fn discarded_only_object_is_not_linked() {
        let map = parse(MAP).unwrap();
        let gc = map
            .usage(&id("zephyr/subsys/net/libsubsys__net.a", "gc.c.obj"))
            .unwrap();
        // Only discarded sections and debug information: garbage-collected.
        assert!(!gc.is_linked(), "{gc:?}");
        // The discarded `.debug_info` is counted, not kept.
        assert_eq!(gc.discarded.len(), 1);
        assert_eq!(gc.non_allocated, 2);
        // Listed as an included archive member all the same.
        assert!(
            map.archive_members()
                .iter()
                .any(|m| m.object.member == "gc.c.obj")
        );
    }

    #[test]
    fn object_with_only_debug_discard_or_zero_size_sections_is_not_linked() {
        let map = parse(MAP).unwrap();
        // log_core: `/DISCARD/`, `.debug_info` and `.comment` only.
        let log = map
            .usage(&id("zephyr/libzephyr.a", "log_core.c.obj"))
            .unwrap();
        assert!(!log.is_linked(), "{log:?}");
        assert_eq!(log.discarded.len(), 1);
        assert!(log.linked.is_empty(), "{log:?}");
        assert_eq!(log.non_allocated, 2);
        // offsets.c.obj: a zero-size section only.
        let offsets =
            ObjectId::parse("zephyr/CMakeFiles/offsets.dir/arch/arm/core/offsets/offsets.c.obj");
        assert!(!map.usage(&offsets).unwrap().is_linked());
        // linker stubs: zero-size veneers.
        assert!(
            !map.usage(&ObjectId::parse("linker stubs"))
                .unwrap()
                .is_linked()
        );
    }

    #[test]
    fn fill_load_stubs_symbol_and_pattern_lines_are_ignored() {
        let map = parse(MAP).unwrap();
        let loads: Vec<&str> = map.loads().iter().map(|l| l.path.as_str()).collect();
        assert_eq!(
            loads,
            [
                "zephyr/CMakeFiles/offsets.dir/arch/arm/core/offsets/offsets.c.obj",
                "app/libapp.a",
                "/sdk/lib/libc.a",
                "linker stubs",
                "linker stubs",
            ]
        );
        // No object named after a symbol, `*fill*`, `FILL`, a pattern or `PROVIDE`.
        for (object, _) in map.objects() {
            let text = object.to_string();
            assert!(
                !text.contains('*')
                    && !text.contains("PROVIDE")
                    && !["main", "mask", "0x00", "_region_min_align"].contains(&text.as_str()),
                "{text}"
            );
        }
        assert_eq!(
            map.objects().count(),
            7,
            "{:#?}",
            map.objects().collect::<Vec<_>>()
        );
    }

    #[test]
    fn start_and_end_group_lines_are_not_output_sections() {
        let map = parse(
            "Linker script and memory map\n\ntext            0x00000000      0x100\nSTART GROUP\nLOAD a/libm.a\nEND GROUP\n .text.x        0x00000000       0x10 a/libm.a(x.o)\n",
        )
        .unwrap();
        let usage = map.usage(&ObjectId::parse("a/libm.a(x.o)")).unwrap();
        assert!(usage.is_linked());
        assert_eq!(
            usage.first_linked().map(|s| s.output_section.as_str()),
            Some("text")
        );
        let loads: Vec<&str> = map.loads().iter().map(|l| l.path.as_str()).collect();
        assert_eq!(loads, ["a/libm.a"]);
    }

    #[test]
    fn paths_are_normalised() {
        assert_eq!(normalise_path("a/./b/../c"), "a/c");
        assert_eq!(normalise_path("..\\x\\y.a"), "../x/y.a");
        assert_eq!(normalise_path("/sdk/bin/../lib/libc.a"), "/sdk/lib/libc.a");
        assert_eq!(normalise_path("/../x"), "/x");
        assert_eq!(
            normalise_path("./zephyr//libzephyr.a"),
            "zephyr/libzephyr.a"
        );
        let object = ObjectId::parse("zephyr\\.\\lib.a(x.c.obj)");
        assert_eq!(object.archive.as_deref(), Some("zephyr/lib.a"));
        assert_eq!(object.source_name(), "x.c");
        assert_eq!(ObjectId::parse("crt0.o").source_name(), "crt0");
        assert_eq!(ObjectId::parse("dir/a.S.obj").source_name(), "a.S");
        // Not an archive member: no archive before the parenthesis.
        assert_eq!(ObjectId::parse("(x.o)").archive, None);
    }

    #[test]
    fn crlf_accepted() {
        let crlf = MAP.replace('\n', "\r\n");
        assert_eq!(parse(&crlf).unwrap(), parse(MAP).unwrap());
    }

    #[test]
    fn missing_memory_map_header_is_not_gnu_ld() {
        let without = MAP.replace(MEMORY_MAP, "Memory map");
        assert_eq!(parse(&without), Err(LinkerMapError::NotGnuLd));
        // An lld map.
        let lld = "             VMA              LMA     Size Align Out     In      Symbol\n               0                0      1f4     1 . = 0x1000\n";
        assert_eq!(parse(lld), Err(LinkerMapError::NotGnuLd));
    }

    #[test]
    fn bad_hex_is_error_with_line() {
        let bad = MAP.replace(" .text.main     0x00001000", " .text.main     0x0000zz00");
        assert_eq!(
            parse(&bad),
            Err(LinkerMapError::BadNumber {
                line: 33,
                token: "0x0000zz00".to_owned()
            })
        );
        // Wider than 64 bits.
        let wide = MAP.replace("0x1c8 zephyr/subsys", "0x10000000000000000 zephyr/subsys");
        let e = parse(&wide).unwrap_err();
        assert!(
            matches!(e, LinkerMapError::BadNumber { line: 36, .. }),
            "{e}"
        );
        assert!(e.to_string().starts_with("line 36: "), "{e}");
        // `0x` alone.
        let empty = MAP.replace(" .text.main     0x00001000", " .text.main     0x");
        assert!(matches!(
            parse(&empty),
            Err(LinkerMapError::BadNumber { line: 33, .. })
        ));
    }

    #[test]
    fn empty_and_truncated_never_panic() {
        assert_eq!(parse(""), Err(LinkerMapError::NotGnuLd));
        assert_eq!(parse("\n\n\r\n"), Err(LinkerMapError::NotGnuLd));
        // Header only: a map with nothing linked.
        let map = parse(MEMORY_MAP).unwrap();
        assert_eq!(map.objects().count(), 0);
        // Cut at every byte: never a panic. Cut at a line end, the objects read are a subset
        // of the full map's.
        let full = parse(MAP).unwrap();
        for cut in 0..=MAP.len() {
            let Some(prefix) = MAP.get(..cut) else {
                continue;
            };
            let result = parse(prefix);
            if MAP.get(cut..).is_some_and(|rest| rest.starts_with('\n'))
                && let Ok(map) = result
            {
                for (object, _) in map.objects() {
                    assert!(full.usage(object).is_some(), "cut {cut}: {object}");
                }
            }
        }
        // A wrapped name with no address line.
        let map = parse(&format!("{MEMORY_MAP}\ntext 0x0 0x10\n .text.dangling\n")).unwrap();
        assert_eq!(map.objects().count(), 0);
    }

    #[test]
    fn non_allocated_sections() {
        for name in [
            ".debug_info",
            ".debug_str",
            ".comment",
            ".ARM.attributes",
            ".stab",
            ".xt.prop",
        ] {
            assert!(is_non_allocated(name), "{name}");
        }
        for name in [
            ".text",
            "text",
            "rodata",
            ".data",
            "bss",
            ".note.gnu.build-id",
        ] {
            assert!(!is_non_allocated(name), "{name}");
        }
    }

    proptest! {
        #[test]
        fn arbitrary_text_never_panics(text in "\\PC{0,400}") {
            let _ = parse(&text);
            let _ = parse(&format!("{MEMORY_MAP}\n{text}"));
            let _ = parse(&format!("{ARCHIVE_MEMBERS}\n{text}\n{DISCARDED}\n{text}\n{MEMORY_MAP}\n{text}"));
        }

        #[test]
        fn mutated_map_never_panics(cut in 0usize..MAP.len(), insert in "[ \\t\\n()x0-9a-f.*/]{0,6}") {
            let mut text = MAP.get(..cut).unwrap_or(MAP).to_owned();
            text.push_str(&insert);
            text.push_str(MAP.get(cut..).unwrap_or(""));
            let _ = parse(&text);
        }
    }
}
