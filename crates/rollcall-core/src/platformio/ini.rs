//! `platformio.ini`: PlatformIO's project configuration, a Python `configparser` dialect.
//!
//! [`parse`] reads the file into sections and options, keeping every value line's line
//! number. [`ProjectConfig::get`] resolves an option the way PlatformIO Core 6.1.18 does
//! (`platformio/project/config.py`, cited by line below):
//!
//! - **Syntax** (`configparser.ConfigParser(inline_comment_prefixes=("#", ";"))`, line 97).
//!   `[section]` headers; `key = value` or `key: value` (the first `=` or `:` separates;
//!   keys are case-insensitive and stored lowercase, configparser's default `optionxform`,
//!   which PlatformIO does not override); a line starting with whitespace continues the
//!   previous option's value (blank lines inside a value are allowed); full-line comments
//!   start with `;` or `#`, and an inline comment is `;` or `#` after whitespace. A section
//!   or option defined twice is an error (`strict`). A UTF-8 byte-order mark and CRLF line
//!   endings are accepted.
//! - **Inheritance** (`walk_options`, lines 170-185). An option is searched for in a stack of
//!   sections: for `[env:NAME]` the stack starts as `[env]`, `[env:NAME]`; the top section is
//!   popped and searched, and the sections its `extends` names are pushed in order, so the
//!   *last* of them is searched next (depth first). `[env]` is searched last. The first
//!   section that sets the option wins (`_traverse_for_value`, lines 264-274). Any section
//!   can `extends`. A name that is no section is skipped (line 178), with a warning here. A
//!   loop of `extends`, on which PlatformIO itself never returns, is [`IniError::ExtendsCycle`].
//! - **Interpolation** (`_re_interpolation_handler`, lines 343-379). `${section.option}` is
//!   replaced by that option as resolved for `section` (`${env.option}` reads `[env]`).
//!   `${this.option}` reads the section being resolved and `${this.__env__}` is its
//!   environment name (an error outside an environment). An unknown option is
//!   [`IniError::UnknownReference`]. `${sysenv.NAME}` and the built-in `${PROJECT_DIR}`,
//!   `${PROJECT_HASH}` and `${UNIX_TIME}` depend on the machine that built, and any other
//!   `${NAME}` is a SCons variable PlatformIO leaves as written: all of them are left as
//!   written and reported in [`Value::warnings`].
//! - **Lists** ([`ProjectConfig::list`], `parse_multi_values`, lines 67-81). A multi-line
//!   value is one item per line, a one-line value is split at `", "`; items starting with `;`
//!   or `#` are dropped and an inline `;` comment after whitespace is cut.
//!
//! - **Not modelled.** PlatformIO's `configparser.ConfigParser` keeps configparser's default
//!   `BasicInterpolation`, so `%%` is a literal `%` and `%(name)s` is replaced by another
//!   option of the same section (a lone `%` is an error to PlatformIO); and options in a
//!   `[DEFAULT]` section apply to every section. rollcall applies neither: values are read
//!   as written and `[DEFAULT]` is an ordinary section. The ingester warns, with the line,
//!   when the file has a `[DEFAULT]` section or a value it reads (`platform`, `framework`,
//!   `lib_deps`, `platform_packages`, `default_envs`, `extends`) contains `%`.
//!
//! Every error carries the line it is about. Nothing here panics on any input, and every
//! resolution is bounded: section walks and resolved values are memoised, a resolution may
//! take at most 10 000 steps (sections searched, `extends` edges and references followed)
//! and nest references at most 64 deep, and a resolved value may hold at most 1 MiB; beyond
//! any of these, [`IniError::TooLarge`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::rc::Rc;

/// The most steps (sections searched, `extends` edges, references followed) one resolution
/// may take.
pub const MAX_STEPS: usize = 10_000;
/// The deepest chain of nested `${…}` references followed.
pub const MAX_DEPTH: usize = 64;
/// The largest resolved value, in bytes.
const MAX_VALUE_BYTES: usize = 1024 * 1024;
/// PlatformIO's built-in variables (`BUILTIN_VARS`, `config.py` lines 48-56).
const BUILTIN_VARS: [&str; 3] = ["PROJECT_DIR", "PROJECT_HASH", "UNIX_TIME"];

/// Why `platformio.ini` could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IniError {
    /// An option before any `[section]`.
    #[error("line {line}: option outside any [section]")]
    MissingSectionHeader {
        /// The line.
        line: u32,
    },
    /// A `[section` header without its `]`, or an empty `[]`.
    #[error("line {line}: malformed section header {text:?}")]
    BadSectionHeader {
        /// The line.
        line: u32,
        /// The header as written.
        text: String,
    },
    /// A line that is neither a header, an option, a continuation nor a comment.
    #[error("line {line}: expected `key = value`, found {text:?}")]
    NoSeparator {
        /// The line.
        line: u32,
        /// The line as written.
        text: String,
    },
    /// `= value` with no key.
    #[error("line {line}: option with an empty name")]
    EmptyKey {
        /// The line.
        line: u32,
    },
    /// A section defined twice.
    #[error("line {line}: section [{name}] already defined on line {first}")]
    DuplicateSection {
        /// The section.
        name: String,
        /// The second definition.
        line: u32,
        /// The first.
        first: u32,
    },
    /// An option set twice in one section.
    #[error("line {line}: option {key:?} already set in [{section}] on line {first}")]
    DuplicateOption {
        /// The section.
        section: String,
        /// The option.
        key: String,
        /// The second setting.
        line: u32,
        /// The first.
        first: u32,
    },
    /// `${section.option}` names something that does not exist.
    #[error("line {line}: ${{{reference}}} names no option")]
    UnknownReference {
        /// The line holding the reference.
        line: u32,
        /// The reference, without `${` and `}`.
        reference: String,
    },
    /// `${this.__env__}` in a section that is not an environment.
    #[error(
        "line {line}: ${{this.__env__}} used in [{section}], which is not an [env:NAME] section"
    )]
    EnvOutsideEnvironment {
        /// The line holding the reference.
        line: u32,
        /// The section it was resolved for.
        section: String,
    },
    /// `${…}` references that loop.
    #[error("line {line}: interpolation loops: {}", chain.join(" -> "))]
    InterpolationCycle {
        /// The line holding the reference that closes the loop.
        line: u32,
        /// `section.option` of each step.
        chain: Vec<String>,
    },
    /// `extends` chains that loop.
    #[error("line {line}: extends loops: {}", chain.join(" -> "))]
    ExtendsCycle {
        /// The `extends` line closing the loop.
        line: u32,
        /// The sections in the loop.
        chain: Vec<String>,
    },
    /// A resolution that takes more than [`MAX_STEPS`] steps, nests references deeper than
    /// [`MAX_DEPTH`], or makes a value larger than 1 MiB.
    #[error(
        "line {line}: resolving this option takes more than {MAX_STEPS} steps, {MAX_DEPTH} nested references or 1 MiB (too many nested references or extends)"
    )]
    TooLarge {
        /// The line being resolved.
        line: u32,
    },
}

/// One option as written: its value lines (comments and blank lines removed), each with
/// its line number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawOption {
    /// The line of `key = …`.
    pub line: u32,
    /// The value's lines (the first is the text after the separator, if any).
    pub lines: Vec<(String, u32)>,
}

/// One `[section]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The header's line.
    pub line: u32,
    /// Options by lowercase key.
    pub options: BTreeMap<String, RawOption>,
}

/// A parsed `platformio.ini`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProjectConfig {
    /// Sections by name.
    pub sections: BTreeMap<String, Section>,
}

/// One line of a resolved value: its text and the `platformio.ini` line it came from (the
/// referenced option's line when interpolated).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Item {
    /// The text.
    pub text: String,
    /// The line it was written on.
    pub line: u32,
}

/// A resolved option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// The line of the `key = …` that set it.
    pub line: u32,
    /// The section that set it (after inheritance).
    pub section: String,
    /// Its lines, interpolated.
    pub lines: Vec<Item>,
    /// What was left as written or skipped while resolving it: (line, message), sorted.
    pub warnings: ValueWarnings,
}

impl Value {
    /// The value as one string, lines joined with `\n`.
    pub fn text(&self) -> String {
        self.lines
            .iter()
            .map(|i| i.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn line_no(index: usize) -> u32 {
    u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX)
}

/// `text` without an inline comment (`;` or `#` after whitespace), trimmed.
fn strip_inline_comment(text: &str) -> &str {
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if (b == b';' || b == b'#')
            && i > 0
            && bytes.get(i - 1).is_some_and(u8::is_ascii_whitespace)
        {
            return text.get(..i).unwrap_or(text).trim();
        }
    }
    text.trim()
}

/// Parses `platformio.ini`.
pub fn parse(text: &str) -> Result<ProjectConfig, IniError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut config = ProjectConfig::default();
    let mut section: Option<String> = None;
    let mut option: Option<String> = None;
    for (index, raw) in text.split('\n').enumerate() {
        let line = line_no(index);
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }
        let indented = raw.starts_with([' ', '\t']);
        if indented
            && let (Some(s), Some(o)) = (&section, &option)
            && let Some(opt) = config
                .sections
                .get_mut(s)
                .and_then(|sec| sec.options.get_mut(o))
        {
            let value = strip_inline_comment(trimmed);
            if !value.is_empty() {
                opt.lines.push((value.to_owned(), line));
            }
            continue;
        }
        if trimmed.starts_with('[') {
            let header = strip_inline_comment(trimmed);
            let name = header
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .ok_or_else(|| IniError::BadSectionHeader {
                    line,
                    text: trimmed.to_owned(),
                })?;
            if let Some(first) = config.sections.get(name) {
                return Err(IniError::DuplicateSection {
                    name: name.to_owned(),
                    line,
                    first: first.line,
                });
            }
            config.sections.insert(
                name.to_owned(),
                Section {
                    line,
                    options: BTreeMap::new(),
                },
            );
            section = Some(name.to_owned());
            option = None;
            continue;
        }
        let Some(at) = trimmed.find(['=', ':']) else {
            return Err(IniError::NoSeparator {
                line,
                text: trimmed.to_owned(),
            });
        };
        let key = trimmed.get(..at).unwrap_or_default().trim().to_lowercase();
        if key.is_empty() {
            return Err(IniError::EmptyKey { line });
        }
        let Some(current) = &section else {
            return Err(IniError::MissingSectionHeader { line });
        };
        let value = strip_inline_comment(trimmed.get(at + 1..).unwrap_or_default());
        let Some(sec) = config.sections.get_mut(current) else {
            return Err(IniError::MissingSectionHeader { line });
        };
        if let Some(first) = sec.options.get(&key) {
            return Err(IniError::DuplicateOption {
                section: current.clone(),
                key,
                line,
                first: first.line,
            });
        }
        let lines = if value.is_empty() {
            Vec::new()
        } else {
            vec![(value.to_owned(), line)]
        };
        sec.options.insert(key.clone(), RawOption { line, lines });
        option = Some(key);
    }
    Ok(config)
}

/// A `${…}` reference: (section, option), as PlatformIO's `VARTPL_RE` splits it
/// (`config.py` line 46): the section, if any, holds no `.`, `}`, `(` or `)`.
fn split_reference(inner: &str) -> (Option<&str>, &str) {
    match inner.split_once('.') {
        Some((section, option)) if !section.is_empty() && !section.contains(['(', ')']) => {
            (Some(section), option)
        }
        _ => (None, inner),
    }
}

/// `text` without a `;` comment after whitespace (`INLINE_COMMENT_RE`, `config.py` line 45).
fn cut_inline_comment(text: &str) -> &str {
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b';' && i > 0 && bytes.get(i - 1).is_some_and(u8::is_ascii_whitespace) {
            return text.get(..i).unwrap_or(text).trim();
        }
    }
    text.trim()
}

/// Splits `items` as PlatformIO's `parse_multi_values` (`config.py` lines 67-81).
fn multi_values(items: &[Item]) -> Vec<Item> {
    let multi = items.len() > 1 || items.iter().any(|i| i.text.contains('\n'));
    let mut pieces: Vec<Item> = Vec::new();
    for item in items {
        let separator = if multi { "\n" } else { ", " };
        for piece in item.text.split(separator) {
            pieces.push(Item {
                text: piece.to_owned(),
                line: item.line,
            });
        }
    }
    pieces
        .into_iter()
        .filter_map(|mut item| {
            let text = item.text.trim();
            if text.is_empty() || text.starts_with(';') || text.starts_with('#') {
                return None;
            }
            let text = cut_inline_comment(text);
            if text.is_empty() {
                return None;
            }
            item.text = text.to_owned();
            Some(item)
        })
        .collect()
}

/// What resolving an option left as written or skipped: (line, message).
pub type ValueWarnings = Vec<(u32, String)>;

/// A depth-first search frame: a section, the sections it extends (with the `extends` line),
/// and the next one to visit.
type Frame = (String, Vec<(String, u32)>, usize);

/// A resolved option, memoised: (the section that set it, its line, its lines).
type Resolved = Option<(String, u32, Rc<Vec<Item>>)>;

/// One resolution's state: its step and byte budget, memoised section walks and values,
/// the references being expanded, and what to warn about.
struct Resolver<'c> {
    config: &'c ProjectConfig,
    steps: usize,
    bytes: usize,
    walks: BTreeMap<String, Rc<Vec<String>>>,
    values: BTreeMap<(String, String), Resolved>,
    resolving: Vec<String>,
    warnings: BTreeSet<(u32, String)>,
}

impl<'c> Resolver<'c> {
    fn new(config: &'c ProjectConfig) -> Self {
        Self {
            config,
            steps: 0,
            bytes: 0,
            walks: BTreeMap::new(),
            values: BTreeMap::new(),
            resolving: Vec::new(),
            warnings: BTreeSet::new(),
        }
    }

    fn step(&mut self, line: u32) -> Result<(), IniError> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > MAX_STEPS {
            return Err(IniError::TooLarge { line });
        }
        Ok(())
    }

    fn produced(&mut self, bytes: usize, line: u32) -> Result<(), IniError> {
        self.bytes = self.bytes.saturating_add(bytes);
        if self.bytes > MAX_VALUE_BYTES {
            return Err(IniError::TooLarge { line });
        }
        Ok(())
    }

    /// The sections `section`'s `extends` names, as PlatformIO splits it (raw, not
    /// interpolated), with the `extends` line.
    fn extends_of(&self, section: &str) -> Vec<(String, u32)> {
        let Some(extends) = self
            .config
            .sections
            .get(section)
            .and_then(|s| s.options.get("extends"))
        else {
            return Vec::new();
        };
        let items: Vec<Item> = extends
            .lines
            .iter()
            .map(|(text, line)| Item {
                text: text.clone(),
                line: *line,
            })
            .collect();
        multi_values(&items)
            .into_iter()
            .map(|i| (i.text, extends.line))
            .collect()
    }

    /// Fails if the `extends` graph reachable from `root` has a loop (an iterative
    /// depth-first search, each edge one step).
    fn check_extends_cycle(&mut self, root: &str) -> Result<(), IniError> {
        // 1: on the current path; 2: done.
        let mut colour: BTreeMap<String, u8> = BTreeMap::new();
        let mut stack: Vec<Frame> = vec![(root.to_owned(), self.extends_of(root), 0)];
        colour.insert(root.to_owned(), 1);
        while let Some((node, targets, next)) = stack.last_mut() {
            let Some((target, line)) = targets.get(*next).cloned() else {
                colour.insert(node.clone(), 2);
                stack.pop();
                continue;
            };
            *next += 1;
            self.step(line)?;
            if !self.config.sections.contains_key(&target) {
                continue;
            }
            match colour.get(&target) {
                Some(1) => {
                    let mut chain: Vec<String> = stack.iter().map(|(n, _, _)| n.clone()).collect();
                    chain.push(target);
                    return Err(IniError::ExtendsCycle { line, chain });
                }
                Some(_) => {}
                None => {
                    colour.insert(target.clone(), 1);
                    let targets = self.extends_of(&target);
                    stack.push((target, targets, 0));
                }
            }
        }
        Ok(())
    }

    /// The sections searched for an option of `root`, in PlatformIO's `walk_options` order
    /// (`config.py` lines 170-185): a stack starting `[env, root]` for an environment
    /// (`[root]` otherwise); pop and search the top, then push its `extends` in order, so
    /// the last one is searched next. A section already searched is not searched again (it
    /// cannot change the first match). Unknown `extends` targets are skipped, as PlatformIO
    /// skips them (line 178), with a warning.
    fn walk(&mut self, root: &str) -> Result<Rc<Vec<String>>, IniError> {
        if let Some(order) = self.walks.get(root) {
            return Ok(Rc::clone(order));
        }
        self.check_extends_cycle(root)?;
        let mut stack: Vec<(String, Option<(String, u32)>)> = Vec::new();
        if root.starts_with("env:") {
            stack.push(("env".to_owned(), None));
        }
        stack.push((root.to_owned(), None));
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut order = Vec::new();
        while let Some((section, named_by)) = stack.pop() {
            let line = named_by.as_ref().map_or(0, |(_, l)| *l);
            self.step(line)?;
            if !seen.insert(section.clone()) {
                continue;
            }
            if !self.config.sections.contains_key(&section) {
                if let Some((from, line)) = named_by {
                    self.warnings.insert((
                        line,
                        format!(
                            "[{from}] extends [{section}], which does not exist; skipped, as PlatformIO skips it"
                        ),
                    ));
                }
                continue;
            }
            for (target, line) in self.extends_of(&section) {
                stack.push((target, Some((section.clone(), line))));
            }
            order.push(section);
        }
        let order = Rc::new(order);
        self.walks.insert(root.to_owned(), Rc::clone(&order));
        Ok(order)
    }

    /// The raw option `key` for `section`: (the section that sets it, the option).
    fn lookup(
        &mut self,
        section: &str,
        key: &str,
    ) -> Result<Option<(String, &'c RawOption)>, IniError> {
        let config = self.config;
        for s in self.walk(section)?.iter() {
            if let Some(opt) = config.sections.get(s).and_then(|sec| sec.options.get(key)) {
                return Ok(Some((s.clone(), opt)));
            }
        }
        Ok(None)
    }

    /// Option `key` resolved for `section` (`this` is `section`), memoised.
    fn resolve(&mut self, section: &str, key: &str, line: u32) -> Result<Resolved, IniError> {
        let memo_key = (section.to_owned(), key.to_owned());
        if let Some(found) = self.values.get(&memo_key) {
            return Ok(found.clone());
        }
        let Some((owner, raw)) = self.lookup(section, key)? else {
            self.values.insert(memo_key, None);
            return Ok(None);
        };
        let id = format!("{section}.{key}");
        if self.resolving.contains(&id) {
            let mut chain = self.resolving.clone();
            chain.push(id);
            return Err(IniError::InterpolationCycle { line, chain });
        }
        if self.resolving.len() >= MAX_DEPTH {
            return Err(IniError::TooLarge { line });
        }
        self.resolving.push(id);
        let mut lines = Vec::new();
        for (text, l) in &raw.lines {
            lines.extend(self.interpolate(text, *l, section)?);
        }
        self.resolving.pop();
        let found = Some((owner, raw.line, Rc::new(lines)));
        self.values.insert(memo_key, found.clone());
        Ok(found)
    }

    /// Interpolates one value line resolved for section `this`. A line that is exactly one
    /// reference to a multi-line value becomes those lines, with their own line numbers.
    fn interpolate(&mut self, text: &str, line: u32, this: &str) -> Result<Vec<Item>, IniError> {
        self.step(line)?;
        let mut out = String::new();
        let mut rest = text;
        while let Some(start) = rest.find("${") {
            let after = rest.get(start + 2..).unwrap_or_default();
            let Some(end) = after.find('}') else {
                break;
            };
            let inner = after.get(..end).unwrap_or_default();
            let whole = start == 0 && end + 3 == rest.len() && out.is_empty();
            out.push_str(rest.get(..start).unwrap_or_default());
            rest = after.get(end + 1..).unwrap_or_default();
            self.step(line)?;
            let verbatim = format!("${{{inner}}}");
            let (section, option) = split_reference(inner);
            let section = match section {
                None => {
                    let why = if BUILTIN_VARS.contains(&option) {
                        "is PlatformIO's built-in variable, which depends on the build machine"
                    } else {
                        "is a SCons variable, which PlatformIO leaves as written"
                    };
                    self.warnings
                        .insert((line, format!("{verbatim} {why}; left as written")));
                    out.push_str(&verbatim);
                    continue;
                }
                Some("sysenv") => {
                    self.warnings.insert((
                        line,
                        format!(
                            "{verbatim} depends on the build machine's environment; left as written"
                        ),
                    ));
                    out.push_str(&verbatim);
                    continue;
                }
                Some("this") if option == "__env__" => {
                    let Some(env) = this.strip_prefix("env:") else {
                        return Err(IniError::EnvOutsideEnvironment {
                            line,
                            section: this.to_owned(),
                        });
                    };
                    out.push_str(env);
                    continue;
                }
                Some("this") => this.to_owned(),
                Some(s) => s.to_owned(),
            };
            let Some((_, _, items)) = self.resolve(&section, &option.to_lowercase(), line)? else {
                return Err(IniError::UnknownReference {
                    line,
                    reference: inner.to_owned(),
                });
            };
            let size: usize = items.iter().map(|i| i.text.len() + 1).sum();
            self.produced(size, line)?;
            if whole {
                return Ok(items.as_ref().clone());
            }
            let joined = items
                .iter()
                .map(|i| i.text.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            out.push_str(&joined);
        }
        out.push_str(rest);
        self.produced(out.len(), line)?;
        Ok(vec![Item { text: out, line }])
    }
}

impl ProjectConfig {
    /// The environment names (`[env:NAME]`), sorted.
    pub fn envs(&self) -> Vec<String> {
        self.sections
            .keys()
            .filter_map(|s| s.strip_prefix("env:"))
            .map(str::to_owned)
            .collect()
    }

    /// The resolved option `key` of `section` (an environment is `env:NAME`): inherited and
    /// interpolated (see the module docs). `Ok(None)` when no section searched sets it.
    pub fn get(&self, section: &str, key: &str) -> Result<Option<Value>, IniError> {
        let mut r = Resolver::new(self);
        let found = r.resolve(section, &key.to_lowercase(), 0)?;
        Ok(found.map(|(owner, line, lines)| Value {
            line,
            section: owner,
            lines: lines.as_ref().clone(),
            warnings: r.warnings.into_iter().collect(),
        }))
    }

    /// The resolved option as a list (see the module docs), with its warnings. Empty when
    /// unset.
    pub fn list(&self, section: &str, key: &str) -> Result<(Vec<Item>, ValueWarnings), IniError> {
        Ok(match self.get(section, key)? {
            Some(value) => (multi_values(&value.lines), value.warnings),
            None => (Vec::new(), Vec::new()),
        })
    }

    /// `[platformio] default_envs`, as a list.
    pub fn default_envs(&self) -> Result<Vec<Item>, IniError> {
        Ok(self.list("platformio", "default_envs")?.0)
    }
}

/// A package specification: a `lib_deps` or `platform_packages` entry, or `platform`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PackageSpec {
    /// From the PlatformIO registry: `[owner/]name[@requirement]`.
    Registry {
        /// The owner, if given.
        owner: Option<String>,
        /// The name.
        name: String,
        /// The version requirement, if given (`^7.2.1`, `7.2.1`, `>=1,<2`).
        requirement: Option<String>,
    },
    /// A version-control repository (`https://github.com/o/r.git#tag`, `git+…`, `git@…`).
    Vcs {
        /// A name given as `name=url` or `name @ url`.
        name: Option<String>,
        /// The URL as written.
        url: String,
    },
    /// An archive URL (`.zip`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar`).
    Archive {
        /// A name given as `name=url` or `name @ url`.
        name: Option<String>,
        /// The URL as written.
        url: String,
    },
    /// A local directory (`file://`, `symlink://`, or a path).
    Local {
        /// A name given as `name=path` or `name @ path`.
        name: Option<String>,
        /// The path as written.
        path: String,
    },
    /// Anything else (an empty entry).
    Unknown(String),
}

impl fmt::Display for PackageSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry {
                owner,
                name,
                requirement,
            } => {
                if let Some(owner) = owner {
                    write!(f, "{owner}/")?;
                }
                write!(f, "{name}")?;
                if let Some(r) = requirement {
                    write!(f, " @ {r}")?;
                }
                Ok(())
            }
            Self::Vcs { url, .. } | Self::Archive { url, .. } => write!(f, "{url}"),
            Self::Local { path, .. } => write!(f, "{path}"),
            Self::Unknown(raw) => write!(f, "{raw}"),
        }
    }
}

fn is_url(s: &str) -> bool {
    s.contains("://") || s.starts_with("git@")
}

fn is_path(s: &str) -> bool {
    s.starts_with('/')
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('~')
        || s.as_bytes().get(1..3) == Some(b":\\")
}

fn source_spec(name: Option<String>, source: &str) -> PackageSpec {
    for scheme in ["file://", "symlink://"] {
        if let Some(path) = source.strip_prefix(scheme) {
            return PackageSpec::Local {
                name,
                path: path.to_owned(),
            };
        }
    }
    if is_path(source) {
        return PackageSpec::Local {
            name,
            path: source.to_owned(),
        };
    }
    let lower = source.to_ascii_lowercase();
    let without_fragment = lower.split(['#', '?']).next().unwrap_or_default();
    let vcs_marked = lower.starts_with("git+")
        || lower.starts_with("git@")
        || lower.starts_with("git://")
        || lower.starts_with("ssh://")
        || without_fragment.ends_with(".git");
    let archive = [".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar"]
        .iter()
        .any(|ext| without_fragment.ends_with(ext));
    if archive && !vcs_marked {
        PackageSpec::Archive {
            name,
            url: source.to_owned(),
        }
    } else {
        PackageSpec::Vcs {
            name,
            url: source.to_owned(),
        }
    }
}

/// Classifies one package specification (see [`PackageSpec`]).
pub fn parse_spec(raw: &str) -> PackageSpec {
    let s = raw.trim();
    if s.is_empty() {
        return PackageSpec::Unknown(raw.to_owned());
    }
    // `name=url` names a source package.
    if let Some((name, source)) = s.split_once('=') {
        let (name, source) = (name.trim(), source.trim());
        if !name.is_empty() && (is_url(source) || is_path(source)) {
            return source_spec(Some(name.to_owned()), source);
        }
    }
    // `name @ url` (platform_packages) names a source package too.
    if let Some((name, source)) = s.split_once('@') {
        let (name, source) = (name.trim(), source.trim());
        if !name.is_empty() && !is_url(name) && (is_url(source) || is_path(source)) {
            let name = name.rsplit('/').next().unwrap_or(name).trim();
            return source_spec(Some(name.to_owned()).filter(|n| !n.is_empty()), source);
        }
    }
    if is_url(s) || is_path(s) {
        return source_spec(None, s);
    }
    let (spec, requirement) = match s.split_once('@') {
        Some((spec, req)) => (spec.trim(), Some(req.trim()).filter(|r| !r.is_empty())),
        None => (s, None),
    };
    let (owner, name) = match spec.split_once('/') {
        Some((owner, name)) => (Some(owner.trim()).filter(|o| !o.is_empty()), name.trim()),
        None => (None, spec),
    };
    if name.is_empty() || name.contains('/') {
        return PackageSpec::Unknown(raw.to_owned());
    }
    PackageSpec::Registry {
        owner: owner.map(str::to_owned),
        name: name.to_owned(),
        requirement: requirement.map(str::to_owned),
    }
}

/// The version an exact requirement pins (`6.10.0`, `==6.10.0`, `=6.10.0`); `None` for a
/// range (`^`, `~`, `>`, `<`, `*`, `,`, `!`) or anything that is not a version.
pub fn exact_version(requirement: &str) -> Option<String> {
    let r = requirement.trim();
    let r = r
        .strip_prefix("==")
        .or_else(|| r.strip_prefix('='))
        .unwrap_or(r)
        .trim();
    let starts_with_digit = r.bytes().next().is_some_and(|b| b.is_ascii_digit());
    let plain = r
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_'));
    (starts_with_digit && plain).then(|| r.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const MULTI_ENV: &str = "\u{feff}; a comment\r
[platformio]\r
default_envs = release\r
\r
[env]\r
platform = espressif32 @ 6.10.0\r
framework = arduino\r
lib_deps =\r
    bblanchon/ArduinoJson @ ^7.2.1   ; inline comment\r
\r
[common]\r
lib_deps =\r
    knolleary/PubSubClient @ 2.8\r
    # a commented-out dependency\r
    mathertel/OneButton@2.6.1\r
flags = -DCOMMON\r
\r
[env:release]\r
board = esp32dev\r
lib_deps =\r
    ${env.lib_deps}\r
    ${common.lib_deps}\r
build_flags = ${common.flags} -DENV=${this.__env__}\r
\r
[env:debug]\r
extends = env:release\r
build_type: debug\r
build_flags = ${env:release.build_flags} -DDEBUG ${sysenv.HOME}\r
";

    fn texts(items: &[Item]) -> Vec<(&str, u32)> {
        items.iter().map(|i| (i.text.as_str(), i.line)).collect()
    }

    #[test]
    fn parses_multi_env_project_with_base_env_extends_and_interpolation() {
        let c = parse(MULTI_ENV).unwrap();
        assert_eq!(c.envs(), ["debug", "release"]);
        assert_eq!(texts(&c.default_envs().unwrap()), [("release", 3)]);
        // [env] is the base of every environment.
        let platform = c.get("env:debug", "platform").unwrap().unwrap();
        assert_eq!(platform.text(), "espressif32 @ 6.10.0");
        assert_eq!((platform.section.as_str(), platform.line), ("env", 6));
        // extends: debug inherits release's board and lib_deps.
        assert_eq!(
            c.get("env:debug", "board").unwrap().unwrap().text(),
            "esp32dev"
        );
        let (deps, unresolved) = c.list("env:debug", "lib_deps").unwrap();
        assert!(unresolved.is_empty());
        assert_eq!(
            texts(&deps),
            [
                ("bblanchon/ArduinoJson @ ^7.2.1", 9),
                ("knolleary/PubSubClient @ 2.8", 13),
                ("mathertel/OneButton@2.6.1", 15)
            ]
        );
        // ${this.__env__} is the environment being resolved; ${sysenv.…} is left verbatim.
        assert_eq!(
            c.get("env:release", "build_flags").unwrap().unwrap().text(),
            "-DCOMMON -DENV=release"
        );
        let debug = c.get("env:debug", "build_flags").unwrap().unwrap();
        // `${env:release.build_flags}` is resolved for env:release, so its `${this.__env__}`
        // is release (PlatformIO's nested `get(section, option)`, config.py line 371).
        assert_eq!(
            debug.text(),
            "-DCOMMON -DENV=release -DDEBUG ${sysenv.HOME}"
        );
        assert_eq!(
            debug.warnings,
            [(
                28,
                "${sysenv.HOME} depends on the build machine's environment; left as written"
                    .to_owned()
            )]
        );
        assert_eq!(
            c.get("env:debug", "build_type").unwrap().unwrap().text(),
            "debug"
        );
        // An option nobody sets.
        assert_eq!(c.get("env:debug", "upload_port").unwrap(), None);
        assert_eq!(c.get("common", "platform").unwrap(), None);
    }

    #[test]
    fn multi_line_values_and_comments() {
        let c = parse(
            "[env:a]\nlib_deps = x, y ; trailing\n#full\nbuild_flags =\n  -DA\n\n  -DB # c\n  ; gone\nurl = https://h/x.git#v1\n",
        )
        .unwrap();
        // One line: split at ", ".
        assert_eq!(
            texts(&c.list("env:a", "lib_deps").unwrap().0),
            [("x", 2), ("y", 2)]
        );
        // Blank lines and comment lines inside a value are dropped, not ends of it.
        assert_eq!(
            texts(&c.list("env:a", "build_flags").unwrap().0),
            [("-DA", 5), ("-DB", 7)]
        );
        // `#` without whitespace before it is not a comment.
        assert_eq!(
            c.get("env:a", "url").unwrap().unwrap().text(),
            "https://h/x.git#v1"
        );
        // Keys are case-insensitive.
        let c = parse("[env:a]\nBoard = X\n").unwrap();
        assert_eq!(c.get("env:a", "BOARD").unwrap().unwrap().text(), "X");
    }

    #[test]
    fn lib_deps_forms_are_classified() {
        let registry = |owner: Option<&str>, name: &str, req: Option<&str>| PackageSpec::Registry {
            owner: owner.map(str::to_owned),
            name: name.to_owned(),
            requirement: req.map(str::to_owned),
        };
        assert_eq!(
            parse_spec("bblanchon/ArduinoJson @ ^7.2.1"),
            registry(Some("bblanchon"), "ArduinoJson", Some("^7.2.1"))
        );
        assert_eq!(parse_spec("OneButton"), registry(None, "OneButton", None));
        assert_eq!(
            parse_spec("adafruit/Adafruit NeoPixel@1.15.1"),
            registry(Some("adafruit"), "Adafruit NeoPixel", Some("1.15.1"))
        );
        assert_eq!(
            parse_spec("https://github.com/knolleary/pubsubclient.git#v2.8"),
            PackageSpec::Vcs {
                name: None,
                url: "https://github.com/knolleary/pubsubclient.git#v2.8".into()
            }
        );
        assert_eq!(
            parse_spec("MyLib=git@github.com:me/mylib.git"),
            PackageSpec::Vcs {
                name: Some("MyLib".into()),
                url: "git@github.com:me/mylib.git".into()
            }
        );
        assert_eq!(
            parse_spec("https://example.com/lib-1.0.zip"),
            PackageSpec::Archive {
                name: None,
                url: "https://example.com/lib-1.0.zip".into()
            }
        );
        assert_eq!(
            parse_spec("symlink://../shared/lib"),
            PackageSpec::Local {
                name: None,
                path: "../shared/lib".into()
            }
        );
        assert_eq!(
            parse_spec("./lib/local"),
            PackageSpec::Local {
                name: None,
                path: "./lib/local".into()
            }
        );
        assert_eq!(
            parse_spec(
                "framework-arduinoespressif32 @ https://github.com/espressif/arduino-esp32.git#2.0.17"
            ),
            PackageSpec::Vcs {
                name: Some("framework-arduinoespressif32".into()),
                url: "https://github.com/espressif/arduino-esp32.git#2.0.17".into()
            }
        );
        assert!(matches!(parse_spec("  "), PackageSpec::Unknown(_)));
        assert!(matches!(parse_spec("a/b/c"), PackageSpec::Unknown(_)));
        assert_eq!(exact_version("6.10.0").as_deref(), Some("6.10.0"));
        assert_eq!(exact_version("==2.8").as_deref(), Some("2.8"));
        assert_eq!(
            exact_version("3.20017.241212+sha.dcc1105b").as_deref(),
            Some("3.20017.241212+sha.dcc1105b")
        );
        for range in ["^7.2.1", "~2.8", ">=1,<2", "*", "", "!=1.0"] {
            assert_eq!(exact_version(range), None, "{range}");
        }
        assert_eq!(
            parse_spec("bblanchon/ArduinoJson @ 7.2.1").to_string(),
            "bblanchon/ArduinoJson @ 7.2.1"
        );
    }

    #[test]
    fn default_envs_and_env_selection() {
        let c = parse("[platformio]\ndefault_envs = a, b\n[env:a]\n[env:b]\n[env:c]\n").unwrap();
        assert_eq!(texts(&c.default_envs().unwrap()), [("a", 2), ("b", 2)]);
        assert_eq!(c.envs(), ["a", "b", "c"]);
        let c = parse("[env:only]\nboard = x\n").unwrap();
        assert!(c.default_envs().unwrap().is_empty());
        assert_eq!(c.envs(), ["only"]);
    }

    #[test]
    fn malformed_ini_errors_never_panic() {
        let cases: [(&str, &str); 11] = [
            ("board = x\n", "line 1: option outside any [section]"),
            ("[env:a\nx = 1\n", "line 1: malformed section header"),
            ("[]\n", "line 1: malformed section header"),
            ("[env:a]\njust words\n", "line 2: expected `key = value`"),
            ("[env:a]\n= 1\n", "line 2: option with an empty name"),
            (
                "[a]\n[a]\n",
                "line 2: section [a] already defined on line 1",
            ),
            (
                "[a]\nx=1\nX=2\n",
                "line 3: option \"x\" already set in [a] on line 2",
            ),
            (
                "[env:a]\nx = ${nope.y}\n",
                "line 2: ${nope.y} names no option",
            ),
            (
                "[env:a]\nx = ${this.y}\ny = ${this.x}\n",
                "interpolation loops",
            ),
            (
                "[common]\nx = ${this.__env__}\n[env:a]\ny = ${common.x}\n",
                "line 2: ${this.__env__} used in [common], which is not an [env:NAME] section",
            ),
            (
                "[env:a]\nextends = env:b\n[env:b]\nextends = env:a\n",
                "extends loops",
            ),
        ];
        for (text, needle) in cases {
            let err = parse(text).and_then(|c| {
                for env in c.envs() {
                    for key in ["x", "y", "board"] {
                        c.get(&format!("env:{env}"), key)?;
                    }
                }
                Ok(c)
            });
            let message = err.expect_err(text).to_string();
            assert!(
                message.contains(needle),
                "{text:?}: {message:?} lacks {needle:?}"
            );
        }
        // Truncated anywhere, the multi-env project parses or errors.
        for cut in 0..MULTI_ENV.len() {
            if let Some(prefix) = MULTI_ENV.get(..cut)
                && let Ok(c) = parse(prefix)
            {
                for env in c.envs() {
                    let _ = c.list(&format!("env:{env}"), "lib_deps");
                    let _ = c.get(&format!("env:{env}"), "build_flags");
                }
            }
        }
    }

    /// PlatformIO's `walk_options` (config.py 170-185) is a stack: with `extends = a, b` the
    /// last target, `b`, is searched first, depth first, and `[env]` is searched last of all.
    #[test]
    fn extends_order_matches_platformio_walk_options() {
        let c = parse(
            "[env]\nx = base\ny = base\nz = base\n\
             [a]\nx = from-a\ny = from-a\n\
             [b]\nx = from-b\nextends = c\n\
             [c]\ny = from-c\n\
             [env:e]\nextends = a, b\n",
        )
        .unwrap();
        let get = |k: &str| c.get("env:e", k).unwrap().unwrap();
        // b before a; b's own extends (c) before a; [env] only when nothing else sets it.
        assert_eq!(
            (get("x").text(), get("x").section.as_str()),
            ("from-b".to_owned(), "b")
        );
        assert_eq!(get("y").text(), "from-c");
        assert_eq!(get("z").text(), "base");
        // Any section can extend; the [env] base applies only to environments.
        let c = parse("[env]\nk = base\n[x]\nv = 1\n[y]\nextends = x\n").unwrap();
        assert_eq!(c.get("y", "v").unwrap().unwrap().text(), "1");
        assert_eq!(c.get("y", "k").unwrap(), None);
    }

    /// `[env]` is consulted once, last: an extends target further down wins over it.
    #[test]
    fn env_base_is_searched_after_every_extends_target() {
        let c = parse(
            "[env]\nboard = base\n[a]\nother = 1\n[b]\nboard = from-b\n[env:e]\nextends = b, a\n",
        )
        .unwrap();
        assert_eq!(c.get("env:e", "board").unwrap().unwrap().text(), "from-b");
    }

    /// An `extends` target that is no section is skipped, as PlatformIO skips it (config.py
    /// line 178), with a warning; `a,b` without a space is one (missing) name, as
    /// `parse_multi_values` splits only at ", ".
    #[test]
    fn unknown_extends_target_is_skipped_with_a_warning() {
        let c = parse("[a]\nk = 1\n[env:e]\nextends = missing, a\n[env:f]\nextends = a,missing\n")
            .unwrap();
        let v = c.get("env:e", "k").unwrap().unwrap();
        assert_eq!(v.text(), "1");
        assert_eq!(
            v.warnings,
            [(
                4,
                "[env:e] extends [missing], which does not exist; skipped, as PlatformIO skips it"
                    .to_owned()
            )]
        );
        assert_eq!(c.get("env:f", "k").unwrap(), None);
    }

    /// configparser lowercases option names (PlatformIO keeps the default `optionxform`);
    /// section names keep their case.
    #[test]
    fn option_names_are_case_insensitive_section_names_are_not() {
        let c = parse("[Common]\nLIB_DEPS = a\n[env:e]\nx = ${Common.Lib_Deps}\n").unwrap();
        assert_eq!(c.get("env:e", "X").unwrap().unwrap().text(), "a");
        assert_eq!(c.get("common", "lib_deps").unwrap(), None);
        assert!(matches!(
            parse("[env:e]\nx = ${common.lib_deps}\n[Common]\nlib_deps = a\n")
                .unwrap()
                .get("env:e", "x"),
            Err(IniError::UnknownReference { .. })
        ));
    }

    /// A `${NAME}` with no section is PlatformIO's built-in variable (machine-dependent) or a
    /// SCons variable PlatformIO leaves as written (config.py lines 346-351): left as written,
    /// with a warning, never an error.
    #[test]
    fn sectionless_references_are_left_verbatim_with_a_warning() {
        let c = parse(
            "[env:e]\nlib_deps =\n    symlink://${PROJECT_DIR}/../shared\n    x=${BUILD_DIR}/y\n",
        )
        .unwrap();
        let (items, warnings) = c.list("env:e", "lib_deps").unwrap();
        assert_eq!(
            texts(&items),
            [
                ("symlink://${PROJECT_DIR}/../shared", 3),
                ("x=${BUILD_DIR}/y", 4)
            ]
        );
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].1.contains("built-in variable"), "{warnings:?}");
        assert!(warnings[1].1.contains("SCons variable"), "{warnings:?}");
    }

    fn quick<T>(what: &str, f: impl FnOnce() -> T) -> T {
        let start = std::time::Instant::now();
        let out = f();
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "{what} took {:?}",
            start.elapsed()
        );
        out
    }

    /// Review B1 (a): 30 levels of `v{i} = ${v{i-1}}${v{i-1}}` doubled 2^30 times without
    /// memoisation. Resolved values are memoised, so it resolves at once (to the empty value
    /// PlatformIO would give); with a non-empty seed the 1 MiB cap stops it, and a chain of
    /// references deeper than MAX_DEPTH is refused before the stack can overflow.
    #[test]
    fn exponential_references_are_bounded_and_fast() {
        // `${v…}` (the review's form) has no section: a SCons variable to PlatformIO, left as
        // written. `${this.v…}` is the same doubling as real references.
        let chain = |seed: &str, section: &str| {
            let mut text = format!("[env:a]\nv0 = {seed}\n");
            for i in 1..=30 {
                text.push_str(&format!(
                    "v{i} = ${{{section}v{p}}}${{{section}v{p}}}\n",
                    p = i - 1
                ));
            }
            text.push_str(&format!("lib_deps = ${{{section}v30}}\n"));
            parse(&text).unwrap()
        };
        let c = chain("", "");
        let (items, warnings) = quick("review form", || c.list("env:a", "lib_deps")).unwrap();
        assert_eq!(texts(&items), [("${v30}", 33)]);
        assert!(warnings[0].1.contains("SCons variable"), "{warnings:?}");
        let c = chain("", "this.");
        let (items, _) = quick("empty doubling", || c.list("env:a", "lib_deps")).unwrap();
        assert!(items.is_empty(), "{items:?}");
        let c = chain("xxxxxxxxxxxxxxxx", "this.");
        let err = quick("non-empty doubling", || c.get("env:a", "lib_deps")).unwrap_err();
        assert!(matches!(err, IniError::TooLarge { .. }), "{err}");
        let mut text = "[env:a]\nv0 = x\n".to_owned();
        for i in 1..=200 {
            text.push_str(&format!("v{i} = ${{this.v{}}}\n", i - 1));
        }
        let c = parse(&text).unwrap();
        let err = quick("deep chain", || c.get("env:a", "v200")).unwrap_err();
        assert!(matches!(err, IniError::TooLarge { .. }), "{err:?}");
    }

    /// Review B1 (b): 30 levels of `extends = s{i+1}, s{i+1}` walked 2^30 sections without a
    /// visited set. Each section is searched once, so a missing key is answered at once; an
    /// `extends` graph with more than MAX_STEPS edges is refused.
    #[test]
    fn exponential_extends_are_bounded_and_fast() {
        let mut text = "[env:a]\nextends = s0\n".to_owned();
        for i in 0..30 {
            text.push_str(&format!("[s{i}]\nextends = s{n}, s{n}\n", n = i + 1));
        }
        text.push_str("[s30]\nk = 1\n");
        let c = parse(&text).unwrap();
        assert_eq!(
            quick("missing key", || c.get("env:a", "missing")).unwrap(),
            None
        );
        assert_eq!(
            quick("found key", || c.get("env:a", "k"))
                .unwrap()
                .unwrap()
                .text(),
            "1"
        );
        let mut text = "[env:a]\nextends = w0\n".to_owned();
        let n = 150;
        for i in 0..n {
            let targets: Vec<String> = (i + 1..n).map(|j| format!("w{j}")).collect();
            text.push_str(&format!("[w{i}]\nextends = {}\n", targets.join(", ")));
        }
        let c = parse(&text).unwrap();
        let err = quick("wide extends", || c.get("env:a", "missing")).unwrap_err();
        assert!(matches!(err, IniError::TooLarge { .. }), "{err}");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn ini_parser_never_panics_on_arbitrary_input(text in "(\\[|\\]|=|:|;|#|\\$\\{|\\}|\\.|env:|extends|a|b| |\t|\n|\r|x){0,120}") {
            if let Ok(c) = parse(&text) {
                let sections: Vec<String> = c.sections.keys().cloned().collect();
                for s in sections {
                    for key in ["a", "b", "x", "extends"] {
                        let _ = c.list(&s, key);
                    }
                }
            }
        }

        #[test]
        fn spec_parser_never_panics(text in "\\PC{0,40}") {
            let _ = parse_spec(&text);
            let _ = exact_version(&text);
        }
    }
}
