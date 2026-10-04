//! Command-line interface definition for the `rollcall` binary.

use std::path::PathBuf;
use std::str::FromStr;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use rollcall_core::cyclonedx::{SerialNumber, Timestamp};
use rollcall_core::identify::DbVersion;
use rollcall_core::merge::ProductSpec;

/// Exit code when a document fails validation.
pub const EXIT_INVALID: u8 = 1;
/// Exit code for usage errors and not-yet-implemented subcommands (`EX_USAGE` from sysexits.h).
pub const EXIT_USAGE: u8 = 64;
/// Exit code when an input file is malformed (`EX_DATAERR`).
pub const EXIT_DATAERR: u8 = 65;
/// Exit code when an input file is missing or unreadable (`EX_NOINPUT`).
pub const EXIT_NOINPUT: u8 = 66;
/// Exit code for an internal error, e.g. a report that cannot be serialised (`EX_SOFTWARE`).
pub const EXIT_SOFTWARE: u8 = 70;
/// Exit code when a required external tool (e.g. `cosign`) is not available
/// (`EX_UNAVAILABLE`).
pub const EXIT_UNAVAILABLE: u8 = 69;
/// Exit code when output cannot be written (`EX_IOERR`).
pub const EXIT_IOERR: u8 = 74;
/// `scan` only: an open finding at or above `--fail-on`.
pub const EXIT_SCAN_FINDINGS: u8 = 1;
/// `scan` only: an unresolved finding, with `--fail-on-unresolved`.
pub const EXIT_SCAN_UNRESOLVED: u8 = 2;
/// `scan` only: a scanner is missing or failed, or its output cannot be read.
pub const EXIT_SCAN_SCANNER: u8 = 3;

/// Top-level `rollcall` command line.
///
/// `--version` is rollcall's own flag rather than clap's, because it also reports the
/// identifier databases, which depend on the environment and the cache directory.
#[derive(Debug, Parser)]
#[command(
    name = "rollcall",
    about = "CRA-grade CycloneDX SBOMs from firmware build metadata",
    disable_version_flag = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Print version, and the active and embedded identifier database versions (any
    /// subcommand given with it is ignored)
    #[arg(short = 'V', long)]
    pub version: bool,
    /// Identifier database for `generate` and `--version` (no other command reads it): a YAML
    /// file, a directory holding identifiers.yaml, or `embedded` to pin the embedded one.
    /// Without it: $ROLLCALL_IDENTIFIERS (same forms), else the newest compatible database
    /// under CACHE/rollcall/identifiers/DB_VERSION/ (CACHE: $ROLLCALL_CACHE_DIR,
    /// $XDG_CACHE_HOME or ~/.cache), else the embedded one. With `generate --zephyr` it also
    /// turns module resolution on
    #[arg(long, global = true, value_name = "PATH")]
    pub identifiers: Option<PathBuf>,
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// The `rollcall` subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a CycloneDX SBOM from firmware build metadata
    Generate(GenerateArgs),
    /// Validate an SBOM against the CycloneDX schema and rollcall's rules
    Validate(ValidateArgs),
    /// Merge bootloader, application and blob SBOMs into one product hierarchy
    Merge(MergeArgs),
    /// Emit VEX statements for an SBOM
    Vex(VexArgs),
    /// Scan an SBOM for known vulnerabilities
    Scan(ScanArgs),
    /// Produce a CycloneDX CBOM (cryptographic inventory) for a build
    Assay,
    /// Inspect and lint the identifier database
    Identifiers(IdentifiersArgs),
    /// Produce a readiness report (Markdown or JSON) for an SBOM
    Report(ReportArgs),
}

impl Command {
    /// The subcommand's name as typed on the command line.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Generate(_) => "generate",
            Command::Validate(_) => "validate",
            Command::Merge(_) => "merge",
            Command::Vex(_) => "vex",
            Command::Scan(_) => "scan",
            Command::Assay => "assay",
            Command::Identifiers(_) => "identifiers",
            Command::Report(_) => "report",
        }
    }
}

/// Output formats for `rollcall generate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// CycloneDX 1.6 JSON.
    Cyclonedx,
    /// SPDX (not implemented yet).
    Spdx,
}

/// Arguments of `rollcall generate`.
#[derive(Debug, Args)]
#[command(group = ArgGroup::new("input").required(true).multiple(false))]
#[command(group = ArgGroup::new("db").multiple(false))]
pub struct GenerateArgs {
    /// The rollcall model (`rollcall-model/1` JSON) to render
    #[arg(long, value_name = "FILE", group = "input")]
    pub model: Option<PathBuf>,
    /// Zephyr image build directory (the one holding build_info.yml and spdx/)
    #[arg(long, value_name = "DIR", group = "input")]
    pub zephyr: Option<PathBuf>,
    /// Output of `west list -f "{name} {path} {revision} {url}"`, for module revisions and
    /// URLs (with --zephyr)
    #[arg(
        long,
        value_name = "FILE",
        requires = "zephyr",
        conflicts_with = "model"
    )]
    pub west_list: Option<PathBuf>,
    /// Add the SDK/toolchain as a component (with --zephyr)
    #[arg(long, requires = "zephyr", conflicts_with = "model")]
    pub include_sdk: bool,
    /// --zephyr names a sysbuild top-level build directory: ingest every image it lists
    /// (e.g. MCUboot and the application) and merge them into one product
    #[arg(long, requires = "zephyr", conflicts_with = "model")]
    pub sysbuild: bool,
    /// Put the product under this name and optional version (split at the last @, so
    /// `@scope/widget@1.0.0`), exactly as `merge --product` would. With or without --sysbuild
    #[arg(
        long,
        value_name = "NAME[@VERSION]",
        value_parser = ProductSpec::from_str,
        requires = "zephyr",
        conflicts_with = "model"
    )]
    pub product: Option<ProductSpec>,
    /// Identifier database (YAML) mapping modules to upstream purl, cpe, supplier and
    /// version (with --zephyr). Modules it does not list are warned about once each, and a
    /// stub entry for each is printed to stderr
    #[arg(
        long,
        value_name = "FILE",
        requires = "zephyr",
        conflicts_with = "model",
        group = "db"
    )]
    pub identifier_db: Option<PathBuf>,
    /// Resolve modules with the active identifier database (with --zephyr): --identifiers,
    /// else $ROLLCALL_IDENTIFIERS, else the newest compatible database in the cache directory
    /// that is newer than the embedded one, else the embedded one (see `rollcall --version`)
    #[arg(long, requires = "zephyr", conflicts_with = "model", group = "db")]
    pub identify: bool,
    /// The west workspace (topdir), so identifier database rules can read module sources at
    /// their `west list` path. Requires --identifier-db or --identify, and --west-list
    #[arg(long, value_name = "DIR", requires_all = ["db", "west_list"])]
    pub workspace: Option<PathBuf>,
    /// Also print notes (with --zephyr): why a subsystem the .config enables was not split
    /// out of the zephyr component (none of its code was linked), and linked code left in it
    // `conflicts_with` is not redundant: `requires` alone lets `--model … --verbose` through.
    #[arg(short, long, requires = "zephyr", conflicts_with = "model")]
    pub verbose: bool,
    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Cyclonedx)]
    pub format: Format,
    /// Document timestamp, RFC 3339 (e.g. 2026-01-02T03:04:05Z); normalised to UTC.
    /// Defaults to the current time
    #[arg(long, value_name = "RFC3339", value_parser = Timestamp::from_str)]
    pub timestamp: Option<Timestamp>,
    /// Serial number: urn:uuid: followed by a lowercase UUID. Defaults to one derived from
    /// the model's content
    #[arg(long, value_name = "URN", value_parser = SerialNumber::from_str)]
    pub serial_number: Option<SerialNumber>,
    /// Write the document here instead of to stdout
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// Arguments of `rollcall merge`.
#[derive(Debug, Args)]
pub struct MergeArgs {
    /// CycloneDX 1.6 documents to merge (e.g. from `rollcall generate`)
    #[arg(value_name = "FILE", required_unless_present = "blob_manifest")]
    pub inputs: Vec<PathBuf>,
    /// Put every input's images under this product (NAME, or NAME@VERSION, split at the
    /// last @). Without it the inputs must name the same product and version
    #[arg(long, value_name = "NAME[@VERSION]", value_parser = ProductSpec::from_str)]
    pub product: Option<ProductSpec>,
    /// YAML manifest of opaque binary blobs (name, version, supplier, path, licence, purl,
    /// kind: firmware|library) to add as blob images, hashed with SHA-256
    #[arg(long, value_name = "FILE")]
    pub blob_manifest: Option<PathBuf>,
    /// Document timestamp, RFC 3339 (e.g. 2026-01-02T03:04:05Z); normalised to UTC.
    /// Defaults to the current time
    #[arg(long, value_name = "RFC3339", value_parser = Timestamp::from_str)]
    pub timestamp: Option<Timestamp>,
    /// Serial number: urn:uuid: followed by a lowercase UUID. Defaults to one derived from
    /// the merged model's content
    #[arg(long, value_name = "URN", value_parser = SerialNumber::from_str)]
    pub serial_number: Option<SerialNumber>,
    /// Write the document here instead of to stdout
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// Output formats for `rollcall vex`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum VexFormat {
    /// rollcall's own `rollcall-vex/1` report: statements, unresolved findings with rule
    /// templates, and warnings.
    Rollcall,
    /// A standalone CycloneDX 1.6 VEX BOM whose `affects` are BOM-Links into the SBOM (needs
    /// --sbom).
    Cyclonedx,
    /// An OpenVEX v0.2.0 document whose products are the components' purls.
    Openvex,
}

/// How `rollcall vex --sign` signs the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignSpec {
    /// A detached Ed25519 signature with this PKCS#8 private key PEM, written to
    /// `<output>.sig`.
    Local(PathBuf),
    /// Sigstore keyless signing with `cosign sign-blob`, bundle written to
    /// `<output>.sigstore.json`.
    Cosign,
}

impl FromStr for SignSpec {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cosign" => Ok(Self::Cosign),
            _ => match s.strip_prefix("local:") {
                Some(path) if !path.is_empty() => Ok(Self::Local(PathBuf::from(path))),
                _ => Err(format!("expected local:<key.pem> or cosign, got {s:?}")),
            },
        }
    }
}

/// Subcommands of `rollcall vex`.
#[derive(Debug, Subcommand)]
pub enum VexCommand {
    /// Verify a signed VEX document: its rollcall Ed25519 signature (--key) or its Sigstore
    /// bundle (--cosign)
    Verify(VexVerifyArgs),
    /// Check VEX rules files: every `kconfig_off` and `kconfig_equals` symbol must exist (a
    /// misspelt one makes the rule never apply), rule ids must be unique across files, and a
    /// `kconfig_equals` value must not be bool-like (`true`, `no`, `~`, `null`, …) or empty.
    /// Exit 1 on any warning
    Lint(VexLintArgs),
}

/// Arguments of `rollcall vex lint`.
#[derive(Debug, Args)]
pub struct VexLintArgs {
    /// VEX rules files (YAML) to check. Repeatable
    #[arg(value_name = "FILE")]
    pub files: Vec<PathBuf>,
    /// Also load the starter rule pack (`rollcall vex --starter-rules`): rule ids in FILE that
    /// it already uses are reported. Its Kconfig symbols are checked with --zephyr-tree, but
    /// with --kconfig only when --lint-starter-symbols is given too
    #[arg(long)]
    pub starter_rules: bool,
    /// With --starter-rules and --kconfig, also check the starter pack's Kconfig symbols
    /// against the .config files (with --zephyr-tree they are always checked, so the two
    /// flags conflict). Its Mbed TLS symbols are hidden in a build without Mbed TLS,
    /// so give the .config files of builds that enable everything the pack names
    #[arg(long, requires = "starter_rules", conflicts_with = "zephyr_tree")]
    pub lint_starter_symbols: bool,
    /// A Kconfig `.config` whose symbols (set or `is not set`) are the known ones; an
    /// `IMAGE=` prefix is allowed and ignored. Repeatable: the union is used. Offline, but a
    /// .config lists only the symbols visible in that build, so a valid symbol hidden by an
    /// unmet dependency is warned about too
    #[arg(long, value_name = "[IMAGE=]FILE", conflicts_with = "zephyr_tree")]
    pub kconfig: Vec<String>,
    /// A Zephyr repository checkout (the directory holding VERSION) whose Kconfig files
    /// define the known symbols. Authoritative for that Zephyr version. Repeatable: a symbol
    /// any tree defines is known
    #[arg(long, value_name = "DIR")]
    pub zephyr_tree: Vec<PathBuf>,
}

/// Arguments of `rollcall vex verify`.
#[derive(Debug, Args)]
#[command(
    group = ArgGroup::new("method").required(true).multiple(false),
    group = ArgGroup::new("identity").multiple(false)
)]
pub struct VexVerifyArgs {
    /// The signed document
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// The signer's Ed25519 public key PEM (SPKI; a PKCS#8 private key PEM also works)
    #[arg(long, value_name = "PEM", group = "method")]
    pub key: Option<PathBuf>,
    /// The rollcall signature file (default: FILE.sig)
    #[arg(long, value_name = "FILE", requires = "key")]
    pub signature: Option<PathBuf>,
    /// Verify a Sigstore bundle with `cosign verify-blob`. Requires the signer's identity
    /// (--certificate-identity or --certificate-identity-regexp) and
    /// --certificate-oidc-issuer
    #[arg(long, group = "method", requires_all = ["identity", "certificate_oidc_issuer"])]
    pub cosign: bool,
    /// The Sigstore bundle (default: FILE.sigstore.json)
    #[arg(long, value_name = "FILE", requires = "cosign")]
    pub bundle: Option<PathBuf>,
    /// The signing certificate's expected identity (passed to cosign)
    #[arg(long, value_name = "ID", requires = "cosign", group = "identity")]
    pub certificate_identity: Option<String>,
    /// A regular expression the signing certificate's identity must match (passed to cosign)
    #[arg(long, value_name = "REGEX", requires = "cosign", group = "identity")]
    pub certificate_identity_regexp: Option<String>,
    /// The signing certificate's expected OIDC issuer (passed to cosign)
    #[arg(long, value_name = "URL", requires = "cosign")]
    pub certificate_oidc_issuer: Option<String>,
}

/// Arguments of `rollcall vex`.
#[derive(Debug, Args)]
#[command(
    group = ArgGroup::new("input").required(true).multiple(false),
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
pub struct VexArgs {
    /// Verify a signed VEX document instead of producing one
    #[command(subcommand)]
    pub command: Option<VexCommand>,
    /// The CycloneDX 1.6 SBOM the findings are about (e.g. from `rollcall generate`)
    #[arg(long, value_name = "FILE", group = "input")]
    pub sbom: Option<PathBuf>,
    /// The rollcall model (`rollcall-model/1` JSON) the findings are about
    #[arg(long, value_name = "FILE", group = "input")]
    pub model: Option<PathBuf>,
    /// An image's Kconfig `.config` (e.g. BUILD/IMAGE/zephyr/.config), evidence for
    /// `kconfig_off` conditions on that image's components, as IMAGE=FILE (IMAGE is the
    /// image's name in the SBOM). Repeatable, once per image. A bare FILE is allowed only
    /// when the product has a single image. Components of an image without a .config get
    /// unknown `kconfig_off` conditions. Evidence cites it as IMAGE/zephyr/.config
    #[arg(long, value_name = "[IMAGE=]FILE")]
    pub kconfig: Vec<String>,
    /// Scanner output to triage: grype `-o json` or osv-scanner `--format json` (detected
    /// from the content). Repeatable
    #[arg(long, value_name = "FILE", required = true)]
    pub findings: Vec<PathBuf>,
    /// VEX rules (YAML). Repeatable; rule ids must be unique across files. Only
    /// `kconfig_off`, `kconfig_equals` and `version_in` conditions can be evidenced from the
    /// command line:
    /// `cargo_feature_off` and `symbol_not_linked` always lack evidence (the finding stays
    /// unresolved). `match.subsystem` matches a Zephyr subsystem subcomponent by name
    #[arg(long, value_name = "FILE")]
    pub rules: Vec<PathBuf>,
    /// Also use rollcall's starter rule pack (vex-rules.yaml, shipped with the identifier
    /// database; see docs/vex-rules.md), before any --rules files. Its rule ids must not be
    /// reused in them
    #[arg(long)]
    pub starter_rules: bool,
    /// Output format. cyclonedx and openvex render only the statements; unresolved
    /// findings are summarised on stderr
    #[arg(long, value_enum, default_value_t = VexFormat::Rollcall)]
    pub format: VexFormat,
    /// Write the SBOM (--sbom) with the statements added as its `vulnerabilities`, instead
    /// of a separate VEX document. The input file is never modified; write to -o
    #[arg(long, requires = "sbom")]
    pub embed: bool,
    /// Document timestamp for --format cyclonedx|openvex, RFC 3339; normalised to UTC.
    /// Defaults to the current time
    #[arg(long, value_name = "RFC3339", value_parser = Timestamp::from_str)]
    pub timestamp: Option<Timestamp>,
    /// Document id for --format cyclonedx|openvex: urn:uuid: followed by a lowercase UUID.
    /// Defaults to one derived from the statements and the SBOM's serial number
    #[arg(long, value_name = "URN", value_parser = SerialNumber::from_str)]
    pub id: Option<SerialNumber>,
    /// OpenVEX author. Defaults to the SBOM product's supplier, else "rollcall"
    #[arg(long, value_name = "TEXT")]
    pub author: Option<String>,
    /// Sign the output: local:KEY.pem (Ed25519, detached signature in OUTPUT.sig) or cosign
    /// (Sigstore keyless, bundle in OUTPUT.sigstore.json; needs cosign and an OIDC
    /// identity, e.g. in CI). Requires -o
    #[arg(long, value_name = "local:KEY.pem|cosign", value_parser = SignSpec::from_str, requires = "output")]
    pub sign: Option<SignSpec>,
    /// Write the output here instead of to stdout
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// Which scanners `rollcall scan` runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScannerChoice {
    /// Anchore grype only.
    Grype,
    /// Google osv-scanner only.
    Osv,
    /// Every scanner found on PATH (grype, osv-scanner); a missing one is skipped.
    Auto,
}

/// A `--fail-on` threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SeverityArg {
    /// Critical findings.
    Critical,
    /// High or critical.
    High,
    /// Medium or higher.
    Medium,
    /// Low or higher.
    Low,
    /// Every open finding, including those of unknown severity.
    Unknown,
}

impl From<SeverityArg> for rollcall_core::severity::Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Critical => Self::Critical,
            SeverityArg::High => Self::High,
            SeverityArg::Medium => Self::Medium,
            SeverityArg::Low => Self::Low,
            SeverityArg::Unknown => Self::Unknown,
        }
    }
}

/// Arguments of `rollcall scan`.
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// The CycloneDX 1.6 SBOM to scan (e.g. from `rollcall generate`)
    #[arg(value_name = "SBOM")]
    pub sbom: PathBuf,
    /// A VEX document to triage the findings with: OpenVEX, CycloneDX VEX (standalone, or an
    /// SBOM with embedded vulnerabilities) or rollcall-vex/1 (detected from the content).
    /// Suppressed findings are still listed. Repeatable
    #[arg(long, value_name = "FILE")]
    pub vex: Vec<PathBuf>,
    /// Which scanners to run. auto runs every one found on PATH and skips a missing one
    #[arg(long, value_enum, default_value_t = ScannerChoice::Auto)]
    pub scanner: ScannerChoice,
    /// Scan offline with pre-downloaded databases: grype's in DIR/grype (its
    /// GRYPE_DB_CACHE_DIR, auto-update off) and osv-scanner's in DIR/osv-scanner (its
    /// OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY, --offline). A grype database older than grype's
    /// age limit fails the scan (exit 3); see docs/scan.md
    #[arg(long, value_name = "DIR")]
    pub db_path: Option<PathBuf>,
    /// Exit 1 if an open (not VEX-suppressed) finding is at or above this severity.
    /// unknown is the lowest level
    #[arg(long, value_enum, value_name = "SEVERITY")]
    pub fail_on: Option<SeverityArg>,
    /// Exit 2 if a finding is unresolved: no VEX claim, under_investigation, or conflicting
    /// claims (exit 1 takes precedence)
    #[arg(long)]
    pub fail_on_unresolved: bool,
    /// Print the rollcall-scan/1 JSON report on stdout instead of the table
    #[arg(long)]
    pub json: bool,
}

/// Arguments of `rollcall validate`.
#[derive(Debug, Args)]
#[command(group = ArgGroup::new("checks").required(true).multiple(true))]
pub struct ValidateArgs {
    /// The document to validate
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// Check the document against the vendored CycloneDX 1.6 JSON schema
    #[arg(long, group = "checks")]
    pub schema: bool,
    /// Check the document against a regulator profile: cisa-2026 (CISA 2026 SBOM minimum
    /// elements), cra (EU Cyber Resilience Act), all (both), or the path of a profile YAML
    /// file (any value containing a path separator or ending in .yaml or .yml). Combine with
    /// --schema to run both
    #[arg(long, value_name = "NAME|PATH", group = "checks")]
    pub profile: Option<String>,
    /// Print one JSON object (schema violations and profile findings) on stdout instead of
    /// text, for CI
    #[arg(long)]
    pub json: bool,
}

/// Arguments of `rollcall identifiers`.
#[derive(Debug, Args)]
pub struct IdentifiersArgs {
    /// What to do.
    #[command(subcommand)]
    pub command: IdentifiersCommand,
}

/// The `rollcall identifiers` subcommands.
#[derive(Debug, Subcommand)]
pub enum IdentifiersCommand {
    /// Check an identifier database: schema, purl and CPE syntax, duplicate and unsorted
    /// modules, db_version, that every manual-table row resolves, and (with --fixtures) that
    /// it resolves every module of real Zephyr builds. Exit 1 on any finding
    Lint(LintArgs),
}

/// Arguments of `rollcall identifiers lint`.
#[derive(Debug, Args)]
pub struct LintArgs {
    /// The database: a YAML file, or a directory holding identifiers.yaml. Defaults to the
    /// embedded database, whose db_version must then be the rollcall-identifiers version (the
    /// global --identifiers is not used here)
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,
    /// Zephyr fixture builds to resolve: DIR, or each subdirectory of DIR, holding
    /// build_info.yml and west-list.txt (e.g. fixtures/zephyr). Every module must get a purl
    /// from the database. Repeatable
    #[arg(long, value_name = "DIR")]
    pub fixtures: Vec<PathBuf>,
    /// The db_version the database must declare (e.g. the rollcall-identifiers crate
    /// version)
    #[arg(long, value_name = "VERSION", value_parser = DbVersion::from_str)]
    pub expect_version: Option<DbVersion>,
}

/// Output formats for `rollcall report`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    /// GitHub-flavoured Markdown, for people.
    Md,
    /// `rollcall-report/1` JSON (docs/report-schema.json), for machines.
    Json,
}

/// Arguments of `rollcall report`.
#[derive(Debug, Args)]
pub struct ReportArgs {
    /// The CycloneDX 1.6 SBOM to report on (e.g. from `rollcall generate`)
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// Scanner output for the SBOM: grype `-o json`, osv-scanner `--format json` or
    /// `rollcall scan --json` (rollcall-scan/1; its VEX triage is not used, pass --vex)
    /// (detected from the content). Repeatable. Without it, vulnerabilities are not assessed
    #[arg(long, value_name = "FILE")]
    pub scan: Vec<PathBuf>,
    /// VEX statements for the SBOM: `rollcall vex` output in any format (rollcall-vex/1,
    /// OpenVEX, CycloneDX VEX, or an SBOM with --embed'ed vulnerabilities; detected from the
    /// content). Repeatable
    #[arg(long, value_name = "FILE")]
    pub vex: Vec<PathBuf>,
    /// Output format
    #[arg(long, value_enum)]
    pub format: ReportFormat,
    /// Report timestamp, RFC 3339 (e.g. 2026-01-02T03:04:05Z); normalised to UTC. Defaults
    /// to the current time
    #[arg(long, value_name = "RFC3339", value_parser = Timestamp::from_str)]
    pub timestamp: Option<Timestamp>,
    /// Write the report here instead of to stdout
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}
