//! Command-line interface definition for the `rollcall` binary.

use std::path::PathBuf;
use std::str::FromStr;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use rollcall_core::cyclonedx::{SerialNumber, Timestamp};
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

/// Top-level `rollcall` command line.
#[derive(Debug, Parser)]
#[command(
    name = "rollcall",
    version,
    about = "CRA-grade CycloneDX SBOMs from firmware build metadata"
)]
pub struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
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
    Scan,
    /// Produce a CycloneDX CBOM (cryptographic inventory) for a build
    Assay,
}

impl Command {
    /// The subcommand's name as typed on the command line.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Generate(_) => "generate",
            Command::Validate(_) => "validate",
            Command::Merge(_) => "merge",
            Command::Vex(_) => "vex",
            Command::Scan => "scan",
            Command::Assay => "assay",
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
        conflicts_with = "model"
    )]
    pub identifier_db: Option<PathBuf>,
    /// The west workspace (topdir), so --identifier-db rules can read module sources at their
    /// `west list` path. Requires both --identifier-db and --west-list
    #[arg(long, value_name = "DIR", requires_all = ["identifier_db", "west_list"])]
    pub workspace: Option<PathBuf>,
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
    /// `kconfig_off` and `version_in` conditions can be evidenced from the command line:
    /// `cargo_feature_off` and `symbol_not_linked` always lack evidence (the finding stays
    /// unresolved), and `match.subsystem` is reserved until the subsystem split (SHA-108)
    /// and matches nothing (with a warning)
    #[arg(long, value_name = "FILE")]
    pub rules: Vec<PathBuf>,
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
