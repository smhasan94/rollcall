//! Command-line interface definition for the `rollcall` binary.

use std::path::PathBuf;
use std::str::FromStr;

use clap::{Args, Parser, Subcommand, ValueEnum};
use rollcall_core::cyclonedx::{SerialNumber, Timestamp};

/// Exit code when a document fails validation.
pub const EXIT_INVALID: u8 = 1;
/// Exit code for usage errors and not-yet-implemented subcommands (`EX_USAGE` from sysexits.h).
pub const EXIT_USAGE: u8 = 64;
/// Exit code when an input file is malformed (`EX_DATAERR`).
pub const EXIT_DATAERR: u8 = 65;
/// Exit code when an input file is missing or unreadable (`EX_NOINPUT`).
pub const EXIT_NOINPUT: u8 = 66;
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
    Merge,
    /// Emit VEX statements for an SBOM
    Vex,
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
            Command::Merge => "merge",
            Command::Vex => "vex",
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
pub struct GenerateArgs {
    /// The rollcall model (`rollcall-model/1` JSON) to render
    #[arg(long, value_name = "FILE")]
    pub model: PathBuf,
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

/// Arguments of `rollcall validate`.
#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// The document to validate
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// Check the document against the vendored CycloneDX 1.6 JSON schema (required for now;
    /// rollcall's own rules will be a separate check)
    #[arg(long, required = true)]
    pub schema: bool,
}
