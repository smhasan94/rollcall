//! Command-line interface definition for the `rollcall` binary.

use clap::{Parser, Subcommand};

/// Exit code for usage errors and not-yet-implemented subcommands (`EX_USAGE` from sysexits.h).
pub const EXIT_USAGE: u8 = 64;

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
    Generate,
    /// Validate an SBOM against the CycloneDX schema and rollcall's rules
    Validate,
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
            Command::Generate => "generate",
            Command::Validate => "validate",
            Command::Merge => "merge",
            Command::Vex => "vex",
            Command::Scan => "scan",
            Command::Assay => "assay",
        }
    }
}
