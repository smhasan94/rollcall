//! The `rollcall` binary.

mod cli;
mod commands;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command, EXIT_USAGE};

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // `--help` / `--version` are reported through clap's error path but go to stdout
            // and are not failures. Printing can only fail if stdout/stderr is gone; there is
            // nothing useful left to do in that case.
            let _ = e.print();
            return if e.use_stderr() {
                ExitCode::from(EXIT_USAGE)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    let code = match cli.command {
        Command::Generate(args) => commands::generate::run(args),
        Command::Validate(args) => commands::validate::run(args),
        Command::Merge(args) => commands::merge::run(args),
        Command::Vex(args) => commands::vex::run(args),
        other @ (Command::Scan | Command::Assay) => {
            eprintln!("rollcall {}: not implemented", other.name());
            EXIT_USAGE
        }
    };
    ExitCode::from(code)
}
