//! The `rollcall` binary.

mod cli;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, EXIT_USAGE};

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
    eprintln!("rollcall {}: not implemented", cli.command.name());
    ExitCode::from(EXIT_USAGE)
}
