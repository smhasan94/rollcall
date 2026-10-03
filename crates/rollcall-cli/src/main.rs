//! The `rollcall` binary.

mod cli;
mod commands;

use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Command, EXIT_USAGE};

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // `--help` is reported through clap's error path but goes to stdout and is not a
            // failure. Printing can only fail if stdout/stderr is gone; there is nothing
            // useful left to do in that case.
            let _ = e.print();
            return if e.use_stderr() {
                ExitCode::from(EXIT_USAGE)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    if cli.version {
        return ExitCode::from(commands::version::run(cli.identifiers.as_deref()));
    }
    let Some(command) = cli.command else {
        // Only flags, e.g. `rollcall --identifiers db.yaml`.
        let _ = Cli::command()
            .error(
                clap::error::ErrorKind::MissingSubcommand,
                "a subcommand is required",
            )
            .print();
        return ExitCode::from(EXIT_USAGE);
    };
    let code = match command {
        Command::Generate(args) => commands::generate::run(args, cli.identifiers.as_deref()),
        Command::Validate(args) => commands::validate::run(args),
        Command::Merge(args) => commands::merge::run(args),
        Command::Vex(args) => commands::vex::run(args),
        Command::Identifiers(args) => commands::identifiers::run(args),
        Command::Report(args) => commands::report::run(args),
        other @ (Command::Scan | Command::Assay) => {
            eprintln!("rollcall {}: not implemented", other.name());
            EXIT_USAGE
        }
    };
    ExitCode::from(code)
}
