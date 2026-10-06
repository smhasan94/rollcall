//! `catalogue-sync OURS THEIRS`: checks that a copy of the algorithm catalogue (cbom-infra's,
//! THEIRS) agrees with rollcall's (OURS) on every shared entry. `scripts/check-catalogue-sync.sh`
//! runs it; see `docs/catalogue.md`.
//!
//! Prints the comparison to stdout: the shared count, the entries in one file only (ours as a
//! count, theirs listed), then every disagreement as `NAME[/ID] FIELD: ours X, theirs Y`.
//! Errors go to stderr.
//!
//! Exit codes: 0 every shared entry agrees, 1 at least one disagreement, 64 usage, 65 a file
//! does not load (malformed, wrong format or lint findings), 66 a file cannot be read.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;
use std::process::ExitCode;

use rollcall_assay::catalogue::{Catalogue, CatalogueError, compare};

const USAGE: &str = "usage: catalogue-sync OURS THEIRS";

fn load(what: &str, path: &Path) -> Result<Catalogue, ExitCode> {
    Catalogue::load_path(path).map_err(|e| {
        eprintln!("catalogue-sync: {what}: {e}");
        match e {
            CatalogueError::Read { .. } => ExitCode::from(66),
            _ => ExitCode::from(65),
        }
    })
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn run(ours: &Path, theirs: &Path) -> Result<bool, ExitCode> {
    let ours_catalogue = load("ours", ours)?;
    let theirs_catalogue = load("theirs", theirs)?;
    let comparison = compare(&ours_catalogue, &theirs_catalogue);
    println!("ours:   {}", ours.display());
    println!("theirs: {}", theirs.display());
    let n = comparison.shared.len();
    println!("shared: {n} parameter set{}", plural(n));
    let n = comparison.only_ours.len();
    println!("only in ours: {n} parameter set{}", plural(n));
    let n = comparison.only_theirs.len();
    println!("only in theirs: {n} parameter set{}", plural(n));
    for (name, id) in &comparison.only_theirs {
        println!("  {name}/{id}");
    }
    let n = comparison.disagreements.len();
    println!("disagreements: {n}");
    for disagreement in &comparison.disagreements {
        println!("  {disagreement}");
    }
    if comparison.agrees() {
        println!("agree: every shared entry matches");
    } else {
        println!("disagree: fix the copy, or change rollcall's catalogue first");
    }
    Ok(comparison.agrees())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [ours, theirs] = args.as_slice() else {
        eprintln!("{USAGE}");
        return ExitCode::from(64);
    };
    match run(Path::new(ours), Path::new(theirs)) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(code) => code,
    }
}
