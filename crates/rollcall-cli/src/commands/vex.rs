//! `rollcall vex`: triage scanner findings for an SBOM with VEX rules and build evidence, and
//! write the resulting statements and unresolved findings as `rollcall-vex/1` JSON.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use rollcall_core::cyclonedx;
use rollcall_core::model::{NodePath, Product};
use rollcall_core::vex::{self, BuildEvidence, Finding, RuleSet};
use rollcall_core::warning::Warning;
use rollcall_core::zephyr::kconfig;

use super::output::write_atomically;
use crate::cli::{EXIT_DATAERR, EXIT_IOERR, EXIT_NOINPUT, EXIT_SOFTWARE, EXIT_USAGE, VexArgs};

type Failure = (u8, String);

/// Runs `rollcall vex`, returning the exit code. Unresolved findings and rule conflicts are
/// part of the report and are summarised on stderr; they do not fail the command.
pub fn run(args: VexArgs) -> u8 {
    match report(&args) {
        Ok(text) => match write_output(args.output.as_deref(), &text) {
            Ok(()) => 0,
            Err((code, message)) => fail(code, &message),
        },
        Err((code, message)) => fail(code, &message),
    }
}

fn fail(code: u8, message: &str) -> u8 {
    let _ = writeln!(std::io::stderr(), "rollcall vex: {message}");
    code
}

fn warn(file: Option<&Path>, warnings: &[Warning]) {
    let mut stderr = std::io::stderr().lock();
    for warning in warnings {
        let _ = match file {
            Some(file) => writeln!(
                stderr,
                "rollcall vex: warning: {}: {warning}",
                file.display()
            ),
            None => writeln!(stderr, "rollcall vex: warning: {warning}"),
        };
    }
}

fn read(path: &Path) -> Result<Vec<u8>, Failure> {
    std::fs::read(path).map_err(|e| (EXIT_NOINPUT, format!("{}: {e}", path.display())))
}

fn malformed(path: &Path, error: impl std::fmt::Display) -> Failure {
    (EXIT_DATAERR, format!("{}: {error}", path.display()))
}

/// The product, and for `--sbom` the document's `bom-ref` → node path table.
type Loaded = (Product, Option<BTreeMap<String, NodePath>>);

fn load_product(args: &VexArgs) -> Result<Loaded, Failure> {
    if let Some(path) = &args.sbom {
        let read = cyclonedx::read_bytes(&read(path)?).map_err(|e| malformed(path, e))?;
        warn(Some(path), &read.warnings);
        return Ok((read.product, Some(read.refs)));
    }
    if let Some(path) = &args.model {
        let product = Product::from_json_bytes(&read(path)?).map_err(|e| malformed(path, e))?;
        return Ok((product, None));
    }
    // clap's ArgGroup requires one of them.
    Err((
        EXIT_USAGE,
        "one of --sbom or --model is required".to_owned(),
    ))
}

/// Splits `--kconfig [IMAGE=]FILE`: an `IMAGE=` prefix is recognised when the part before
/// the first `=` is non-empty and contains no path separator.
fn split_kconfig(arg: &str) -> (Option<&str>, &str) {
    match arg.split_once('=') {
        Some((image, path)) if !image.is_empty() && !image.contains(['/', '\\']) => {
            (Some(image), path)
        }
        _ => (None, arg),
    }
}

fn load_evidence(args: &VexArgs, product: &Product) -> Result<BuildEvidence, Failure> {
    let images: BTreeSet<&str> = product.images.iter().map(|i| i.name.as_str()).collect();
    let listed = || {
        images
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut evidence = BuildEvidence::new();
    let mut seen = BTreeSet::new();
    for arg in &args.kconfig {
        let (image, path) = split_kconfig(arg);
        let image = match image {
            Some(image) if images.contains(image) => image.to_owned(),
            Some(image) => {
                return Err((
                    EXIT_USAGE,
                    format!(
                        "--kconfig {arg}: the product has no image {image:?} (its images: {})",
                        listed()
                    ),
                ));
            }
            None => match images.iter().next() {
                Some(only) if images.len() == 1 => (*only).to_owned(),
                _ => {
                    return Err((
                        EXIT_USAGE,
                        format!(
                            "--kconfig {arg}: the product has {} images ({}); say which one \
                             this .config belongs to with --kconfig IMAGE={path}",
                            images.len(),
                            listed()
                        ),
                    ));
                }
            },
        };
        if !seen.insert(image.clone()) {
            return Err((
                EXIT_USAGE,
                format!("--kconfig: image {image:?} is given more than once"),
            ));
        }
        let path = PathBuf::from(path);
        let bytes = read(&path)?;
        let text = std::str::from_utf8(&bytes).map_err(|e| malformed(&path, e))?;
        let config = kconfig::parse(text).map_err(|e| malformed(&path, e))?;
        evidence = evidence.with_kconfig(&image, config);
    }
    Ok(evidence)
}

fn load_findings(args: &VexArgs) -> Result<Vec<Finding>, Failure> {
    let mut all = Vec::new();
    for path in &args.findings {
        let parsed = vex::parse_findings(&read(path)?).map_err(|e| malformed(path, e))?;
        warn(Some(path), &parsed.warnings);
        all.extend(parsed.findings);
    }
    Ok(all)
}

fn load_rules(args: &VexArgs) -> Result<RuleSet, Failure> {
    let mut rules = RuleSet::default();
    for path in &args.rules {
        let name = path.display().to_string();
        // RuleError already starts with the file name.
        let set = vex::parse_rules_bytes(&read(path)?, &name)
            .map_err(|e| (EXIT_DATAERR, e.to_string()))?;
        rules
            .extend_checked(set, &name)
            .map_err(|e| (EXIT_DATAERR, e.to_string()))?;
    }
    Ok(rules)
}

/// Loads every input, evaluates, prints warnings and returns the report text.
fn report(args: &VexArgs) -> Result<String, Failure> {
    let (product, document_refs) = load_product(args)?;
    let evidence = load_evidence(args, &product)?;
    let findings = load_findings(args)?;
    let rules = load_rules(args)?;
    let report = match &document_refs {
        Some(refs) => vex::evaluate_document(&product, refs, &evidence, &findings, &rules),
        None => vex::evaluate(&product, &evidence, &findings, &rules),
    };
    warn(None, &report.warnings);
    if !report.unresolved.is_empty() {
        let _ = writeln!(
            std::io::stderr(),
            "rollcall vex: warning: {} of {} finding(s) unresolved; see `unresolved` in the \
             report for a rule template for each",
            report.unresolved.len(),
            report.unresolved.len() + report.statements.len()
        );
    }
    report
        .to_json()
        .map_err(|e| (EXIT_SOFTWARE, format!("cannot serialise the report: {e}")))
}

fn write_output(output: Option<&Path>, text: &str) -> Result<(), Failure> {
    match output {
        Some(path) => write_atomically(path, text.as_bytes())
            .map_err(|e| (EXIT_IOERR, format!("{}: {e}", path.display()))),
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(text.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|e| (EXIT_IOERR, format!("stdout: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::split_kconfig;

    #[test]
    fn kconfig_argument_forms() {
        assert_eq!(
            split_kconfig("app=build/app/zephyr/.config"),
            (Some("app"), "build/app/zephyr/.config")
        );
        assert_eq!(
            split_kconfig("build/zephyr/.config"),
            (None, "build/zephyr/.config")
        );
        assert_eq!(split_kconfig("./a=b/.config"), (None, "./a=b/.config"));
        assert_eq!(split_kconfig("=x"), (None, "=x"));
    }
}
