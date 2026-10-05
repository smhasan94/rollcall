//! `rollcall vex`: triage scanner findings for an SBOM with VEX rules and build evidence, and
//! write the resulting statements as rollcall's `rollcall-vex/1` report, a CycloneDX 1.6 VEX
//! document, an OpenVEX document, or embedded in the SBOM; optionally signed. `rollcall vex
//! verify` checks a signature; `rollcall vex lint` checks rules files.

mod cosign;
mod lint;
mod sign;
mod verify;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use rollcall_core::cyclonedx::{self, Timestamp};
use rollcall_core::model::{NodePath, Product};
use rollcall_core::vex::{self, BuildEvidence, Finding, Report, RuleSet, SbomIndex, VexOptions};
use rollcall_core::warning::Warning;
use rollcall_core::zephyr::kconfig;

use super::output::write_atomically;
use crate::cli::{
    EXIT_DATAERR, EXIT_IOERR, EXIT_NOINPUT, EXIT_SOFTWARE, EXIT_USAGE, VexArgs, VexCommand,
    VexFormat,
};

type Failure = (u8, String);

/// Runs `rollcall vex` (or `rollcall vex verify`), returning the exit code. Unresolved
/// findings and rule conflicts are summarised on stderr; they do not fail the command.
pub fn run(args: VexArgs) -> u8 {
    match &args.command {
        Some(VexCommand::Verify(verify)) => return verify::run(verify),
        Some(VexCommand::Lint(lint)) => return lint::run(lint),
        None => {}
    }
    match produce(&args) {
        Ok(()) => 0,
        Err((code, message)) => fail(code, &message),
    }
}

/// Rejects flag combinations clap cannot express.
fn check_flags(args: &VexArgs) -> Result<(), Failure> {
    let usage = |m: &str| Err((EXIT_USAGE, m.to_owned()));
    if args.embed && args.format != VexFormat::Cyclonedx {
        return usage("--embed writes CycloneDX: use it with --format cyclonedx");
    }
    if args.format == VexFormat::Cyclonedx && args.sbom.is_none() {
        return usage(
            "--format cyclonedx needs --sbom: its statements link to the SBOM's components by \
             serial number and bom-ref (use --format openvex with --model)",
        );
    }
    let document = matches!(args.format, VexFormat::Cyclonedx | VexFormat::Openvex) && !args.embed;
    if !document && (args.timestamp.is_some() || args.id.is_some()) {
        return usage(
            "--timestamp and --id apply to a VEX document: use them with --format cyclonedx \
             or --format openvex (without --embed)",
        );
    }
    if args.author.is_some() && args.format != VexFormat::Openvex {
        return usage("--author applies to --format openvex");
    }
    Ok(())
}

fn produce(args: &VexArgs) -> Result<(), Failure> {
    check_flags(args)?;
    // Load the signing key (or find cosign) first: a bad key must not leave an unsigned
    // document behind.
    let signer = match &args.sign {
        Some(spec) => Some(sign::Signer::prepare(spec)?),
        None => None,
    };
    let sbom_bytes = match &args.sbom {
        Some(path) => Some(read(path)?),
        None => None,
    };
    let report = evaluate(args, sbom_bytes.as_deref())?;
    let text = render(args, &report, sbom_bytes.as_deref())?;
    write_output(args.output.as_deref(), &text)?;
    if let (Some(signer), Some(output)) = (&signer, &args.output) {
        signer.sign(output, text.as_bytes())?;
    }
    Ok(())
}

fn render(args: &VexArgs, report: &Report, sbom_bytes: Option<&[u8]>) -> Result<String, Failure> {
    let sbom_path = || args.sbom.clone().unwrap_or_default();
    let index = match sbom_bytes {
        Some(bytes) => Some(SbomIndex::from_bytes(bytes).map_err(|e| malformed(&sbom_path(), e))?),
        None => None,
    };
    let mut options = VexOptions::new(args.timestamp.clone().unwrap_or_else(Timestamp::now));
    options.id = args.id.clone();
    options.author = args.author.clone();
    let rendered = match (args.format, sbom_bytes, &index) {
        (VexFormat::Rollcall, _, _) => {
            return report
                .to_json()
                .map_err(|e| (EXIT_SOFTWARE, format!("cannot serialise the report: {e}")));
        }
        (VexFormat::Openvex, _, index) => vex::to_openvex(report, index.as_ref(), &options),
        (VexFormat::Cyclonedx, Some(bytes), _) if args.embed => vex::embed(bytes, report),
        (VexFormat::Cyclonedx, _, Some(index)) => vex::to_cyclonedx_vex(report, index, &options),
        (VexFormat::Cyclonedx, _, None) => {
            return Err((EXIT_USAGE, "--format cyclonedx needs --sbom".to_owned()));
        }
    };
    let rendered = rendered.map_err(|e| match e {
        vex::VexError::Json(_) => (EXIT_SOFTWARE, e.to_string()),
        _ => malformed(&sbom_path(), e),
    })?;
    warn(None, &rendered.warnings);
    Ok(rendered.text)
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

fn load_product(args: &VexArgs, sbom_bytes: Option<&[u8]>) -> Result<Loaded, Failure> {
    if let (Some(path), Some(bytes)) = (&args.sbom, sbom_bytes) {
        let read = cyclonedx::read_bytes(bytes).map_err(|e| malformed(path, e))?;
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

/// The embedded starter rule pack (`rollcall_identifiers::VEX_RULES_YAML`).
fn starter_rules() -> Result<RuleSet, Failure> {
    vex::parse_rules(
        rollcall_identifiers::VEX_RULES_YAML,
        rollcall_identifiers::VEX_RULES_FILE_NAME,
    )
    .map_err(|e| {
        (
            EXIT_SOFTWARE,
            format!("the embedded starter rule pack: {e}"),
        )
    })
}

fn load_rules(args: &VexArgs) -> Result<RuleSet, Failure> {
    let mut rules = if args.starter_rules {
        starter_rules()?
    } else {
        RuleSet::default()
    };
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

/// Loads every input, evaluates, and prints the report's warnings.
fn evaluate(args: &VexArgs, sbom_bytes: Option<&[u8]>) -> Result<Report, Failure> {
    let (product, document_refs) = load_product(args, sbom_bytes)?;
    let evidence = load_evidence(args, &product)?;
    let findings = load_findings(args)?;
    let rules = load_rules(args)?;
    let report = match &document_refs {
        Some(refs) => vex::evaluate_document(&product, refs, &evidence, &findings, &rules),
        None => vex::evaluate(&product, &evidence, &findings, &rules),
    };
    warn(None, &report.warnings);
    if !report.unresolved.is_empty() {
        let unresolved = report.unresolved.len();
        let total = unresolved + report.statements.len();
        let _ = if args.format == VexFormat::Rollcall {
            writeln!(
                std::io::stderr(),
                "rollcall vex: warning: {unresolved} of {total} finding(s) unresolved; see \
                 `unresolved` in the report for a rule template for each"
            )
        } else {
            writeln!(
                std::io::stderr(),
                "rollcall vex: warning: {unresolved} of {total} finding(s) unresolved and not \
                 in the VEX document; run with --format rollcall for a rule template for each"
            )
        };
    }
    Ok(report)
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
