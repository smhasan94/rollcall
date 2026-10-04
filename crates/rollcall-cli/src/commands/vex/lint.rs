//! `rollcall vex lint`: check VEX rules files ([`rollcall_core::vex::lint_rules`] and
//! [`rollcall_core::vex::lint_duplicate_ids`]).
//!
//! Every `kconfig_off` and `kconfig_equals` symbol must be known to the reference: the Zephyr
//! trees given with `--zephyr-tree`, or the union of the `--kconfig` files (not both). With
//! `--kconfig`, the starter pack's own symbols are checked only with `--lint-starter-symbols`:
//! a single build's `.config` hides the symbols of everything it leaves out. Rule ids must be
//! unique across the files (starter pack included). Findings go to stderr, one per line,
//! sorted; a summary line goes to stdout. Exit 0 when there is no finding, 1 when there is
//! any (as `rollcall identifiers lint`), 64 without rules or without a reference, 65 for a
//! malformed rules file, `.config` or tree `VERSION`, 66 for a missing one.

use std::io::Write;
use std::path::PathBuf;

use rollcall_core::subsystems::ZephyrTree;
use rollcall_core::vex::{self, KconfigSymbols, LintFinding, RuleSet, SymbolReference};
use rollcall_core::zephyr::kconfig;

use super::{Failure, malformed, read, split_kconfig, starter_rules};
use crate::cli::{EXIT_DATAERR, EXIT_INVALID, EXIT_NOINPUT, EXIT_USAGE, VexLintArgs};

/// Runs `rollcall vex lint`, returning the exit code.
pub fn run(args: &VexLintArgs) -> u8 {
    match lint(args) {
        Ok((findings, summary)) => {
            let mut stderr = std::io::stderr().lock();
            for finding in &findings {
                let _ = writeln!(stderr, "{finding}");
            }
            let _ = writeln!(
                std::io::stdout().lock(),
                "{summary}; {} finding(s)",
                findings.len()
            );
            if findings.is_empty() { 0 } else { EXIT_INVALID }
        }
        Err((code, message)) => {
            let _ = writeln!(std::io::stderr(), "rollcall vex lint: {message}");
            code
        }
    }
}

/// The reference symbols are checked against.
enum Reference {
    Trees(Vec<ZephyrTree>),
    Configs(KconfigSymbols),
}

impl Reference {
    fn load(args: &VexLintArgs) -> Result<Self, Failure> {
        if !args.zephyr_tree.is_empty() {
            let mut trees = Vec::with_capacity(args.zephyr_tree.len());
            for dir in &args.zephyr_tree {
                let tree = ZephyrTree::open(dir).map_err(|e| {
                    (
                        EXIT_NOINPUT,
                        format!("--zephyr-tree {}: {e}", dir.display()),
                    )
                })?;
                if tree.version().is_none() {
                    return Err((
                        EXIT_DATAERR,
                        format!(
                            "--zephyr-tree {}: VERSION is not a Zephyr VERSION file \
                             (VERSION_MAJOR, VERSION_MINOR, PATCHLEVEL)",
                            dir.display()
                        ),
                    ));
                }
                trees.push(tree);
            }
            return Ok(Self::Trees(trees));
        }
        if args.kconfig.is_empty() {
            return Err((
                EXIT_USAGE,
                "nothing to check symbols against: give --zephyr-tree DIR (a Zephyr \
                 checkout) or --kconfig FILE (a build's .config)"
                    .to_owned(),
            ));
        }
        let mut configs = Vec::with_capacity(args.kconfig.len());
        for arg in &args.kconfig {
            let (_, path) = split_kconfig(arg);
            let path = PathBuf::from(path);
            let bytes = read(&path)?;
            let text = std::str::from_utf8(&bytes).map_err(|e| malformed(&path, e))?;
            configs.push(kconfig::parse(text).map_err(|e| malformed(&path, e))?);
        }
        Ok(Self::Configs(KconfigSymbols::from_configs(&configs)))
    }

    fn lint(&self, rules: &RuleSet, file: &str) -> Vec<LintFinding> {
        match self {
            Self::Trees(trees) => vex::lint_rules(rules, file, trees.as_slice()),
            Self::Configs(configs) => vex::lint_rules(rules, file, configs),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Trees(trees) => trees.as_slice().describe(),
            Self::Configs(configs) => configs.describe(),
        }
    }
}

/// One loaded rules file.
struct Loaded {
    file: String,
    rules: RuleSet,
    /// Whether its Kconfig symbols are checked.
    check_symbols: bool,
}

fn lint(args: &VexLintArgs) -> Result<(Vec<LintFinding>, String), Failure> {
    if args.files.is_empty() && !args.starter_rules {
        return Err((
            EXIT_USAGE,
            "no rules to check: give rules files, --starter-rules, or both".to_owned(),
        ));
    }
    // Every rules file is loaded before the reference, so a malformed one is reported even
    // without a reference.
    let mut loaded = Vec::new();
    if args.starter_rules {
        loaded.push(Loaded {
            file: format!(
                "{} (starter rules)",
                rollcall_identifiers::VEX_RULES_FILE_NAME
            ),
            rules: starter_rules()?,
            check_symbols: !args.zephyr_tree.is_empty() || args.lint_starter_symbols,
        });
    }
    for path in &args.files {
        let file = path.display().to_string();
        let rules = vex::parse_rules_bytes(&read(path)?, &file)
            .map_err(|e| (EXIT_DATAERR, e.to_string()))?;
        loaded.push(Loaded {
            file,
            rules,
            check_symbols: true,
        });
    }
    let reference = Reference::load(args)?;
    let sets: Vec<(&str, &RuleSet)> = loaded.iter().map(|l| (l.file.as_str(), &l.rules)).collect();
    let mut findings = vex::lint_duplicate_ids(&sets);
    let mut rules = 0usize;
    let mut skipped = 0usize;
    for l in &loaded {
        rules = rules.saturating_add(l.rules.rules.len());
        if l.check_symbols {
            findings.extend(reference.lint(&l.rules, &l.file));
        } else {
            skipped = skipped.saturating_add(l.rules.rules.len());
        }
    }
    findings.sort();
    findings.dedup();
    let mut summary = format!(
        "{} rules file(s), {rules} rule(s), checked against {}",
        loaded.len(),
        reference.describe()
    );
    if skipped > 0 {
        summary.push_str(&format!(
            " (the starter pack's {skipped} rule(s) for duplicate ids only; add \
             --lint-starter-symbols to check their symbols too)"
        ));
    }
    Ok((findings, summary))
}
