//! `rollcall assay`: a cryptographic inventory of a build, as a CycloneDX 1.6 CBOM or a
//! Markdown summary.

use std::io::Write;
use std::path::Path;

use rollcall_assay::config::ConfigError;
use rollcall_assay::{AssayError, DETECTORS_PROPERTY, Inputs, summary};
use rollcall_core::cyclonedx::{Property, Timestamp};
use rollcall_core::model::Product;

use super::output::{write_atomically, write_document};
use crate::cli::{
    AssayArgs, AssayFormat, EXIT_DATAERR, EXIT_IOERR, EXIT_NOINPUT, EXIT_SOFTWARE, EXIT_USAGE,
};

type Failure = (u8, String);

/// The exit code for an inventory error: 66 when an input is missing or unreadable, 70 when
/// rollcall's own built-in data fails (a configuration rule set that does not load or agree
/// with the catalogue, an asset the model rejects, the algorithm catalogue), 65 when an input
/// is malformed.
fn exit_code(error: &AssayError) -> u8 {
    match error {
        e if e.is_input_error() => EXIT_NOINPUT,
        AssayError::Catalogue(_)
        | AssayError::Config(ConfigError::Rules { .. } | ConfigError::Model { .. }) => {
            EXIT_SOFTWARE
        }
        _ => EXIT_DATAERR,
    }
}

/// Runs `rollcall assay`, returning the exit code.
pub fn run(args: AssayArgs) -> u8 {
    match produce(args) {
        Ok(()) => 0,
        Err((code, message)) => {
            // Nothing more to do if stderr is gone; the exit code still says it failed.
            let _ = writeln!(std::io::stderr(), "rollcall assay: {message}");
            code
        }
    }
}

/// The product to write and its document properties: from `--model` as it is, or from the
/// inventory of `--source`/`--build`/`--elf`, whose CBOM names the detectors that ran.
fn inventory(args: &AssayArgs) -> Result<(Product, Vec<Property>), Failure> {
    if let Some(path) = &args.model {
        let bytes =
            std::fs::read(path).map_err(|e| (EXIT_NOINPUT, format!("{}: {e}", path.display())))?;
        let product = Product::from_json_bytes(&bytes)
            .map_err(|e| (EXIT_DATAERR, format!("{}: {e}", path.display())))?;
        return Ok((product, Vec::new()));
    }
    // clap requires --product unless --model is given; this is only a fallback.
    let Some(product) = args.product.clone() else {
        return Err((
            EXIT_USAGE,
            "--source, --build and --elf need --product NAME[@VERSION]".to_owned(),
        ));
    };
    let inputs = Inputs {
        source: args.source.as_deref(),
        build: args.build.as_deref(),
        elf: args.elf.as_deref(),
        product,
    };
    let inventory =
        rollcall_assay::assay(&inputs).map_err(|e: AssayError| (exit_code(&e), e.to_string()))?;
    let mut stderr = std::io::stderr().lock();
    for note in &inventory.notes {
        let _ = writeln!(stderr, "rollcall assay: note: {note}");
    }
    let properties = vec![Property {
        name: DETECTORS_PROPERTY,
        value: inventory.detectors_property(),
    }];
    Ok((inventory.product, properties))
}

fn write_text(text: &str, output: Option<&Path>) -> Result<(), Failure> {
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

fn produce(args: AssayArgs) -> Result<(), Failure> {
    let (product, properties) = inventory(&args)?;
    match args.format {
        AssayFormat::Cyclonedx => write_document(
            &product,
            properties,
            args.timestamp,
            args.serial_number,
            args.output.as_deref(),
        ),
        AssayFormat::Md => {
            let timestamp = args.timestamp.unwrap_or_else(Timestamp::now);
            let text = summary::to_markdown(&product, &timestamp, env!("CARGO_PKG_VERSION"));
            write_text(&text, args.output.as_deref())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rollcall_assay::catalogue::CatalogueError;

    use super::*;

    #[test]
    fn exit_code_is_70_for_built_in_data_65_for_malformed_input_66_for_missing_input() {
        let path = || PathBuf::from("build/zephyr/.config");
        let cases: Vec<(AssayError, u8)> = vec![
            (
                AssayError::Config(ConfigError::Rules {
                    message: "config-zephyr.yaml: a: duplicate rule id".into(),
                }),
                EXIT_SOFTWARE,
            ),
            (
                AssayError::Config(ConfigError::Model {
                    message: "an empty component name".into(),
                }),
                EXIT_SOFTWARE,
            ),
            (
                AssayError::Catalogue(CatalogueError::Empty {
                    file: "algorithms.yaml".into(),
                }),
                EXIT_SOFTWARE,
            ),
            (
                AssayError::Config(ConfigError::BuildInfo {
                    path: path(),
                    message: "sysbuild image \"widget\" is not the MAIN image".into(),
                }),
                EXIT_DATAERR,
            ),
            (
                AssayError::Config(ConfigError::NotUtf8 { path: path() }),
                EXIT_DATAERR,
            ),
            (
                AssayError::Config(ConfigError::Missing { path: path() }),
                EXIT_NOINPUT,
            ),
            (
                AssayError::NotADirectory {
                    what: "--build",
                    path: path(),
                },
                EXIT_NOINPUT,
            ),
        ];
        for (error, code) in cases {
            assert_eq!(exit_code(&error), code, "{error}");
        }
    }
}
