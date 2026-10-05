//! `rollcall generate`: render a model, a Zephyr image or sysbuild build directory, a Rust
//! package (`cargo metadata` and a `cargo auditable` ELF), an ESP-IDF project and its build,
//! or a PlatformIO project, as CycloneDX 1.6 JSON. A positional DIR is any of those, told
//! from its files ([`rollcall_core::detect`]) or named by `--ecosystem`.

use std::io::Write;
use std::path::{Path, PathBuf};

use rollcall_core::cargo::{self, CargoOptions};
use rollcall_core::detect::{self, DetectOptions, Ecosystem, Inferred};
use rollcall_core::esp_idf::{self, EspIdfOptions};
use rollcall_core::identify::{self, DbSource, LoadedDbs};
use rollcall_core::merge::{self, ProductSpec};
use rollcall_core::model::Product;
use rollcall_core::platformio::{self, PlatformIoOptions};
use rollcall_core::zephyr::{self, IngestOptions, Note, UnknownModule, Warning};

use super::output::write_document;
use crate::cli::{
    EXIT_DATAERR, EXIT_NOINPUT, EXIT_UNAVAILABLE, EXIT_USAGE, EcosystemArg, Format, GenerateArgs,
};

/// The input to render, from an input flag or a positional DIR.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    /// `--model FILE`.
    Model(PathBuf),
    /// `--zephyr DIR`, or a Zephyr DIR.
    Zephyr {
        /// The build directory.
        dir: PathBuf,
        /// A sysbuild top-level directory.
        sysbuild: bool,
        /// The west list, if any.
        west_list: Option<PathBuf>,
    },
    /// `--cargo DIR`, or a DIR holding Cargo.toml.
    CargoPackage(PathBuf),
    /// `--cargo-metadata FILE`, or DIR/cargo-metadata.json.
    CargoMetadata(PathBuf),
    /// `--esp-idf DIR`, or an ESP-IDF DIR.
    EspIdf(PathBuf),
    /// `--platformio DIR`, or a PlatformIO DIR.
    PlatformIo(PathBuf),
}

impl Source {
    fn ecosystem(&self) -> Option<Ecosystem> {
        match self {
            Self::Model(_) => None,
            Self::Zephyr { .. } => Some(Ecosystem::Zephyr),
            Self::CargoPackage(_) | Self::CargoMetadata(_) => Some(Ecosystem::Cargo),
            Self::EspIdf(_) => Some(Ecosystem::EspIdf),
            Self::PlatformIo(_) => Some(Ecosystem::PlatformIo),
        }
    }
}

/// The input the flags name: an explicit input flag as given, or DIR detected (or taken as
/// `--ecosystem` says) with the files it implies (a Zephyr sysbuild's domains.yaml and
/// west-list.txt, a Cargo DIR's cargo-metadata.json). Exit 64 when DIR matches several
/// ecosystems, 66 when it matches none or is not a directory.
fn resolve_input(args: &GenerateArgs) -> Result<Source, (u8, String)> {
    if let Some(model) = &args.model {
        return Ok(Source::Model(model.clone()));
    }
    if let Some(dir) = &args.zephyr {
        return Ok(Source::Zephyr {
            dir: dir.clone(),
            sysbuild: args.sysbuild,
            west_list: args.west_list.clone(),
        });
    }
    if let Some(dir) = &args.cargo {
        return Ok(Source::CargoPackage(dir.clone()));
    }
    if let Some(file) = &args.cargo_metadata {
        return Ok(Source::CargoMetadata(file.clone()));
    }
    if let Some(dir) = &args.esp_idf {
        return Ok(Source::EspIdf(dir.clone()));
    }
    if let Some(dir) = &args.platformio {
        return Ok(Source::PlatformIo(dir.clone()));
    }
    // clap guarantees exactly one input.
    let Some(dir) = &args.dir else {
        return Err((
            EXIT_USAGE,
            "one of DIR, --model, --zephyr, --cargo, --cargo-metadata, --esp-idf or --platformio is required"
                .to_owned(),
        ));
    };
    let options = DetectOptions {
        build_dir: args.build.clone(),
    };
    let forced = match args.ecosystem {
        None | Some(EcosystemArg::Auto) => None,
        Some(EcosystemArg::Zephyr) => Some(Ecosystem::Zephyr),
        Some(EcosystemArg::Cargo) => Some(Ecosystem::Cargo),
        Some(EcosystemArg::EspIdf) => Some(Ecosystem::EspIdf),
        Some(EcosystemArg::Platformio) => Some(Ecosystem::PlatformIo),
    };
    let detection = match forced {
        Some(ecosystem) => detect::detect_as(dir, ecosystem, &options),
        None => detect::detect(dir, &options),
    }
    .map_err(|e| (super::detect::exit_code(&e), e.to_string()))?;
    let source = match detection.inferred {
        Inferred::Zephyr {
            sysbuild,
            west_list,
        } => Source::Zephyr {
            dir: dir.clone(),
            sysbuild: sysbuild || args.sysbuild,
            west_list: args.west_list.clone().or(west_list),
        },
        Inferred::CargoPackage => Source::CargoPackage(dir.clone()),
        Inferred::CargoMetadata(file) => Source::CargoMetadata(file),
        Inferred::EspIdf => Source::EspIdf(dir.clone()),
        Inferred::PlatformIo => Source::PlatformIo(dir.clone()),
    };
    check_flags_fit(args, &source)?;
    Ok(source)
}

/// With a positional DIR, exit 64 when a flag of another ecosystem than DIR's is given (clap
/// checks the explicit input flags).
fn check_flags_fit(args: &GenerateArgs, source: &Source) -> Result<(), (u8, String)> {
    let Some(ecosystem) = source.ecosystem() else {
        return Ok(());
    };
    let flags: [(&str, bool, &[Ecosystem]); 13] = [
        (
            "--west-list",
            args.west_list.is_some(),
            &[Ecosystem::Zephyr],
        ),
        ("--include-sdk", args.include_sdk, &[Ecosystem::Zephyr]),
        ("--sysbuild", args.sysbuild, &[Ecosystem::Zephyr]),
        (
            "--identifier-db",
            args.identifier_db.is_some(),
            &[Ecosystem::Zephyr],
        ),
        ("--identify", args.identify, &[Ecosystem::Zephyr]),
        (
            "--workspace",
            args.workspace.is_some(),
            &[Ecosystem::Zephyr],
        ),
        ("--build", args.build.is_some(), &[Ecosystem::EspIdf]),
        ("--idf-path", args.idf_path.is_some(), &[Ecosystem::EspIdf]),
        ("--target", args.target.is_some(), &[Ecosystem::Cargo]),
        ("--elf", args.elf.is_some(), &[Ecosystem::Cargo]),
        ("--env", args.env.is_some(), &[Ecosystem::PlatformIo]),
        (
            "--pio-core",
            args.pio_core.is_some(),
            &[Ecosystem::PlatformIo],
        ),
        (
            "--verbose",
            args.verbose,
            &[Ecosystem::Zephyr, Ecosystem::EspIdf],
        ),
    ];
    for (flag, given, fits) in flags {
        if given && !fits.contains(&ecosystem) {
            let names: Vec<&str> = fits.iter().map(|e| e.as_str()).collect();
            return Err((
                EXIT_USAGE,
                format!(
                    "{flag} applies to {} input, but DIR is {ecosystem}",
                    names.join(" or ")
                ),
            ));
        }
    }
    // --include-unlinked needs --elf, which clap checks.
    if args.target.is_some() && matches!(source, Source::CargoMetadata(_)) {
        return Err((
            EXIT_USAGE,
            "--target applies to a package directory (Cargo.toml), but DIR holds captured cargo-metadata.json (resolved when it was captured)"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Runs `rollcall generate`, returning the exit code. `identifiers` is the global
/// `--identifiers` path.
pub fn run(args: GenerateArgs, identifiers: Option<&Path>) -> u8 {
    if args.format == Format::Spdx {
        eprintln!("rollcall generate --format spdx: not implemented");
        return EXIT_USAGE;
    }
    let source = match resolve_input(&args) {
        Ok(source) => source,
        Err((code, message)) => {
            eprintln!("rollcall generate: {message}");
            return code;
        }
    };
    let dbs = match select_db(&args, &source, identifiers) {
        Ok(dbs) => dbs,
        Err((code, message)) => {
            eprintln!("rollcall generate: {message}");
            return code;
        }
    };
    let product = match load_product(&args, &source, dbs.as_ref()) {
        Ok(Loaded {
            product,
            warnings,
            unknown_modules,
            notes,
        }) => {
            print_warnings(&warnings);
            if args.verbose {
                print_notes(&notes);
            }
            print_stubs(dbs.as_ref(), &unknown_modules);
            product
        }
        Err((code, message)) => {
            eprintln!("rollcall generate: {message}");
            return code;
        }
    };
    let product = match apply_product(product, args.product.as_ref()) {
        Ok(product) => product,
        Err((code, message)) => {
            eprintln!("rollcall generate: {message}");
            return code;
        }
    };
    // Which identifier database resolved the modules, if any (no paths: deterministic).
    let properties = dbs
        .as_ref()
        .map(|d| identify::provenance(&d.active, &d.source))
        .unwrap_or_default();
    match write_document(
        &product,
        properties,
        args.timestamp,
        args.serial_number,
        args.output.as_deref(),
    ) {
        Ok(()) => 0,
        Err((code, message)) => {
            eprintln!("rollcall generate: {message}");
            code
        }
    }
}

/// With `--product`, puts `product` under the spec exactly as `merge --product` does, so the
/// output is byte-identical to `generate` followed by `merge --product`. Without it, returns
/// `product` unchanged.
fn apply_product(product: Product, spec: Option<&ProductSpec>) -> Result<Product, (u8, String)> {
    let Some(spec) = spec else {
        return Ok(product);
    };
    merge::merge(vec![product], Some(spec))
        .map_err(|e| (EXIT_DATAERR, format!("cannot apply --product {spec}: {e}")))
}

/// What `--model`, `--zephyr`, `--cargo`/`--cargo-metadata`, `--esp-idf`, `--platformio` or
/// DIR gave.
struct Loaded {
    product: Product,
    warnings: Vec<Warning>,
    unknown_modules: Vec<UnknownModule>,
    notes: Vec<Note>,
}

/// The identifier database to resolve modules with, if module resolution is on: with
/// Zephyr input and any of `--identifier-db FILE` (that file), `--identify` or the global
/// `--identifiers PATH` (the active database, [`identify::select`]). Skipped cache entries
/// are printed as warnings, and a database picked up from the cache is named on stderr.
fn select_db(
    args: &GenerateArgs,
    source: &Source,
    identifiers: Option<&Path>,
) -> Result<Option<LoadedDbs>, (u8, String)> {
    let wanted = matches!(source, Source::Zephyr { .. })
        && (args.identify || args.identifier_db.is_some() || identifiers.is_some());
    if !wanted {
        return Ok(None);
    }
    let explicit = args.identifier_db.as_deref().or(identifiers);
    let loaded = identify::select(explicit, &|name| std::env::var_os(name)).map_err(|e| {
        let code = if e.is_read_error() {
            EXIT_NOINPUT
        } else {
            EXIT_DATAERR
        };
        (code, e.to_string())
    })?;
    let mut stderr = std::io::stderr().lock();
    for warning in &loaded.warnings {
        let _ = writeln!(stderr, "rollcall generate: warning: identifiers: {warning}");
    }
    if let DbSource::Cache(path) = &loaded.source {
        let version = loaded
            .active
            .db_version()
            .map_or_else(String::new, ToString::to_string);
        let _ = writeln!(
            stderr,
            "rollcall generate: note: identifier database {version} from the cache ({})",
            path.display()
        );
    }
    Ok(Some(loaded))
}

/// Reads the input `source`, resolving Zephyr modules with `dbs` if given: the product, any
/// warnings and modules missing from the identifier database, or the exit code and message to
/// fail with.
fn load_product(
    args: &GenerateArgs,
    source: &Source,
    dbs: Option<&LoadedDbs>,
) -> Result<Loaded, (u8, String)> {
    match source {
        Source::CargoPackage(dir) => load_cargo(args, None, Some(dir)),
        Source::CargoMetadata(file) => load_cargo(args, Some(file), None),
        Source::EspIdf(dir) => load_esp_idf(args, dir),
        Source::PlatformIo(dir) => load_platformio(args, dir),
        Source::Zephyr {
            dir,
            sysbuild,
            west_list,
        } => {
            let mut options = IngestOptions::new(dir)
                .with_include_sdk(args.include_sdk)
                .with_sysbuild(*sysbuild);
            if let Some(west_list) = west_list {
                options = options.with_west_list(west_list);
            }
            // The database's file, if it has one, locates errors in its values.
            if let Some(DbSource::Flag(file) | DbSource::Env(file) | DbSource::Cache(file)) =
                dbs.map(|d| &d.source)
            {
                options = options.with_identifier_db(file);
            }
            if let Some(workspace) = &args.workspace {
                options = options.with_workspace(workspace);
            }
            match zephyr::ingest_with_db(&options, dbs.map(|d| &d.active)) {
                Ok(ingest) => Ok(Loaded {
                    product: ingest.product,
                    warnings: ingest.warnings,
                    unknown_modules: ingest.unknown_modules,
                    notes: ingest.notes,
                }),
                // Missing or unreadable input (including a directory where a file should be).
                Err(e) if e.is_read_error() => Err((EXIT_NOINPUT, e.to_string())),
                Err(e) => Err((EXIT_DATAERR, e.to_string())),
            }
        }
        Source::Model(model) => {
            let bytes = std::fs::read(model)
                .map_err(|e| (EXIT_NOINPUT, format!("{}: {e}", model.display())))?;
            let product =
                Product::from_json_bytes(&bytes).map_err(|e| (EXIT_DATAERR, e.to_string()))?;
            Ok(Loaded {
                product,
                warnings: Vec::new(),
                unknown_modules: Vec::new(),
                notes: Vec::new(),
            })
        }
    }
}

/// Reads a PlatformIO project (`--platformio DIR`) for `--env` (default: `default_envs`, else
/// the only environment), with the platform and framework versions from `--pio-core`, else
/// `$PLATFORMIO_CORE_DIR` when set (named on stderr), else the exact pins in platformio.ini.
fn load_platformio(args: &GenerateArgs, dir: &Path) -> Result<Loaded, (u8, String)> {
    let mut options = PlatformIoOptions::new(dir);
    if let Some(env) = &args.env {
        options = options.with_env(env);
    }
    let core = args.pio_core.clone().or_else(|| {
        let from_env: Option<PathBuf> = std::env::var_os("PLATFORMIO_CORE_DIR")
            .filter(|p| !p.is_empty())
            .map(Into::into);
        // Named on stderr, as $IDF_PATH is: the core directory decides the versions.
        if let Some(path) = &from_env {
            let _ = writeln!(
                std::io::stderr().lock(),
                "rollcall generate: note: no --pio-core; reading the platform and framework packages from $PLATFORMIO_CORE_DIR ({})",
                path.display()
            );
        }
        from_env
    });
    if let Some(core) = core {
        options = options.with_core_dir(core);
    }
    let ingest = platformio::ingest(&options).map_err(|e| {
        let code = if e.is_usage_error() {
            EXIT_USAGE
        } else if e.is_read_error() {
            EXIT_NOINPUT
        } else {
            EXIT_DATAERR
        };
        (code, e.to_string())
    })?;
    Ok(Loaded {
        product: ingest.product,
        warnings: ingest.warnings,
        unknown_modules: Vec::new(),
        notes: Vec::new(),
    })
}

/// Reads a Rust package: captured metadata (`--cargo-metadata FILE`, or a DIR's
/// cargo-metadata.json), or `cargo metadata` run in the package directory (`--cargo DIR`, or a
/// DIR holding Cargo.toml) for `--target`, and the `--elf` binary's `.dep-v0` list if given.
fn load_cargo(
    args: &GenerateArgs,
    metadata: Option<&PathBuf>,
    package: Option<&PathBuf>,
) -> Result<Loaded, (u8, String)> {
    let (options, unfiltered) = match (metadata, package) {
        (Some(file), _) => (CargoOptions::from_metadata_file(file), None),
        (None, Some(dir)) => {
            let text = run_cargo_metadata(dir, args.target.as_deref())?;
            let options = CargoOptions::from_metadata_text(text, cargo::LOCKFILE_LOCATION);
            (options, args.target.is_none().then_some(dir))
        }
        (None, None) => {
            return Err((
                EXIT_USAGE,
                "one of --cargo or --cargo-metadata is required".to_owned(),
            ));
        }
    };
    let mut options = options.with_include_unlinked(args.include_unlinked);
    if let Some(elf) = &args.elf {
        options = options.with_elf(elf);
    }
    let ingest = cargo::ingest(&options).map_err(|e| {
        let code = if e.is_read_error() {
            EXIT_NOINPUT
        } else {
            EXIT_DATAERR
        };
        (code, e.to_string())
    })?;
    let mut warnings = Vec::new();
    if let Some(dir) = unfiltered {
        warnings.push(Warning::new(
            dir.join("Cargo.toml").display().to_string(),
            "no --target: cargo metadata lists every platform's dependencies; pass the \
             binary's target triple to resolve for it",
        ));
    }
    warnings.extend(ingest.warnings);
    Ok(Loaded {
        product: ingest.product,
        warnings,
        unknown_modules: Vec::new(),
        notes: Vec::new(),
    })
}

/// Reads an ESP-IDF project (`--esp-idf DIR`), built in `--build` (default `DIR/build`), with
/// blobs hashed from `--idf-path`, else `$IDF_PATH` when set.
fn load_esp_idf(args: &GenerateArgs, dir: &Path) -> Result<Loaded, (u8, String)> {
    let mut options = EspIdfOptions::new(dir);
    if let Some(build) = &args.build {
        options = options.with_build_dir(build);
    }
    let idf_path = args.idf_path.clone().or_else(|| {
        let from_env: Option<std::path::PathBuf> = std::env::var_os("IDF_PATH")
            .filter(|p| !p.is_empty())
            .map(Into::into);
        // Named on stderr, as a database picked up from the cache is: the tree changes the
        // blob hashes, so the user must see which one was read.
        if let Some(path) = &from_env {
            let _ = writeln!(
                std::io::stderr().lock(),
                "rollcall generate: note: no --idf-path; reading blobs and the version file from $IDF_PATH ({})",
                path.display()
            );
        }
        from_env
    });
    if let Some(idf_path) = idf_path {
        options = options.with_idf_path(idf_path);
    }
    let ingest = esp_idf::ingest(&options).map_err(|e| {
        let code = if e.is_read_error() {
            EXIT_NOINPUT
        } else {
            EXIT_DATAERR
        };
        (code, e.to_string())
    })?;
    Ok(Loaded {
        product: ingest.product,
        warnings: ingest.warnings,
        unknown_modules: Vec::new(),
        notes: ingest.notes,
    })
}

/// Runs `cargo metadata` for the package in `dir` ([`cargo::metadata_command`], in `dir` so its
/// `.cargo/config.toml` applies) with `$CARGO`, else `cargo` on PATH: its stdout, or exit 66
/// (no `Cargo.toml`), 69 (cargo cannot be run) or 65 (cargo failed, with the end of its
/// stderr). Cargo may use the network; it honours `CARGO_NET_OFFLINE`.
fn run_cargo_metadata(dir: &Path, target: Option<&str>) -> Result<String, (u8, String)> {
    let manifest = dir.join("Cargo.toml");
    if !manifest.is_file() {
        return Err((
            EXIT_NOINPUT,
            format!("{}: no such file", manifest.display()),
        ));
    }
    let cargo_bin = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = cargo::metadata_command(&cargo_bin, dir, target)
        .output()
        .map_err(|e| {
            (
                EXIT_UNAVAILABLE,
                format!(
                    "cannot run {}: {e} (install cargo, or set $CARGO to it)",
                    cargo_bin.to_string_lossy()
                ),
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lines: Vec<&str> = stderr.lines().collect();
        let tail = lines
            .get(lines.len().saturating_sub(20)..)
            .unwrap_or_default()
            .join("\n");
        return Err((
            EXIT_DATAERR,
            format!(
                "{}: cargo metadata failed ({}):\n{tail}",
                manifest.display(),
                output.status
            ),
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| {
        (
            EXIT_DATAERR,
            format!(
                "{}: cargo metadata printed non-UTF-8 output",
                manifest.display()
            ),
        )
    })
}

/// One `rollcall generate: warning: …` line per warning on stderr. A closed stderr is not an
/// error: the warnings are advisory.
fn print_warnings(warnings: &[Warning]) {
    let mut stderr = std::io::stderr().lock();
    for warning in warnings {
        let _ = writeln!(stderr, "rollcall generate: warning: {warning}");
    }
}

/// With `--verbose`, one `rollcall generate: note: …` line per note on stderr, after the
/// warnings. A closed stderr is not an error.
fn print_notes(notes: &[Note]) {
    let mut stderr = std::io::stderr().lock();
    for note in notes {
        let _ = writeln!(stderr, "rollcall generate: note: {note}");
    }
}

/// After the warnings, the stub entries for modules missing from the identifier database, on
/// stderr, ready to paste under its `modules:` mapping.
fn print_stubs(dbs: Option<&LoadedDbs>, unknown: &[UnknownModule]) {
    if unknown.is_empty() {
        return;
    }
    let db = dbs.map_or_else(
        || "the identifier database".to_owned(),
        |d| d.active.name().to_owned(),
    );
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "rollcall generate: {} module(s) not in {db}; paste and fill in:",
        unknown.len()
    );
    for module in unknown {
        let _ = write!(stderr, "{}", module.stub);
    }
    // The embedded database cannot be edited in place.
    if dbs.is_some_and(|d| d.source == DbSource::Embedded) {
        let _ = writeln!(
            stderr,
            "rollcall generate: the embedded database is read-only: add the entries to a copy of \
             it and pass that with --identifiers PATH, or contribute them (CONTRIBUTING.md)"
        );
    }
}
