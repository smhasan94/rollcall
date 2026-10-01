//! Selecting the active identifier database (SHA-104): explicit path, `$ROLLCALL_IDENTIFIERS`,
//! the cache directory, or the embedded database. The environment is injected, so these tests
//! never read the real one.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use rollcall_core::identify::source::{ENV_CACHE_DIR, ENV_IDENTIFIERS, scan_cache};
use rollcall_core::identify::{DbSource, DbVersion, SourceError, select};

/// The shipped database text with another `db_version`.
fn shipped_as(version: &str) -> String {
    let text = rollcall_identifiers::IDENTIFIERS_YAML;
    let line = format!("db_version: '{}'", rollcall_identifiers::DB_VERSION);
    assert!(text.contains(&line));
    text.replace(&line, &format!("db_version: '{version}'"))
}

/// Writes `<root>/rollcall/identifiers/<dir>/identifiers.yaml`.
fn cache_entry(root: &Path, dir: &str, text: &str) -> PathBuf {
    let dir = root.join("rollcall/identifiers").join(dir);
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("identifiers.yaml");
    fs::write(&file, text).unwrap();
    file
}

/// An environment of exactly these variables.
fn env(vars: &[(&str, &Path)]) -> impl Fn(&str) -> Option<OsString> + use<> {
    let vars: BTreeMap<String, OsString> = vars
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.as_os_str().to_owned()))
        .collect();
    move |name| vars.get(name).cloned()
}

/// The embedded database's version with MINOR raised by `n` (`v(0)` is the embedded
/// version), so the tests keep working as the database is released.
fn v(n: u64) -> String {
    let embedded: semver::Version = rollcall_identifiers::DB_VERSION.parse().unwrap();
    format!("{}.{}.0", embedded.major, embedded.minor + n)
}

fn version_of(loaded: &rollcall_core::identify::LoadedDbs) -> String {
    loaded.active.db_version().unwrap().to_string()
}

#[test]
fn precedence_flag_env_cache_embedded() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cache");
    let cached = cache_entry(&cache, &v(1), &shipped_as(&v(1)));
    let env_file = dir.path().join("env.yaml");
    fs::write(&env_file, shipped_as(&v(2))).unwrap();
    let flag_file = dir.path().join("flag.yaml");
    fs::write(&flag_file, shipped_as(&v(3))).unwrap();

    let all = env(&[(ENV_CACHE_DIR, &cache), (ENV_IDENTIFIERS, &env_file)]);
    let loaded = select(Some(&flag_file), &all).unwrap();
    assert_eq!(loaded.source, DbSource::Flag(flag_file.clone()));
    assert_eq!(version_of(&loaded), v(3));

    let loaded = select(None, &all).unwrap();
    assert_eq!(loaded.source, DbSource::Env(env_file.clone()));
    assert_eq!(version_of(&loaded), v(2));

    let cache_only = env(&[(ENV_CACHE_DIR, &cache)]);
    let loaded = select(None, &cache_only).unwrap();
    assert_eq!(loaded.source, DbSource::Cache(cached.clone()));
    assert_eq!(version_of(&loaded), v(1));
    // The embedded database is loaded alongside, unchanged.
    assert_eq!(
        loaded.embedded.db_version().unwrap().to_string(),
        rollcall_identifiers::DB_VERSION
    );
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);

    let empty = dir.path().join("empty-cache");
    let loaded = select(None, &env(&[(ENV_CACHE_DIR, &empty)])).unwrap();
    assert_eq!(loaded.source, DbSource::Embedded);
    assert_eq!(loaded.active, loaded.embedded);

    // A directory names its identifiers.yaml.
    let loaded = select(Some(cached.parent().unwrap()), &cache_only).unwrap();
    assert_eq!(loaded.source, DbSource::Flag(cached));
    // An empty variable is no variable.
    let blank = PathBuf::new();
    let loaded = select(
        None,
        &env(&[(ENV_IDENTIFIERS, &blank), (ENV_CACHE_DIR, &empty)]),
    )
    .unwrap();
    assert_eq!(loaded.source, DbSource::Embedded);
}

#[test]
fn scan_cache_picks_highest_compatible() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path();
    let embedded: DbVersion = rollcall_identifiers::DB_VERSION.parse().unwrap();
    assert_eq!(embedded.to_string(), v(0));
    // The embedded version itself: skipped silently.
    cache_entry(cache, &v(0), &shipped_as(&v(0)));
    cache_entry(cache, "0.9.0", &shipped_as("0.9.0"));
    cache_entry(cache, &v(1), &shipped_as(&v(1)));
    let best = cache_entry(cache, &v(10), &shipped_as(&v(10)));
    cache_entry(cache, &v(2), &shipped_as(&v(2)));
    cache_entry(cache, "2.0.0", &shipped_as("2.0.0"));
    cache_entry(cache, &v(11), &shipped_as(&v(12)));
    cache_entry(cache, &v(13), "schema: 1\nmodules: [");
    cache_entry(cache, &v(14), "schema: 1\nmodules: {}\n");
    cache_entry(cache, "latest", &shipped_as(&v(15)));
    // Noise, ignored silently: a file, a dotfile, a dot-directory.
    fs::write(cache.join("rollcall/identifiers/README"), "not a database").unwrap();
    fs::write(cache.join("rollcall/identifiers/.DS_Store"), "x").unwrap();
    cache_entry(cache, ".tmp-1.99.0", &shipped_as("1.99.0"));
    fs::create_dir_all(cache.join("rollcall/identifiers").join(v(16))).unwrap();

    let root = cache.join("rollcall/identifiers");
    let (found, warnings) = scan_cache(&root, Some(&embedded));
    let (db, file) = found.unwrap();
    assert_eq!(file, best);
    assert_eq!(db.db_version().unwrap().to_string(), v(10));
    // One warning per skipped entry, sorted by path, each naming why.
    let reasons: Vec<String> = warnings
        .iter()
        .map(|w| {
            w.strip_prefix(&format!("{}/", root.display()))
                .unwrap_or(w)
                .to_owned()
        })
        .collect();
    let mismatch = format!("declares db_version {}, not {}", v(12), v(11));
    let expect = [
        ("0.9.0".to_owned(), "older than 1.0.0, the minimum"),
        (v(11), mismatch.as_str()),
        (v(13), "identifiers.yaml"),
        (v(14), "declares no db_version"),
        (v(16), "No such file"),
        ("2.0.0".to_owned(), "major version 2"),
    ];
    assert_eq!(reasons.len(), expect.len(), "{reasons:#?}");
    for (reason, (entry, why)) in reasons.iter().zip(&expect) {
        assert!(
            reason.starts_with(&format!("{entry}: skipped: ")) && reason.contains(why),
            "{reason:?} is not {entry}: …{why}…"
        );
    }
    // Deterministic: the same scan gives the same answer.
    let (again, warnings_again) = scan_cache(&root, Some(&embedded));
    assert_eq!(again.unwrap().1, best);
    assert_eq!(warnings_again, warnings);
    // Against a newer embedded database, an older compatible entry is skipped with a warning.
    let newer: DbVersion = v(10).parse().unwrap();
    let (none, warnings) = scan_cache(&root, Some(&newer));
    assert!(none.is_none());
    let older = format!(
        "{0}: skipped: db_version {0} is older than the embedded {1}",
        v(2),
        v(10)
    );
    assert!(warnings.iter().any(|w| w.contains(&older)), "{warnings:#?}");
    // A missing cache is an empty one.
    let (none, warnings) = scan_cache(&dir.path().join("absent"), Some(&embedded));
    assert!(none.is_none() && warnings.is_empty());
}

#[test]
fn unreadable_dir_is_error_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let none = env(&[(ENV_CACHE_DIR, &dir.path().join("cache"))]);
    // A directory without identifiers.yaml, and a missing path: read errors (exit 66).
    for path in [dir.path().to_owned(), dir.path().join("absent.yaml")] {
        let e = select(Some(&path), &none).unwrap_err();
        assert!(e.is_read_error(), "{}: {e}", path.display());
        assert!(
            e.to_string().contains(&*dir.path().to_string_lossy()),
            "{e}"
        );
    }
    // Not UTF-8, empty, malformed: errors, not read errors (exit 65).
    let bad = dir.path().join("bad.yaml");
    for bytes in [
        &b"schema: 1\n\xff\xfe"[..],
        b"",
        b"schema: 1\nmodules: [",
        b"schema: 1\ndb_version: 'one'\nmodules: {}\n",
    ] {
        fs::write(&bad, bytes).unwrap();
        let e = select(Some(&bad), &none).unwrap_err();
        assert!(!e.is_read_error(), "{e}");
        assert!(e.to_string().starts_with(&*bad.to_string_lossy()), "{e}");
    }
    // Explicit databases outside the pin are refused, naming the file and the minimum.
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/identifiers");
    for (name, needle) in [
        ("too-old", "older than 1.0.0"),
        ("schema-2", "major version 2"),
    ] {
        let file = data.join(name).join("identifiers.yaml");
        let e = select(Some(&file), &none).unwrap_err();
        assert!(matches!(e, SourceError::Incompatible { .. }), "{e:?}");
        assert!(
            e.to_string()
                .starts_with(&format!("{}: db_version", file.display())),
            "{e}"
        );
        assert!(e.to_string().contains(needle), "{e}");
        // The same file via $ROLLCALL_IDENTIFIERS.
        let via_env = env(&[(ENV_IDENTIFIERS, &file)]);
        assert!(matches!(
            select(None, &via_env),
            Err(SourceError::Incompatible { .. })
        ));
    }
    // A database without db_version (a user's own) is used as is.
    let own = dir.path().join("own.yaml");
    fs::write(&own, "schema: 1\nmodules: {}\n").unwrap();
    let loaded = select(Some(&own), &none).unwrap();
    assert_eq!(loaded.active.db_version(), None);
}

#[test]
fn embedded_keyword_pins_the_embedded_database() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cache");
    cache_entry(&cache, &v(1), &shipped_as(&v(1)));
    let cached = env(&[(ENV_CACHE_DIR, &cache)]);
    // Without the pin the newer cached database wins; with it, the embedded one.
    assert!(matches!(
        select(None, &cached).unwrap().source,
        DbSource::Cache(_)
    ));
    let loaded = select(Some(Path::new("embedded")), &cached).unwrap();
    assert_eq!(loaded.source, DbSource::Embedded);
    assert_eq!(loaded.active, loaded.embedded);
    let word = PathBuf::from("embedded");
    let loaded = select(
        None,
        &env(&[(ENV_CACHE_DIR, &cache), (ENV_IDENTIFIERS, &word)]),
    )
    .unwrap();
    assert_eq!(loaded.source, DbSource::Embedded);
    // A file called `embedded` is still reachable as ./embedded.
    let e = select(Some(Path::new("./embedded")), &cached).unwrap_err();
    assert!(e.is_read_error(), "{e}");
}

#[test]
fn relative_cache_variables_are_ignored() {
    let rel = PathBuf::from("relative/cache");
    let loaded = select(None, &env(&[(ENV_CACHE_DIR, &rel)])).unwrap();
    assert_eq!(loaded.source, DbSource::Embedded);
    assert_eq!(
        rollcall_core::identify::source::cache_root(&env(&[(ENV_CACHE_DIR, &rel)]), false),
        None
    );
}

#[cfg(unix)]
#[test]
fn world_writable_entry_is_skipped_with_warning() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path();
    let root = cache.join("rollcall/identifiers");
    let embedded: DbVersion = rollcall_identifiers::DB_VERSION.parse().unwrap();
    // A writable directory, a writable file, and a good entry below them.
    let good = cache_entry(cache, &v(1), &shipped_as(&v(1)));
    cache_entry(cache, &v(2), &shipped_as(&v(2)));
    fs::set_permissions(root.join(v(2)), fs::Permissions::from_mode(0o777)).unwrap();
    let file = cache_entry(cache, &v(3), &shipped_as(&v(3)));
    fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
    let (found, warnings) = scan_cache(&root, Some(&embedded));
    assert_eq!(found.unwrap().1, good);
    assert_eq!(warnings.len(), 2, "{warnings:#?}");
    assert!(
        warnings[0].starts_with(&format!("{}: skipped: ", root.join(v(2)).display()))
            && warnings[0].ends_with("is writable by group or others (mode 777)"),
        "{warnings:#?}"
    );
    assert!(
        warnings[1].ends_with("identifiers.yaml is writable by group or others (mode 666)"),
        "{warnings:#?}"
    );
    // A writable root is not read at all.
    fs::set_permissions(&root, fs::Permissions::from_mode(0o757)).unwrap();
    let (found, warnings) = scan_cache(&root, Some(&embedded));
    assert!(found.is_none());
    assert_eq!(
        warnings,
        [format!(
            "{0}: skipped: {0} is writable by group or others (mode 757)",
            root.display()
        )]
    );
}

#[cfg(unix)]
#[test]
fn symlinks_out_of_the_cache_root_are_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cache");
    let root = cache.join("rollcall/identifiers");
    fs::create_dir_all(&root).unwrap();
    let embedded: DbVersion = rollcall_identifiers::DB_VERSION.parse().unwrap();
    // An entry directory linking outside the root.
    let outside = dir.path().join("elsewhere");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("identifiers.yaml"), shipped_as(&v(5))).unwrap();
    std::os::unix::fs::symlink(&outside, root.join(v(5))).unwrap();
    // An entry whose file links outside the root.
    let outside_file = dir.path().join("db.yaml");
    fs::write(&outside_file, shipped_as(&v(4))).unwrap();
    fs::create_dir(root.join(v(4))).unwrap();
    std::os::unix::fs::symlink(&outside_file, root.join(v(4)).join("identifiers.yaml")).unwrap();
    // A link inside the root is fine.
    let inside = cache_entry(&cache, "store-1", &shipped_as(&v(3)));
    std::os::unix::fs::symlink(inside.parent().unwrap(), root.join(v(3))).unwrap();
    let (found, warnings) = scan_cache(&root, Some(&embedded));
    let (db, _) = found.unwrap();
    assert_eq!(db.db_version().unwrap().to_string(), v(3));
    assert_eq!(warnings.len(), 2, "{warnings:#?}");
    for w in &warnings {
        assert!(w.contains("is a symlink out of the cache root"), "{w}");
    }
}
