//! The identifier database's version pin (SHA-104): which `db_version`s this rollcall accepts.

use rollcall_core::identify::{
    BUILTIN_DB_VERSION, DbVersion, Incompatible, MIN_DB_VERSION, SUPPORTED_DB_MAJOR,
    check_compatible,
};

fn v(text: &str) -> DbVersion {
    text.parse().unwrap_or_else(|e| panic!("{text}: {e}"))
}

#[test]
fn compatible_accepts_min_and_newer_minor() {
    assert_eq!(MIN_DB_VERSION, "1.0.0");
    assert_eq!(SUPPORTED_DB_MAJOR, 1);
    for ok in ["1.0.0", "1.0.1", "1.1.0", "1.2.0-rc.1", "1.99.7"] {
        assert_eq!(check_compatible(&v(ok)), Ok(()), "{ok}");
    }
    // The embedded database is always compatible with the rollcall it is built into.
    assert_eq!(check_compatible(&v(BUILTIN_DB_VERSION)), Ok(()));
}

#[test]
fn rejects_below_min() {
    for old in ["0.9.0", "0.0.1", "1.0.0-rc.1"] {
        let e = check_compatible(&v(old)).unwrap_err();
        assert!(matches!(e, Incompatible::TooOld { .. }), "{old}: {e:?}");
        let shown = e.to_string();
        assert!(
            shown.contains(old) && shown.contains("older than 1.0.0"),
            "{shown}"
        );
    }
}

#[test]
fn rejects_other_schema_major() {
    for other in ["2.0.0", "3.1.4"] {
        let e = check_compatible(&v(other)).unwrap_err();
        assert!(
            matches!(e, Incompatible::OtherMajor { .. }),
            "{other}: {e:?}"
        );
        assert!(e.to_string().contains("reads major version 1"), "{e}");
    }
}

#[test]
fn versions_order_by_semver_not_text() {
    assert!(v("1.10.0") > v("1.9.0"));
    assert!(v("1.1.0") > v("1.1.0-rc.2"));
    assert_eq!(v("1.2.3").to_string(), "1.2.3");
}

#[test]
fn malformed_versions_are_errors_not_panics() {
    for bad in [
        "", "1", "1.0", "v1.0.0", "1.0.0.0", "1.0.x", "😀", "1.0.0\n",
    ] {
        let e = bad.parse::<DbVersion>().unwrap_err();
        assert!(
            e.to_string()
                .contains("is not a semver version such as 1.2.0"),
            "{bad:?}: {e}"
        );
    }
}
