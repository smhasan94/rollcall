//! rollcall's identifier database, as data.
//!
//! [`IDENTIFIERS_YAML`] is `db/identifiers.yaml`: for each Zephyr module, its upstream
//! project, purl and CPE templates and how to derive the upstream version of a fork revision.
//! The schema, the loader and the resolver are in `rollcall_core::identify`; this crate holds
//! only the data, so a new database is a new release of this crate (or a copy of
//! `db/identifiers.yaml` dropped into rollcall's cache directory), not a new rollcall.
//!
//! The crate version is the database's `db_version`. rollcall refuses a database older than
//! its minimum or of another major version; see the crate README.
//!
//! [`VEX_RULES_YAML`] is `db/vex-rules.yaml`, the starter VEX rule pack that `rollcall vex
//! --starter-rules` loads (format and examples: `docs/vex-rules.md`). It ships with the
//! database but has no version of its own and is always the embedded copy.

/// The database's version: this crate's version, and the `db_version` in
/// [`IDENTIFIERS_YAML`] (`rollcall identifiers lint` checks that they agree).
pub const DB_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The file name the database is cited by in warnings, evidence and lint findings.
pub const FILE_NAME: &str = "identifiers.yaml";

/// The database's path inside this crate (and inside a release tarball).
pub const PATH: &str = "db/identifiers.yaml";

/// The database text (`db/identifiers.yaml`).
pub const IDENTIFIERS_YAML: &str = include_str!("../db/identifiers.yaml");

/// The file name the starter VEX rule pack is cited by in rule errors and lint findings.
pub const VEX_RULES_FILE_NAME: &str = "vex-rules.yaml";

/// The starter VEX rule pack's path inside this crate (a release tarball has it as
/// `<db_version>/vex-rules.yaml`, next to `identifiers.yaml`).
pub const VEX_RULES_PATH: &str = "db/vex-rules.yaml";

/// The starter VEX rule pack text (`db/vex-rules.yaml`).
pub const VEX_RULES_YAML: &str = include_str!("../db/vex-rules.yaml");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn include_path_and_constants_agree() {
        assert_eq!(PATH, format!("db/{FILE_NAME}"));
        assert!(IDENTIFIERS_YAML.contains("\nschema: 1\n"));
        assert_eq!(VEX_RULES_PATH, format!("db/{VEX_RULES_FILE_NAME}"));
        assert!(VEX_RULES_YAML.contains("\nversion: 1\nrules:\n"));
    }

    /// The `db_version:` line is the crate version (the full check, with the YAML parser, is
    /// `rollcall identifiers lint`).
    #[test]
    fn db_version_line_is_the_crate_version() {
        let line = IDENTIFIERS_YAML
            .lines()
            .find(|l| l.starts_with("db_version:"))
            .unwrap_or_default();
        assert_eq!(line, format!("db_version: '{DB_VERSION}'"));
    }
}
