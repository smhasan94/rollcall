//! Stub entries for modules the database does not list.
//!
//! A stub is YAML for one entry, indented to paste under `modules:`. It is valid YAML as
//! printed; once its blanks are filled it loads:
//!
//! - `""` values (upstream name, homepage, supplier, and the upstream version of the build's
//!   revision in the `manual` table),
//! - `<revision>`, the `manual` table key, when no revision was recorded for the module: until
//!   it is replaced with the module's git revision the module resolves with `Low` confidence,
//! - `<vendor>` and `<product>` in the CPE (or delete the `cpe` line if the project has no
//!   CPE).
//!
//! The purl is prefilled from the module's repository URL: `pkg:github/<owner>/<repo>@v{version}`
//! for GitHub, else `pkg:generic/<module>@{version}`. A Zephyr module's URL is usually the
//! Zephyr *fork*, so the comment beside it asks for the upstream repository.

use std::fmt;

use super::github_repo;

/// A paste-ready entry for one module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stub {
    module: String,
    text: String,
}

impl Stub {
    /// The module it is for.
    pub fn module(&self) -> &str {
        &self.module
    }
}

impl fmt::Display for Stub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// A YAML double-quoted scalar.
fn quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A plain YAML key if `s` is a simple module name, else a quoted one.
fn key(s: &str) -> String {
    let plain = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'+' | b'-'))
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_');
    if plain { s.to_owned() } else { quoted(s) }
}

/// The table key of a stub for a module with no recorded revision.
const NO_REVISION: &str = "<revision>";

/// The stub entry for `module`, prefilled from its repository `url` and `revision`.
pub fn stub(module: &str, url: Option<&str>, revision: Option<&str>) -> Stub {
    let (purl, purl_hint) = match url.and_then(github_repo) {
        Some((owner, repo)) => (
            format!("pkg:github/{owner}/{repo}@v{{version}}"),
            "# from the module URL: point it at the upstream repository, not a Zephyr fork",
        ),
        None => (
            format!("pkg:generic/{module}@{{version}}"),
            "# prefer pkg:github/<owner>/<repo>@v{version} for the upstream repository",
        ),
    };
    let revision = revision.map(str::trim).filter(|r| !r.is_empty());
    let table_hint = match revision {
        Some(_) => "# the upstream release this revision corresponds to",
        None => {
            "# replace <revision> with the module's git revision (without one the module stays Low), and give its upstream release"
        }
    };
    let lines = [
        format!("  {}:", key(module)),
        "    upstream:".to_owned(),
        "      name: \"\"        # upstream project name".to_owned(),
        "      homepage: \"\"    # project homepage URL (or delete this line)".to_owned(),
        "      supplier: \"\"    # who publishes it upstream (or delete this line)".to_owned(),
        format!("    purl: {}    {purl_hint}", quoted(&purl)),
        "    cpe: \"cpe:2.3:a:<vendor>:<product>:{version}:*:*:*:*:*:*:*\"    # NVD vendor and product (or delete this line)".to_owned(),
        "    version_rule:".to_owned(),
        "      kind: manual".to_owned(),
        "      table:".to_owned(),
        format!(
            "        {}: \"\"    {table_hint}",
            quoted(revision.unwrap_or(NO_REVISION))
        ),
    ];
    let mut text = lines.join("\n");
    text.push('\n');
    Stub {
        module: module.to_owned(),
        text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identify::{Level, Outcome, Query, Resolver, load_str};

    const SHA: &str = "30a859f44ef8ab4dc8f84b03ed586fd16ccf9d74";

    #[test]
    fn stub_is_valid_yaml_as_printed() {
        let stub = stub(
            "cmsis_6",
            Some("https://github.com/zephyrproject-rtos/CMSIS_6"),
            Some(SHA),
        );
        let text = format!("schema: 1\nmodules:\n{stub}");
        let value: yaml_serde::Value = yaml_serde::from_str(&text).unwrap();
        let entry = &value["modules"]["cmsis_6"];
        assert_eq!(
            entry["purl"].as_str(),
            Some("pkg:github/zephyrproject-rtos/CMSIS_6@v{version}")
        );
        assert_eq!(entry["version_rule"]["table"][SHA].as_str(), Some(""));
        // As printed it does not load: the blanks must be filled first.
        assert!(load_str("identifiers.yaml", &text).is_err());
    }

    #[test]
    fn stub_entry_loads_after_blanks_are_filled() {
        let cases = [
            (
                "cmsis_6",
                Some("https://github.com/zephyrproject-rtos/CMSIS_6"),
                Some(SHA),
            ),
            (
                "hal_nordic",
                Some("https://git.example.com/hal_nordic"),
                Some(SHA),
            ),
            ("lib.x+y", None, None),
            ("odd \"name\"", None, Some("v1.0")),
        ];
        for (module, url, revision) in cases {
            let stub = stub(module, url, revision);
            assert_eq!(stub.module(), module);
            let filled = stub
                .to_string()
                .replace("name: \"\"", "name: \"Upstream\"")
                .replace("homepage: \"\"", "homepage: \"https://example.com/\"")
                .replace("supplier: \"\"", "supplier: \"Example\"")
                .replace("<vendor>", "example")
                .replace("<product>", "product")
                .replace(": \"\"    # the upstream", ": \"2.0.0\"    # the upstream")
                .replace(": \"\"    # replace", ": \"2.0.0\"    # replace");
            // A stub without a revision has the placeholder key, with a hint.
            assert_eq!(
                filled.contains("\"<revision>\": \"2.0.0\"    # replace <revision>"),
                revision.is_none(),
                "{filled}"
            );
            // Fill in the revision the module is queried with.
            let real = revision.unwrap_or(SHA);
            let filled = filled.replace("\"<revision>\"", &format!("\"{real}\""));
            let text = format!("schema: 1\nmodules:\n{filled}");
            let loaded = load_str("identifiers.yaml", &text);
            if module.contains('"') {
                // Not a valid module name: refused, with the name in the error.
                let e = loaded.unwrap_err().to_string();
                assert!(e.contains("must match"), "{e}");
                continue;
            }
            let db = loaded.unwrap_or_else(|e| panic!("{module}: {e}\n{text}"));
            let mut resolver = Resolver::new(&db);
            let query = Query {
                module,
                revision: Some(real),
                path: None,
            };
            let Outcome::Identified(id) = resolver.resolve(&query, None) else {
                panic!("{module}: not identified");
            };
            assert_eq!(id.version.as_deref(), Some("2.0.0"), "{module}");
            assert_eq!(id.level, Level::High);
            assert!(id.purl.is_some() && id.cpe.is_some(), "{module}: {id:?}");
        }
    }

    #[test]
    fn stub_without_revision_loads_but_stays_low_until_filled() {
        let filled = stub("lib", None, None)
            .to_string()
            .replace("name: \"\"", "name: \"Lib\"")
            .replace("homepage: \"\"", "homepage: \"https://example.com/\"")
            .replace("supplier: \"\"", "supplier: \"Example\"")
            .replace("<vendor>", "example")
            .replace("<product>", "lib")
            .replace(": \"\"    # replace", ": \"2.0.0\"    # replace");
        assert!(filled.contains("\"<revision>\": \"2.0.0\""), "{filled}");
        let db = load_str(
            "identifiers.yaml",
            &format!("schema: 1\nmodules:\n{filled}"),
        )
        .unwrap();
        let mut resolver = Resolver::new(&db);
        for revision in [None, Some(SHA)] {
            let query = Query {
                module: "lib",
                revision,
                path: None,
            };
            let Outcome::Identified(id) = resolver.resolve(&query, None) else {
                panic!("not identified");
            };
            assert_eq!(
                (id.version, id.level, id.purl),
                (None, Level::Low, None),
                "{revision:?}"
            );
        }
    }
}
