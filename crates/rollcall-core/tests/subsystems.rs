//! The built-in subsystem table (`db/subsystems.yaml`) against the Zephyr build fixtures and
//! the pinned Zephyr tree.
//!
//! Offline tests use `fixtures/zephyr/` (read-only). The `#[ignore]`d tests need the pinned
//! Zephyr checkout: `scripts/verify-subsystems.sh` fetches it and runs them (the `subsystems`
//! CI job). They look for it at `$ROLLCALL_ZEPHYR_TREE`, else at
//! `<repo>/.cache/zephyr-workspace/zephyr`, and fail (never skip) when it is missing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use rollcall_core::subsystems::{
    self, Reason, Rule, SubsystemTable, SubsystemsError, ZephyrTree, lint_against,
};
use rollcall_core::zephyr::{Kconfig, kconfig};

const NEEDS_TREE: &str = "needs the pinned Zephyr tree; run scripts/verify-subsystems.sh";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> PathBuf {
    repo_root().join("fixtures/zephyr")
}

fn table() -> SubsystemTable {
    subsystems::builtin().unwrap_or_else(|e| panic!("{e}"))
}

/// Every image directory with a `.config`, relative to `fixtures/zephyr`, and the sysbuild
/// top-level directories (whose `.config` is sysbuild's own).
const CONFIGS: [&str; 9] = [
    "baseline",
    "baseline/mcuboot",
    "baseline/with_mcuboot",
    "bt",
    "bt/beacon",
    "bt/mcuboot",
    "tls",
    "tls/http_server",
    "tls/mcuboot",
];

fn config(image: &str) -> Kconfig {
    let path = fixtures().join(image).join("zephyr/.config");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    kconfig::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn zephyr_tree_root() -> PathBuf {
    std::env::var_os("ROLLCALL_ZEPHYR_TREE")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join(".cache/zephyr-workspace/zephyr"))
}

/// The pinned tree, scanned once per test binary. Panics (never skips) when it is missing.
fn zephyr_tree() -> &'static ZephyrTree {
    static TREE: OnceLock<Result<ZephyrTree, String>> = OnceLock::new();
    let tree = TREE.get_or_init(|| {
        let root = zephyr_tree_root();
        if !root.join("VERSION").is_file() {
            return Err(format!(
                "the pinned Zephyr tree is not at {} ({NEEDS_TREE}, or set ROLLCALL_ZEPHYR_TREE)",
                root.display()
            ));
        }
        ZephyrTree::open(&root).map_err(|e| e.to_string())
    });
    match tree {
        Ok(tree) => tree,
        Err(e) => panic!("{e}"),
    }
}

/// Every `CVE-YYYY-N…` ID in `text`, as `YYYY-N…`.
fn cited_cves(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r"CVE-(\d{4}-\d+)").unwrap();
    re.captures_iter(text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .collect()
}

#[test]
fn builtin_table_has_at_least_fifteen_subsystems() {
    let t = table();
    let names: Vec<&str> = t.subsystems.iter().map(|s| s.name.as_str()).collect();
    assert!(
        names.len() >= 15,
        "only {} subsystems: {names:?}",
        names.len()
    );
    // The ticket's initial coverage.
    for name in [
        "bluetooth-controller",
        "bluetooth-host",
        "crypto-drivers",
        "dfu",
        "fatfs",
        "ip-stack",
        "json",
        "littlefs",
        "logging",
        "mbedtls-integration",
        "mcumgr",
        "networking-core",
        "power-management",
        "settings",
        "shell",
        "tls-sockets",
        "usb-device",
    ] {
        assert!(t.get(name).is_some(), "{name} is not mapped");
    }
}

#[test]
fn every_entry_has_reasons_and_rationale() {
    for s in &table().subsystems {
        assert!(!s.reasons.is_empty(), "{}: no reasons", s.name);
        assert!(
            s.rationale.trim().len() >= 40,
            "{}: rationale too thin: {:?}",
            s.name,
            s.rationale
        );
        if s.reasons.contains(&Reason::CveHistory) {
            assert!(
                !cited_cves(&s.rationale).is_empty(),
                "{}: cve-history without a CVE-YYYY-N ID in the rationale",
                s.name
            );
        }
        if s.reasons.contains(&Reason::UpstreamLibrary) {
            assert!(
                s.module.is_some(),
                "{}: upstream-library without a module",
                s.name
            );
        }
    }
}

#[test]
fn symbol_sets_are_non_empty_and_well_formed() {
    for s in &table().subsystems {
        assert!(!s.symbols.is_empty(), "{}: no symbols", s.name);
        for symbol in &s.symbols {
            let bare = symbol.strip_prefix("CONFIG_").unwrap_or_else(|| {
                panic!("{}: {symbol} lacks the CONFIG_ prefix", s.name);
            });
            assert!(
                !bare.is_empty()
                    && bare
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "{}: {symbol}",
                s.name
            );
        }
        assert!(!s.sources.is_empty(), "{}: no sources", s.name);
    }
}

#[test]
fn fixture_configs_enable_expected_subsystems() {
    let t = table();
    let expected: BTreeMap<&str, &[&str]> = [
        ("baseline", &[][..]),
        ("baseline/mcuboot", &["logging", "mbedtls-integration"][..]),
        ("baseline/with_mcuboot", &[][..]),
        ("bt", &[][..]),
        (
            "bt/beacon",
            &["bluetooth-controller", "bluetooth-host", "logging"][..],
        ),
        ("bt/mcuboot", &["logging", "mbedtls-integration"][..]),
        ("tls", &[][..]),
        (
            "tls/http_server",
            &[
                "filesystem",
                "ip-stack",
                "json",
                "logging",
                "mbedtls-integration",
                "networking-core",
                "shell",
                "tls-sockets",
                "usb-device",
            ][..],
        ),
        ("tls/mcuboot", &["logging", "mbedtls-integration"][..]),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        expected.keys().copied().collect::<Vec<_>>(),
        CONFIGS,
        "every fixture .config has an expectation"
    );

    // Table symbols that some fixture sets: these are real Kconfig names by construction.
    let mut seen = BTreeSet::new();
    for image in CONFIGS {
        let cfg = config(image);
        let enabled: Vec<&str> = t.enabled_in(&cfg).iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            enabled,
            expected.get(image).copied().unwrap_or_default(),
            "{image}"
        );
        for s in &t.subsystems {
            for symbol in &s.symbols {
                if cfg.is_set(symbol) {
                    seen.insert(symbol.as_str());
                }
            }
        }
    }
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        [
            "CONFIG_BT_HCI_HOST",
            "CONFIG_BT_LL_SW_SPLIT",
            "CONFIG_FILE_SYSTEM",
            "CONFIG_JSON_LIBRARY",
            "CONFIG_LOG",
            "CONFIG_MBEDTLS",
            "CONFIG_NETWORKING",
            "CONFIG_NET_IP",
            "CONFIG_NET_SOCKETS_SOCKOPT_TLS",
            "CONFIG_SHELL",
            "CONFIG_TLS_CREDENTIALS",
            "CONFIG_USB_DEVICE_STACK_NEXT",
        ],
        "table symbols set by the fixtures (the rest are proven by \
         every_symbol_is_defined_in_pinned_zephyr_tree)"
    );
}

#[test]
fn enabled_subsystems_have_compiled_files_in_fixture_spdx() {
    let t = table();
    let mut checked = 0;
    for image in CONFIGS {
        let spdx = fixtures().join(image).join("spdx/zephyr.spdx");
        if !spdx.exists() {
            continue; // a sysbuild top-level directory
        }
        let text = std::fs::read_to_string(&spdx).unwrap();
        let files: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("FileName: ./zephyr/"))
            .collect();
        assert!(!files.is_empty(), "{}", spdx.display());
        for s in t.enabled_in(&config(image)) {
            let compiled = files.iter().any(|f| {
                s.sources.iter().any(|source| {
                    *f == source.as_str()
                        || f.strip_prefix(source.as_str())
                            .is_some_and(|rest| rest.starts_with('/'))
                })
            });
            assert!(
                compiled,
                "{image}: {} is enabled but none of {:?} was compiled",
                s.name, s.sources
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 9 + 3 + 2 * 3, "subsystem/image pairs checked");
}

#[test]
fn table_pin_matches_fixture_manifest() {
    let text = std::fs::read_to_string(fixtures().join("MANIFEST.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&text).unwrap();
    let t = table();
    assert_eq!(
        manifest.pointer("/zephyr/tag").and_then(|v| v.as_str()),
        Some(t.zephyr.tag.as_str())
    );
    assert_eq!(
        manifest.pointer("/zephyr/commit").and_then(|v| v.as_str()),
        Some(t.zephyr.commit.as_str())
    );
}

#[test]
fn load_str_rejects_duplicate_name_with_lines() {
    let entry = "  - name: shell\n    description: Shell\n    symbols: [CONFIG_SHELL]\n    sources: [subsys/shell]\n    reasons: [size]\n    rationale: Large.\n";
    let text = format!(
        "format: rollcall-subsystems/1\nzephyr:\n  tag: v4.4.2\n  commit: dccb09599635bdff17633fa7e9dab014b91dce90\nsubsystems:\n{entry}{entry}"
    );
    let e = subsystems::load_str(&text).unwrap_err();
    let SubsystemsError::Lint { findings, .. } = &e else {
        panic!("not a lint error: {e}");
    };
    assert_eq!(
        findings.iter().map(|f| f.rule).collect::<Vec<_>>(),
        [Rule::DuplicateName]
    );
    assert_eq!(
        e.to_string(),
        "subsystems.yaml:12: shell: subsystem shell is listed twice (lines 6 and 12) [duplicate-name]"
    );
}

#[test]
#[ignore = "needs the pinned Zephyr tree; run scripts/verify-subsystems.sh"]
fn every_source_exists_in_pinned_zephyr_tree() {
    let findings: Vec<String> = lint_against(&table(), zephyr_tree())
        .into_iter()
        .filter(|f| f.rule == Rule::UnknownSource)
        .map(|f| f.to_string())
        .collect();
    assert_eq!(findings, Vec::<String>::new());
}

#[test]
#[ignore = "needs the pinned Zephyr tree; run scripts/verify-subsystems.sh"]
fn every_symbol_is_defined_in_pinned_zephyr_tree() {
    let findings: Vec<String> = lint_against(&table(), zephyr_tree())
        .into_iter()
        .filter(|f| f.rule == Rule::UnknownSymbol)
        .map(|f| f.to_string())
        .collect();
    assert_eq!(findings, Vec::<String>::new());
}

/// The commit `HEAD` points at, through one `ref:` (loose or packed) if need be.
fn head_commit(root: &Path) -> Option<String> {
    let git = root.join(".git");
    let head = std::fs::read_to_string(git.join("HEAD")).ok()?;
    let head = head.trim();
    let Some(reference) = head.strip_prefix("ref: ") else {
        return Some(head.to_owned());
    };
    if let Ok(commit) = std::fs::read_to_string(git.join(reference)) {
        return Some(commit.trim().to_owned());
    }
    let packed = std::fs::read_to_string(git.join("packed-refs")).ok()?;
    packed.lines().find_map(|l| {
        let (commit, name) = l.split_once(' ')?;
        (name == reference).then(|| commit.to_owned())
    })
}

#[test]
#[ignore = "needs the pinned Zephyr tree; run scripts/verify-subsystems.sh"]
fn pinned_tree_version_matches_table_pin() {
    let t = table();
    let tree = zephyr_tree();
    assert_eq!(tree.version(), Some(t.zephyr.tag.as_str()));
    assert_eq!(
        head_commit(tree.root()).as_deref(),
        Some(t.zephyr.commit.as_str()),
        "the tree at {} is not checked out at the pinned commit",
        tree.root().display()
    );
    let all: Vec<String> = lint_against(&t, tree)
        .iter()
        .map(|f| f.to_string())
        .collect();
    assert_eq!(all, Vec::<String>::new());
}

fn c_lines(path: &Path) -> usize {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if meta.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        entries.iter().map(|p| c_lines(p)).sum()
    } else if meta.is_file() && path.extension().is_some_and(|e| e == "c") {
        let bytes = std::fs::read(path).unwrap();
        bytes.iter().filter(|b| **b == b'\n').count()
    } else {
        0
    }
}

#[test]
#[ignore = "needs the pinned Zephyr tree; run scripts/verify-subsystems.sh"]
fn size_reasons_are_backed_by_line_count() {
    let root = zephyr_tree().root().to_owned();
    for s in &table().subsystems {
        if !s.reasons.contains(&Reason::Size) {
            continue;
        }
        let lines: usize = s.sources.iter().map(|p| c_lines(&root.join(p))).sum();
        assert!(
            lines > 2000,
            "{}: `size` claimed, but its sources hold only {lines} lines of C",
            s.name
        );
    }
}

#[test]
#[ignore = "needs the pinned Zephyr tree; run scripts/verify-subsystems.sh"]
fn every_entry_has_c_sources_in_pinned_tree() {
    let root = zephyr_tree().root().to_owned();
    for s in &table().subsystems {
        let files: usize = s.sources.iter().map(|p| c_files(&root.join(p))).sum();
        assert!(
            files > 0,
            "{}: none of {:?} holds a .c file in the pinned tree",
            s.name,
            s.sources
        );
    }
}

fn c_files(path: &Path) -> usize {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if meta.is_dir() {
        std::fs::read_dir(path)
            .unwrap()
            .map(|e| c_files(&e.unwrap().path()))
            .sum()
    } else {
        usize::from(meta.is_file() && path.extension().is_some_and(|e| e == "c"))
    }
}

#[test]
#[ignore = "needs the pinned Zephyr tree; run scripts/verify-subsystems.sh"]
fn every_cited_cve_is_listed_in_pinned_tree() {
    let list = zephyr_tree()
        .root()
        .join("doc/security/vulnerabilities.rst");
    let text = std::fs::read_to_string(&list)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", list.display()));
    let mut cited = 0;
    for s in &table().subsystems {
        for id in cited_cves(&s.rationale) {
            assert!(
                text.contains(&format!(":cve:`{id}`")),
                "{}: CVE-{id} is not listed in {}",
                s.name,
                list.display()
            );
            cited += 1;
        }
    }
    assert!(cited > 0, "no CVE cited at all");
}
