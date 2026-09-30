//! Checks on the Zephyr build fixtures in `fixtures/zephyr/` (see `docs/fixtures.md`).
//!
//! The fixtures are produced only by `scripts/regen-fixtures.sh`; these tests check that the
//! committed tree is what its `MANIFEST.json` says it is, and that each variant was built with
//! the options it claims.
//!
//! `ROLLCALL_FIXTURES_DIR` points the tests at another tree; the script uses it to test a
//! staged tree before installing it. By default they check the repository's `fixtures/zephyr`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};

const VARIANTS: [&str; 3] = ["baseline", "bt", "tls"];
const SPDX_DOCS: [&str; 4] = ["app", "zephyr", "build", "modules-deps"];
const MAX_TOTAL_BYTES: u64 = 50_000_000;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures_root() -> PathBuf {
    match std::env::var_os("ROLLCALL_FIXTURES_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => repo_root().join("fixtures/zephyr"),
    }
}

fn manifest() -> Value {
    let path = fixtures_root().join("MANIFEST.json");
    let text =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Every file under `dir`, as `/`-separated paths relative to `dir`, sorted.
fn walk(dir: &Path) -> Vec<String> {
    fn go(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let entries =
            fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                go(base, &path, out);
            } else {
                let rel = path.strip_prefix(base).expect("path under base");
                let parts: Vec<String> = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                out.push(parts.join("/"));
            }
        }
    }
    let mut out = Vec::new();
    go(dir, dir, &mut out);
    out.sort();
    out
}

/// True if the Kconfig text sets `key` to `y` (a line exactly `KEY=y`).
fn config_is_set(text: &str, key: &str) -> bool {
    let want = format!("{key}=y");
    text.lines().any(|l| l.trim_end_matches('\r') == want)
}

/// True if the Kconfig text has `# KEY is not set`.
fn config_is_unset(text: &str, key: &str) -> bool {
    let want = format!("# {key} is not set");
    text.lines().any(|l| l.trim_end_matches('\r') == want)
}

/// Reads a fixture as text, replacing invalid UTF-8 rather than failing.
fn read_text(rel: &str) -> String {
    let path = fixtures_root().join(rel);
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The application image name of a variant, from the manifest.
fn app_image(manifest: &Value, variant: &str) -> String {
    manifest
        .pointer(&format!("/variants/{variant}/images/app"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("manifest has no variants.{variant}.images.app"))
        .to_owned()
}

fn manifest_files(manifest: &Value) -> Vec<&Value> {
    manifest
        .get("files")
        .and_then(Value::as_array)
        .expect("manifest has a files array")
        .iter()
        .collect()
}

fn is_text_fixture(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        name,
        ".config"
            | "build_info.yml"
            | "domains.yaml"
            | "zephyr.meta"
            | "zephyr.map"
            | "west-list.txt"
    ) || name.ends_with(".spdx")
}

#[test]
fn config_helpers_tolerate_malformed_lines() {
    let text = "\n\u{0}\r\nCONFIG_BT\nCONFIG_BT=yes\nCONFIG_BT_X=y\n=y\n# CONFIG_BT is not set really\n\
                #CONFIG_BT is not set\nCONFIG_BT= y\n\u{fffd}\u{fffd}=y\n";
    assert!(!config_is_set(text, "CONFIG_BT"));
    assert!(!config_is_unset(text, "CONFIG_BT"));
    assert!(!config_is_set("", "CONFIG_BT"));
    assert!(!config_is_unset("", ""));
    assert!(config_is_set("CONFIG_BT=y\r\n", "CONFIG_BT"));
    assert!(config_is_unset("x\n# CONFIG_BT is not set", "CONFIG_BT"));
    // A key that is a prefix of another is not confused with it.
    assert!(!config_is_set("CONFIG_BT_HCI=y\n", "CONFIG_BT"));
    // Invalid UTF-8 read through `read_text`'s lossy path still yields searchable text.
    let lossy = String::from_utf8_lossy(b"\xff\xfeCONFIG_BT=y\n\xc3\nCONFIG_MBEDTLS=y\n");
    assert!(config_is_set(&lossy, "CONFIG_MBEDTLS"));
    assert!(!config_is_set(&lossy, "CONFIG_BT"));
}

#[test]
fn manifest_pins_zephyr_revision_and_sdk_version() {
    let m = manifest();
    assert_eq!(
        m.get("format").and_then(Value::as_str),
        Some("rollcall-fixtures/1")
    );
    assert_eq!(
        m.pointer("/zephyr/tag").and_then(Value::as_str),
        Some("v4.4.2")
    );
    let commit = m
        .pointer("/zephyr/commit")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert_eq!(
        commit.len(),
        40,
        "zephyr.commit is not 40 hex digits: {commit:?}"
    );
    assert!(
        commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "zephyr.commit is not lowercase hex: {commit:?}"
    );
    assert_eq!(
        m.pointer("/sdk/version").and_then(Value::as_str),
        Some("1.0.1")
    );
    let variants: Vec<&str> = m
        .get("variants")
        .and_then(Value::as_object)
        .expect("manifest has variants")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(variants, VARIANTS, "manifest variants");
}

#[test]
fn every_variant_has_the_required_file_set() {
    let m = manifest();
    let root = fixtures_root();
    for v in VARIANTS {
        let app = app_image(&m, v);
        let mut required = vec![
            format!("{v}/west-list.txt"),
            format!("{v}/build_info.yml"),
            format!("{v}/domains.yaml"),
            format!("{v}/zephyr/.config"),
            format!("{v}/{app}/zephyr/zephyr.signed.hex"),
            format!("{v}/mcuboot/zephyr/zephyr.hex"),
        ];
        for img in [app.as_str(), "mcuboot"] {
            for f in [
                "build_info.yml",
                "zephyr/.config",
                "zephyr/zephyr.map",
                "zephyr/zephyr.meta",
                "zephyr/zephyr.elf",
            ] {
                required.push(format!("{v}/{img}/{f}"));
            }
            for doc in SPDX_DOCS {
                required.push(format!("{v}/{img}/spdx/{doc}.spdx"));
            }
        }
        for rel in &required {
            let path = root.join(rel);
            assert!(path.is_file(), "missing fixture {rel}");
            let len = fs::metadata(&path).map(|md| md.len()).unwrap_or(0);
            assert!(len > 0, "empty fixture {rel}");
        }
    }
}

#[test]
fn manifest_lists_exactly_the_committed_files() {
    let m = manifest();
    let listed: Vec<String> = manifest_files(&m)
        .iter()
        .map(|e| {
            e.get("path")
                .and_then(Value::as_str)
                .expect("file entry has a path")
                .to_owned()
        })
        .collect();
    let mut sorted = listed.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(listed, sorted, "manifest files are not sorted and unique");
    let on_disk: Vec<String> = walk(&fixtures_root())
        .into_iter()
        .filter(|p| p != "MANIFEST.json")
        .collect();
    assert_eq!(listed, on_disk, "manifest file list differs from the tree");
    let total: u64 = manifest_files(&m)
        .iter()
        .map(|e| e.get("bytes").and_then(Value::as_u64).unwrap_or(0))
        .sum();
    assert_eq!(m.get("total_bytes").and_then(Value::as_u64), Some(total));
}

#[test]
fn manifest_sha256s_match_committed_files() {
    let m = manifest();
    let root = fixtures_root();
    let files = manifest_files(&m);
    assert!(!files.is_empty(), "manifest lists no files");
    for entry in files {
        let rel = entry.get("path").and_then(Value::as_str).expect("path");
        let bytes = fs::read(root.join(rel)).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"));
        assert_eq!(
            entry.get("sha256").and_then(Value::as_str),
            Some(sha256_hex(&bytes).as_str()),
            "sha256 of {rel}"
        );
        assert_eq!(
            entry.get("bytes").and_then(Value::as_u64),
            Some(bytes.len() as u64),
            "size of {rel}"
        );
    }
}

#[test]
fn fixture_tree_is_under_50_mb() {
    let root = fixtures_root();
    let total: u64 = walk(&root)
        .iter()
        .map(|rel| fs::metadata(root.join(rel)).map(|md| md.len()).unwrap_or(0))
        .sum();
    assert!(total > 0, "fixture tree is empty");
    assert!(
        total < MAX_TOTAL_BYTES,
        "fixture tree is {total} bytes, limit {MAX_TOTAL_BYTES}"
    );
}

#[test]
fn baseline_config_has_bt_and_mbedtls_off() {
    let m = manifest();
    let config = read_text(&format!(
        "baseline/{}/zephyr/.config",
        app_image(&m, "baseline")
    ));
    assert!(
        config_is_unset(&config, "CONFIG_BT"),
        "baseline: CONFIG_BT is not off"
    );
    assert!(
        config_is_unset(&config, "CONFIG_MBEDTLS"),
        "baseline: CONFIG_MBEDTLS is not off"
    );
}

#[test]
fn bt_config_has_bt_on_and_mbedtls_off() {
    let m = manifest();
    let config = read_text(&format!("bt/{}/zephyr/.config", app_image(&m, "bt")));
    assert!(
        config_is_set(&config, "CONFIG_BT"),
        "bt: CONFIG_BT is not on"
    );
    assert!(
        config_is_unset(&config, "CONFIG_MBEDTLS"),
        "bt: CONFIG_MBEDTLS is not off"
    );
}

#[test]
fn tls_config_has_mbedtls_and_tls_sockets_on_and_bt_off() {
    let m = manifest();
    let config = read_text(&format!("tls/{}/zephyr/.config", app_image(&m, "tls")));
    assert!(
        config_is_set(&config, "CONFIG_MBEDTLS"),
        "tls: CONFIG_MBEDTLS is not on"
    );
    assert!(
        config_is_set(&config, "CONFIG_NET_SOCKETS_SOCKOPT_TLS"),
        "tls: CONFIG_NET_SOCKETS_SOCKOPT_TLS is not on"
    );
    assert!(
        config_is_unset(&config, "CONFIG_BT"),
        "tls: CONFIG_BT is not off"
    );
}

#[test]
fn every_variant_enables_mcuboot_via_sysbuild() {
    let m = manifest();
    for v in VARIANTS {
        let sysbuild = read_text(&format!("{v}/zephyr/.config"));
        assert!(
            config_is_set(&sysbuild, "SB_CONFIG_BOOTLOADER_MCUBOOT"),
            "{v}: sysbuild does not enable MCUboot"
        );
        let app = read_text(&format!("{v}/{}/zephyr/.config", app_image(&m, v)));
        assert!(
            config_is_set(&app, "CONFIG_BOOTLOADER_MCUBOOT"),
            "{v}: app is not built for MCUboot"
        );
        let boot = read_text(&format!("{v}/mcuboot/zephyr/.config"));
        assert!(
            config_is_set(&boot, "CONFIG_MCUBOOT"),
            "{v}: mcuboot image is not MCUboot"
        );
    }
}

#[test]
fn spdx_documents_are_2_3_with_pinned_namespace() {
    let m = manifest();
    for v in VARIANTS {
        let app = app_image(&m, v);
        for img in [app.as_str(), "mcuboot"] {
            for doc in SPDX_DOCS {
                let rel = format!("{v}/{img}/spdx/{doc}.spdx");
                let text = read_text(&rel);
                assert_eq!(
                    text.lines().next(),
                    Some("SPDXVersion: SPDX-2.3"),
                    "{rel}: not SPDX 2.3"
                );
                let want =
                    format!("DocumentNamespace: http://spdx.org/spdxdocs/rollcall-{v}-{img}/");
                assert!(
                    text.lines().any(|l| l.starts_with(&want)),
                    "{rel}: no namespace starting {want:?}"
                );
            }
        }
    }
}

#[test]
fn text_fixtures_contain_no_host_paths() {
    let root = fixtures_root();
    let mut build_infos = 0;
    for rel in walk(&root).iter().filter(|p| is_text_fixture(p)) {
        let text = read_text(rel);
        for needle in [
            "/Users/",
            "/home/",
            "/private/",
            "/root/",
            "/work/",
            "/opt/hostedtoolcache",
        ] {
            assert!(
                !text.contains(needle),
                "{rel} contains host path {needle:?}"
            );
        }
        if rel.ends_with("build_info.yml") {
            build_infos += 1;
            assert!(
                text.contains("/zephyrproject"),
                "{rel} does not use /zephyrproject"
            );
        }
    }
    assert_eq!(build_infos, VARIANTS.len() * 3, "build_info.yml count");
}

#[test]
fn fixtures_doc_has_required_sections() {
    let path = repo_root().join("docs/fixtures.md");
    let doc =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    for heading in [
        "# Zephyr build fixtures",
        "## What is here",
        "## Pins",
        "## Prerequisites",
        "## Regenerating",
        "## Determinism",
        "## Trimming",
        "## Checks",
        "## Bumping the pin",
    ] {
        assert!(
            doc.lines().any(|l| l.trim_end() == heading),
            "docs/fixtures.md lacks {heading:?}"
        );
    }
    for term in [
        "scripts/regen-fixtures.sh",
        "--check-stable",
        "gh workflow run regen-fixtures.yml",
        "gh run download",
        "canonical",
        "v4.4.2",
        "1.0.1",
        "/zephyrproject",
        "/zephyr-sdk",
    ] {
        assert!(
            doc.contains(term),
            "docs/fixtures.md does not mention {term:?}"
        );
    }
}

// --- `scripts/regen-fixtures.sh compare` -------------------------------------------------------

fn tool_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Runs `bash scripts/regen-fixtures.sh compare <a> <b>`: true for PASS (exit 0), false for
/// FAIL (exit 1); any other outcome fails the test.
fn compare_passes(a: &Path, b: &Path) -> bool {
    let out = Command::new("bash")
        .arg(repo_root().join("scripts/regen-fixtures.sh"))
        .arg("compare")
        .arg(a)
        .arg(b)
        .output()
        .expect("run bash");
    match out.status.code() {
        Some(0) => true,
        Some(1) => false,
        other => panic!(
            "compare exited with {other:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create dir");
    for rel in walk(src) {
        let to = dst.join(&rel);
        fs::create_dir_all(to.parent().expect("parent")).expect("create dir");
        fs::copy(src.join(&rel), &to).unwrap_or_else(|e| panic!("copy {rel}: {e}"));
    }
}

/// Two one-file trees `<tmp>/<case>/{a,b}/<name>` holding `a` and `b`.
fn file_pair(tmp: &Path, case: &str, name: &str, a: &[u8], b: &[u8]) -> (PathBuf, PathBuf) {
    let (da, db) = (tmp.join(case).join("a"), tmp.join(case).join("b"));
    for (dir, bytes) in [(&da, a), (&db, b)] {
        let path = dir.join(name);
        fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
        fs::write(&path, bytes).expect("write");
    }
    (da, db)
}

/// One Intel HEX line split into its record bytes and its line terminator.
fn hex_record(line: &str) -> Option<(Vec<u8>, &str)> {
    let body = line.trim_end_matches(['\r', '\n']);
    let term = &line[body.len()..];
    let hex = body.strip_prefix(':')?;
    if hex.len() % 2 != 0 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect();
    Some((bytes?, term))
}

fn hex_line(record: &[u8], term: &str) -> String {
    let mut raw = record.to_vec();
    if let Some(last) = raw.last_mut() {
        let sum = record[..record.len() - 1]
            .iter()
            .fold(0u8, |s, b| s.wrapping_add(*b));
        *last = sum.wrapping_neg();
    }
    let hex: String = raw.iter().map(|b| format!("{b:02X}")).collect();
    format!(":{hex}{term}")
}

/// The data bytes of an Intel HEX text by absolute address, as (line index, byte index in the
/// record) so a byte can be changed in place.
fn hex_layout(text: &str) -> Vec<(u32, usize, usize, u8)> {
    let mut out = Vec::new();
    let mut base = 0u32;
    for (i, line) in text.split_inclusive('\n').enumerate() {
        let Some((rec, _)) = hex_record(line) else {
            continue;
        };
        if rec.len() < 5 {
            continue;
        }
        let (count, addr, kind) = (
            usize::from(rec[0]),
            u32::from(rec[1]) << 8 | u32::from(rec[2]),
            rec[3],
        );
        match kind {
            0 => {
                for k in 0..count.min(rec.len().saturating_sub(5)) {
                    out.push((base + addr + k as u32, i, 4 + k, rec[4 + k]));
                }
            }
            4 if count == 2 => base = (u32::from(rec[4]) << 8 | u32::from(rec[5])) << 16,
            _ => {}
        }
    }
    out
}

/// Flips the low bit of the byte at `addr`, keeping the record checksum valid.
fn hex_flip_byte(text: &str, addr: u32) -> Option<String> {
    let (_, line_idx, byte_idx, _) = *hex_layout(text).iter().find(|e| e.0 == addr)?;
    let mut lines: Vec<String> = text.split_inclusive('\n').map(str::to_owned).collect();
    let (mut rec, term) = hex_record(&lines[line_idx]).map(|(r, t)| (r, t.to_owned()))?;
    rec[byte_idx] ^= 0x01;
    lines[line_idx] = hex_line(&rec, &term);
    Some(lines.concat())
}

/// Start of the image, first image-body address after the header, and the (address, length)
/// of the single RSA-PSS signature TLV (0x20).
fn mcuboot_layout(text: &str) -> Option<(u32, u32, (u32, u32))> {
    let layout = hex_layout(text);
    let lo = layout.iter().map(|e| e.0).min()?;
    let byte = |a: u32| layout.iter().find(|e| e.0 == a).map(|e| e.3);
    let u16_at = |a: u32| Some(u32::from(byte(a)?) | u32::from(byte(a + 1)?) << 8);
    let u32_at = |a: u32| Some(u16_at(a)? | u16_at(a + 2)? << 16);
    if u32_at(lo)? != 0x96f3_b83d {
        return None;
    }
    let (hdr, prot, img) = (u16_at(lo + 8)?, u16_at(lo + 10)?, u32_at(lo + 12)?);
    let mut off = lo + hdr + img + prot;
    if u16_at(off)? != 0x6907 {
        return None;
    }
    let end = off + u16_at(off + 2)?;
    off += 4;
    while off < end {
        let (kind, len) = (u16_at(off)?, u16_at(off + 2)?);
        if kind == 0x20 {
            return Some((lo, lo + hdr, (off + 4, len)));
        }
        off += 4 + len;
    }
    None
}

/// Index ranges of the consecutive runs of `Relationship:` lines.
fn relationship_runs(lines: &[String]) -> Vec<(usize, usize)> {
    let mut runs = Vec::new();
    let mut start = None;
    for (i, l) in lines.iter().enumerate() {
        match (l.starts_with("Relationship:"), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                runs.push((s, i));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        runs.push((s, lines.len()));
    }
    runs
}

#[test]
fn compare_detects_real_differences_and_ignores_only_approved_ones() {
    for tool in ["bash", "python3"] {
        if !tool_available(tool) {
            eprintln!("skipping compare test: {tool} is not available");
            return;
        }
    }
    let m = manifest();
    let tmp = tempfile::tempdir().expect("tempdir");
    let tmp = tmp.path();

    // Identical copies of the whole tree.
    let (a, b) = (tmp.join("full/a"), tmp.join("full/b"));
    copy_tree(&fixtures_root(), &a);
    copy_tree(&fixtures_root(), &b);
    assert!(compare_passes(&a, &b), "identical copies must PASS");

    // Signed hex: image body vs signature.
    let hex_rel = format!(
        "baseline/{}/zephyr/zephyr.signed.hex",
        app_image(&m, "baseline")
    );
    let hex = read_text(&hex_rel);
    assert!(!hex.contains('\r'), "{hex_rel} is expected to be LF");
    let (_, body, (sig, sig_len)) = mcuboot_layout(&hex).expect("MCUboot layout");
    assert!(sig_len > 0, "empty signature TLV");
    let name = "x/zephyr.signed.hex";
    let body_flip = hex_flip_byte(&hex, body + 0x40).expect("image byte");
    let (a, b) = file_pair(tmp, "hex-body", name, hex.as_bytes(), body_flip.as_bytes());
    assert!(!compare_passes(&a, &b), "a flipped image byte must FAIL");
    let sig_flip = hex_flip_byte(&hex, sig + sig_len / 2).expect("signature byte");
    assert_ne!(sig_flip, hex);
    let (a, b) = file_pair(tmp, "hex-sig", name, hex.as_bytes(), sig_flip.as_bytes());
    assert!(compare_passes(&a, &b), "a flipped signature byte must PASS");
    let crlf = hex.replace('\n', "\r\n");
    let (a, b) = file_pair(tmp, "hex-crlf", name, hex.as_bytes(), crlf.as_bytes());
    assert!(!compare_passes(&a, &b), "a CRLF-converted hex must FAIL");

    // Kconfig value.
    let config = read_text("baseline/zephyr/.config");
    let changed = config.replace(
        "SB_CONFIG_BOOTLOADER_MCUBOOT=y",
        "SB_CONFIG_BOOTLOADER_MCUBOOT=n",
    );
    assert_ne!(changed, config);
    let (a, b) = file_pair(
        tmp,
        "config",
        "x/zephyr/.config",
        config.as_bytes(),
        changed.as_bytes(),
    );
    assert!(!compare_passes(&a, &b), "a .config value change must FAIL");

    // SPDX relationships and Created:.
    let spdx = read_text(&format!(
        "baseline/{}/spdx/build.spdx",
        app_image(&m, "baseline")
    ));
    let lines: Vec<String> = spdx.split_inclusive('\n').map(str::to_owned).collect();
    let runs = relationship_runs(&lines);
    let (r1, r2) = (
        *runs
            .iter()
            .find(|(s, e)| e - s >= 2 && lines[*s] != lines[s + 1])
            .expect("a relationship run of two distinct lines"),
        *runs.last().expect("relationship runs"),
    );
    assert_ne!(r1, r2, "need two relationship runs");
    let name = "x/build.spdx";
    let with = |f: &dyn Fn(&mut Vec<String>)| -> String {
        let mut l = lines.clone();
        f(&mut l);
        l.concat()
    };
    let swapped = with(&|l| l.swap(r1.0, r1.0 + 1));
    let (a, b) = file_pair(tmp, "rel-swap", name, spdx.as_bytes(), swapped.as_bytes());
    assert!(compare_passes(&a, &b), "reordering within a run must PASS");
    let moved = with(&|l| {
        let line = l.remove(r1.0);
        l.insert(r2.0 - 1, line);
    });
    let (a, b) = file_pair(tmp, "rel-move", name, spdx.as_bytes(), moved.as_bytes());
    assert!(
        !compare_passes(&a, &b),
        "moving a relationship to another run must FAIL"
    );
    let retargeted = with(&|l| l[r1.0] = format!("{}X\n", l[r1.0].trim_end()));
    let (a, b) = file_pair(
        tmp,
        "rel-target",
        name,
        spdx.as_bytes(),
        retargeted.as_bytes(),
    );
    assert!(
        !compare_passes(&a, &b),
        "changing a relationship target must FAIL"
    );
    let created = lines
        .iter()
        .position(|l| l.starts_with("Created:"))
        .expect("Created: line");
    let injected = with(&|l| l.insert(created, "Created: 2000-01-01T00:00:00Z\n".to_owned()));
    let (a, b) = file_pair(tmp, "created", name, spdx.as_bytes(), injected.as_bytes());
    assert!(!compare_passes(&a, &b), "an extra Created: line must FAIL");

    // Unreadable SPDX on both sides.
    for (case, bytes) in [
        ("garbage", &b"\xff\xfe\x00 not spdx\n"[..]),
        ("empty", &b""[..]),
    ] {
        let (a, b) = file_pair(tmp, case, name, bytes, bytes);
        assert!(
            !compare_passes(&a, &b),
            "{case} SPDX on both sides must FAIL"
        );
    }
}
