//! Hermetic tests for the release scripts (SHA-124) and the release workflows' shape:
//!
//! - `scripts/release-version.sh`, `scripts/package-release.sh` and `scripts/release-sums.sh`
//!   run for real on temporary files;
//! - `scripts/publish-crates.sh` runs with a fake `curl` (the crates.io API, answering from a
//!   temporary directory) and a fake `cargo` (logging each publish, failing on request) on
//!   `PATH`;
//! - `scripts/install-check-{cargo,pip,tamper}.sh` run with a fake `cargo`, `python` (venv, pip
//!   and the installed wrapper) and `curl`, so their checks (version, checksums, cache, the
//!   tampered install's exit code and message) are pinned offline. The real installs run in
//!   `.github/workflows/install-check.yml`;
//! - `.github/workflows/release.yml` and `install-check.yml` are parsed and checked for the
//!   jobs, matrices and pins the ticket's test plan names.
//!
//! Unix only (the scripts and fakes are shell scripts); needs bash and python3.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PLATFORMS: [&str; 4] = [
    "darwin-universal",
    "linux-amd64",
    "linux-arm64",
    "windows-amd64",
];

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn script(name: &str) -> PathBuf {
    workspace().join("scripts").join(name)
}

fn text(out: &Output) -> String {
    format!(
        "exit {:?}\n--- stdout\n{}\n--- stderr\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn write_exe(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn tag() -> String {
    format!("v{VERSION}")
}

/// The SHA-256 of `path` from the system tool, as the scripts compute it.
fn sha256_of(path: &Path) -> String {
    let out = Command::new("sh")
        .arg("-c")
        .arg(
            "if command -v sha256sum >/dev/null 2>&1; then sha256sum \"$1\"; \
             else shasum -a 256 \"$1\"; fi",
        )
        .arg("sh")
        .arg(path)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    stdout(&out).split_whitespace().next().unwrap().to_owned()
}

/// A temporary directory with `bin/` (fakes, first on `PATH`) and `fake/` (their state).
struct Sandbox {
    dir: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("bin")).unwrap();
        std::fs::create_dir_all(dir.path().join("fake")).unwrap();
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn fake(&self, name: &str, body: &str) {
        write_exe(&self.path("bin").join(name), body);
    }

    fn state(&self, name: &str) -> PathBuf {
        self.path("fake").join(name)
    }

    fn read_state(&self, name: &str) -> String {
        std::fs::read_to_string(self.state(name)).unwrap_or_default()
    }

    /// `scripts/NAME ARGS` with the fakes first on `PATH` and no stray release variables.
    fn run(&self, name: &str, args: &[&str], env: &[(&str, &str)]) -> Output {
        let path = format!(
            "{}:{}",
            self.path("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut cmd = Command::new("bash");
        cmd.arg(script(name)).args(args).env("PATH", path);
        cmd.env("FAKE", self.path("fake"));
        for (key, _) in std::env::vars() {
            if key.starts_with("ROLLCALL_") || key == "GITHUB_OUTPUT" || key == "SOURCE_DATE_EPOCH"
            {
                cmd.env_remove(key);
            }
        }
        cmd.env("ROLLCALL_RETRY_DELAY", "0");
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }
}

// --- release-version.sh ------------------------------------------------------------------------

#[test]
fn release_version_check_passes_on_the_workspace() {
    let s = Sandbox::new();
    let out = s.run("release-version.sh", &["check"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let prerelease = VERSION.contains('-');
    let pep440 = stdout(&s.run("release-version.sh", &["pep440"], &[]));
    assert_eq!(
        stdout(&out),
        format!(
            "tag=v{VERSION}\nversion={VERSION}\npep440={}\nprerelease={prerelease}\n",
            pep440.trim_end()
        )
    );
    // With GITHUB_OUTPUT the same lines are the step's outputs.
    let outputs = s.path("github-output");
    let out = s.run(
        "release-version.sh",
        &["check", tag().as_str()],
        &[("GITHUB_OUTPUT", outputs.to_str().unwrap())],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(stdout(&out).is_empty());
    let written = std::fs::read_to_string(&outputs).unwrap();
    assert!(written.starts_with(&format!("tag=v{VERSION}\nversion={VERSION}\n")));
    let version = stdout(&s.run("release-version.sh", &["version"], &[]));
    assert_eq!(version, format!("{VERSION}\n"));
}

#[test]
fn release_version_pep440_maps_prereleases() {
    let s = Sandbox::new();
    for (semver, pep440) in [
        ("0.1.0", "0.1.0"),
        ("0.1.0-rc.1", "0.1.0rc1"),
        ("1.2.3-alpha.2", "1.2.3a2"),
        ("1.0.0-beta.10", "1.0.0b10"),
    ] {
        let out = s.run("release-version.sh", &["pep440", semver], &[]);
        assert_eq!(out.status.code(), Some(0), "{semver}: {}", text(&out));
        assert_eq!(stdout(&out), format!("{pep440}\n"), "{semver}");
    }
    for bad in [
        "1.0",
        "1.0.0-dev.1",
        "1.0.0-rc1",
        "v1.0.0",
        "1.0.0+build",
        "",
        "1.0.0\n",
    ] {
        let out = s.run("release-version.sh", &["pep440", bad], &[]);
        assert_eq!(out.status.code(), Some(65), "{bad:?}: {}", text(&out));
        assert!(
            stderr(&out).contains("is not a release version"),
            "{}",
            text(&out)
        );
    }
}

#[test]
fn release_version_check_rejects_a_tag_that_is_not_the_version() {
    let s = Sandbox::new();
    let out = s.run("release-version.sh", &["check", "v9.9.9"], &[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stderr(&out).contains(&format!(
            "::error::release-version: tag v9.9.9 does not match the workspace version {VERSION}"
        )),
        "{}",
        text(&out)
    );
    assert!(stdout(&out).is_empty(), "outputs written on failure");
    for bad in [
        "9.9.9",
        "v1.0",
        "v1.0.0;touch x",
        "refs/tags/v1.0.0",
        "v1.0.0-preview.1",
    ] {
        let out = s.run("release-version.sh", &["check", bad], &[]);
        assert_eq!(out.status.code(), Some(65), "{bad}: {}", text(&out));
        assert!(
            stderr(&out).contains("is not a release tag"),
            "{}",
            text(&out)
        );
    }
}

#[test]
fn release_version_check_names_every_file_that_disagrees() {
    let s = Sandbox::new();
    let root = s.path("repo");
    std::fs::create_dir_all(root.join("python/src/rollcall")).unwrap();
    let cargo = std::fs::read_to_string(workspace().join("Cargo.toml"))
        .unwrap()
        .replace(
            &format!(
                "rollcall-assay = {{ path = \"crates/rollcall-assay\", version = \"{VERSION}\" }}"
            ),
            "rollcall-assay = { path = \"crates/rollcall-assay\", version = \"0.0.0\" }",
        );
    assert!(
        cargo.contains("version = \"0.0.0\""),
        "the fixture edit did not apply"
    );
    std::fs::write(root.join("Cargo.toml"), cargo).unwrap();
    std::fs::write(
        root.join("python/pyproject.toml"),
        "[project]\nname = \"rollcall\"\nversion = \"9.9.9\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("python/src/rollcall/__init__.py"),
        "__version__ = \"9.9.9\"\nTAG = \"v9.9.9\"\n",
    )
    .unwrap();
    let out = s.run(
        "release-version.sh",
        &["check"],
        &[("ROLLCALL_ROOT", root.to_str().unwrap())],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let err = stderr(&out);
    for needle in [
        "rollcall-assay has version '0.0.0'",
        "python/pyproject.toml version is '9.9.9'",
        "__init__.py __version__ is '9.9.9'",
        "__init__.py TAG is 'v9.9.9'",
    ] {
        assert!(err.contains(needle), "{needle}: {}", text(&out));
    }
    assert!(!err.contains("rollcall-core has"), "{}", text(&out));
    // Missing files are named too; a root without Cargo.toml is exit 66.
    std::fs::remove_file(root.join("python/pyproject.toml")).unwrap();
    let out = s.run(
        "release-version.sh",
        &["check"],
        &[("ROLLCALL_ROOT", root.to_str().unwrap())],
    );
    assert!(
        stderr(&out).contains("python/pyproject.toml is missing"),
        "{}",
        text(&out)
    );
    let empty = s.path("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let out = s.run(
        "release-version.sh",
        &["check"],
        &[("ROLLCALL_ROOT", empty.to_str().unwrap())],
    );
    assert_eq!(out.status.code(), Some(66), "{}", text(&out));
}

#[test]
fn release_version_usage_errors_exit_64() {
    let s = Sandbox::new();
    for args in [
        &[][..],
        &["bump"],
        &["check", "v1.0.0", "x"],
        &["version", "x"],
    ] {
        let out = s.run("release-version.sh", args, &[]);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", text(&out));
        assert!(stderr(&out).contains("usage:"), "{}", text(&out));
    }
}

// --- package-release.sh ------------------------------------------------------------------------

/// The members of a release asset as `[name, mode, uid, gid, mtime, size]`, by Python's own
/// tarfile/zipfile (what the PyPI wrapper uses to unpack it).
fn members(asset: &Path) -> Value {
    let out = Command::new("python3")
        .arg("-c")
        .arg(
            r#"
import json, sys, tarfile, zipfile, gzip, struct
p = sys.argv[1]
rows = []
if p.endswith(".zip"):
    with zipfile.ZipFile(p) as z:
        for i in z.infolist():
            rows.append([i.filename, (i.external_attr >> 16) & 0o7777, None, None, list(i.date_time), i.file_size])
    header = None
else:
    with tarfile.open(p, "r:gz") as t:
        for i in t.getmembers():
            rows.append([i.name, i.mode, i.uid, i.gid, i.mtime, i.size, i.uname, i.gname, i.type.decode()])
    raw = open(p, "rb").read(10)
    header = {"mtime": struct.unpack("<I", raw[4:8])[0], "flags": raw[3]}
print(json.dumps({"members": rows, "gzip": header}))
"#,
        )
        .arg(asset)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    serde_json::from_slice(&out.stdout).unwrap()
}

fn package(s: &Sandbox, binary: &Path, platform: &str, outdir: &str, epoch: &str) -> Output {
    s.run(
        "package-release.sh",
        &[
            binary.to_str().unwrap(),
            tag().as_str(),
            platform,
            s.path(outdir).to_str().unwrap(),
        ],
        &[("SOURCE_DATE_EPOCH", epoch)],
    )
}

#[test]
fn package_release_lays_out_the_asset_install_sh_and_the_wrapper_expect() {
    let s = Sandbox::new();
    let bin = s.path("rollcall");
    write_exe(&bin, "#!/bin/sh\necho rollcall\n");
    let epoch = "1767225600"; // 2026-01-01T00:00:00Z
    let t = tag();
    let t = t.as_str();
    for platform in ["linux-amd64", "linux-arm64", "darwin-universal"] {
        let out = package(&s, &bin, platform, "dist", epoch);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        let asset = s.path(&format!("dist/rollcall-{t}-{platform}.tar.gz"));
        assert_eq!(stdout(&out).trim_end(), asset.to_str().unwrap());
        let m = members(&asset);
        let prefix = format!("rollcall-{t}-{platform}");
        let license = std::fs::metadata(workspace().join("LICENSE"))
            .unwrap()
            .len();
        let readme = std::fs::metadata(workspace().join("README.md"))
            .unwrap()
            .len();
        let size = std::fs::metadata(&bin).unwrap().len();
        assert_eq!(
            m["members"],
            serde_json::json!([
                [
                    format!("{prefix}/LICENSE"),
                    0o644,
                    0,
                    0,
                    1767225600,
                    license,
                    "",
                    "",
                    "0"
                ],
                [
                    format!("{prefix}/README.md"),
                    0o644,
                    0,
                    0,
                    1767225600,
                    readme,
                    "",
                    "",
                    "0"
                ],
                [
                    format!("{prefix}/rollcall"),
                    0o755,
                    0,
                    0,
                    1767225600,
                    size,
                    "",
                    "",
                    "0"
                ],
            ]),
            "{platform}"
        );
        // The gzip header carries the same mtime and no file name (FNAME, flag 8).
        assert_eq!(m["gzip"]["mtime"], 1767225600);
        assert_eq!(m["gzip"]["flags"].as_u64().unwrap() & 8, 0);
    }
    let out = package(&s, &bin, "windows-amd64", "dist", epoch);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let zip = s.path(&format!("dist/rollcall-{t}-windows-amd64.zip"));
    let m = members(&zip);
    let names: Vec<&str> = m["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r[0].as_str().unwrap())
        .collect();
    let prefix = format!("rollcall-{t}-windows-amd64");
    assert_eq!(
        names,
        [
            format!("{prefix}/LICENSE"),
            format!("{prefix}/README.md"),
            format!("{prefix}/rollcall.exe"),
        ]
    );
    assert_eq!(m["members"][2][1], 0o755);
    assert_eq!(m["members"][0][4], serde_json::json!([2026, 1, 1, 0, 0, 0]));
}

#[test]
fn package_release_is_deterministic() {
    let s = Sandbox::new();
    let bin = s.path("rollcall");
    write_exe(&bin, "#!/bin/sh\necho rollcall\n");
    let t = tag();
    let t = t.as_str();
    for (platform, ext) in [("linux-amd64", "tar.gz"), ("windows-amd64", "zip")] {
        let out = package(&s, &bin, platform, "a", "1767225600");
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        // The binary's own mtime and permissions on disk do not matter.
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&bin, "#!/bin/sh\necho rollcall\n").unwrap();
        let out = package(&s, &bin, platform, "b", "1767225600");
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        let name = format!("rollcall-{t}-{platform}.{ext}");
        let a = std::fs::read(s.path("a").join(&name)).unwrap();
        let b = std::fs::read(s.path("b").join(&name)).unwrap();
        assert!(a == b, "{name} differs between two runs");
        // SOURCE_DATE_EPOCH is the only time in it.
        // (A day later: zip times have a two-second resolution.)
        let out = package(&s, &bin, platform, "c", "1767312000");
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        assert_ne!(a, std::fs::read(s.path("c").join(&name)).unwrap());
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // Without SOURCE_DATE_EPOCH: 1980-01-01, still reproducible.
    let run = |dir: &str| {
        s.run(
            "package-release.sh",
            &[
                bin.to_str().unwrap(),
                t,
                "linux-arm64",
                s.path(dir).to_str().unwrap(),
            ],
            &[],
        )
    };
    assert!(run("d").status.success() && run("e").status.success());
    let name = format!("rollcall-{t}-linux-arm64.tar.gz");
    assert_eq!(
        std::fs::read(s.path("d").join(&name)).unwrap(),
        std::fs::read(s.path("e").join(&name)).unwrap()
    );
    assert_eq!(
        members(&s.path("d").join(&name))["gzip"]["mtime"],
        315532800
    );
}

/// (arguments, environment, exit code, stderr needle)
type BadPackage<'a> = (&'a [&'a str], &'a [(&'a str, &'a str)], i32, &'a str);

#[test]
fn package_release_rejects_bad_arguments() {
    let s = Sandbox::new();
    let bin = s.path("rollcall");
    write_exe(&bin, "#!/bin/sh\n");
    let b = bin.to_str().unwrap();
    let out_dir = s.path("dist");
    let o = out_dir.to_str().unwrap();
    let t = tag();
    let t = t.as_str();
    let cases: [BadPackage; 7] = [
        (&[b, t, "linux-amd64"], &[], 64, "usage:"),
        (&[b, t, "darwin-arm64", o], &[], 64, "PLATFORM must be"),
        (&[b, t, "../x", o], &[], 64, "PLATFORM must be"),
        (&[b, "1.0.0", "linux-amd64", o], &[], 64, "TAG must be"),
        (
            &[b, "v1.0.0/../x", "linux-amd64", o],
            &[],
            64,
            "TAG must be",
        ),
        (
            &[b, t, "linux-amd64", o],
            &[("SOURCE_DATE_EPOCH", "0")],
            64,
            "SOURCE_DATE_EPOCH",
        ),
        (
            &["/nonexistent/rollcall", t, "linux-amd64", o],
            &[],
            66,
            "no such binary",
        ),
    ];
    for (args, env, code, needle) in cases {
        let out = s.run("package-release.sh", args, env);
        assert_eq!(out.status.code(), Some(code), "{args:?}: {}", text(&out));
        assert!(stderr(&out).contains(needle), "{args:?}: {}", text(&out));
    }
    assert!(!out_dir.exists(), "something was written");
}

// --- release-sums.sh ---------------------------------------------------------------------------

fn fake_assets(dir: &Path, tag: &str) {
    std::fs::create_dir_all(dir).unwrap();
    for p in PLATFORMS {
        let ext = if p.starts_with("windows") {
            "zip"
        } else {
            "tar.gz"
        };
        std::fs::write(dir.join(format!("rollcall-{tag}-{p}.{ext}")), p).unwrap();
    }
}

#[test]
fn release_sums_lists_assets_sorted_in_sha256sum_format() {
    let s = Sandbox::new();
    let dir = s.path("dist");
    let t = tag();
    let t = t.as_str();
    fake_assets(&dir, t);
    std::fs::write(dir.join("notes.txt"), "not an asset").unwrap();
    let out = s.run("release-sums.sh", &[dir.to_str().unwrap(), t], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
    assert_eq!(stdout(&out), sums);
    let want: String = PLATFORMS
        .iter()
        .map(|p| {
            let ext = if p.starts_with("windows") {
                "zip"
            } else {
                "tar.gz"
            };
            let name = format!("rollcall-{t}-{p}.{ext}");
            format!("{}  {name}\n", sha256_of(&dir.join(&name)))
        })
        .collect();
    assert_eq!(sums, want);
    // The system checker agrees.
    let check = Command::new("sh")
        .arg("-c")
        .arg(
            "cd \"$1\" && if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS; \
             else shasum -a 256 -c SHA256SUMS; fi",
        )
        .arg("sh")
        .arg(&dir)
        .output()
        .unwrap();
    assert!(check.status.success(), "{}", text(&check));
    // Re-running gives the same file.
    let out = s.run("release-sums.sh", &[dir.to_str().unwrap()], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap(),
        sums
    );
}

#[test]
fn release_sums_requires_exactly_the_four_assets_of_the_tag() {
    let s = Sandbox::new();
    let dir = s.path("dist");
    let t = tag();
    let t = t.as_str();
    fake_assets(&dir, t);
    std::fs::remove_file(dir.join(format!("rollcall-{t}-linux-arm64.tar.gz"))).unwrap();
    std::fs::write(dir.join("rollcall-v0.0.0-linux-amd64.tar.gz"), "old").unwrap();
    let out = s.run("release-sums.sh", &[dir.to_str().unwrap(), t], &[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let err = stderr(&out);
    assert!(
        err.contains(&format!("missing: rollcall-{t}-linux-arm64.tar.gz")),
        "{}",
        text(&out)
    );
    assert!(
        err.contains("unexpected: rollcall-v0.0.0-linux-amd64.tar.gz"),
        "{err}"
    );
    assert!(!dir.join("SHA256SUMS").exists());
    let empty = s.path("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let out = s.run("release-sums.sh", &[empty.to_str().unwrap()], &[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stderr(&out).contains("no rollcall-*.tar.gz"),
        "{}",
        text(&out)
    );
    let out = s.run("release-sums.sh", &[], &[]);
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
}

// --- publish-crates.sh -------------------------------------------------------------------------

/// The fake crates.io API: logs each URL, answers `$FAKE/http/<crate>-<version>`'s status code
/// (default 404), as curl's `-w '%{http_code}'` prints it.
const FAKE_CURL_API: &str = r#"#!/bin/sh
url=""
for a in "$@"; do case "$a" in http*) url="$a" ;; esac; done
echo "$url" >> "$FAKE/curl.log"
key=$(echo "$url" | sed 's|.*/crates/||; s|/|-|')
if [ -f "$FAKE/http/$key" ]; then cat "$FAKE/http/$key"; else printf 404; fi
"#;

/// The fake cargo: logs `cargo publish` calls; fails for crates with a `$FAKE/fail-<crate>`.
const FAKE_CARGO_PUBLISH: &str = r#"#!/bin/sh
echo "$*" >> "$FAKE/cargo.log"
[ "$1" = publish ] || { echo "fake cargo: unexpected $*" >&2; exit 2; }
if [ -f "$FAKE/fail-$3" ]; then
  echo "error: failed to publish $3: the remote server responded with an error (status 403 Forbidden)" >&2
  exit 101
fi
echo "   Published $3" >&2
"#;

fn identifiers_version() -> String {
    let text = std::fs::read_to_string(workspace().join("crates/rollcall-identifiers/Cargo.toml"))
        .unwrap();
    let manifest: toml::Value = toml::from_str(&text).unwrap();
    manifest["package"]["version"].as_str().unwrap().to_owned()
}

fn publish_sandbox(http: &[(&str, &str)]) -> Sandbox {
    let s = Sandbox::new();
    s.fake("curl", FAKE_CURL_API);
    s.fake("cargo", FAKE_CARGO_PUBLISH);
    std::fs::create_dir_all(s.state("http")).unwrap();
    for (key, code) in http {
        std::fs::write(s.state("http").join(key), code).unwrap();
    }
    s
}

fn api_url(krate: &str, version: &str) -> String {
    format!("https://crates.io/api/v1/crates/{krate}/{version}")
}

#[test]
fn publish_crates_skips_published_versions_in_dependency_order() {
    let ids = identifiers_version();
    let s = publish_sandbox(&[(&format!("rollcall-identifiers-{ids}"), "200")]);
    let out = s.run("publish-crates.sh", &[], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        s.read_state("curl.log"),
        format!(
            "{}\n{}\n{}\n{}\n",
            api_url("rollcall-identifiers", &ids),
            api_url("rollcall-core", VERSION),
            api_url("rollcall-assay", VERSION),
            api_url("rollcall", VERSION)
        )
    );
    assert_eq!(
        s.read_state("cargo.log"),
        "publish -p rollcall-core --locked --no-verify\n\
         publish -p rollcall-assay --locked --no-verify\n\
         publish -p rollcall --locked --no-verify\n"
    );
    let o = stdout(&out);
    assert!(
        o.contains(&format!(
            "publish-crates: skip rollcall-identifiers {ids}: already on crates.io"
        )),
        "{}",
        text(&out)
    );
    assert!(o.contains(&format!("publish-crates: publishing rollcall {VERSION}")));
    let err = stderr(&out);
    assert!(
        err.contains(&format!(
            "publish-crates: published: rollcall-core@{VERSION} rollcall-assay@{VERSION} rollcall@{VERSION}"
        )),
        "{err}"
    );
    assert!(err.contains("publish-crates: not attempted: none"), "{err}");
}

/// A re-run of a finished release publishes nothing and succeeds.
#[test]
fn publish_crates_rerun_after_success_is_a_no_op() {
    let ids = identifiers_version();
    let s = publish_sandbox(&[
        (&format!("rollcall-identifiers-{ids}"), "200"),
        (&format!("rollcall-core-{VERSION}"), "200"),
        (&format!("rollcall-assay-{VERSION}"), "200"),
        (&format!("rollcall-{VERSION}"), "200"),
    ]);
    let out = s.run("publish-crates.sh", &[], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(s.read_state("cargo.log"), "", "published something");
    assert_eq!(stdout(&out).matches("already on crates.io").count(), 4);
    assert!(stderr(&out).contains("publish-crates: published: none"));
}

#[test]
fn publish_crates_fails_clearly_when_a_publish_fails() {
    let ids = identifiers_version();
    let s = publish_sandbox(&[(&format!("rollcall-identifiers-{ids}"), "200")]);
    std::fs::write(s.state("fail-rollcall-assay"), "").unwrap();
    let out = s.run("publish-crates.sh", &[], &[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    // Nothing after the failure is attempted: rollcall is neither queried nor published.
    assert_eq!(
        s.read_state("cargo.log"),
        "publish -p rollcall-core --locked --no-verify\n\
         publish -p rollcall-assay --locked --no-verify\n"
    );
    assert!(!s.read_state("curl.log").contains("/crates/rollcall/"));
    let err = stderr(&out);
    for line in [
        format!(
            "::error::publish-crates: cargo publish failed for rollcall-assay {VERSION} (exit 101); nothing after it was attempted"
        ),
        "status 403 Forbidden".to_owned(),
        format!("publish-crates: published: rollcall-core@{VERSION}\n"),
        format!("publish-crates: already on crates.io: rollcall-identifiers@{ids}\n"),
        format!("publish-crates: failed: rollcall-assay@{VERSION}\n"),
        format!("publish-crates: not attempted: rollcall@{VERSION}\n"),
    ] {
        assert!(err.contains(&line), "{line}: {}", text(&out));
    }
    // The re-run, once crates.io has rollcall-core, skips it and finishes.
    std::fs::remove_file(s.state("fail-rollcall-assay")).unwrap();
    std::fs::write(
        s.state("http").join(format!("rollcall-core-{VERSION}")),
        "200",
    )
    .unwrap();
    std::fs::remove_file(s.state("cargo.log")).unwrap();
    let out = s.run("publish-crates.sh", &[], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        s.read_state("cargo.log"),
        "publish -p rollcall-assay --locked --no-verify\n\
         publish -p rollcall --locked --no-verify\n"
    );
}

#[test]
fn publish_crates_stops_when_crates_io_is_unavailable() {
    let ids = identifiers_version();
    for code in ["503", "429", "000", "302"] {
        let s = publish_sandbox(&[
            (&format!("rollcall-identifiers-{ids}"), "200"),
            (&format!("rollcall-core-{VERSION}"), code),
        ]);
        let out = s.run("publish-crates.sh", &[], &[]);
        assert_eq!(out.status.code(), Some(2), "{code}: {}", text(&out));
        assert_eq!(
            s.read_state("cargo.log"),
            "",
            "{code}: published without an answer"
        );
        // Asked three times, then stopped before the next crate.
        assert_eq!(
            s.read_state("curl.log")
                .matches("/crates/rollcall-core/")
                .count(),
            3,
            "{code}"
        );
        assert!(!s.read_state("curl.log").contains("/crates/rollcall-assay/"));
        let err = stderr(&out);
        assert!(
            err.contains(&format!(
                "::error::publish-crates: crates.io answered HTTP {code} for rollcall-core {VERSION}"
            )),
            "{code}: {err}"
        );
        assert!(
            err.contains(&format!(
                "publish-crates: not attempted: rollcall-assay@{VERSION} rollcall@{VERSION}"
            )),
            "{err}"
        );
    }
    let s = publish_sandbox(&[]);
    let out = s.run("publish-crates.sh", &["--all"], &[]);
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
}

// --- install-check-cargo.sh --------------------------------------------------------------------

/// The fake cargo for `cargo install`: fails `$FAKE/fails` times (index propagation), then
/// installs a rollcall printing `rollcall $FAKE_VERSION` into `--root`/bin.
const FAKE_CARGO_INSTALL: &str = r#"#!/bin/sh
echo "$*" >> "$FAKE/cargo.log"
n=$(cat "$FAKE/fails" 2>/dev/null || echo 0)
if [ "$n" -gt 0 ]; then
  echo $((n - 1)) > "$FAKE/fails"
  echo "error: could not find \`rollcall\` in registry \`crates-io\` with version \`=$FAKE_VERSION\`" >&2
  exit 101
fi
root=""; prev=""
for a in "$@"; do [ "$prev" = --root ] && root="$a"; prev="$a"; done
mkdir -p "$root/bin"
cat > "$root/bin/rollcall" <<EOF
#!/bin/sh
[ "\$1" = --help ] && { echo "Usage: rollcall"; exit 0; }
echo "rollcall $FAKE_VERSION"
echo "identifiers 1.0.0 (embedded, minimum 1.0.0)"
EOF
chmod +x "$root/bin/rollcall"
"#;

#[test]
fn install_check_cargo_retries_until_the_index_has_the_version() {
    let s = Sandbox::new();
    s.fake("cargo", FAKE_CARGO_INSTALL);
    std::fs::write(s.state("fails"), "2").unwrap();
    let root = s.path("root");
    let out = s.run(
        "install-check-cargo.sh",
        &["v1.2.3-rc.1"],
        &[
            ("FAKE_VERSION", "1.2.3-rc.1"),
            ("ROLLCALL_INSTALL_ROOT", root.to_str().unwrap()),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let install = format!(
        "install rollcall --version =1.2.3-rc.1 --locked --root {}\n",
        root.display()
    );
    assert_eq!(s.read_state("cargo.log"), install.repeat(3));
    assert!(
        stdout(&out).ends_with(
            "install-check-cargo: PASS cargo install rollcall 1.2.3-rc.1: rollcall 1.2.3-rc.1\n"
        ),
        "{}",
        text(&out)
    );
    assert_eq!(stderr(&out).matches("retrying").count(), 2);
}

#[test]
fn install_check_cargo_fails_on_a_version_mismatch_or_no_install() {
    let s = Sandbox::new();
    s.fake("cargo", FAKE_CARGO_INSTALL);
    let out = s.run(
        "install-check-cargo.sh",
        &["v1.2.3"],
        &[
            ("FAKE_VERSION", "1.2.2"),
            ("ROLLCALL_INSTALL_ROOT", s.path("a").to_str().unwrap()),
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stderr(&out).contains("--version printed 'rollcall 1.2.2', not 'rollcall 1.2.3'"),
        "{}",
        text(&out)
    );
    std::fs::write(s.state("fails"), "5").unwrap();
    let out = s.run(
        "install-check-cargo.sh",
        &["v1.2.3"],
        &[
            ("FAKE_VERSION", "1.2.3"),
            ("ROLLCALL_INSTALL_ROOT", s.path("b").to_str().unwrap()),
            ("ROLLCALL_INSTALL_ATTEMPTS", "3"),
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stderr(&out).contains(
            "::error::install-check-cargo: cargo install rollcall --version =1.2.3 failed 3 times"
        ),
        "{}",
        text(&out)
    );
    let out = s.run("install-check-cargo.sh", &["1.2.3"], &[]);
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
}

// --- install-check-pip.sh and install-check-tamper.sh ------------------------------------------

/// The fake python: `-m venv DIR` makes DIR/bin/python (itself); `-m pip install` logs its
/// arguments, fails `$FAKE/pip-fails` times, then installs `$FAKE/rollcall` as the venv's
/// console script; `-c` prints `$FAKE/info` (what the real script's query of the installed
/// package prints: version, tag, platform, asset, embedded SHA-256).
const FAKE_PYTHON: &str = r#"#!/bin/sh
if [ "$1" = -m ] && [ "$2" = venv ]; then
  mkdir -p "$3/bin" && cp "$0" "$3/bin/python" && exit 0
fi
if [ "$1" = -m ] && [ "$2" = pip ]; then
  echo "$*" >> "$FAKE/pip.log"
  n=$(cat "$FAKE/pip-fails" 2>/dev/null || echo 0)
  if [ "$n" -gt 0 ]; then
    echo $((n - 1)) > "$FAKE/pip-fails"
    echo "ERROR: No matching distribution found for rollcall" >&2
    exit 1
  fi
  cp "$FAKE/rollcall" "$(dirname "$0")/rollcall" && chmod +x "$(dirname "$0")/rollcall"
  exit 0
fi
if [ "$1" = -c ]; then cat "$FAKE/info"; exit 0; fi
echo "fake python: unexpected $*" >&2
exit 2
"#;

/// The fake curl for downloads: `-o DEST URL` copies `$FAKE/release/<basename of URL>`.
const FAKE_CURL_DOWNLOAD: &str = r#"#!/bin/sh
dest=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in -o) dest="$2"; shift ;; --retry) shift ;; -*) ;; *) url="$1" ;; esac
  shift
done
echo "$url" >> "$FAKE/curl.log"
src="$FAKE/release/$(basename "$url")"
[ -f "$src" ] || { echo "curl: (22) The requested URL returned error: 404" >&2; exit 22; }
cp "$src" "$dest"
"#;

struct PipCase {
    s: Sandbox,
    asset: String,
    sha: String,
}

/// A sandbox for install-check-pip.sh: a fake release (one linux-amd64 asset and its
/// SHA256SUMS), and a wrapper whose first run caches a binary and prints `rollcall VERSION`.
fn pip_case(version_line: &str) -> PipCase {
    let s = Sandbox::new();
    s.fake("python", FAKE_PYTHON);
    s.fake("curl", FAKE_CURL_DOWNLOAD);
    let t = tag();
    let t = t.as_str();
    let asset = format!("rollcall-{t}-linux-amd64.tar.gz");
    std::fs::create_dir_all(s.state("release")).unwrap();
    std::fs::write(s.state("release").join(&asset), "the real asset").unwrap();
    let sha = sha256_of(&s.state("release").join(&asset));
    std::fs::write(
        s.state("release").join("SHA256SUMS"),
        format!("{sha}  {asset}\n"),
    )
    .unwrap();
    write_exe(
        &s.state("rollcall"),
        &format!(
            "#!/bin/sh\n[ \"$1\" = --help ] && exit 0\n\
             d=\"$ROLLCALL_CACHE_DIR/rollcall/bin/{t}/linux-amd64\"\n\
             mkdir -p \"$d\" && : > \"$d/rollcall\"\n\
             echo '{version_line}'\n"
        ),
    );
    let pep440 = stdout(&s.run("release-version.sh", &["pep440"], &[]));
    std::fs::write(
        s.state("info"),
        format!("{} {t} linux-amd64 {asset} {sha}\n", pep440.trim_end()),
    )
    .unwrap();
    PipCase { s, asset, sha }
}

impl PipCase {
    fn run(&self, args: &[&str]) -> Output {
        let python = self.s.path("bin/python");
        let mut all = vec![tag()];
        all.extend(args.iter().map(|a| a.to_string()));
        let all: Vec<&str> = all.iter().map(String::as_str).collect();
        self.s.run(
            "install-check-pip.sh",
            &all,
            &[
                ("ROLLCALL_PYTHON", python.to_str().unwrap()),
                (
                    "ROLLCALL_RELEASE_BASE_URL",
                    "https://example.invalid/release",
                ),
            ],
        )
    }
}

#[test]
fn install_check_pip_checks_version_and_checksums() {
    let c = pip_case(&format!("rollcall {VERSION}"));
    std::fs::write(c.s.state("pip-fails"), "1").unwrap();
    let out = c.run(&[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let pep440 = stdout(&c.s.run("release-version.sh", &["pep440"], &[]));
    let spec = format!("rollcall=={}", pep440.trim_end());
    let pip = c.s.read_state("pip.log");
    assert_eq!(pip.lines().count(), 2, "{pip}");
    assert!(pip.lines().all(|l| l.ends_with(&spec)), "{pip}");
    assert_eq!(
        c.s.read_state("curl.log"),
        format!(
            "https://example.invalid/release/SHA256SUMS\nhttps://example.invalid/release/{}\n",
            c.asset
        )
    );
    assert!(
        stdout(&out).contains(&format!(
            "install-check-pip: PASS pip install {spec} (linux-amd64): rollcall {VERSION}; sha256 {} (embedded = SHA256SUMS = downloaded)",
            c.sha
        )),
        "{}",
        text(&out)
    );
    // --test-pypi installs from TestPyPI; --wheel installs the file.
    let c = pip_case(&format!("rollcall {VERSION}"));
    assert!(c.run(&["--test-pypi"]).status.success());
    assert!(
        c.s.read_state("pip.log")
            .contains("--index-url https://test.pypi.org/simple/ rollcall==")
    );
    let wheel = c.s.path("rollcall-x-py3-none-any.whl");
    std::fs::write(&wheel, "").unwrap();
    assert!(
        c.run(&["--wheel", wheel.to_str().unwrap()])
            .status
            .success()
    );
    assert!(c.s.read_state("pip.log").contains(wheel.to_str().unwrap()));
    for bad in [
        &["--wheel"][..],
        &["--wheel", "/nonexistent.whl"],
        &["--pypi"],
    ] {
        let out = c.run(bad);
        assert_eq!(out.status.code(), Some(64), "{bad:?}: {}", text(&out));
    }
}

#[test]
fn install_check_pip_fails_when_the_checksums_disagree() {
    // The embedded digest is not SHA256SUMS'.
    let c = pip_case(&format!("rollcall {VERSION}"));
    let info = c.s.read_state("info").replace(&c.sha, &"0".repeat(64));
    std::fs::write(c.s.state("info"), info).unwrap();
    let out = c.run(&[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stderr(&out).contains(&format!(
            "the package embeds sha256 {} for {}, but SHA256SUMS of {} lists {}",
            "0".repeat(64),
            c.asset,
            tag(),
            c.sha
        )),
        "{}",
        text(&out)
    );
    // The published asset is not what SHA256SUMS says.
    let c = pip_case(&format!("rollcall {VERSION}"));
    std::fs::write(c.s.state("release").join(&c.asset), "swapped").unwrap();
    let out = c.run(&[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stderr(&out).contains(&format!("{} has sha256 ", c.asset)),
        "{}",
        text(&out)
    );
    // The wrapper ran some other version.
    let c = pip_case("rollcall 0.0.0");
    let out = c.run(&[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stderr(&out).contains(&format!(
            "printed 'rollcall 0.0.0', not 'rollcall {VERSION}'"
        )),
        "{}",
        text(&out)
    );
}

fn tamper_case(wrapper: &str) -> (Sandbox, Output) {
    let s = Sandbox::new();
    s.fake("python", FAKE_PYTHON);
    write_exe(&s.state("rollcall"), wrapper);
    let wheel = s.path("rollcall-x-py3-none-any.whl");
    std::fs::write(&wheel, "").unwrap();
    let python = s.path("bin/python");
    let out = s.run(
        "install-check-tamper.sh",
        &[tag().as_str(), "--wheel", wheel.to_str().unwrap()],
        &[("ROLLCALL_PYTHON", python.to_str().unwrap())],
    );
    (s, out)
}

#[test]
fn install_check_tamper_requires_exit_65_a_clear_message_and_an_empty_cache() {
    let t = tag();
    let t = t.as_str();
    let refused = format!(
        "#!/bin/sh\necho 'rollcall: downloading rollcall {t} (linux-amd64) from https://x/y' >&2\n\
         echo 'rollcall: checksum mismatch for rollcall-{t}-linux-amd64.tar.gz: expected {}, got {}; the download was discarded' >&2\n\
         mkdir -p \"$ROLLCALL_CACHE_DIR/rollcall/bin\"\nexit 65\n",
        "1".repeat(64),
        "0".repeat(64)
    );
    let (_s, out) = tamper_case(&refused);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stdout(&out).contains(
            "install-check-tamper: PASS the tampered wheel refused the download (exit 65)"
        ),
        "{}",
        text(&out)
    );
    // Installed anyway: the check fails.
    let (_s, out) = tamper_case(&format!("#!/bin/sh\necho 'rollcall {VERSION}'\n"));
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stderr(&out).contains("exited 0, not 65: the tampered checksum did not abort the install"),
        "{}",
        text(&out)
    );
    // Refused, but without the message.
    let (_s, out) = tamper_case("#!/bin/sh\necho 'rollcall: something else' >&2\nexit 65\n");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stderr(&out).contains("stderr does not say"),
        "{}",
        text(&out)
    );
    // Refused, but the download was kept.
    let kept = refused.replace(
        "exit 65",
        "touch \"$ROLLCALL_CACHE_DIR/rollcall/bin/rollcall-x.tar.gz\"\nexit 65",
    );
    let (_s, out) = tamper_case(&kept);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stderr(&out).contains("files were left in the cache"),
        "{}",
        text(&out)
    );
    let s = Sandbox::new();
    let out = s.run("install-check-tamper.sh", &[t], &[]);
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
}

// --- the workflows -----------------------------------------------------------------------------

fn workflow(name: &str) -> Value {
    let text = std::fs::read_to_string(workspace().join(".github/workflows").join(name)).unwrap();
    yaml_serde::from_str(&text).unwrap()
}

fn uses_lines(name: &str) -> Vec<String> {
    std::fs::read_to_string(workspace().join(".github/workflows").join(name))
        .unwrap()
        .lines()
        .filter_map(|l| {
            let l = l.trim_start().trim_start_matches("- ");
            l.strip_prefix("uses: ").map(str::to_owned)
        })
        .collect()
}

fn step_runs(job: &Value) -> String {
    job["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["run"].as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// `name: uses` for every action of a workflow, or of one job of it.
fn uses_of(name: &str, job: Option<&str>) -> Vec<String> {
    match job {
        None => uses_lines(name),
        Some(job) => workflow(name)["jobs"][job]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s["uses"].as_str())
            .map(str::to_owned)
            .collect(),
    }
}

/// Every action in the release workflows, and in CI's publish-dry-run job, is pinned to a full
/// commit SHA, with its version in a comment (in the raw file); the only other `uses:` is the
/// local install-check workflow.
#[test]
fn release_workflows_pin_every_action_to_a_commit_sha() {
    let ci = std::fs::read_to_string(workspace().join(".github/workflows/ci.yml")).unwrap();
    for u in uses_of("ci.yml", Some("publish-dry-run")) {
        assert!(
            ci.contains(&format!("uses: {u} # v")) || ci.contains(&format!("uses: {u} # master")),
            "ci.yml publish-dry-run: {u} has no version comment"
        );
    }
    for (name, job) in [
        ("release.yml", None),
        ("install-check.yml", None),
        ("ci.yml", Some("publish-dry-run")),
    ] {
        let uses = uses_of(name, job);
        assert!(!uses.is_empty(), "{name}");
        for u in uses {
            if u == "./.github/workflows/install-check.yml" {
                continue;
            }
            let (action, rest) = u.split_once('@').unwrap_or_else(|| panic!("{name}: {u}"));
            let (sha, comment) = rest.split_once(" # ").unwrap_or((rest, ""));
            assert!(
                sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
                "{name}: {action} is not pinned to a commit SHA: {u}"
            );
            // (A job's parsed `uses` has no comment; checked on the raw file above.)
            assert!(
                job.is_some() || !comment.is_empty(),
                "{name}: {action} has no version comment"
            );
        }
    }
}

/// TP: CI install matrix (macOS, Ubuntu) for both install paths, and the Windows `--help` job;
/// release.yml runs it after both publishes.
#[test]
fn install_check_workflow_covers_both_install_paths_and_windows() {
    let w = workflow("install-check.yml");
    let jobs = &w["jobs"];
    let both = serde_json::json!(["ubuntu-24.04", "macos-15"]);
    assert_eq!(jobs["cargo-install"]["strategy"]["matrix"]["os"], both);
    assert!(step_runs(&jobs["cargo-install"]).contains("scripts/install-check-cargo.sh \"$TAG\""));
    assert_eq!(jobs["pip-install"]["strategy"]["matrix"]["os"], both);
    assert_eq!(
        jobs["pip-install"]["strategy"]["matrix"]["python"],
        serde_json::json!(["3.9", "3.12"])
    );
    assert!(step_runs(&jobs["pip-install"]).contains("scripts/install-check-pip.sh \"$TAG\""));
    let tamper = step_runs(&jobs["pip-tamper"]);
    assert!(tamper.contains("embed-release.py --sums SHA256SUMS --tag \"$TAG\" --tamper"));
    assert!(tamper.contains("scripts/install-check-tamper.sh \"$TAG\" --wheel"));
    assert_eq!(jobs["windows-help"]["runs-on"], "windows-2025");
    assert!(
        step_runs(&jobs["windows-help"])
            .contains("./scripts/install-check-windows.ps1 -Tag $env:TAG")
    );
    let ps1 =
        std::fs::read_to_string(workspace().join("scripts/install-check-windows.ps1")).unwrap();
    assert!(ps1.contains("& $exe --help") && ps1.contains("Get-FileHash"));
    for trigger in ["workflow_call", "workflow_dispatch"] {
        assert_eq!(
            w["on"][trigger]["inputs"]["tag"]["required"], true,
            "{trigger}"
        );
        assert_eq!(w["on"][trigger]["inputs"]["test_pypi"]["type"], "boolean");
    }

    let r = workflow("release.yml");
    let call = &r["jobs"]["install-check"];
    assert_eq!(call["uses"], "./.github/workflows/install-check.yml");
    assert_eq!(
        call["needs"],
        serde_json::json!(["publish-crates", "publish-pypi"])
    );
}

/// The release builds the four assets the action and the wrapper download, publishes only
/// after the GitHub Release exists, and every step is safe to re-run.
#[test]
fn release_workflow_builds_four_assets_and_reruns_safely() {
    let r = workflow("release.yml");
    assert_eq!(r["on"]["push"]["tags"], serde_json::json!(["v[0-9]*"]));
    assert_eq!(
        r["on"]["workflow_dispatch"]["inputs"]["tag"]["required"],
        true
    );
    assert_eq!(r["concurrency"]["cancel-in-progress"], false);
    assert_eq!(r["permissions"], serde_json::json!({"contents": "read"}));
    let jobs = &r["jobs"];
    let mut platforms: Vec<&str> = jobs["build"]["strategy"]["matrix"]["include"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["platform"].as_str().unwrap())
        .collect();
    platforms.sort_unstable();
    assert_eq!(platforms, PLATFORMS);
    let preflight = step_runs(&jobs["preflight"]);
    assert!(preflight.contains("scripts/release-version.sh check \"$TAG\""));
    assert!(preflight.contains("cargo publish --workspace --dry-run --locked"));
    let build = step_runs(&jobs["build"]);
    assert!(build.contains("cargo build --profile dist --locked -p rollcall"));
    assert!(build.contains("--remap-path-prefix"));
    assert!(build.contains("SOURCE_DATE_EPOCH"));
    assert!(build.contains("scripts/package-release.sh"));
    assert!(build.contains("--version"));
    let assemble = step_runs(&jobs["assemble"]);
    assert!(assemble.contains("scripts/release-sums.sh dist \"$TAG\""));
    assert!(assemble.contains("scripts/install-check-tamper.sh"));
    // A re-run uses the published assets; the release job compares before it attests, and
    // uploads only to a release without assets (release_upload_* test the script).
    assert!(assemble.contains("scripts/release-upload.sh adopt \"$TAG\" dist"));
    let adopt = assemble.find("release-upload.sh adopt").unwrap();
    assert!(adopt < assemble.find("embed-release.py").unwrap());
    let release = step_runs(&jobs["github-release"]);
    assert!(release.contains("scripts/release-upload.sh check \"$TAG\" dist"));
    assert!(release.contains("scripts/release-upload.sh publish \"$TAG\" dist"));
    assert!(!release.contains("gh release upload"));
    let attest = jobs["github-release"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| {
            s["uses"]
                .as_str()
                .is_some_and(|u| u.starts_with("actions/attest-build-provenance@"))
        })
        .unwrap();
    assert_eq!(attest["if"], "steps.upload.outputs.upload == 'true'");
    // TestPyPI first for a pre-release.
    let pypi_needs = jobs["publish-pypi"]["needs"].as_array().unwrap();
    assert!(pypi_needs.iter().any(|n| n == "publish-testpypi"));
    assert!(
        jobs["publish-pypi"]["if"]
            .as_str()
            .unwrap()
            .contains("needs.publish-testpypi.result == 'skipped'")
    );
    // Windows: static C runtime, checked; Windows paths remapped.
    assert!(build.contains("+crt-static"));
    assert!(build.contains("cygpath -w"));
    assert!(build.contains("llvm-readobj") && build.contains("vcruntime"));
    assert!(step_runs(&jobs["publish-crates"]).contains("scripts/publish-crates.sh"));
    for job in ["publish-crates", "publish-pypi", "publish-testpypi"] {
        let needs = jobs[job]["needs"].as_array().unwrap();
        assert!(
            needs.iter().any(|n| n == "github-release"),
            "{job} must wait for the GitHub Release"
        );
    }
    for job in ["publish-pypi", "publish-testpypi"] {
        let steps = jobs[job]["steps"].as_array().unwrap();
        let publish = steps
            .iter()
            .find(|s| {
                s["uses"]
                    .as_str()
                    .is_some_and(|u| u.starts_with("pypa/gh-action-pypi-publish@"))
            })
            .unwrap();
        assert_eq!(publish["with"]["skip-existing"], true, "{job}");
    }
    assert_eq!(
        jobs["publish-testpypi"]["if"],
        "needs.preflight.outputs.prerelease == 'true'"
    );
}

// --- release-upload.sh -------------------------------------------------------------------------

/// The fake gh: `release view` answers from `$FAKE/release/` (missing: "release not found";
/// `$FAKE/view-fails`: an HTTP error), listing its files as the asset names; `release download
/// -p PATTERN -D DIR` copies the matching files; `release create` makes the directory;
/// `release upload` copies the files in. Every call is logged to `$FAKE/gh.log`.
const FAKE_GH_RELEASE: &str = r#"#!/bin/sh
echo "$*" >> "$FAKE/gh.log"
rel="$FAKE/release"
[ "$1" = release ] || { echo "fake gh: unexpected $*" >&2; exit 2; }
case "$2" in
  view)
    [ -f "$FAKE/view-fails" ] && { echo "HTTP 502: Bad Gateway" >&2; exit 1; }
    [ -d "$rel" ] || { echo "release not found" >&2; exit 1; }
    ls "$rel" ;;
  download)
    shift 3; pat=""; dir=""
    while [ $# -gt 0 ]; do case "$1" in -p) pat="$2"; shift ;; -D) dir="$2"; shift ;; esac; shift; done
    mkdir -p "$dir"; found=0
    for f in "$rel"/$pat; do [ -f "$f" ] && cp "$f" "$dir"/ && found=1; done
    [ "$found" = 1 ] || { echo "no assets match the file pattern" >&2; exit 1; } ;;
  create) mkdir -p "$rel" ;;
  upload)
    shift 3
    for f in "$@"; do [ "$f" = --clobber ] || cp "$f" "$rel"/; done ;;
  *) echo "fake gh: unexpected $*" >&2; exit 2 ;;
esac
"#;

/// A sandbox with the fake gh and this run's four assets (contents `<prefix><platform>`) plus
/// their SHA256SUMS in `dist/`.
fn upload_sandbox(prefix: &str) -> Sandbox {
    let s = Sandbox::new();
    s.fake("gh", FAKE_GH_RELEASE);
    write_release_dir(&s, &s.path("dist"), prefix);
    s
}

fn write_release_dir(s: &Sandbox, dir: &Path, prefix: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let t = tag();
    for p in PLATFORMS {
        let ext = if p.starts_with("windows") {
            "zip"
        } else {
            "tar.gz"
        };
        std::fs::write(
            dir.join(format!("rollcall-{t}-{p}.{ext}")),
            format!("{prefix}{p}"),
        )
        .unwrap();
    }
    let out = s.run("release-sums.sh", &[dir.to_str().unwrap(), &t], &[]);
    assert!(out.status.success(), "{}", text(&out));
}

fn upload(s: &Sandbox, mode: &str, env: &[(&str, &str)]) -> Output {
    let dist = s.path("dist");
    s.run(
        "release-upload.sh",
        &[mode, tag().as_str(), dist.to_str().unwrap()],
        env,
    )
}

fn release_files(s: &Sandbox) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(s.state("release"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn release_upload_creates_the_release_and_uploads_when_there_is_none() {
    let s = upload_sandbox("new ");
    let out = upload(&s, "check", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stdout(&out), "upload=true\n");
    std::fs::remove_file(s.state("gh.log")).unwrap();
    let out = upload(&s, "publish", &[("PRERELEASE", "true")]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let t = tag();
    let log = s.read_state("gh.log");
    let calls: Vec<&str> = log.lines().collect();
    assert_eq!(
        calls[1],
        format!(
            "release create {t} --verify-tag --title rollcall {t} --prerelease --generate-notes"
        )
    );
    // The assets first, SHA256SUMS last: a release with SHA256SUMS has all four.
    assert!(
        calls[2].starts_with(&format!("release upload {t} ")),
        "{log}"
    );
    assert!(
        calls[2].ends_with("--clobber") && !calls[2].contains("SHA256SUMS"),
        "{log}"
    );
    assert!(calls[3].ends_with("/SHA256SUMS --clobber"), "{log}");
    assert_eq!(calls.len(), 4, "{log}");
    assert_eq!(release_files(&s).len(), 5);
    assert_eq!(
        std::fs::read(s.state("release/SHA256SUMS")).unwrap(),
        std::fs::read(s.path("dist/SHA256SUMS")).unwrap()
    );
    // adopt on a release without assets keeps this run's.
    let s = upload_sandbox("new ");
    let out = upload(&s, "adopt", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(stdout(&out).contains("has no assets yet; using this run's"));
}

#[test]
fn release_upload_skips_identical_assets_and_adds_no_attestation() {
    let s = upload_sandbox("same ");
    write_release_dir(&s, &s.state("release"), "same ");
    let before = release_files(&s);
    let out = upload(&s, "check", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stdout(&out), "upload=false\n");
    let out = upload(&s, "publish", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        stdout(&out).contains("already has these assets (identical SHA256SUMS); nothing uploaded"),
        "{}",
        text(&out)
    );
    let log = s.read_state("gh.log");
    assert!(
        !log.contains("release upload") && !log.contains("release create"),
        "{log}"
    );
    assert_eq!(release_files(&s), before);
    let out = upload(&s, "adopt", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(stdout(&out).contains("identical to the published ones"));
}

#[test]
fn release_upload_refuses_to_replace_different_assets() {
    let s = upload_sandbox("rebuilt ");
    write_release_dir(&s, &s.state("release"), "published ");
    let published = std::fs::read(s.state("release/SHA256SUMS")).unwrap();
    for mode in ["check", "publish"] {
        let out = upload(&s, mode, &[]);
        assert_eq!(out.status.code(), Some(1), "{mode}: {}", text(&out));
        assert!(
            stderr(&out).contains(&format!(
                "::error::release-upload: release {} already has different assets (SHA256SUMS differ); a changed binary needs a new version. To finish a partial run use `gh run rerun --failed`.",
                tag()
            )),
            "{mode}: {}",
            text(&out)
        );
        assert!(
            stdout(&out).is_empty(),
            "{mode}: no upload= output on failure"
        );
    }
    assert!(!s.read_state("gh.log").contains("release upload"));
    assert_eq!(
        std::fs::read(s.state("release/SHA256SUMS")).unwrap(),
        published
    );
}

/// assemble: a re-run whose rebuild differs uses the published assets, so the wheel embeds
/// what the release serves; published assets that do not match their SHA256SUMS fail.
#[test]
fn release_upload_adopt_uses_the_published_assets() {
    let s = upload_sandbox("rebuilt ");
    write_release_dir(&s, &s.state("release"), "published ");
    let out = upload(&s, "adopt", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(stderr(&out).contains("::warning::release-upload: the rebuilt assets differ"));
    let t = tag();
    for p in PLATFORMS {
        let ext = if p.starts_with("windows") {
            "zip"
        } else {
            "tar.gz"
        };
        let name = format!("rollcall-{t}-{p}.{ext}");
        assert_eq!(
            std::fs::read_to_string(s.path("dist").join(&name)).unwrap(),
            format!("published {p}")
        );
    }
    assert_eq!(
        std::fs::read(s.path("dist/SHA256SUMS")).unwrap(),
        std::fs::read(s.state("release/SHA256SUMS")).unwrap()
    );
    // Then the release job finds them identical.
    assert_eq!(stdout(&upload(&s, "check", &[])), "upload=false\n");

    let s = upload_sandbox("rebuilt ");
    write_release_dir(&s, &s.state("release"), "published ");
    std::fs::write(
        s.state("release")
            .join(format!("rollcall-{t}-linux-amd64.tar.gz")),
        "corrupted",
    )
    .unwrap();
    let out = upload(&s, "adopt", &[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stderr(&out).contains("do not match its SHA256SUMS"),
        "{}",
        text(&out)
    );
}

#[test]
fn release_upload_existing_release_without_assets_is_uploaded_to() {
    let s = upload_sandbox("new ");
    std::fs::create_dir_all(s.state("release")).unwrap();
    std::fs::write(
        s.state("release")
            .join(format!("rollcall-{}-linux-amd64.tar.gz", tag())),
        "partial",
    )
    .unwrap();
    assert_eq!(stdout(&upload(&s, "check", &[])), "upload=true\n");
    let out = upload(&s, "publish", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let log = s.read_state("gh.log");
    assert!(!log.contains("release create"), "{log}");
    assert_eq!(release_files(&s).len(), 5);
    // gh failing for any other reason than a missing release stops everything.
    std::fs::write(s.state("view-fails"), "").unwrap();
    let out = upload(&s, "check", &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(stderr(&out).contains("HTTP 502"), "{}", text(&out));
    for args in [
        &["upload", "v0.0.1", "x"][..],
        &["check", "1.0", "x"],
        &["check"],
    ] {
        let out = s.run("release-upload.sh", args, &[]);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", text(&out));
    }
}
