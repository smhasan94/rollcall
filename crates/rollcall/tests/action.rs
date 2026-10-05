//! Hermetic tests for `rollcall-action` (`action/`): its scripts run as the composite action
//! runs them, against the real build fixtures under `fixtures/` (read only), with:
//!
//! - `ROLLCALL_BIN` set to the `rollcall` binary under test;
//! - a fake `grype` on `PATH` printing a real capture from
//!   `crates/rollcall-core/tests/data/findings/` (or no findings);
//! - a fake `gh` that records every call and serves canned GitHub API responses (workflow runs,
//!   artifacts, pull-request comments) from a temporary directory;
//! - `GITHUB_OUTPUT`, `GITHUB_EVENT_PATH`, `GITHUB_REPOSITORY`, `GITHUB_WORKFLOW_REF` and the
//!   rest pointing at temporary files.
//!
//! The real workflow (`.github/workflows/rollcall-example.yml`) exercises the action on GitHub;
//! these tests pin its behaviour offline. Unix only (the fakes and the action are shell
//! scripts); needs bash and jq on the system `PATH`.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use tempfile::TempDir;

const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";
const REPO: &str = "smhasan94/rollcall";
const WORKFLOW_REF: &str =
    "smhasan94/rollcall/.github/workflows/rollcall-example.yml@refs/pull/7/merge";

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn script(name: &str) -> PathBuf {
    workspace().join("action/scripts").join(name)
}

fn capture(file: &str) -> PathBuf {
    workspace()
        .join("crates/rollcall-core/tests/data/findings")
        .join(file)
}

fn text(out: &Output) -> String {
    format!(
        "exit {:?}\n--- stdout\n{}\n--- stderr\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn write_exe(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// The fake `gh`: logs `METHOD PATH` (or `run download ID`) to `$FAKE_GH/requests.log`, with
/// `-f`/`-F` fields appended as the query string gh builds for `-X GET` (URL-encoded with
/// jq's `@uri`, as gh encodes them), copies each `--input` body to `$FAKE_GH/input.N.json`,
/// and answers from `$FAKE_GH`: `user.json` for `gh api user` (missing: HTTP 403, as for the
/// workflow token), `runs.json` for the workflow-runs listing (missing: HTTP 404),
/// `artifacts/RUN/` for `gh run download RUN` (missing: no artifact), `comments.json` for the
/// comment listing (default `[]`), and `{"id": 9001}` for a POST unless `post-fails` exists
/// (HTTP 403).
const FAKE_GH: &str = r#"#!/bin/sh
d="$FAKE_GH"
n=$(cat "$d/requests.log" 2>/dev/null | wc -l | tr -d ' ')
if [ "$1" = run ] && [ "$2" = download ]; then
  id="$3"; shift 3; dir=""
  while [ $# -gt 0 ]; do case "$1" in -D) dir="$2"; shift ;; esac; shift; done
  echo "run download $id" >> "$d/requests.log"
  [ -d "$d/artifacts/$id" ] || { echo "no valid artifacts found to download" >&2; exit 1; }
  mkdir -p "$dir" && cp "$d/artifacts/$id"/* "$dir"/
  exit 0
fi
[ "$1" = api ] || { echo "fake gh: unexpected $*" >&2; exit 2; }
shift
method=GET; input=""; path=""; query=""
while [ $# -gt 0 ]; do
  case "$1" in
    -X) method="$2"; shift ;;
    --input) input="$2"; shift ;;
    -f|-F)
      key="${2%%=*}"; value="${2#*=}"
      enc=$(jq -rn --arg v "$value" '$v|@uri')
      query="${query:+$query&}$key=$enc"; shift ;;
    --paginate) ;;
    *) path="$1" ;;
  esac
  shift
done
[ -n "$query" ] && path="$path?$query"
echo "$method $path" >> "$d/requests.log"
[ -n "$input" ] && cp "$input" "$d/input.$n.json"
case "$method $path" in
  "GET user")
    [ -f "$d/user.json" ] || { echo "gh: Resource not accessible by integration (HTTP 403)" >&2; exit 1; }
    cat "$d/user.json" ;;
  "GET "*/actions/workflows/*/runs*)
    [ -f "$d/runs.json" ] || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
    cat "$d/runs.json" ;;
  "GET "*/issues/*/comments*)
    if [ -f "$d/comments.json" ]; then cat "$d/comments.json"; else echo '[]'; fi ;;
  "POST "*)
    [ -f "$d/post-fails" ] && { echo "gh: Resource not accessible by integration (HTTP 403)" >&2; exit 1; }
    echo '{"id": 9001}' ;;
  "PATCH "*/issues/comments/*)
    echo "{\"id\": ${path##*/}}" ;;
  *) echo "fake gh: unexpected $method $path" >&2; exit 2 ;;
esac
"#;

/// A temporary runner: `bin/` (fake grype and gh), `gh/` (the fake gh's state), `out/` (the
/// action's out-dir), and files for the GitHub variables.
struct Runner {
    dir: TempDir,
}

impl Runner {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for sub in ["bin", "gh", "gh/artifacts"] {
            std::fs::create_dir_all(dir.path().join(sub)).unwrap();
        }
        let r = Self { dir };
        write_exe(&r.path("bin/gh"), FAKE_GH);
        r.grype(None);
        r.event(json!({}));
        r
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn out(&self) -> PathBuf {
        self.path("out")
    }

    /// Installs a fake grype printing `capture` (JSON), or no findings.
    fn grype(&self, capture: Option<Value>) {
        let file = self.path("grype-output.json");
        let value = capture.unwrap_or_else(|| json!({"matches": []}));
        std::fs::write(&file, serde_json::to_vec(&value).unwrap()).unwrap();
        write_exe(
            &self.path("bin/grype"),
            &format!(
                "#!/bin/sh\nif [ \"$1\" = version ]; then echo 'Version: 0.119.0'; exit 0; fi\ncat '{}'\n",
                file.display()
            ),
        );
    }

    /// Writes the event payload `GITHUB_EVENT_PATH` points at.
    fn event(&self, value: Value) {
        std::fs::write(self.path("event.json"), serde_json::to_vec(&value).unwrap()).unwrap();
    }

    /// Runs an action script with these RC_* inputs, as a `pull_request` (or `push`) job.
    fn run(&self, name: &str, event: &str, inputs: &[(&str, &str)]) -> Output {
        // Each step appends to GITHUB_OUTPUT; give each its own, as the runner does.
        let outputs = self.path(&format!("{name}.github-output"));
        let _ = std::fs::remove_file(&outputs);
        let mut cmd = Command::new(script(name));
        cmd.env_clear()
            .current_dir(workspace())
            .env(
                "PATH",
                format!(
                    "{}:/usr/local/bin:/usr/bin:/bin",
                    self.path("bin").display()
                ),
            )
            .env("HOME", self.dir.path())
            .env("ROLLCALL_BIN", env!("CARGO_BIN_EXE_rollcall"))
            .env("FAKE_GH", self.path("gh"))
            .env("RC_RETRY_DELAY", "0")
            .env("RC_OUT_DIR", self.out())
            .env("RC_GITHUB_TOKEN", "fake-token")
            .env("GITHUB_OUTPUT", &outputs)
            .env("GITHUB_EVENT_NAME", event)
            .env("GITHUB_EVENT_PATH", self.path("event.json"))
            .env("GITHUB_REPOSITORY", REPO)
            .env("GITHUB_WORKFLOW_REF", WORKFLOW_REF)
            .env("GITHUB_BASE_REF", "main");
        for (k, v) in inputs {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }

    /// The step outputs a script wrote (last value of each key).
    fn outputs(&self, name: &str) -> BTreeMap<String, String> {
        let text = std::fs::read_to_string(self.path(&format!("{name}.github-output")))
            .unwrap_or_default();
        text.lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    /// The fake gh's request log.
    fn requests(&self) -> Vec<String> {
        std::fs::read_to_string(self.path("gh/requests.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Runs pipeline.sh then diff.sh (and base.sh first on a pull request), asserting both
    /// succeed; returns diff.sh's outputs.
    fn pipeline(&self, build_dir: &str, event: &str, fail_on: &str) -> BTreeMap<String, String> {
        self.pipeline_with(build_dir, event, fail_on, &[])
    }

    /// [`Runner::pipeline`] with extra pipeline.sh inputs.
    fn pipeline_with(
        &self,
        build_dir: &str,
        event: &str,
        fail_on: &str,
        extra: &[(&str, &str)],
    ) -> BTreeMap<String, String> {
        let build = workspace().join(build_dir);
        let build = build.to_str().unwrap();
        let mut inputs = vec![("RC_BUILD_DIR", build), ("RC_TIMESTAMP", GOLDEN_TIMESTAMP)];
        inputs.extend_from_slice(extra);
        let out = self.run("pipeline.sh", event, &inputs);
        assert_eq!(out.status.code(), Some(0), "pipeline: {}", text(&out));
        let mut base = "absent".to_owned();
        if event == "pull_request" {
            let out = self.run("base.sh", event, &[("RC_ARTIFACT_NAME", "rollcall-zephyr")]);
            assert_eq!(out.status.code(), Some(0), "base: {}", text(&out));
            base = self.outputs("base.sh")["base"].clone();
        }
        let out = self.run(
            "diff.sh",
            event,
            &[("RC_FAIL_ON", fail_on), ("RC_BASE", base.as_str())],
        );
        assert_eq!(out.status.code(), Some(0), "diff: {}", text(&out));
        self.outputs("diff.sh")
    }

    /// Publishes the current out-dir's artifact files as run `id`'s artifact, and lists that
    /// run as the base branch's latest.
    fn publish_base(&self, id: u64) {
        let dir = self.path(&format!("gh/artifacts/{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        for file in artifact_files() {
            let from = self.out().join(&file);
            if from.is_file() {
                std::fs::copy(&from, dir.join(&file)).unwrap();
            }
        }
        std::fs::write(
            self.path("gh/runs.json"),
            serde_json::to_vec(&json!({"total_count": 1, "workflow_runs": [{"id": id}]})).unwrap(),
        )
        .unwrap();
    }

    fn gate(&self, gate: &str, fail_on: &str) -> Output {
        self.gate_on("pull_request", gate, fail_on, &[])
    }

    fn gate_on(&self, event: &str, gate: &str, fail_on: &str, extra: &[(&str, &str)]) -> Output {
        let mut inputs = vec![("RC_GATE", gate), ("RC_FAIL_ON", fail_on)];
        inputs.extend_from_slice(extra);
        self.run("gate.sh", event, &inputs)
    }
}

fn action_yml() -> Value {
    let text = std::fs::read_to_string(workspace().join("action/action.yml")).unwrap();
    yaml_serde::from_str(&text).unwrap()
}

/// The files the action's upload step lists, relative to the out-dir.
fn artifact_files() -> Vec<String> {
    let action = action_yml();
    let steps = action["runs"]["steps"].as_array().unwrap();
    let upload = steps
        .iter()
        .find(|s| {
            s["uses"]
                .as_str()
                .is_some_and(|u| u.starts_with("actions/upload-artifact@"))
        })
        .expect("an upload-artifact step");
    upload["with"]["path"]
        .as_str()
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            l.trim()
                .strip_prefix("${{ inputs.out-dir }}/")
                .unwrap_or_else(|| panic!("upload path outside the out-dir: {l}"))
                .to_owned()
        })
        .collect()
}

fn pr_event(head_repo: &str) -> Value {
    json!({"pull_request": {"number": 7, "head": {"repo": {"full_name": head_repo}}}})
}

/// AC1: on the example's main build (fixtures/zephyr/tls, no findings), the pipeline is
/// green, writes every file the upload step lists, and the gate passes; on a push the
/// comment step does nothing.
#[test]
fn pipeline_on_tls_fixture_is_clean_and_uploads_every_artifact_file() {
    let r = Runner::new();
    let outputs = r.pipeline("fixtures/zephyr/tls", "push", "high");
    assert_eq!(outputs["gate"], "clean");
    assert_eq!(outputs["new-findings"], "0");
    let pipeline = r.outputs("pipeline.sh");
    assert_eq!(pipeline["ecosystem"], "zephyr");
    for key in ["sbom", "vex", "scan", "report", "report-json"] {
        assert!(
            Path::new(&pipeline[key]).is_file(),
            "{key}: {}",
            pipeline[key]
        );
    }
    assert!(pipeline["score"].parse::<u32>().unwrap() <= 100);
    let files = artifact_files();
    assert_eq!(files.len(), 8, "{files:?}");
    for file in &files {
        let path = r.out().join(file);
        let meta = std::fs::metadata(&path).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert!(meta.len() > 0, "{file} is empty");
    }
    // The SBOM is the sysbuild product, valid CycloneDX, with the pinned timestamp.
    let sbom: Value =
        serde_json::from_slice(&std::fs::read(r.out().join("sbom.cdx.json")).unwrap()).unwrap();
    assert_eq!(sbom["metadata"]["timestamp"], GOLDEN_TIMESTAMP);
    let comment = std::fs::read_to_string(r.out().join("comment.md")).unwrap();
    assert!(
        comment.contains("✅ **No new open findings at or above high.**"),
        "{comment}"
    );
    let out = r.gate("clean", "high");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    // A push has no pull request: no comment, no API call.
    let out = r.run(
        "comment.sh",
        "push",
        &[("RC_ARTIFACT_NAME", "rollcall-zephyr")],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(r.outputs("comment.sh")["comment-action"], "skipped");
    assert!(r.requests().is_empty(), "{:?}", r.requests());
    // A second pipeline run on the same inputs is byte-identical (deterministic artifact).
    let first: Vec<Vec<u8>> = files
        .iter()
        .map(|f| std::fs::read(r.out().join(f)).unwrap())
        .collect();
    r.pipeline("fixtures/zephyr/tls", "push", "high");
    for (file, before) in files.iter().zip(first) {
        assert_eq!(std::fs::read(r.out().join(file)).unwrap(), before, "{file}");
    }
}

/// AC2 / TP2: main's artifact (fixtures/zephyr/tls) is the base; the pull request swaps in
/// the old-mbedTLS build (real grype capture). The gate is `findings`, the comment names the
/// new CVEs, the posted comment carries them, and gate.sh fails the job naming them.
#[test]
fn pipeline_on_old_mbedtls_fixture_sets_gate_findings_and_names_cves_in_comment() {
    let r = Runner::new();
    // main: the push run that uploads the base artifact.
    r.pipeline("fixtures/zephyr/tls", "push", "high");
    r.publish_base(1001);
    // The pull request.
    r.grype(Some(
        serde_json::from_slice(&std::fs::read(capture("zephyr-old-mbedtls.grype.json")).unwrap())
            .unwrap(),
    ));
    r.event(pr_event(REPO));
    let outputs = r.pipeline(
        "fixtures/zephyr-old-mbedtls/old-mbedtls",
        "pull_request",
        "high",
    );
    assert_eq!(r.outputs("base.sh")["base"], "present");
    assert_eq!(r.outputs("base.sh")["base-run"], "1001");
    assert_eq!(outputs["gate"], "findings");
    let diff: Value =
        serde_json::from_slice(&std::fs::read(r.out().join("diff.json")).unwrap()).unwrap();
    assert_eq!(diff["base"]["present"], true);
    assert_eq!(diff["base"]["product"]["name"], "http_server");
    let gated: Vec<&str> = diff["findings"]["new"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| {
            f["triage"] != "suppressed"
                && ["high", "critical"].contains(&f["severity"].as_str().unwrap())
        })
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        diff["gate"]["new_open_at_or_above"].as_u64().unwrap(),
        gated.len() as u64
    );
    let comment = std::fs::read_to_string(r.out().join("comment.md")).unwrap();
    assert!(comment.contains("❌"), "{comment}");
    for cve in ["CVE-2026-34872", "CVE-2026-34875", "CVE-2026-34877"] {
        assert!(gated.contains(&cve), "{cve}: {gated:?}");
        assert!(comment.contains(&format!("| {cve} |")), "{cve}\n{comment}");
    }
    // The comment is posted with those CVEs.
    let out = r.run(
        "comment.sh",
        "pull_request",
        &[("RC_ARTIFACT_NAME", "rollcall-zephyr")],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(r.outputs("comment.sh")["comment-action"], "created");
    let posted = posted_bodies(&r);
    let [body] = posted.as_slice() else {
        panic!("{posted:?}")
    };
    assert!(body.starts_with("<!-- rollcall-action:rollcall-zephyr -->\n## rollcall:"));
    assert!(body.contains("| CVE-2026-34872 |"));
    // The check goes red, naming them.
    let out = r.gate("findings", "high");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("::error::"), "{stderr}");
    for cve in ["CVE-2026-34872", "CVE-2026-34875", "CVE-2026-34877"] {
        assert!(stderr.contains(cve), "{cve}: {stderr}");
    }
}

/// The bodies the fake gh received with --input, in order.
fn posted_bodies(r: &Runner) -> Vec<String> {
    let mut files: Vec<(usize, PathBuf)> = std::fs::read_dir(r.path("gh"))
        .unwrap()
        .filter_map(|e| {
            let path = e.unwrap().path();
            let name = path.file_name()?.to_str()?.to_owned();
            let n = name
                .strip_prefix("input.")?
                .strip_suffix(".json")?
                .parse()
                .ok()?;
            Some((n, path))
        })
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|(_, p)| {
            let v: Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
            v["body"].as_str().unwrap().to_owned()
        })
        .collect()
}

/// TP3: with `fail-on: critical` (the example's cargo job), the old-heapless build's `high`
/// advisory passes the gate but is listed in the comment.
#[test]
fn fail_on_critical_pipeline_passes_with_high_listed() {
    let r = Runner::new();
    // The old-heapless capture, re-pointed at the fixture's heapless 0.5.6 (in a temp copy).
    let mut grype: Value =
        serde_json::from_slice(&std::fs::read(capture("old-heapless.grype.json")).unwrap())
            .unwrap();
    let text_value = serde_json::to_string(&grype)
        .unwrap()
        .replace("0.5.0", "0.5.6");
    grype = serde_json::from_str(&text_value).unwrap();
    r.grype(Some(grype));
    let outputs = r.pipeline("fixtures/cargo-old-heapless", "push", "critical");
    assert_eq!(r.outputs("pipeline.sh")["ecosystem"], "cargo");
    assert_eq!(outputs["gate"], "clean");
    assert_eq!(outputs["new-findings"], "1");
    let diff: Value =
        serde_json::from_slice(&std::fs::read(r.out().join("diff.json")).unwrap()).unwrap();
    let new = &diff["findings"]["new"][0];
    assert_eq!(new["severity"], "high");
    assert_eq!(new["name"], "heapless");
    assert_eq!(new["in_sbom"], true);
    let id = new["id"].as_str().unwrap();
    let comment = std::fs::read_to_string(r.out().join("comment.md")).unwrap();
    assert!(
        comment.contains("✅ **No new open findings at or above critical.**"),
        "{comment}"
    );
    assert!(comment.contains(&format!("| high | {id} |")), "{comment}");
    let out = r.gate("clean", "critical");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    // The same build at fail-on high fails.
    let outputs = r.pipeline("fixtures/cargo-old-heapless", "push", "high");
    assert_eq!(outputs["gate"], "findings");
    assert_eq!(r.gate("findings", "high").status.code(), Some(1));
}

/// AC3: the first run POSTs a comment; a re-run finds it by its marker and PATCHes it, never
/// POSTing again. With the workflow token (`gh api user` refused) "ours" is a bot's comment;
/// others' comments, even quoting the marker, are left alone. An oversized body is cut at a
/// character boundary into valid UTF-8. A fork's (or a deleted fork's) read-only token gives a
/// notice and success; any other failure fails the step; a bad artifact name exits 64.
#[test]
fn comment_script_creates_when_absent_and_patches_when_marker_found() {
    let r = Runner::new();
    std::fs::create_dir_all(r.out()).unwrap();
    std::fs::write(
        r.out().join("comment.md"),
        "## rollcall: demo\n\nbody one\n",
    )
    .unwrap();
    r.event(pr_event(REPO));
    let marker = "<!-- rollcall-action:rollcall-zephyr -->";
    let inputs = [("RC_ARTIFACT_NAME", "rollcall-zephyr")];
    // First run: only a human's comment quoting the marker, and a bot's without it.
    std::fs::write(
        r.path("gh/comments.json"),
        serde_json::to_vec(&json!([
            {"id": 11, "user": {"login": "someone", "type": "User"}, "body": format!("{marker}\nquoted")},
            {"id": 12, "user": {"login": "github-actions[bot]", "type": "Bot"}, "body": "other bot"}
        ]))
        .unwrap(),
    )
    .unwrap();
    let out = r.run("comment.sh", "pull_request", &inputs);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(r.outputs("comment.sh")["comment-action"], "created");
    assert_eq!(r.outputs("comment.sh")["comment-id"], "9001");
    assert_eq!(
        r.requests(),
        [
            "GET user".to_owned(),
            format!("GET repos/{REPO}/issues/7/comments?per_page=100"),
            format!("POST repos/{REPO}/issues/7/comments"),
        ]
    );
    assert_eq!(
        posted_bodies(&r),
        [format!("{marker}\n## rollcall: demo\n\nbody one\n")]
    );

    // Re-run: the listing (two pages, as --paginate prints them) now has the bot's comment.
    std::fs::remove_file(r.path("gh/requests.log")).unwrap();
    std::fs::write(
        r.out().join("comment.md"),
        "## rollcall: demo\n\nbody two\n",
    )
    .unwrap();
    std::fs::write(
        r.path("gh/comments.json"),
        format!(
            "{}{}",
            json!([{"id": 11, "user": {"type": "User"}, "body": format!("{marker}\nquoted")}]),
            json!([{"id": 4242, "user": {"login": "github-actions[bot]", "type": "Bot"}, "body": format!("{marker}\n## rollcall: demo\n\nbody one\n")}])
        ),
    )
    .unwrap();
    let out = r.run("comment.sh", "pull_request", &inputs);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(r.outputs("comment.sh")["comment-action"], "updated");
    assert_eq!(r.outputs("comment.sh")["comment-id"], "4242");
    let requests = r.requests();
    assert_eq!(
        requests,
        [
            "GET user".to_owned(),
            format!("GET repos/{REPO}/issues/7/comments?per_page=100"),
            format!("PATCH repos/{REPO}/issues/comments/4242"),
        ]
    );
    assert!(!requests.iter().any(|q| q.starts_with("POST")));
    assert_eq!(
        posted_bodies(&r).last().unwrap(),
        &format!("{marker}\n## rollcall: demo\n\nbody two\n")
    );

    // An oversized comment whose three-byte `—` straddles byte 64000 of the body (marker line
    // included) is cut at a character boundary: valid UTF-8, within GitHub's limit, pointing
    // at the artifact.
    std::fs::write(r.path("gh/comments.json"), "[]").unwrap();
    let prefix = marker.len() + 1;
    let big = format!("{}{}", "a".repeat(63_999 - prefix), "—".repeat(3_000));
    let body_bytes = format!("{marker}\n{big}").into_bytes();
    assert_eq!(
        &body_bytes[63_999..64_002],
        "—".as_bytes(),
        "the dash straddles 64000"
    );
    std::fs::write(r.out().join("comment.md"), &big).unwrap();
    let out = r.run("comment.sh", "pull_request", &inputs);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let raw = std::fs::read(r.out().join("comment.payload.json")).unwrap();
    let raw = String::from_utf8(raw).expect("payload is valid UTF-8");
    let payload: Value = serde_json::from_str(&raw).unwrap();
    let body = payload["body"].as_str().unwrap();
    assert!(String::from_utf8(body.as_bytes().to_vec()).is_ok());
    assert!(body.chars().count() <= 65_536, "{}", body.chars().count());
    assert!(
        !body.contains('\u{fffd}'),
        "a replacement character: the cut split a character"
    );
    assert!(body.starts_with(&format!("{marker}\naaa")));
    assert!(
        body.contains("a—"),
        "the straddling character is kept whole"
    );
    assert!(body.contains("artifact `rollcall-zephyr`"));
    assert_eq!(posted_bodies(&r).pop().unwrap(), body);

    // Posting fails: on a fork, a notice and success; on the repository itself, an error.
    std::fs::write(r.out().join("comment.md"), "## rollcall: demo\n").unwrap();
    std::fs::write(r.path("gh/post-fails"), "").unwrap();
    r.event(pr_event("someone/fork"));
    let out = r.run("comment.sh", "pull_request", &inputs);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("::notice::"));
    assert_eq!(r.outputs("comment.sh")["comment-action"], "skipped");
    // A deleted fork: the head repository is null.
    r.event(json!({"pull_request": {"number": 7, "head": {"repo": null}}}));
    let out = r.run("comment.sh", "pull_request", &inputs);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("::notice::"));
    r.event(pr_event(REPO));
    let out = r.run("comment.sh", "pull_request", &inputs);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("pull-requests: write"));

    // An artifact name that would break the marker is refused before any API call.
    std::fs::remove_file(r.path("gh/requests.log")).unwrap();
    for bad in ["a b", "x-->y", "rollcall/zephyr"] {
        let out = r.run("comment.sh", "pull_request", &[("RC_ARTIFACT_NAME", bad)]);
        assert_eq!(out.status.code(), Some(64), "{bad}: {}", text(&out));
        assert!(String::from_utf8_lossy(&out.stderr).contains("artifact-name"));
    }
    assert!(
        !r.requests()
            .iter()
            .any(|q| q.starts_with("PATCH") || q.starts_with("POST")),
        "{:?}",
        r.requests()
    );
}

/// With a personal access token, `gh api user` names the token's user: the re-run PATCHes
/// that user's comment (a `User`, not a bot) and never POSTs a duplicate; a bot's comment
/// carrying the same marker is not ours then.
#[test]
fn comment_script_patches_comment_by_token_login() {
    let r = Runner::new();
    std::fs::create_dir_all(r.out()).unwrap();
    std::fs::write(r.out().join("comment.md"), "## rollcall: demo\n\nbody\n").unwrap();
    r.event(pr_event(REPO));
    let marker = "<!-- rollcall-action:rollcall -->";
    std::fs::write(
        r.path("gh/user.json"),
        r#"{"login": "release-bot-pat", "type": "User"}"#,
    )
    .unwrap();
    std::fs::write(
        r.path("gh/comments.json"),
        serde_json::to_vec(&json!([
            {"id": 88, "user": {"login": "github-actions[bot]", "type": "Bot"}, "body": format!("{marker}\nold bot")},
            {"id": 77, "user": {"login": "release-bot-pat", "type": "User"}, "body": format!("{marker}\nold")},
            {"id": 66, "user": {"login": "someone", "type": "User"}, "body": format!("{marker}\nquoted")}
        ]))
        .unwrap(),
    )
    .unwrap();
    let out = r.run(
        "comment.sh",
        "pull_request",
        &[("RC_ARTIFACT_NAME", "rollcall")],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(r.outputs("comment.sh")["comment-action"], "updated");
    assert_eq!(r.outputs("comment.sh")["comment-id"], "77");
    let requests = r.requests();
    assert_eq!(
        requests,
        [
            "GET user".to_owned(),
            format!("GET repos/{REPO}/issues/7/comments?per_page=100"),
            format!("PATCH repos/{REPO}/issues/comments/77"),
        ]
    );
    assert!(!requests.iter().any(|q| q.starts_with("POST")));
    // No comment of the token's user yet: a new one is POSTed (the bot's is not ours).
    std::fs::remove_file(r.path("gh/requests.log")).unwrap();
    std::fs::write(
        r.path("gh/comments.json"),
        serde_json::to_vec(&json!([
            {"id": 88, "user": {"login": "github-actions[bot]", "type": "Bot"}, "body": format!("{marker}\nold bot")}
        ]))
        .unwrap(),
    )
    .unwrap();
    let out = r.run(
        "comment.sh",
        "pull_request",
        &[("RC_ARTIFACT_NAME", "rollcall")],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(r.outputs("comment.sh")["comment-action"], "created");
}

/// No base artifact never fails the job: no workflow run on main yet (the API's 404), no
/// completed run, runs without the artifact, or not a pull request at all all give
/// `base=absent` with a reason, and the diff then treats every finding as new.
#[test]
fn base_script_absent_run_reports_no_base_without_failing() {
    let r = Runner::new();
    r.event(pr_event(REPO));
    let inputs = [("RC_ARTIFACT_NAME", "rollcall-zephyr")];
    // The workflow does not exist on main yet: 404.
    let out = r.run("base.sh", "pull_request", &inputs);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let o = r.outputs("base.sh");
    assert_eq!(o["base"], "absent");
    assert!(o["base-reason"].contains("rollcall-example.yml"), "{o:?}");
    assert!(
        r.requests()[0].starts_with(&format!(
            "GET repos/{REPO}/actions/workflows/rollcall-example.yml/runs?branch=main&event=push&status=completed"
        )),
        "{:?}",
        r.requests()
    );
    // No completed run.
    std::fs::write(
        r.path("gh/runs.json"),
        r#"{"total_count": 0, "workflow_runs": []}"#,
    )
    .unwrap();
    let out = r.run("base.sh", "pull_request", &inputs);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(r.outputs("base.sh")["base"], "absent");
    // Runs whose artifact expired (download fails).
    std::fs::write(
        r.path("gh/runs.json"),
        r#"{"workflow_runs": [{"id": 5}, {"id": 4}]}"#,
    )
    .unwrap();
    let out = r.run("base.sh", "pull_request", &inputs);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(r.outputs("base.sh")["base"], "absent");
    assert!(r.requests().contains(&"run download 5".to_owned()));
    assert!(r.requests().contains(&"run download 4".to_owned()));
    assert!(!r.out().join("base").exists());
    // Garbage from the API.
    std::fs::write(r.path("gh/runs.json"), "not json").unwrap();
    let out = r.run("base.sh", "pull_request", &inputs);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(r.outputs("base.sh")["base"], "absent");
    // Not a pull request (pull_request_target is not supported either).
    for event in ["push", "pull_request_target"] {
        let out = r.run("base.sh", event, &inputs);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        assert_eq!(r.outputs("base.sh")["base"], "absent");
        assert!(r.outputs("base.sh")["base-reason"].contains("not a pull request"));
    }
    // A base branch whose name needs encoding is passed to gh as a field, never spliced into
    // the URL: gh (here the fake, encoding as gh does) builds the query string.
    std::fs::remove_file(r.path("gh/requests.log")).unwrap();
    let out = r.run(
        "base.sh",
        "pull_request",
        &[
            ("RC_ARTIFACT_NAME", "rollcall-zephyr"),
            ("GITHUB_BASE_REF", "release/1.0+x&y#z%"),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        r.requests()[0],
        format!(
            "GET repos/{REPO}/actions/workflows/rollcall-example.yml/runs?branch=release%2F1.0%2Bx%26y%23z%25&event=push&status=completed&per_page=5"
        )
    );
    // A bad artifact name is a usage error.
    let out = r.run("base.sh", "pull_request", &[("RC_ARTIFACT_NAME", "a b")]);
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
    // And the diff with no base: every finding is new, the comment says why.
    r.grype(Some(
        serde_json::from_slice(&std::fs::read(capture("zephyr-old-mbedtls.grype.json")).unwrap())
            .unwrap(),
    ));
    std::fs::remove_file(r.path("gh/runs.json")).unwrap();
    let outputs = r.pipeline(
        "fixtures/zephyr-old-mbedtls/old-mbedtls",
        "pull_request",
        "high",
    );
    assert_eq!(outputs["gate"], "findings");
    let diff: Value =
        serde_json::from_slice(&std::fs::read(r.out().join("diff.json")).unwrap()).unwrap();
    assert_eq!(diff["base"]["present"], false);
    assert_eq!(
        diff["findings"]["new"].as_array().unwrap().len() as u64,
        diff["findings"]["head_total"].as_u64().unwrap()
    );
    let comment = std::fs::read_to_string(r.out().join("comment.md")).unwrap();
    assert!(
        comment.contains("every open finding counts as new"),
        "{comment}"
    );
}

/// `ecosystem: auto` runs `rollcall detect` (the detection `rollcall generate DIR` uses) and
/// tells all four ecosystems apart: a Zephyr build, captured cargo metadata and a Cargo
/// package, an ESP-IDF project and a PlatformIO project. A directory several ecosystems match
/// exits 64 and one none matches 66, each with an error annotation; an unknown ecosystem is
/// 64; an explicit ecosystem the directory is not fails naming what is missing.
#[test]
fn ecosystem_auto_uses_rollcall_detect_for_all_four_ecosystems() {
    let r = Runner::new();
    let detect = |dir: &Path, ecosystem: &str| {
        let out = r.run(
            "pipeline.sh",
            "push",
            &[
                ("RC_BUILD_DIR", dir.to_str().unwrap()),
                ("RC_ECOSYSTEM", ecosystem),
            ],
        );
        (out, r.outputs("pipeline.sh").get("ecosystem").cloned())
    };
    for (dir, expected) in [
        ("fixtures/zephyr/tls", "zephyr"),
        ("fixtures/cargo-keelsign", "cargo"),
        ("fixtures/esp-idf/hello-world", "esp-idf"),
        ("fixtures/platformio/arduino-mqtt", "platformio"),
    ] {
        let (out, eco) = detect(&workspace().join(dir), "auto");
        assert_eq!(out.status.code(), Some(0), "{dir}: {}", text(&out));
        assert_eq!(eco.as_deref(), Some(expected), "{dir}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(&format!("ecosystem: {expected}")),
            "{dir}"
        );
        // The same choice made explicitly gives the same SBOM.
        let auto = std::fs::read(r.out().join("sbom.cdx.json")).unwrap();
        let (out, eco) = detect(&workspace().join(dir), expected);
        assert_eq!(out.status.code(), Some(0), "{dir}: {}", text(&out));
        assert_eq!(eco.as_deref(), Some(expected));
        let explicit = std::fs::read(r.out().join("sbom.cdx.json")).unwrap();
        // Timestamps differ (none is pinned here); compare without them.
        let strip = |b: &[u8]| {
            let mut v: Value = serde_json::from_slice(b).unwrap();
            v["metadata"]["timestamp"] = Value::Null;
            v
        };
        assert_eq!(strip(&auto), strip(&explicit), "{dir}");
    }
    // A package directory (Cargo.toml) is a Cargo build, run with cargo metadata; here a fake
    // cargo fails (as for a package without Cargo.lock), so `rollcall generate` fails after
    // detection with exit 65, and the step exits with that code.
    write_exe(
        &r.path("bin/cargo"),
        "#!/bin/sh\necho 'error: the lock file needs to be updated' >&2\nexit 101\n",
    );
    let package = r.path("pkg");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(package.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    let (out, eco) = detect(&package, "auto");
    assert_eq!(eco.as_deref(), Some("cargo"));
    assert_eq!(out.status.code(), Some(65), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--ecosystem cargo"),
        "{}",
        text(&out)
    );
    // Several ecosystems: 64, listing them.
    std::fs::write(package.join("platformio.ini"), "[env:a]\n").unwrap();
    let (out, eco) = detect(&package, "auto");
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
    assert_eq!(eco, None);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("::error::"), "{stderr}");
    assert!(
        stderr.contains("cargo (Cargo.toml), platformio (platformio.ini)"),
        "{stderr}"
    );
    // None: 66.
    let empty = r.path("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let (out, eco) = detect(&empty, "auto");
    assert_eq!(out.status.code(), Some(66), "{}", text(&out));
    assert_eq!(eco, None);
    assert!(String::from_utf8_lossy(&out.stderr).contains("::error::"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no ecosystem recognised"));
    // Wrong explicit ecosystem, unknown ecosystem, missing directory.
    let (out, _) = detect(&workspace().join("fixtures/cargo-keelsign"), "zephyr");
    assert_eq!(out.status.code(), Some(66), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not a zephyr directory: no build_info.yml"),
        "{}",
        text(&out)
    );
    let (out, _) = detect(&workspace().join("fixtures/zephyr/tls"), "espidf");
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
    let (out, _) = detect(&r.path("nowhere"), "auto");
    assert_eq!(out.status.code(), Some(66), "{}", text(&out));
}

/// TP3, local proxy for the example workflow's `platformio` job: on the PlatformIO fixture
/// with `ecosystem: auto` and `fail-on: none` (Arduino-ESP32 2.0.17 has open CVEs), the
/// pipeline detects PlatformIO, writes every file the upload step lists, names the framework
/// and the three libraries, reports a (fake grype) finding on arduino-esp32 as open, and the
/// gate stays clean on a pull request. The workflow's own check step is then run on those
/// outputs, so its assertions are the ones tested here.
#[test]
fn pipeline_on_platformio_fixture_with_ecosystem_auto_is_clean() {
    let fixture = "fixtures/platformio/arduino-mqtt";
    let r = Runner::new();
    // A first run for the framework's bom-ref, which the fake grype match points at.
    r.pipeline_with(fixture, "push", "none", &[("RC_ECOSYSTEM", "auto")]);
    let sbom: Value =
        serde_json::from_slice(&std::fs::read(r.out().join("sbom.cdx.json")).unwrap()).unwrap();
    let framework = sbom["components"][0]["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "arduino-esp32")
        .expect("an arduino-esp32 component")
        .clone();
    let cpe = framework["cpe"].as_str().unwrap();
    r.grype(Some(json!({"matches": [{
        "vulnerability": {
            "id": "CVE-2099-0001",
            "severity": "High",
            "namespace": "nvd:cpe",
            "fix": {"versions": [], "state": "not-fixed"}
        },
        "matchDetails": [{
            "type": "cpe-match",
            "matcher": "stock-matcher",
            "searchedBy": {
                "namespace": "nvd:cpe",
                "cpes": [cpe],
                "package": {"name": "arduino-esp32", "version": "2.0.17"}
            }
        }],
        "artifact": {
            "id": framework["bom-ref"],
            "name": "arduino-esp32",
            "version": "2.0.17",
            "type": "UnknownPackage",
            "purl": framework["purl"],
            "cpes": [cpe],
            "locations": null
        }
    }]})));
    r.event(pr_event(REPO));
    let outputs = r.pipeline_with(fixture, "pull_request", "none", &[("RC_ECOSYSTEM", "auto")]);
    assert_eq!(outputs["gate"], "clean");
    assert_eq!(outputs["new-findings"], "1");
    let pipeline = r.outputs("pipeline.sh");
    assert_eq!(pipeline["ecosystem"], "platformio");
    for file in artifact_files() {
        assert!(r.out().join(&file).is_file(), "{file} was not written");
    }
    let sbom: Value =
        serde_json::from_slice(&std::fs::read(r.out().join("sbom.cdx.json")).unwrap()).unwrap();
    let components = sbom["components"][0]["components"].as_array().unwrap();
    let purls: Vec<&str> = components
        .iter()
        .filter_map(|c| c["purl"].as_str())
        .collect();
    for purl in [
        "pkg:generic/bblanchon/ArduinoJson@7.2.1?repository_url=https:%2F%2Fregistry.platformio.org",
        "pkg:generic/knolleary/PubSubClient@2.8?repository_url=https:%2F%2Fregistry.platformio.org",
        "pkg:generic/mathertel/OneButton@2.6.1?repository_url=https:%2F%2Fregistry.platformio.org",
        "pkg:generic/arduino-esp32@2.0.17?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fespressif%2Farduino-esp32",
    ] {
        assert!(purls.contains(&purl), "{purl} not in {purls:?}");
    }
    // fail-on none: the gate step passes on a pull request despite the open high finding.
    let out = r.gate("clean", "none");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    // The example workflow's job: ecosystem auto, fail-on none, on this fixture.
    let example: Value = yaml_serde::from_str(
        &std::fs::read_to_string(workspace().join(".github/workflows/rollcall-example.yml"))
            .unwrap(),
    )
    .unwrap();
    let steps = example["jobs"]["platformio"]["steps"].as_array().unwrap();
    let action = steps.iter().find(|s| s["uses"] == "./action").unwrap();
    assert_eq!(action["with"]["build-dir"], fixture);
    assert_eq!(action["with"]["ecosystem"], "auto");
    assert_eq!(action["with"]["fail-on"], "none");
    let id = action["id"].as_str().expect("the action step has an id");
    let check = steps
        .iter()
        .find(|s| s["run"].is_string())
        .expect("a check step");
    let script = check["run"].as_str().unwrap();
    for needle in [
        "ArduinoJson@7.2.1",
        "PubSubClient@2.8",
        "OneButton@2.6.1",
        "arduino-esp32",
    ] {
        assert!(script.contains(needle), "the check step lacks {needle}");
    }
    // Its inputs come only through env, from the action's outputs.
    assert!(
        !script.contains("${{"),
        "expression interpolated into shell"
    );
    let env = check["env"].as_object().unwrap();
    let mut values = BTreeMap::new();
    for (key, output) in [
        ("ECOSYSTEM", "ecosystem"),
        ("SBOM", "sbom"),
        ("SCAN", "scan"),
        ("GATE", "gate"),
    ] {
        assert_eq!(
            env[key],
            format!("${{{{ steps.{id}.outputs.{output} }}}}"),
            "{key}"
        );
        let value = match output {
            "gate" => outputs["gate"].clone(),
            other => pipeline[other].clone(),
        };
        values.insert(key, value);
    }
    // Run the check step itself on this run's outputs: it passes...
    let run_check = |values: &BTreeMap<&str, String>| {
        let mut cmd = Command::new("bash");
        cmd.arg("-c")
            .arg(script)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin")
            .current_dir(workspace());
        for (k, v) in values {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    };
    let out = run_check(&values);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("open findings on arduino-esp32: 1"));
    // ...and fails without a finding on the framework, or with a tripped gate.
    let empty = r.path("empty-scan.json");
    std::fs::write(&empty, r#"{"schema": "rollcall-scan/1", "findings": []}"#).unwrap();
    let mut no_findings = values.clone();
    no_findings.insert("SCAN", empty.display().to_string());
    assert_eq!(run_check(&no_findings).status.code(), Some(1));
    let mut tripped = values.clone();
    tripped.insert("GATE", "findings".to_owned());
    assert_eq!(run_check(&tripped).status.code(), Some(1));
}

/// The `pio-core` input passes the core directory to `rollcall generate --pio-core` (a leading
/// `~/` is the runner's home): the SBOM then carries the installed packages' facts (the
/// platform's licence, `pio-core/` evidence), which the exact pins alone do not give. A
/// build-dir starting with `-` is refused (it would be read as a flag).
#[test]
fn pio_core_input_reaches_generate_and_dash_build_dir_is_refused() {
    let r = Runner::new();
    let platform_licence = |r: &Runner| {
        let sbom: Value =
            serde_json::from_slice(&std::fs::read(r.out().join("sbom.cdx.json")).unwrap()).unwrap();
        sbom["components"][0]["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "espressif32")
            .unwrap()["licenses"]
            .clone()
    };
    let fixture = "fixtures/platformio/arduino-mqtt";
    r.pipeline_with(fixture, "push", "high", &[]);
    assert_eq!(platform_licence(&r), Value::Null);
    // The core directory copied under the runner's home, named as ~/core.
    let home_core = r.path("core");
    let src = workspace().join(fixture).join("pio-core");
    for rel in [
        "platforms/espressif32/platform.json",
        "platforms/espressif32/.piopm",
        "packages/framework-arduinoespressif32/package.json",
        "packages/framework-arduinoespressif32/.piopm",
    ] {
        let to = home_core.join(rel);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(src.join(rel), &to).unwrap();
    }
    let out = r.run(
        "pipeline.sh",
        "push",
        &[
            ("RC_BUILD_DIR", workspace().join(fixture).to_str().unwrap()),
            ("RC_PIO_CORE", "~/core"),
            ("RC_TIMESTAMP", GOLDEN_TIMESTAMP),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains(&format!("--pio-core {}", home_core.display())),
        "{stderr}"
    );
    assert_eq!(platform_licence(&r), json!([{"expression": "Apache-2.0"}]));
    // Another ecosystem: ignored with a warning.
    let out = r.run(
        "pipeline.sh",
        "push",
        &[
            (
                "RC_BUILD_DIR",
                workspace()
                    .join("fixtures/cargo-keelsign")
                    .to_str()
                    .unwrap(),
            ),
            ("RC_PIO_CORE", "~/core"),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("pio-core is ignored for a cargo build"));
    // A build-dir that looks like a flag.
    let out = r.run("pipeline.sh", "push", &[("RC_BUILD_DIR", "--help")]);
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("must not start with '-'"));
}

/// The ```yaml blocks of a Markdown file.
fn yaml_blocks(markdown: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in markdown.lines() {
        match &mut current {
            None if line.trim() == "```yaml" => current = Some(String::new()),
            Some(block) if line.trim() == "```" => {
                blocks.push(std::mem::take(block));
                current = None;
            }
            Some(block) => {
                block.push_str(line);
                block.push('\n');
            }
            None => {}
        }
    }
    blocks
}

/// Every step in a workflow that uses the action (`uses` ending in `/action@…` or `./action`).
fn action_steps(workflow: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    for job in workflow["jobs"].as_object().unwrap().values() {
        for step in job["steps"].as_array().unwrap() {
            let uses = step["uses"].as_str().unwrap_or("");
            if uses == "./action" || uses.contains("/rollcall/action@") {
                out.push(step.clone());
            }
        }
    }
    out
}

/// The action declares the scope's inputs (build-dir required, ecosystem defaulting to auto,
/// identifiers-version, fail-on, vex-rules) and outputs; it is composite, every step runs an
/// executable script under action/scripts/ with inputs only in `env` (never interpolated into
/// shell), and every third-party action is pinned to a full commit SHA. The README's
/// copy-paste workflow and the example workflow use only declared inputs, with the
/// permissions the action needs, and the example's build directories exist.
#[test]
fn action_yml_declares_scope_inputs_and_readme_workflow_uses_only_declared_inputs() {
    let action = action_yml();
    let inputs = action["inputs"].as_object().unwrap();
    for name in [
        "build-dir",
        "ecosystem",
        "identifiers-version",
        "fail-on",
        "vex-rules",
    ] {
        assert!(inputs.contains_key(name), "missing input {name}");
        assert!(
            inputs[name]["description"]
                .as_str()
                .is_some_and(|d| !d.is_empty()),
            "{name} has no description"
        );
    }
    assert_eq!(inputs["build-dir"]["required"], true);
    assert_eq!(inputs["ecosystem"]["default"], "auto");
    assert_eq!(inputs["fail-on"]["default"], "high");
    assert_eq!(inputs["identifiers-version"]["default"], "embedded");
    assert_eq!(inputs["rollcall-version"]["default"], "source");
    let outputs = action["outputs"].as_object().unwrap();
    for name in [
        "ecosystem",
        "sbom",
        "vex",
        "scan",
        "report",
        "comment",
        "score",
        "new-findings",
        "gate",
    ] {
        assert!(outputs.contains_key(name), "missing output {name}");
    }
    assert_eq!(action["runs"]["using"], "composite");
    let steps = action["runs"]["steps"].as_array().unwrap();
    let mut scripts = Vec::new();
    for step in steps {
        if let Some(uses) = step["uses"].as_str() {
            let (_, sha) = uses.split_once('@').unwrap();
            assert!(
                sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()),
                "{uses} is not pinned to a commit SHA"
            );
        }
        if let Some(run) = step["run"].as_str() {
            assert_eq!(step["shell"], "bash", "{run}");
            assert!(
                !run.contains("${{"),
                "expression interpolated into shell: {run}"
            );
            let name = run
                .trim()
                .trim_matches('"')
                .strip_prefix("$GITHUB_ACTION_PATH/scripts/")
                .unwrap_or_else(|| panic!("step does not run a script: {run}"));
            let path = script(name);
            let mode = std::fs::metadata(&path)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
                .permissions()
                .mode();
            assert!(mode & 0o111 != 0, "{name} is not executable");
            scripts.push(name.to_owned());
        }
    }
    assert_eq!(
        scripts,
        [
            "install.sh",
            "pipeline.sh",
            "base.sh",
            "diff.sh",
            "comment.sh",
            "gate.sh"
        ]
    );

    let check_workflow = |label: &str, workflow: &Value, expect_steps: usize| {
        let steps = action_steps(workflow);
        assert_eq!(steps.len(), expect_steps, "{label}: {workflow:#}");
        for step in &steps {
            let with = step["with"].as_object().unwrap();
            assert!(with.contains_key("build-dir"), "{label}: no build-dir");
            for key in with.keys() {
                assert!(inputs.contains_key(key), "{label}: undeclared input {key}");
            }
        }
        for (name, job) in workflow["jobs"].as_object().unwrap() {
            let perms = &job["permissions"];
            let perms = if perms.is_null() {
                &workflow["permissions"]
            } else {
                perms
            };
            assert_eq!(perms["pull-requests"], "write", "{label}/{name}");
            assert_eq!(perms["actions"], "read", "{label}/{name}");
            assert_eq!(perms["contents"], "read", "{label}/{name}");
        }
        steps
    };

    let readme = std::fs::read_to_string(workspace().join("action/README.md")).unwrap();
    let workflows: Vec<Value> = yaml_blocks(&readme)
        .iter()
        .filter_map(|b| yaml_serde::from_str::<Value>(b).ok())
        .filter(|v| v.get("jobs").is_some())
        .collect();
    assert!(!workflows.is_empty(), "action/README.md has no workflow");
    check_workflow("README", &workflows[0], 1);
    for input in inputs.keys() {
        assert!(
            readme.contains(&format!("`{input}`")),
            "README does not document {input}"
        );
    }

    let example: Value = yaml_serde::from_str(
        &std::fs::read_to_string(workspace().join(".github/workflows/rollcall-example.yml"))
            .unwrap(),
    )
    .unwrap();
    let steps = check_workflow("rollcall-example.yml", &example, 3);
    let mut names = Vec::new();
    for step in &steps {
        let dir = step["with"]["build-dir"].as_str().unwrap();
        assert!(workspace().join(dir).is_dir(), "{dir}");
        names.push(step["with"]["artifact-name"].as_str().unwrap().to_owned());
    }
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 3, "each job needs its own artifact name");
}

/// The old-mbedTLS build's diff (no base) with these extra pipeline inputs.
fn old_mbedtls_diff(r: &Runner, extra: &[(&str, &str)]) -> Value {
    r.grype(Some(
        serde_json::from_slice(&std::fs::read(capture("zephyr-old-mbedtls.grype.json")).unwrap())
            .unwrap(),
    ));
    r.pipeline_with(
        "fixtures/zephyr-old-mbedtls/old-mbedtls",
        "push",
        "high",
        extra,
    );
    serde_json::from_slice(&std::fs::read(r.out().join("diff.json")).unwrap()).unwrap()
}

/// The triage of every new finding with this id (one per image).
fn triages(diff: &Value, id: &str) -> Vec<String> {
    diff["findings"]["new"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["id"] == id)
        .map(|f| f["triage"].as_str().unwrap().to_owned())
        .collect()
}

fn gated(diff: &Value) -> u64 {
    diff["gate"]["new_open_at_or_above"].as_u64().unwrap()
}

/// `vex-rules`: every non-blank line (whitespace trimmed) is a rules file passed with
/// `--rules`, after the starter pack; each file's rule suppresses its CVE (in both images of
/// the sysbuild), so the gate count drops by exactly those findings. A listed file that does
/// not exist exits 66 before anything runs.
#[test]
fn vex_rules_input_applies_each_listed_file_and_rejects_missing() {
    let r = Runner::new();
    let rule = |id: &str, cve: &str| {
        format!(
            "version: 1\nrules:\n  - id: {id}\n    match:\n      name: mbedtls\n      cves: [{cve}]\n    \
             status: not_affected\n    justification: vulnerable_code_not_in_execute_path\n    \
             detail: Test rule for rollcall-action.\n"
        )
    };
    let one = r.path("rules-one.yml");
    let two = r.path("rules two.yml");
    std::fs::write(&one, rule("action-test-34872", "CVE-2026-34872")).unwrap();
    std::fs::write(&two, rule("action-test-34875", "CVE-2026-34875")).unwrap();

    let before = old_mbedtls_diff(&r, &[]);
    for cve in ["CVE-2026-34872", "CVE-2026-34875"] {
        assert_eq!(triages(&before, cve), ["unresolved", "unresolved"], "{cve}");
    }
    let list = format!("\n  {}  \n\n\t{}\n", one.display(), two.display());
    let after = old_mbedtls_diff(&r, &[("RC_VEX_RULES", list.as_str())]);
    for cve in ["CVE-2026-34872", "CVE-2026-34875"] {
        assert_eq!(triages(&after, cve), ["suppressed", "suppressed"], "{cve}");
    }
    // Both are critical: 2 CVEs x 2 images fewer gated findings; everything else unchanged.
    assert_eq!(gated(&after), gated(&before) - 4);
    assert_eq!(
        triages(&after, "CVE-2026-34877"),
        triages(&before, "CVE-2026-34877")
    );
    let vex = std::fs::read_to_string(r.out().join("vex.openvex.json")).unwrap();
    assert!(vex.contains("Test rule for rollcall-action."), "{vex}");

    // A missing rules file: exit 66, naming it, before generating anything.
    std::fs::remove_dir_all(r.out()).unwrap();
    let missing = format!("{}\n{}", one.display(), r.path("nope.yml").display());
    let build = workspace().join("fixtures/zephyr-old-mbedtls/old-mbedtls");
    let out = r.run(
        "pipeline.sh",
        "push",
        &[
            ("RC_BUILD_DIR", build.to_str().unwrap()),
            ("RC_VEX_RULES", missing.as_str()),
        ],
    );
    assert_eq!(out.status.code(), Some(66), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("nope.yml"));
    assert!(!r.out().join("sbom.cdx.json").exists());
}

/// `starter-rules: false` leaves the starter pack out: CVE-2026-34873, which the pack
/// suppresses (TLS 1.3 compiled out), stays open and gated; any other value exits 64.
#[test]
fn starter_rules_false_skips_the_starter_pack() {
    let r = Runner::new();
    let with = old_mbedtls_diff(&r, &[]);
    assert_eq!(
        triages(&with, "CVE-2026-34873"),
        ["suppressed", "suppressed"]
    );
    let without = old_mbedtls_diff(&r, &[("RC_STARTER_RULES", "false")]);
    assert_eq!(
        triages(&without, "CVE-2026-34873"),
        ["unresolved", "unresolved"]
    );
    assert!(gated(&without) > gated(&with));
    let build = workspace().join("fixtures/zephyr/tls");
    let out = r.run(
        "pipeline.sh",
        "push",
        &[
            ("RC_BUILD_DIR", build.to_str().unwrap()),
            ("RC_STARTER_RULES", "maybe"),
        ],
    );
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
}

/// install.sh: a downloaded release whose SHA-256 does not match its `SHA256SUMS` entry
/// (served by a fake `curl`) exits 1 with "sha256 mismatch" and leaves no tarball behind; a
/// bad `identifiers-version` or `rollcall-version` exits 64; `ROLLCALL_BIN` is passed through
/// without downloading rollcall (a pinned grype already in the tools directory is reused).
#[test]
fn install_script_verifies_checksums() {
    let r = Runner::new();
    let tools = r.path("tools");
    std::fs::create_dir_all(&tools).unwrap();
    let tools_s = tools.to_str().unwrap();
    // The fake curl logs each URL and writes a bogus tarball, or SHA256SUMS listing a wrong
    // hash for every asset it was asked for.
    write_exe(
        &r.path("bin/curl"),
        r#"#!/bin/sh
dest=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in -o) dest="$2"; shift ;; -*) ;; *) url="$1" ;; esac
  shift
done
echo "$url" >> "$FAKE_GH/curl.log"
case "$url" in
  */SHA256SUMS)
    for a in $(sed 's|.*/||' "$FAKE_GH/curl.log" | grep -v SHA256SUMS); do
      echo "0000000000000000000000000000000000000000000000000000000000000000  $a"
    done > "$dest" ;;
  *) printf 'not really a tarball' > "$dest" ;;
esac
"#,
    );
    let out = r.run(
        "install.sh",
        "push",
        &[
            ("ROLLCALL_BIN", ""),
            ("ROLLCALL_TOOLS_DIR", tools_s),
            ("RC_ROLLCALL_VERSION", "v9.9.9"),
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("sha256 mismatch"),
        "{}",
        text(&out)
    );
    let curl = std::fs::read_to_string(r.path("gh/curl.log")).unwrap();
    assert!(
        curl.contains("/releases/download/v9.9.9/rollcall-v9.9.9-"),
        "{curl}"
    );
    assert!(
        curl.contains("/releases/download/v9.9.9/SHA256SUMS"),
        "{curl}"
    );
    let left: Vec<String> = std::fs::read_dir(tools.join("rollcall-v9.9.9"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tar.gz"))
        .collect();
    assert!(left.is_empty(), "the bad download was kept: {left:?}");

    // Bad versions are usage errors, before any download.
    std::fs::remove_file(r.path("gh/curl.log")).unwrap();
    for (key, value) in [
        ("RC_IDENTIFIERS_VERSION", "abc"),
        ("RC_ROLLCALL_VERSION", "v1;touch x"),
        ("RC_ROLLCALL_VERSION", "../../etc"),
    ] {
        let out = r.run(
            "install.sh",
            "push",
            &[("ROLLCALL_TOOLS_DIR", tools_s), (key, value)],
        );
        assert_eq!(out.status.code(), Some(64), "{key}={value}: {}", text(&out));
    }
    assert!(!r.path("gh/curl.log").exists());

    // ROLLCALL_BIN passthrough, with the pinned grype already installed: nothing downloaded.
    write_exe(&tools.join("grype"), "#!/bin/sh\necho 'Version: 0.119.0'\n");
    let github_path = r.path("github-path");
    let out = r.run(
        "install.sh",
        "push",
        &[
            ("ROLLCALL_TOOLS_DIR", tools_s),
            ("GITHUB_PATH", github_path.to_str().unwrap()),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let o = r.outputs("install.sh");
    assert_eq!(o["rollcall-bin"], env!("CARGO_BIN_EXE_rollcall"));
    assert_eq!(o["identifiers"], "embedded");
    assert!(!r.path("gh/curl.log").exists(), "downloaded something");
    let path = std::fs::read_to_string(&github_path).unwrap();
    assert!(path.trim_end().ends_with("tools"), "{path}");
}

/// common.sh: the rollcall release asset for both Macs is the one universal binary
/// (`darwin_universal`, as release.yml builds it), while the pinned tools keep their
/// per-architecture assets; an unsupported machine exits 1 naming it.
#[test]
fn rollcall_platform_maps_both_macs_to_the_universal_asset() {
    let dir = tempfile::tempdir().unwrap();
    let uname = dir.path().join("uname");
    let run = |os: &str, arch: &str| {
        write_exe(
            &uname,
            &format!("#!/bin/sh\ncase \"$1\" in -s) echo {os} ;; -m) echo {arch} ;; esac\n"),
        );
        Command::new("bash")
            .arg("-c")
            .arg(". \"$1\"; platform; rollcall_platform")
            .arg("bash")
            .arg(script("common.sh"))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    dir.path().display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .output()
            .unwrap()
    };
    for (os, arch, tool, asset) in [
        ("Darwin", "arm64", "darwin_arm64", "darwin_universal"),
        ("Darwin", "x86_64", "darwin_amd64", "darwin_universal"),
        ("Linux", "x86_64", "linux_amd64", "linux_amd64"),
        ("Linux", "aarch64", "linux_arm64", "linux_arm64"),
    ] {
        let out = run(os, arch);
        assert_eq!(out.status.code(), Some(0), "{os} {arch}: {}", text(&out));
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("{tool}\n{asset}\n"),
            "{os} {arch}"
        );
    }
    let out = run("Linux", "riscv64");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unsupported architecture riscv64"),
        "{}",
        text(&out)
    );
}

/// Outside a pull request there is no base, so every open finding is new: the gate notes the
/// outcome and passes unless `gate-on-push: true`; on a pull request it always applies; any
/// other gate-on-push value exits 64.
#[test]
fn gate_is_not_enforced_on_push_unless_gate_on_push() {
    let r = Runner::new();
    r.grype(Some(
        serde_json::from_slice(&std::fs::read(capture("zephyr-old-mbedtls.grype.json")).unwrap())
            .unwrap(),
    ));
    let outputs = r.pipeline("fixtures/zephyr-old-mbedtls/old-mbedtls", "push", "high");
    assert_eq!(outputs["gate"], "findings");
    for event in ["push", "workflow_dispatch", "schedule"] {
        let out = r.gate_on(event, "findings", "high", &[]);
        assert_eq!(out.status.code(), Some(0), "{event}: {}", text(&out));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("::notice::") && stderr.contains("gate-on-push"),
            "{stderr}"
        );
        let out = r.gate_on(event, "findings", "high", &[("RC_GATE_ON_PUSH", "false")]);
        assert_eq!(out.status.code(), Some(0), "{event}: {}", text(&out));
    }
    let out = r.gate_on("push", "findings", "high", &[("RC_GATE_ON_PUSH", "true")]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("CVE-2026-34872"));
    let out = r.gate_on("push", "clean", "high", &[("RC_GATE_ON_PUSH", "true")]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let out = r.gate_on("pull_request", "findings", "high", &[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let out = r.gate_on("push", "findings", "high", &[("RC_GATE_ON_PUSH", "yes")]);
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
    // The action passes the input through to the gate step.
    let action = action_yml();
    assert_eq!(action["inputs"]["gate-on-push"]["default"], "false");
    let gate_step = action["runs"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["run"].as_str().is_some_and(|r| r.contains("gate.sh")))
        .unwrap();
    assert_eq!(
        gate_step["env"]["RC_GATE_ON_PUSH"],
        "${{ inputs.gate-on-push }}"
    );
}
