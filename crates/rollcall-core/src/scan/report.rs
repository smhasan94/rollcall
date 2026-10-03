//! The scan report (`rollcall-scan/1` JSON and the table), and the exit-code gate.

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use super::apply::{ScanFinding, Triage};
use crate::model::{ModelError, to_canonical_json};
use crate::severity::Severity;
use crate::vex::{SbomIndex, Scanner};
use crate::warning::Warning;

/// The `schema` of a [`ScanReport`].
pub const SCAN_SCHEMA: &str = "rollcall-scan/1";

/// How a scanner's run went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScannerStatus {
    /// It ran and its output was read.
    Ok,
    /// Not run: not installed, and not asked for by name (`--scanner auto`).
    Skipped,
    /// Missing although asked for, failed, or its output could not be read.
    Failed,
}

impl ScannerStatus {
    /// `ok`, `skipped` or `failed`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }
}

/// One scanner's run.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScannerRun {
    /// The scanner.
    pub scanner: Scanner,
    /// The version it reported, if it ran.
    pub version: Option<String>,
    /// How it went.
    pub status: ScannerStatus,
    /// Whether it used only a local database (`--db-path`).
    pub offline: bool,
}

impl Serialize for ScannerRun {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("ScannerRun", 4)?;
        st.serialize_field("name", &self.scanner.to_string())?;
        st.serialize_field("version", &self.version)?;
        st.serialize_field("status", self.status.as_str())?;
        st.serialize_field("offline", &self.offline)?;
        st.end()
    }
}

/// Open (not suppressed) findings per severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct OpenBySeverity {
    /// Critical.
    pub critical: usize,
    /// High.
    pub high: usize,
    /// Medium.
    pub medium: usize,
    /// Low.
    pub low: usize,
    /// Unknown.
    pub unknown: usize,
}

/// Counts over a report's findings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Every finding.
    pub total: usize,
    /// Suppressed by VEX.
    pub suppressed: usize,
    /// Claimed affected.
    pub affected: usize,
    /// Unresolved.
    pub unresolved: usize,
    /// Open findings per severity.
    pub open_by_severity: OpenBySeverity,
}

/// The scan report. Build it with [`ScanReport::new`] (or [`super::scan`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    /// The SBOM's `serialNumber`, if it has one.
    pub serial_number: Option<String>,
    /// The SBOM's `version`.
    pub version: u64,
    /// The scanners, sorted by name.
    pub scanners: Vec<ScannerRun>,
    /// The findings, sorted by severity (highest first), then id, then `bom-ref`.
    pub findings: Vec<ScanFinding>,
    /// Non-fatal problems, sorted and without duplicates.
    pub warnings: Vec<Warning>,
}

impl ScanReport {
    /// Assembles a report, sorting everything (see the [module docs](super)).
    pub fn new(
        sbom: &SbomIndex,
        mut scanners: Vec<ScannerRun>,
        mut findings: Vec<ScanFinding>,
        mut warnings: Vec<Warning>,
    ) -> Self {
        scanners.sort();
        scanners.dedup();
        findings.sort_by(|a, b| a.finding.sort_key().cmp(&b.finding.sort_key()));
        warnings.sort();
        warnings.dedup();
        Self {
            serial_number: sbom.serial_number.as_ref().map(|s| s.as_str().to_owned()),
            version: sbom.version,
            scanners,
            findings,
            warnings,
        }
    }

    /// Counts the findings.
    pub fn summary(&self) -> Summary {
        let mut s = Summary {
            total: self.findings.len(),
            ..Summary::default()
        };
        for f in &self.findings {
            match f.triage {
                Triage::Suppressed => s.suppressed += 1,
                Triage::Affected => s.affected += 1,
                Triage::Unresolved => s.unresolved += 1,
            }
            if f.triage.is_open() {
                let o = &mut s.open_by_severity;
                match f.finding.severity {
                    Severity::Critical => o.critical += 1,
                    Severity::High => o.high += 1,
                    Severity::Medium => o.medium += 1,
                    Severity::Low => o.low += 1,
                    Severity::Unknown => o.unknown += 1,
                }
            }
        }
        s
    }

    /// How many open findings have an unknown severity (they fail only `--fail-on unknown`).
    pub fn open_unknown_severity(&self) -> usize {
        self.summary().open_by_severity.unknown
    }

    /// The report as canonical `rollcall-scan/1` JSON, ending in a newline.
    pub fn to_json(&self) -> Result<String, ModelError> {
        to_canonical_json(self)
    }

    /// The report as a table: one row per finding (suppressed ones included), then a summary
    /// line and the scanners. Columns are as wide as their widest cell; no trailing spaces.
    pub fn to_table(&self) -> String {
        let mut rows: Vec<[String; 8]> = vec![[
            "SEVERITY".to_owned(),
            "ID".to_owned(),
            "COMPONENT".to_owned(),
            "VERSION".to_owned(),
            "FIXED".to_owned(),
            "TRIAGE".to_owned(),
            "VEX".to_owned(),
            "SOURCES".to_owned(),
        ]];
        let or_dash = |s: String| if s.is_empty() { "-".to_owned() } else { s };
        for f in &self.findings {
            let n = &f.finding;
            let (name, version) = match &n.component {
                Some(c) => (c.name.clone(), c.version.clone()),
                None => (
                    format!("{} (not in SBOM)", n.package.name),
                    n.package.version.clone(),
                ),
            };
            let mut scanners: Vec<String> =
                n.sources.iter().map(|s| s.scanner.to_string()).collect();
            scanners.dedup();
            let mut vex: Vec<&str> = f.vex.iter().map(|c| c.status.as_str()).collect();
            vex.sort_unstable();
            vex.dedup();
            rows.push([
                n.severity.to_string(),
                n.id.clone(),
                name,
                or_dash(version.unwrap_or_default()),
                or_dash(
                    n.fixed_versions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                f.triage.as_str().to_owned(),
                or_dash(vex.join(",")),
                or_dash(scanners.join(",")),
            ]);
        }
        // Cells come from scanner output and the SBOM: escape control characters so they
        // cannot drive the terminal or break the layout.
        for row in &mut rows {
            for cell in row.iter_mut() {
                if cell.chars().any(char::is_control) {
                    *cell = escape_controls(cell);
                }
            }
        }
        let mut widths = [0usize; 8];
        for row in &rows {
            for (w, cell) in widths.iter_mut().zip(row) {
                *w = (*w).max(cell.chars().count());
            }
        }
        let mut out = String::new();
        if self.findings.is_empty() {
            out.push_str("no findings\n");
        } else {
            for row in &rows {
                let mut line = String::new();
                for (i, (cell, w)) in row.iter().zip(widths).enumerate() {
                    if i > 0 {
                        line.push_str("  ");
                    }
                    line.push_str(cell);
                    let pad = w.saturating_sub(cell.chars().count());
                    line.extend(std::iter::repeat_n(' ', pad));
                }
                out.push_str(line.trim_end());
                out.push('\n');
            }
        }
        let s = self.summary();
        let o = s.open_by_severity;
        out.push_str(&format!(
            "\n{} finding(s): {} suppressed, {} affected, {} unresolved; open: {} critical, {} \
             high, {} medium, {} low, {} unknown\n",
            s.total,
            s.suppressed,
            s.affected,
            s.unresolved,
            o.critical,
            o.high,
            o.medium,
            o.low,
            o.unknown
        ));
        let scanners: Vec<String> = self
            .scanners
            .iter()
            .map(|r| {
                let mut text = r.scanner.to_string();
                if let Some(v) = &r.version {
                    text.push(' ');
                    text.push_str(v);
                }
                text.push_str(&format!(" ({}", r.status.as_str()));
                if r.offline {
                    text.push_str(", offline");
                }
                text.push(')');
                text
            })
            .collect();
        out.push_str(&format!("scanners: {}\n", scanners.join(", ")));
        out
    }
}

/// `text` with every control character written as a `\u{…}` escape.
fn escape_controls(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_unicode().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

impl Serialize for ScanReport {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Sbom<'a> {
            #[serde(rename = "serialNumber")]
            serial_number: &'a Option<String>,
            version: u64,
        }
        #[derive(Serialize)]
        struct W<'a> {
            location: &'a str,
            message: &'a str,
        }
        let warnings: Vec<W<'_>> = self
            .warnings
            .iter()
            .map(|w| W {
                location: &w.location,
                message: &w.message,
            })
            .collect();
        let mut st = s.serialize_struct("ScanReport", 6)?;
        st.serialize_field("schema", SCAN_SCHEMA)?;
        st.serialize_field(
            "sbom",
            &Sbom {
                serial_number: &self.serial_number,
                version: self.version,
            },
        )?;
        st.serialize_field("scanners", &self.scanners)?;
        st.serialize_field("findings", &self.findings)?;
        st.serialize_field("summary", &self.summary())?;
        st.serialize_field("warnings", &warnings)?;
        st.end()
    }
}

/// What a scan's gate decided. [`Outcome::code`] is the exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Exit 0: no gate failed.
    Clean,
    /// Exit 1: an open finding at or above `--fail-on`.
    Findings,
    /// Exit 2: an unresolved finding, with `--fail-on-unresolved`.
    Unresolved,
    /// Exit 3: a scanner was missing or failed, or its output was unreadable.
    ScannerFailed,
}

impl Outcome {
    /// The exit code: 0, 1, 2 or 3.
    pub fn code(self) -> u8 {
        match self {
            Self::Clean => 0,
            Self::Findings => 1,
            Self::Unresolved => 2,
            Self::ScannerFailed => 3,
        }
    }
}

/// The CI gate: `--fail-on` and `--fail-on-unresolved`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Gate {
    /// Fail (exit 1) on an open finding at or above this severity.
    pub fail_on: Option<Severity>,
    /// Fail (exit 2) on an unresolved finding.
    pub fail_on_unresolved: bool,
}

impl Gate {
    /// Decides the outcome: [`Outcome::ScannerFailed`] if any scanner failed or none ran,
    /// else [`Outcome::Findings`] if an open finding is at or above `fail_on`, else
    /// [`Outcome::Unresolved`] if `fail_on_unresolved` and a finding is unresolved, else
    /// [`Outcome::Clean`].
    pub fn decide(&self, report: &ScanReport) -> Outcome {
        let failed = report
            .scanners
            .iter()
            .any(|r| r.status == ScannerStatus::Failed);
        let none_ran = !report
            .scanners
            .iter()
            .any(|r| r.status == ScannerStatus::Ok);
        if failed || none_ran {
            return Outcome::ScannerFailed;
        }
        if let Some(threshold) = self.fail_on
            && report
                .findings
                .iter()
                .any(|f| f.triage.is_open() && f.finding.severity >= threshold)
        {
            return Outcome::Findings;
        }
        if self.fail_on_unresolved
            && report
                .findings
                .iter()
                .any(|f| f.triage == Triage::Unresolved)
        {
            return Outcome::Unresolved;
        }
        Outcome::Clean
    }
}

#[cfg(test)]
mod tests {
    use super::escape_controls;

    #[test]
    fn table_cells_escape_control_characters() {
        assert_eq!(escape_controls("CVE-1\u{1b}[2J\n"), "CVE-1\\u{1b}[2J\\u{a}");
        assert_eq!(escape_controls("mbedtls"), "mbedtls");
    }
}
