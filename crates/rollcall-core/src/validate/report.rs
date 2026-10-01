//! The result of validating a document against profiles.

use std::fmt;

use serde::{Deserialize, Serialize};

/// How serious a finding is. Errors fail validation; warnings do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Reported, but the document still passes.
    Warning,
    /// The document fails the profile.
    Error,
}

impl Severity {
    /// `"warning"` or `"error"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `pad`, not `write_str`, so width and alignment (`{:<7}`) apply.
        f.pad(self.as_str())
    }
}

/// The source text a profile check encodes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Citation {
    /// The id of the profile citing it.
    pub profile: String,
    /// The source document, e.g. `Regulation (EU) 2024/2847 (Cyber Resilience Act)`.
    pub document: String,
    /// Where to read it, if the profile gives a URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The clause, e.g. `Annex I, Part II, point (1)`.
    pub clause: String,
}

/// One failed check, at one place in the document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The profiles that require this check (with these parameters).
    pub profiles: Vec<String>,
    /// The check id, e.g. `component.supplier`.
    pub check: String,
    /// Error or warning.
    pub severity: Severity,
    /// The failing component's `bom-ref`, if it is a component that has one.
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
    /// JSON pointer to the failing component or field.
    pub path: String,
    /// The failing component's name, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The failing component's version, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// What is wrong.
    pub message: String,
    /// How to fix it.
    pub fix: String,
    /// The clause each profile cites for the check.
    pub citations: Vec<Citation>,
    /// Sort key: (document-level 0 or node index + 1, check position, path, message).
    #[serde(skip)]
    pub(crate) order: (usize, usize),
}

impl fmt::Display for Finding {
    /// One line: `error  component.supplier  <bom-ref or path>  name@version: message.
    /// Fix: fix. [profile: clause; …]`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let location = self.r#ref.as_deref().unwrap_or(&self.path);
        write!(f, "{:<7}  {}  {}  ", self.severity, self.check, location)?;
        if let Some(name) = &self.name {
            f.write_str(name)?;
            if let Some(version) = &self.version {
                write!(f, "@{version}")?;
            }
            f.write_str(": ")?;
        }
        write!(f, "{}. Fix: {}.", self.message, self.fix)?;
        let cites: Vec<String> = self
            .citations
            .iter()
            .map(|c| format!("{}: {}", c.profile, c.clause))
            .collect();
        if !cites.is_empty() {
            write!(f, " [{}]", cites.join("; "))?;
        }
        Ok(())
    }
}

/// The result of [`super::validate_profiles`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// The profile ids, in the order given.
    pub profiles: Vec<String>,
    /// How many distinct checks ran (a check two profiles require with the same parameters
    /// runs once).
    pub checks_run: usize,
    /// Error-severity findings.
    pub errors: usize,
    /// Warning-severity findings.
    pub warnings: usize,
    /// Every finding: document-level first, then by component in document order, then by
    /// check.
    pub findings: Vec<Finding>,
}

impl Report {
    /// Whether the document passes: no error-severity findings (warnings are allowed).
    pub fn passed(&self) -> bool {
        self.errors == 0
    }
}
