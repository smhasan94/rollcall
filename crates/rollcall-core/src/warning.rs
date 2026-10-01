//! Non-fatal problems with inputs, shared by every ingester and reader.

use std::fmt;

/// A non-fatal problem with the inputs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Warning {
    /// The input it is about, e.g. `spdx/app.spdx` or `spdx/zephyr.spdx:1210`.
    pub location: String,
    /// What is wrong and what rollcall did about it.
    pub message: String,
}

impl Warning {
    /// A warning about `location`.
    pub fn new(location: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            location: location.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}
