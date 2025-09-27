//! Loads a `.toml` policy file into a strongly-typed `Policy` struct.
//!
//! A policy file is the thing a human (you) actually edits. Everything
//! else in this project exists to turn it into kernel enforcement. See
//! `policies/*.toml` for real examples with comments.

use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Policy {
    /// Free-text name, purely for logging/reporting (e.g. "web-server").
    pub name: String,

    /// What to do about syscalls that are NOT in `allowed_syscalls`.
    /// One of: "kill", "log-and-kill", "errno". See README for trade-offs.
    #[serde(default = "default_action")]
    pub default_action: String,

    /// Exact syscall names (as in `man 2 syscalls` / strace output) this
    /// policy allows. Everything else is denied.
    pub allowed_syscalls: Vec<String>,

    /// Optional soft resource limits applied before the seccomp filter is
    /// installed (belt-and-braces: even allowed syscalls can be capped).
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Deserialize, Default)]
pub struct Limits {
    /// Max CPU time in seconds. 0/omitted = no extra limit imposed.
    #[serde(default)]
    pub cpu_seconds: u64,
    /// Max address space size in megabytes. 0/omitted = no extra limit.
    #[serde(default)]
    pub address_space_mb: u64,
    /// Max number of file descriptors. 0/omitted = no extra limit.
    #[serde(default)]
    pub open_files: u64,
}

fn default_action() -> String {
    "log-and-kill".to_string()
}

#[derive(Debug)]
pub enum PolicyError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Empty,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::Io(e) => write!(f, "could not read policy file: {e}"),
            PolicyError::Parse(e) => write!(f, "could not parse policy TOML: {e}"),
            PolicyError::Empty => write!(f, "policy has an empty allowed_syscalls list"),
        }
    }
}

pub fn load_policy(path: &Path) -> Result<Policy, PolicyError> {
    let text = fs::read_to_string(path).map_err(PolicyError::Io)?;
    let policy: Policy = toml::from_str(&text).map_err(PolicyError::Parse)?;
    if policy.allowed_syscalls.is_empty() {
        return Err(PolicyError::Empty);
    }
    Ok(policy)
}
