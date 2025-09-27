//! sentinel-launcher
//! ------------------
//! Rust core of the Sentinel Sandbox project. This binary is normally
//! invoked BY the Python CLI (`python/sentinel_cli`), but it is a
//! complete, independent tool on its own:
//!
//!   sentinel-launcher --policy policies/web-server.toml \
//!                      --log logs/violations.jsonl \
//!                      -- /usr/bin/my-server --port 8080
//!
//! Responsibilities that live HERE rather than in Python or C:
//!   - parsing the human-editable policy file (policy.rs)
//!   - forking/exec'ing the target program with rlimits + the seccomp
//!     filter applied in the narrow pre-fork/pre-exec window (launcher.rs)
//!   - translating the C library's int error codes into readable messages
//!
//! Why Rust for this layer and not more C? This is exactly the kind of
//! code (argument parsing, string handling, process orchestration) where
//! memory-safety bugs are historically common in security tooling written
//! in C, and where Rust's ownership model removes whole bug classes for
//! free, while still letting us drop to `unsafe` FFI in the one place
//! (ffi.rs/launcher.rs) where we truly need raw C interop.

mod ffi;
mod launcher;
mod policy;

use std::path::PathBuf;
use std::process::ExitCode;

struct Args {
    policy_path: PathBuf,
    log_path: PathBuf,
    target_cmd: Vec<String>,
}

fn print_usage(program: &str) {
    eprintln!(
        "Usage: {program} --policy <policy.toml> --log <violations.jsonl> -- <target-cmd> [args...]\n\n\
         Example:\n  {program} --policy ../policies/untrusted-script.toml --log ../logs/violations.jsonl -- /bin/ls -la"
    );
}

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().collect();
    let program = raw.first().cloned().unwrap_or_else(|| "sentinel-launcher".into());

    let mut policy_path: Option<PathBuf> = None;
    let mut log_path: Option<PathBuf> = None;
    let mut target_cmd: Vec<String> = Vec::new();

    let mut i = 1;
    while i < raw.len() {
        match raw[i].as_str() {
            "--policy" => {
                i += 1;
                policy_path = Some(PathBuf::from(
                    raw.get(i).ok_or("--policy needs a value")?,
                ));
            }
            "--log" => {
                i += 1;
                log_path = Some(PathBuf::from(raw.get(i).ok_or("--log needs a value")?));
            }
            "--help" | "-h" => {
                print_usage(&program);
                std::process::exit(0);
            }
            "--" => {
                target_cmd = raw[i + 1..].to_vec();
                break;
            }
            other => return Err(format!("unrecognised argument: {other}")),
        }
        i += 1;
    }

    let policy_path = policy_path.ok_or("missing required --policy <file>")?;
    let log_path = log_path.ok_or("missing required --log <file>")?;
    if target_cmd.is_empty() {
        return Err("missing target command; put it after a literal `--`".into());
    }

    Ok(Args { policy_path, log_path, target_cmd })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[sentinel-launcher] error: {e}\n");
            print_usage("sentinel-launcher");
            return ExitCode::from(2);
        }
    };

    let policy = match policy::load_policy(&args.policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[sentinel-launcher] {e}");
            return ExitCode::from(2);
        }
    };

    eprintln!(
        "[sentinel-launcher] policy=\"{}\" default_action={} allowed_syscalls={} target={:?}",
        policy.name,
        policy.default_action,
        policy.allowed_syscalls.len(),
        args.target_cmd
    );

    match launcher::run_sandboxed(&policy, &args.log_path, &args.target_cmd) {
        Ok(launcher::Outcome::Exited(code)) => {
            eprintln!("[sentinel-launcher] target exited normally with code {code}");
            ExitCode::from(code as u8)
        }
        Ok(launcher::Outcome::Killed(sig)) => {
            eprintln!(
                "[sentinel-launcher] target was killed by signal {sig} \
                 (this is expected if it tripped the sandbox policy -- check the log)"
            );
            ExitCode::from(128u8.wrapping_add(sig as u8))
        }
        Ok(launcher::Outcome::SetupFailed) => {
            eprintln!("[sentinel-launcher] sandbox setup failed before the target could run");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[sentinel-launcher] launch failed: {e}");
            ExitCode::FAILURE
        }
    }
}
