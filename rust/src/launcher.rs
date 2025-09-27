//! The safe(r) layer between `main.rs` and the raw C FFI in `ffi.rs`.
//!
//! All the actual forking/ptrace/seccomp work happens in one C call,
//! `sentinel_run_sandboxed()`; this module's job is just to turn Rust
//! data (the parsed `Policy`, a target argv) into the C-shaped
//! arguments that call needs, and turn its integer result back into
//! something a Rust `main()` can act on.

use crate::ffi::{self, SentinelDefaultAction, SentinelLimits};
use crate::policy::Policy;
use std::ffi::CString;
use std::path::Path;

pub struct LaunchError(pub String);

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What happened to the sandboxed program, decoded from the raw
/// waitpid-style status `sentinel_run_sandboxed` returns.
pub enum Outcome {
    /// Ran to completion; carries its exit code.
    Exited(i32),
    /// Killed by a signal (e.g. SIGKILL because it tripped the sandbox,
    /// or a real crash like SIGSEGV). Carries the signal number.
    Killed(i32),
    /// Something failed before/around the child even ran.
    SetupFailed,
}

fn action_from_str(s: &str) -> Result<SentinelDefaultAction, LaunchError> {
    match s {
        "kill" => Ok(SentinelDefaultAction::KillProcess),
        "log-and-kill" => Ok(SentinelDefaultAction::LogAndKill),
        "errno" => Ok(SentinelDefaultAction::Errno),
        other => Err(LaunchError(format!(
            "unknown default_action \"{other}\" (expected kill | log-and-kill | errno)"
        ))),
    }
}

/// Decodes a Linux waitpid()-style status int the same way the
/// WIFEXITED/WEXITSTATUS/WIFSIGNALED/WTERMSIG macros would, without
/// pulling in a whole extra crate for four bit-twiddling macros.
fn decode_status(status: i32) -> Outcome {
    if status < 0 {
        return Outcome::SetupFailed;
    }
    let status = status as u32;
    if status & 0x7f == 0 {
        Outcome::Exited(((status & 0xff00) >> 8) as i32)
    } else {
        // WIFSIGNALED: low 7 bits are the signal, and (status & 0x7f) + 1
        // isn't 0x7f (that special value means "stopped", not our case
        // here since we always waitpid without WUNTRACED at the top
        // level).
        Outcome::Killed((status & 0x7f) as i32)
    }
}

/// Runs `target_cmd` (program + args) under `policy`, blocking until it
/// finishes. Violations are appended to `log_path` (only meaningful for
/// the `log-and-kill` default action).
pub fn run_sandboxed(
    policy: &Policy,
    log_path: &Path,
    target_cmd: &[String],
) -> Result<Outcome, LaunchError> {
    if target_cmd.is_empty() {
        return Err(LaunchError("no target command given after `--`".into()));
    }

    let default_action = action_from_str(&policy.default_action)?;

    let log_path_c = CString::new(log_path.to_string_lossy().as_bytes())
        .map_err(|e| LaunchError(format!("log path has embedded NUL: {e}")))?;
    let label_c = CString::new(policy.name.as_bytes())
        .map_err(|e| LaunchError(format!("policy name has embedded NUL: {e}")))?;

    let syscalls_c: Vec<CString> = policy
        .allowed_syscalls
        .iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|e| LaunchError(format!("bad syscall name: {e}")))?;
    let syscall_ptrs: Vec<*const std::os::raw::c_char> =
        syscalls_c.iter().map(|c| c.as_ptr()).collect();

    let argv_c: Vec<CString> = target_cmd
        .iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|e| LaunchError(format!("bad argument (embedded NUL): {e}")))?;
    // execve-style argv must be NULL-terminated.
    let mut argv_ptrs: Vec<*const std::os::raw::c_char> =
        argv_c.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    let limits = SentinelLimits {
        cpu_seconds: policy.limits.cpu_seconds,
        address_space_mb: policy.limits.address_space_mb,
        open_files: policy.limits.open_files,
    };

    // SAFETY: every pointer handed to C below is backed by a CString (or
    // a Vec of them) that stays alive for the whole call because it's
    // still in scope right here; `sentinel_run_sandboxed` is documented
    // to only read them for the duration of the (blocking) call, never
    // to retain them afterward.
    let status = unsafe {
        ffi::sentinel_run_sandboxed(
            syscall_ptrs.as_ptr(),
            syscall_ptrs.len(),
            default_action,
            log_path_c.as_ptr(),
            label_c.as_ptr(),
            &limits as *const SentinelLimits,
            argv_ptrs.as_ptr(),
        )
    };

    Ok(decode_status(status))
}
