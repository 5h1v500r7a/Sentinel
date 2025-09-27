//! Raw FFI bindings to `c/seccomp_filter.h`.
//!
//! Beginner note: Rust can't call `seccomp_filter.c` directly by magic --
//! it needs to know the exact function signatures the C compiler
//! generated. `extern "C"` blocks are Rust's way of saying "trust me,
//! these functions exist with this shape, link against them". Every call
//! into this module is `unsafe` because Rust's compiler cannot verify
//! anything about what the C side does with the pointers we hand it --
//! that safety proof is on us instead. Keeping the unsafe surface small
//! and in one file, behind a single high-level entrypoint
//! (`sentinel_run_sandboxed`), is the standard pattern for wrapping a C
//! library: quarantine the danger, expose a safe API to the rest of the
//! program (see `launcher.rs`).

use std::os::raw::{c_char, c_int};

#[repr(C)]
#[derive(Copy, Clone)]
pub enum SentinelDefaultAction {
    KillProcess = 0,
    LogAndKill = 1,
    Errno = 2,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SentinelLimits {
    pub cpu_seconds: u64,
    pub address_space_mb: u64,
    pub open_files: u64,
}

extern "C" {
    /// See seccomp_filter.h for the full contract. `limits` may be null.
    /// `argv` must be NULL-terminated, matching execve()'s convention.
    pub fn sentinel_run_sandboxed(
        allowed_syscalls: *const *const c_char,
        count: usize,
        default_action: SentinelDefaultAction,
        log_path: *const c_char,
        policy_label: *const c_char,
        limits: *const SentinelLimits,
        argv: *const *const c_char,
    ) -> c_int;
}
