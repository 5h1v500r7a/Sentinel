// build.rs runs before compilation and tells cargo/rustc how to find the
// C library we depend on. Without this, the linker has no idea where
// `libsentinel_filter` or `libseccomp` live.
use std::path::PathBuf;

fn main() {
    // ../c/build relative to this crate, i.e. sentinel-sandbox/c/build
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut c_build_dir = PathBuf::from(manifest_dir);
    c_build_dir.pop(); // out of rust/
    c_build_dir.push("c");
    c_build_dir.push("build");

    println!("cargo:rustc-link-search=native={}", c_build_dir.display());
    println!("cargo:rustc-link-lib=dylib=sentinel_filter");
    println!("cargo:rustc-link-lib=dylib=seccomp");

    // Make sure the linked library actually exists at build time with a
    // clear error instead of a cryptic "cannot find -lsentinel_filter".
    if !c_build_dir.join("libsentinel_filter.so").exists() {
        panic!(
            "libsentinel_filter.so not found in {}.\n\
             Run `make` in the c/ directory first (see README.md).",
            c_build_dir.display()
        );
    }

    println!("cargo:rerun-if-changed=../c/seccomp_filter.c");
    println!("cargo:rerun-if-changed=../c/seccomp_filter.h");
}
