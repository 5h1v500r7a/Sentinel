"""
sentinel_cli
============
The Python "front door" of the Sentinel Sandbox project.

This package deliberately does NOT reimplement any sandboxing logic --
that all lives in the Rust launcher (rust/) and the C seccomp/ptrace
engine (c/). This package's job is purely orchestration and reporting:

  * find and invoke the compiled sentinel-launcher binary correctly
    (right working directory, right LD_LIBRARY_PATH, right arguments)
  * run the bundled demo attack suite and explain what happened
  * shell out to the C++ log analyzer and present its report nicely

If you're a recruiter or a beginner skimming this project: this is the
"friendly" layer. Read README.md first, then this package if you want to
see how the pieces are wired together without needing to read C, Rust,
or C++ first.
"""

__version__ = "0.1.0"
