//! Cross-platform launcher for the angr-backed Ghidra decompiler core.
//!
//! Ghidra spawns an executable literally named `decompile` (`decompile.exe` on
//! Windows) with no arguments and speaks the decompiler protocol over
//! stdin/stdout in binary mode. This launcher stands in for that binary: it
//! locates a Python interpreter and the angr core entry point, then hands over
//! the process's stdio transparently so the Python core talks to Ghidra directly.
//!
//! It is a drop-in replacement for the old `bin/decompile` bash shim and honours
//! the same environment variables:
//!
//!   ANGR_GHIDRA_PYTHON    python interpreter to use (default: search PATH)
//!   ANGR_GHIDRA_CORE      path to the angr core entry (default: next to this
//!                         binary, else run `-m angr_ghidra_core.core.angr_core`)
//!   ANGR_GHIDRA_FALLBACK  if set, exec this stock `decompile` binary instead
//!                         (escape hatch to restore the original C++ core)
//!
//! No third-party crates: pure std for painless cross-compilation.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> ! {
    let args: Vec<OsString> = env::args_os().skip(1).collect();

    // Escape hatch: run the stock C++ decompiler instead.
    if let Some(fallback) = non_empty_env("ANGR_GHIDRA_FALLBACK") {
        let mut cmd = Command::new(fallback);
        cmd.args(&args);
        hand_over(cmd);
    }

    let exe_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));

    let python = resolve_python();
    let mut cmd = Command::new(&python);
    match resolve_core(&exe_dir) {
        Some(core) => {
            cmd.arg(core);
        }
        None => {
            // rely on the interpreter having the package importable
            cmd.arg("-m").arg("angr_ghidra_core.core.angr_core");
        }
    }
    cmd.args(&args);
    // stdin/stdout/stderr are inherited by default, giving a transparent,
    // binary-safe pass-through between Ghidra and the Python core.
    hand_over(cmd);
}

/// Resolve the value of an environment variable, treating empty as unset.
fn non_empty_env(key: &str) -> Option<OsString> {
    match env::var_os(key) {
        Some(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

fn resolve_python() -> PathBuf {
    if let Some(p) = non_empty_env("ANGR_GHIDRA_PYTHON") {
        return PathBuf::from(p);
    }
    // Prefer versioned names; on Windows the `py` launcher is a common fallback.
    let candidates: &[&str] = if cfg!(windows) {
        &["python", "python3", "py"]
    } else {
        &["python3", "python"]
    };
    for name in candidates {
        if let Some(found) = find_in_path(name) {
            return found;
        }
    }
    // Last resort: let the OS resolve a bare name at spawn time.
    PathBuf::from(candidates[0])
}

/// Locate the angr core entry point. Prefer an explicit override, then a file
/// sitting next to this launcher, else fall back to module execution (`-m`).
fn resolve_core(exe_dir: &Path) -> Option<PathBuf> {
    if let Some(c) = non_empty_env("ANGR_GHIDRA_CORE") {
        return Some(PathBuf::from(c));
    }
    for name in ["angr-decompile", "angr-decompile.py", "angr_decompile.py"] {
        let cand = exe_dir.join(name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

/// Search PATH for an executable, honouring PATHEXT on Windows.
fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let direct = dir.join(name);
        if is_file(&direct) {
            return Some(direct);
        }
        if cfg!(windows) {
            let exts = env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.BAT;.CMD".to_string());
            for ext in exts.split(';') {
                let ext = ext.trim();
                if ext.is_empty() {
                    continue;
                }
                let cand = dir.join(format!("{name}{ext}"));
                if is_file(&cand) {
                    return Some(cand);
                }
            }
        }
    }
    None
}

fn is_file(p: &Path) -> bool {
    p.is_file()
}

/// Transfer control to the child command. On Unix this replaces the current
/// process image (so Ghidra's process id is the Python core and signals reach
/// it directly). Elsewhere it spawns, waits, and propagates the exit code.
#[cfg(unix)]
fn hand_over(mut cmd: Command) -> ! {
    use std::os::unix::process::CommandExt;
    // exec only returns if it failed.
    let err = cmd.exec();
    eprintln!("angr-decompile: failed to exec {:?}: {err}", cmd.get_program());
    std::process::exit(127);
}

#[cfg(not(unix))]
fn hand_over(mut cmd: Command) -> ! {
    match cmd.status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(err) => {
            eprintln!(
                "angr-decompile: failed to spawn {:?}: {err}",
                cmd.get_program()
            );
            std::process::exit(127);
        }
    }
}
