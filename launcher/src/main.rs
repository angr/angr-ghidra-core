//! Cross-platform launcher for the angr-backed Ghidra decompiler core.
//!
//! Ghidra spawns an executable literally named `decompile` (`decompile.exe` on
//! Windows) with no arguments and speaks the decompiler protocol over
//! stdin/stdout in binary mode. This launcher stands in for that binary: it
//! locates a Python interpreter and the angr core entry point, then hands over
//! the process's stdio transparently so the Python core talks to Ghidra directly.
//!
//! Environment variables:
//!   ANGR_GHIDRA_PYTHON    python interpreter to use (default: search PATH)
//!   ANGR_GHIDRA_CORE      path to the angr core entry (default: next to this
//!                         binary, else run `-m angr_ghidra_core.core.angr_core`)
//!   ANGR_GHIDRA_FALLBACK  if set, exec this stock `decompile` binary instead
//!   ANGR_GHIDRA_LOG       if set, write a debug log here. A directory gets a
//!                         per-pid file (angr-decompile-<pid>.log); otherwise the
//!                         value is the log file path (appended to). Captures
//!                         launcher diagnostics and the child's stderr (e.g. a
//!                         Python traceback explaining "the pipe has ended").
//!   ANGR_GHIDRA_LOG_IO    with ANGR_GHIDRA_LOG set, also dump the raw protocol
//!                         bytes to <log>.stdin.bin / <log>.stdout.bin.
//!
//! No third-party crates: pure std for painless cross-compilation.

use std::env;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> ! {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    let logging = Logging::from_env();

    // Decide what to run, recording the resolution for the log.
    let mut plan: Vec<String> = Vec::new();
    let cmd = if let Some(fallback) = non_empty_env("ANGR_GHIDRA_FALLBACK") {
        plan.push(format!("mode=fallback program={fallback:?}"));
        let mut c = Command::new(fallback);
        c.args(&args);
        c
    } else {
        let exe_dir = env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."));
        let python = resolve_python();
        plan.push(format!("python={python:?}"));
        let mut c = Command::new(&python);
        match resolve_core(&exe_dir) {
            Some(core) => {
                plan.push(format!("core={core:?}"));
                c.arg(core);
            }
            None => {
                plan.push("core=(module) -m angr_ghidra_core.core.angr_core".to_string());
                c.arg("-m").arg("angr_ghidra_core.core.angr_core");
            }
        }
        c.args(&args);
        c
    };

    match logging {
        Some(lg) => {
            lg.header(&plan, &args);
            run_logged(cmd, lg)
        }
        None => hand_over(cmd),
    }
}

/// Resolve an environment variable, treating empty as unset.
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
    PathBuf::from(candidates[0])
}

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

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let direct = dir.join(name);
        if direct.is_file() {
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
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
    }
    None
}

/// Transfer control with no logging: replace the process on Unix (so Ghidra's
/// pid is the Python core and signals reach it directly), spawn-and-wait
/// elsewhere.
#[cfg(unix)]
fn hand_over(mut cmd: Command) -> ! {
    use std::os::unix::process::CommandExt;
    let err = cmd.exec();
    eprintln!("angr-decompile: failed to exec {:?}: {err}", cmd.get_program());
    std::process::exit(127);
}

#[cfg(not(unix))]
fn hand_over(mut cmd: Command) -> ! {
    match cmd.status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(err) => {
            eprintln!("angr-decompile: failed to spawn {:?}: {err}", cmd.get_program());
            std::process::exit(127);
        }
    }
}

// --------------------------------------------------------------------------
// Logging
// --------------------------------------------------------------------------

struct Logging {
    text: Arc<Mutex<File>>,
    path: PathBuf,
    trace_io: bool,
}

impl Logging {
    fn from_env() -> Option<Logging> {
        let raw = non_empty_env("ANGR_GHIDRA_LOG")?;
        let base = PathBuf::from(&raw);
        let path = if base.is_dir() {
            base.join(format!("angr-decompile-{}.log", std::process::id()))
        } else {
            base
        };
        let file = match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("angr-decompile: cannot open log {path:?}: {e}");
                return None;
            }
        };
        let trace_io = matches!(non_empty_env("ANGR_GHIDRA_LOG_IO"), Some(v) if v != "0");
        Some(Logging {
            text: Arc::new(Mutex::new(file)),
            path,
            trace_io,
        })
    }

    fn log(&self, msg: &str) {
        log_to(&self.text, msg);
    }

    fn header(&self, plan: &[String], args: &[OsString]) {
        self.log(&format!(
            "=== angr-decompile launcher v{} pid={} ===",
            env!("CARGO_PKG_VERSION"),
            std::process::id()
        ));
        if let Ok(cwd) = env::current_dir() {
            self.log(&format!("cwd={cwd:?}"));
        }
        if let Ok(exe) = env::current_exe() {
            self.log(&format!("exe={exe:?}"));
        }
        self.log(&format!("args={args:?}"));
        for line in plan {
            self.log(line);
        }
        for key in [
            "ANGR_GHIDRA_PYTHON",
            "ANGR_GHIDRA_CORE",
            "ANGR_GHIDRA_FALLBACK",
            "PYTHONPATH",
            "VIRTUAL_ENV",
            "PATH",
        ] {
            if let Some(v) = env::var_os(key) {
                self.log(&format!("env {key}={v:?}"));
            }
        }
        if self.trace_io {
            self.log(&format!(
                "io-trace=on stdin->{:?} stdout->{:?}",
                io_path(&self.path, "stdin"),
                io_path(&self.path, "stdout")
            ));
        }
    }
}

fn log_to(file: &Arc<Mutex<File>>, msg: &str) {
    // Include the pid on every line: Ghidra runs several decompile processes at
    // once (ParallelDecompiler), so a shared log file interleaves them.
    if let Ok(mut f) = file.lock() {
        let _ = writeln!(f, "[{} pid={}] {}", utc_stamp(), std::process::id(), msg);
        let _ = f.flush();
    }
}

fn io_path(base: &Path, which: &str) -> PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(format!(".{which}.bin"));
    PathBuf::from(s)
}

/// Spawn the child, capture its stderr (and optionally the protocol streams) to
/// the log, forward everything so Ghidra still sees it, then exit with the
/// child's status.
fn run_logged(mut cmd: Command, lg: Logging) -> ! {
    cmd.stderr(Stdio::piped());
    if lg.trace_io {
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
    } else {
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            lg.log(&format!("spawn FAILED: {e}"));
            eprintln!("angr-decompile: failed to spawn: {e}");
            std::process::exit(127);
        }
    };
    lg.log(&format!("spawned child pid={}", child.id()));

    // Threads that end on their own (child EOF) and should be joined before exit.
    let mut joinable = Vec::new();

    if let Some(cerr) = child.stderr.take() {
        let logfile = Arc::clone(&lg.text);
        joinable.push(thread::spawn(move || tee_stderr(cerr, logfile)));
    }

    if lg.trace_io {
        // Our stdin -> child stdin (+ capture). Reads Ghidra's stdin, which may
        // block indefinitely, so this thread is detached (not joined).
        if let Some(cin) = child.stdin.take() {
            let path = io_path(&lg.path, "stdin");
            thread::spawn(move || {
                let _ = tee_stream(std::io::stdin().lock(), cin, &path);
            });
        }
        // Child stdout -> our stdout (+ capture). Ends on child EOF; joined.
        if let Some(cout) = child.stdout.take() {
            let path = io_path(&lg.path, "stdout");
            joinable.push(thread::spawn(move || {
                let _ = tee_stream(cout, std::io::stdout().lock(), &path);
            }));
        }
    }

    let status = child.wait();
    match &status {
        Ok(s) => lg.log(&format!("child exited: {s}")),
        Err(e) => lg.log(&format!("wait failed: {e}")),
    }
    for h in joinable {
        let _ = h.join();
    }
    lg.log("launcher exiting");

    let code = status.ok().and_then(|s| s.code()).unwrap_or(1);
    std::process::exit(code);
}

/// Copy child stderr line by line to our stderr (so Ghidra still receives it)
/// and to the text log with a prefix.
fn tee_stderr(cerr: ChildStderr, logfile: Arc<Mutex<File>>) {
    let reader = BufReader::new(cerr);
    let mut errout = std::io::stderr();
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let _ = writeln!(errout, "{line}");
        let _ = errout.flush();
        log_to(&logfile, &format!("child-stderr: {line}"));
    }
}

/// Binary-safe copy from reader to writer, teeing every chunk to a capture file.
/// Flushes after each chunk so protocol bursts are delivered promptly.
fn tee_stream<R: Read, W: Write>(mut r: R, mut w: W, capture: &Path) -> std::io::Result<()> {
    let mut cap = File::create(capture).ok();
    let mut buf = [0u8; 8192];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if w.write_all(&buf[..n]).is_err() {
            break;
        }
        let _ = w.flush();
        if let Some(ref mut f) = cap {
            let _ = f.write_all(&buf[..n]);
            let _ = f.flush();
        }
    }
    Ok(())
}

/// UTC timestamp `YYYY-MM-DDThh:mm:ss.mmmZ` with no external crates.
fn utc_stamp() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs() as i64;
    let ms = d.subsec_millis();
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{ms:03}Z")
}
