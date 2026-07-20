//! Cross-platform launcher for the angr-backed Ghidra decompiler core.
//!
//! Ghidra spawns an executable literally named `decompile` (`decompile.exe` on
//! Windows) with no arguments and speaks the decompiler protocol over
//! stdin/stdout in binary mode. This launcher stands in for that binary: it
//! locates a Python interpreter and the angr core entry point, then hands over
//! the process's stdio transparently so the Python core talks to Ghidra directly.
//!
//! Configuration comes from a file sitting next to this executable
//! (`angr-decompile.conf`, or `decompile.conf`) and/or environment variables.
//! An environment variable wins when set; otherwise the config file value is
//! used. Relative paths in the config file are resolved against the config's
//! directory. See `angr-decompile.conf.example`.
//!
//!   setting       config key   env var                default
//!   interpreter   python       ANGR_GHIDRA_PYTHON     search PATH
//!   core entry    core         ANGR_GHIDRA_CORE       `angr-decompile` beside
//!                                                     the binary, else
//!                                                     `-m angr_ghidra_core...`
//!   fallback bin  fallback     ANGR_GHIDRA_FALLBACK   (none)
//!   PYTHONPATH    pythonpath   PYTHONPATH (prepended) (inherited)
//!   log target    log          ANGR_GHIDRA_LOG        (off)
//!   log raw io    log_io       ANGR_GHIDRA_LOG_IO     off
//!   child env     env.NAME     (that var, if exported) inherited
//!   server mode   server       ANGR_GHIDRA_SERVER     off
//!   server socket server_socket ANGR_GHIDRA_SERVER_SOCKET  per-user temp path
//!   server idle   server_idle  ANGR_GHIDRA_SERVER_IDLE   600 (seconds)
//!   cfg max size  cfg_max_size ANGR_GHIDRA_CFG_MAX_SIZE  512000 (bytes)
//!
//! In **server mode** the launcher connects to a shared, long-lived angr server
//! (starting it if absent) and proxies Ghidra's stdio to it over a local socket,
//! instead of starting a fresh Python+angr process each time. This keeps the
//! whole-image CFG cache warm across decompiles. On any connect/spawn failure it
//! falls back to the direct per-call mode below. Enabling `log` also uses the
//! direct mode so the debug log captures the core's stderr.
//!
//! No third-party crates: pure std for painless cross-compilation.

use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> ! {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));

    let cfg = Config::load(&exe_dir);
    let logging = Logging::from_config(&cfg);

    // Server mode: proxy to a shared long-lived angr server (starting it if
    // needed). Skipped when a fallback binary is set or logging is on (which
    // wants the core's own stderr). Returns only on failure -> direct mode.
    let has_fallback = cfg.path("ANGR_GHIDRA_FALLBACK", "fallback").is_some();
    if logging.is_none() && !has_fallback && cfg.flag("ANGR_GHIDRA_SERVER", "server") {
        try_server_mode(&cfg, &exe_dir);
        // fell through: server unavailable, continue to direct mode
    }

    let mut plan: Vec<String> = Vec::new();
    plan.push(match &cfg.source {
        Some(p) => format!("config={p:?}"),
        None => "config=(none)".to_string(),
    });

    let cmd = if let Some(fallback) = cfg.path("ANGR_GHIDRA_FALLBACK", "fallback") {
        plan.push(format!("mode=fallback program={fallback:?}"));
        let mut c = Command::new(fallback);
        c.args(&args);
        c
    } else {
        let python = resolve_python(&cfg);
        plan.push(format!("python={python:?}"));
        let mut c = Command::new(&python);
        match resolve_core(&cfg, &exe_dir) {
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
        apply_child_env(&mut c, &cfg, &mut plan);
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

// --------------------------------------------------------------------------
// Configuration (file beside the executable + environment overrides)
// --------------------------------------------------------------------------

struct Config {
    values: HashMap<String, String>,
    child_env: Vec<(String, String)>,
    dir: PathBuf,
    source: Option<PathBuf>,
}

impl Config {
    fn load(exe_dir: &Path) -> Config {
        for name in ["angr-decompile.conf", "decompile.conf"] {
            let candidate = exe_dir.join(name);
            if candidate.is_file() {
                if let Ok(text) = fs::read_to_string(&candidate) {
                    return Config::parse(&text, exe_dir.to_path_buf(), Some(candidate));
                }
            }
        }
        Config {
            values: HashMap::new(),
            child_env: Vec::new(),
            dir: exe_dir.to_path_buf(),
            source: None,
        }
    }

    fn parse(text: &str, dir: PathBuf, source: Option<PathBuf>) -> Config {
        let mut values = HashMap::new();
        let mut child_env = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some(idx) = line.find(['=', ':']) else {
                continue;
            };
            let key = line[..idx].trim();
            let value = strip_quotes(line[idx + 1..].trim());
            if let Some(name) = key.strip_prefix("env.") {
                child_env.push((name.trim().to_string(), value.to_string()));
            } else {
                values.insert(key.to_ascii_lowercase(), value.to_string());
            }
        }
        Config {
            values,
            child_env,
            dir,
            source,
        }
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    /// Resolve a path setting: the environment variable wins; otherwise the
    /// config value (relative paths resolved against the config directory).
    fn path(&self, env_key: &str, cfg_key: &str) -> Option<PathBuf> {
        if let Some(v) = non_empty_env(env_key) {
            return Some(PathBuf::from(v));
        }
        self.get(cfg_key).map(|s| self.resolve(s))
    }

    /// Resolve a scalar (non-path) setting: environment variable wins.
    fn scalar(&self, env_key: &str, cfg_key: &str) -> Option<String> {
        if let Some(v) = non_empty_env(env_key) {
            return v.into_string().ok();
        }
        self.get(cfg_key).map(str::to_string)
    }

    fn flag(&self, env_key: &str, cfg_key: &str) -> bool {
        matches!(self.scalar(env_key, cfg_key), Some(v) if !v.is_empty() && v != "0")
    }

    fn resolve(&self, value: &str) -> PathBuf {
        let p = PathBuf::from(value);
        if p.is_absolute() {
            p
        } else {
            self.dir.join(p)
        }
    }
}

fn strip_quotes(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn non_empty_env(key: &str) -> Option<OsString> {
    match env::var_os(key) {
        Some(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

fn resolve_python(cfg: &Config) -> PathBuf {
    if let Some(p) = cfg.path("ANGR_GHIDRA_PYTHON", "python") {
        return p;
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

fn resolve_core(cfg: &Config, exe_dir: &Path) -> Option<PathBuf> {
    if let Some(c) = cfg.path("ANGR_GHIDRA_CORE", "core") {
        return Some(c);
    }
    for name in ["angr-decompile", "angr-decompile.py", "angr_decompile.py"] {
        let cand = exe_dir.join(name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

/// Apply child environment: prepend a configured `pythonpath` to PYTHONPATH and
/// pass through any `env.NAME` entries.
fn apply_child_env(cmd: &mut Command, cfg: &Config, plan: &mut Vec<String>) {
    if let Some(pp) = cfg.path("", "pythonpath") {
        let mut entries: Vec<PathBuf> = vec![pp.clone()];
        if let Some(existing) = env::var_os("PYTHONPATH") {
            entries.extend(env::split_paths(&existing));
        }
        if let Ok(joined) = env::join_paths(&entries) {
            plan.push(format!("PYTHONPATH={joined:?}"));
            cmd.env("PYTHONPATH", joined);
        }
    }
    for (name, value) in &cfg.child_env {
        plan.push(format!("env {name}={value:?}"));
        cmd.env(name, value);
    }
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
// Server mode: proxy Ghidra's stdio to a shared long-lived angr server
// --------------------------------------------------------------------------

/// Try to connect to (or start) the shared server and proxy stdio to it. On
/// success this never returns (it exits with the session's status). On any
/// setup failure it returns so the caller can use direct mode.
fn try_server_mode(cfg: &Config, exe_dir: &Path) {
    let socket_path = server_socket_path(cfg);
    let idle = cfg
        .scalar("ANGR_GHIDRA_SERVER_IDLE", "server_idle")
        .unwrap_or_else(|| "600".to_string());

    // one quick attempt to connect; if it fails, start a server and retry
    if let Some(stream) = connect_socket(&socket_path) {
        proxy_and_exit(stream);
    }
    if !spawn_server(cfg, exe_dir, &socket_path, &idle) {
        return; // couldn't even launch a server -> direct mode
    }
    // the server races to bind; poll for it to come up (~10s)
    for _ in 0..200 {
        if let Some(stream) = connect_socket(&socket_path) {
            proxy_and_exit(stream);
        }
        thread::sleep(std::time::Duration::from_millis(50));
    }
    // server never came up -> fall back to direct mode
}

/// Default per-user socket path (overridable). Kept per-user so different users
/// never share a server; the directory is created 0700.
fn server_socket_path(cfg: &Config) -> PathBuf {
    if let Some(p) = cfg.path("ANGR_GHIDRA_SERVER_SOCKET", "server_socket") {
        return p;
    }
    #[cfg(unix)]
    {
        let uid = unsafe { libc_getuid() };
        let base = env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| env::temp_dir());
        let dir = base.join(format!("angr-ghidra-{uid}"));
        let _ = fs::create_dir_all(&dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        dir.join("decompile.sock")
    }
    #[cfg(not(unix))]
    {
        // Windows: a token file holding "port\ntoken"
        env::temp_dir().join("angr-ghidra-decompile.token")
    }
}

#[cfg(unix)]
extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}

#[cfg(unix)]
fn connect_socket(path: &Path) -> Option<ServerStream> {
    use std::os::unix::net::UnixStream;
    UnixStream::connect(path).ok().map(ServerStream::Unix)
}

#[cfg(not(unix))]
fn connect_socket(token_path: &Path) -> Option<ServerStream> {
    use std::net::TcpStream;
    let text = fs::read_to_string(token_path).ok()?;
    let mut lines = text.lines();
    let port: u16 = lines.next()?.trim().parse().ok()?;
    let token = lines.next()?.trim().to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    // hand the token to the server first so it can authenticate the connection
    stream.write_all(format!("{token}\n").as_bytes()).ok()?;
    Some(ServerStream::Tcp(stream))
}

/// Start the server daemon detached: it must outlive this launcher process and
/// serve later invocations. Its stdio is discarded (it speaks over the socket).
fn spawn_server(cfg: &Config, exe_dir: &Path, socket_path: &Path, idle: &str) -> bool {
    let python = resolve_python(cfg);
    let mut c = Command::new(&python);
    c.arg("-m").arg("angr_ghidra_core.core.server_daemon");
    #[cfg(unix)]
    {
        c.arg("--socket").arg(socket_path);
    }
    #[cfg(not(unix))]
    {
        c.arg("--tcp").arg(socket_path);
    }
    c.arg("--idle").arg(idle);
    let mut plan = Vec::new();
    apply_child_env(&mut c, cfg, &mut plan);
    if let Some(ms) = cfg.scalar("ANGR_GHIDRA_CFG_MAX_SIZE", "cfg_max_size") {
        c.env("ANGR_GHIDRA_CFG_MAX_SIZE", ms);
    }
    let _ = exe_dir; // core module is resolved via PYTHONPATH/env, like direct mode
    c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    detach(&mut c);
    c.spawn().is_ok()
}

/// Put the spawned server in its own session so it is not torn down when Ghidra
/// reaps this launcher (Unix: setsid via pre_exec).
#[cfg(unix)]
fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            // detach from the controlling terminal/process group
            extern "C" {
                fn setsid() -> i32;
            }
            setsid();
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn detach(_cmd: &mut Command) {}

enum ServerStream {
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    #[cfg(not(unix))]
    Tcp(std::net::TcpStream),
}

/// Proxy Ghidra's stdin/stdout to the server socket byte-for-byte, then exit.
/// Ends when either side closes: Ghidra's stdin EOF (tool shutdown) or the
/// server closing the connection (deregisterProgram).
fn proxy_and_exit(stream: ServerStream) -> ! {
    let (mut to_srv, mut from_srv) = match stream {
        #[cfg(unix)]
        ServerStream::Unix(s) => {
            let r = s.try_clone().expect("clone socket");
            (StreamBox::Unix(s), StreamBox::Unix(r))
        }
        #[cfg(not(unix))]
        ServerStream::Tcp(s) => {
            let r = s.try_clone().expect("clone socket");
            (StreamBox::Tcp(s), StreamBox::Tcp(r))
        }
    };

    // stdin -> server (detached: reading Ghidra's stdin may block indefinitely;
    // on EOF we shut the write half so the server sees the session end)
    thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let _ = copy_stream(&mut stdin, &mut to_srv);
        to_srv.shutdown_write();
    });

    // server -> stdout (this is the lifetime of the session)
    let mut stdout = std::io::stdout().lock();
    let _ = copy_stream(&mut from_srv, &mut stdout);
    let _ = stdout.flush();
    std::process::exit(0);
}

enum StreamBox {
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    #[cfg(not(unix))]
    Tcp(std::net::TcpStream),
}

impl StreamBox {
    fn shutdown_write(&self) {
        match self {
            #[cfg(unix)]
            StreamBox::Unix(s) => {
                let _ = s.shutdown(std::net::Shutdown::Write);
            }
            #[cfg(not(unix))]
            StreamBox::Tcp(s) => {
                let _ = s.shutdown(std::net::Shutdown::Write);
            }
        }
    }
}

impl Read for StreamBox {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            StreamBox::Unix(s) => s.read(buf),
            #[cfg(not(unix))]
            StreamBox::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for StreamBox {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            StreamBox::Unix(s) => s.write(buf),
            #[cfg(not(unix))]
            StreamBox::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            StreamBox::Unix(s) => s.flush(),
            #[cfg(not(unix))]
            StreamBox::Tcp(s) => s.flush(),
        }
    }
}

/// Binary-safe copy that flushes each chunk (the protocol is interactive, so we
/// must not buffer a burst waiting for more input).
fn copy_stream<R: Read, W: Write>(r: &mut R, w: &mut W) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        w.write_all(&buf[..n])?;
        w.flush()?;
    }
    Ok(())
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
    fn from_config(cfg: &Config) -> Option<Logging> {
        let base = cfg.path("ANGR_GHIDRA_LOG", "log")?;
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
        Some(Logging {
            text: Arc::new(Mutex::new(file)),
            path,
            trace_io: cfg.flag("ANGR_GHIDRA_LOG_IO", "log_io"),
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

    let mut joinable = Vec::new();

    if let Some(cerr) = child.stderr.take() {
        let logfile = Arc::clone(&lg.text);
        joinable.push(thread::spawn(move || tee_stderr(cerr, logfile)));
    }

    if lg.trace_io {
        if let Some(cin) = child.stdin.take() {
            let path = io_path(&lg.path, "stdin");
            // Reads Ghidra's stdin, which may block indefinitely; detached.
            thread::spawn(move || {
                let _ = tee_stream(std::io::stdin().lock(), cin, &path);
            });
        }
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
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{ms:03}Z")
}
