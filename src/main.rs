#![cfg(windows)]

use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use open;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
use windows::Win32::System::ProcessStatus::K32GetModuleFileNameExW;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const STARTUP_POLL_ATTEMPTS: usize = 20;
const SHUTDOWN_POLL_ATTEMPTS: usize = 20;
const POLL_DELAY_MS: u64 = 250;

#[derive(Parser)]
#[command(
    name = "lampctl",
    version,
    about = "CLI mirroring the XAMPP Control Panel's Apache actions"
)]
struct Cli {
    #[command(subcommand)]
    command: CommandGroup,
}

#[derive(Subcommand)]
enum CommandGroup {
    /// Apache operations (start/stop/restart/logs/admin/config)
    Apache {
        #[command(subcommand)]
        action: ApacheAction,
    },
    /// Print detected XAMPP root directory
    Root,
    /// Show LampCTL, Apache, and PHP versions
    Version,
}

#[derive(Subcommand, Clone, Copy, Debug, Eq, PartialEq)]
enum ApacheAction {
    /// Start Apache (foreground instance)
    Start {
        /// Print Apache output in this terminal (do not run hidden)
        #[arg(long)]
        output: bool,
    },
    /// Stop Apache
    Stop,
    /// Restart Apache
    Restart,
    /// Show running status (PID or stopped)
    Status,
    /// Open apache\logs\error.log in the default viewer
    Logs,
    /// Open http://localhost/ in the default browser
    Admin,
    /// Open apache\conf\httpd.conf in the default editor
    Config,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = detect_xampp_root()?;

    match cli.command {
        CommandGroup::Apache { action } => handle_apache(action, &root)?,
        CommandGroup::Root => println!("{}", root.display()),
        CommandGroup::Version => show_versions(&root)?,
    }

    Ok(())
}

fn handle_apache(action: ApacheAction, root: &Path) -> Result<()> {
    match action {
        ApacheAction::Start { output } => start_apache(root, output),
        ApacheAction::Stop => stop_apache(root),
        ApacheAction::Restart => restart_apache(root),
        ApacheAction::Status => status_apache(root),
        ApacheAction::Logs => open_logs(root),
        ApacheAction::Admin => open_admin(),
        ApacheAction::Config => open_config(root),
    }
}

fn start_apache(root: &Path, output: bool) -> Result<()> {
    if let Some(pid) = current_apache_pid(root)? {
        println!("Apache already running (PID {}).", pid);
        return Ok(());
    }

    let httpd = httpd_path(root)?;

    if output {
        // Run httpd in the current terminal, inheriting stdio so output appears directly.
        // This will block until httpd exits; closing the terminal will terminate Apache.
        let status = Command::new(&httpd)
            .current_dir(root)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| format!("failed to run {}", httpd.display()))?;

        if status.success() {
            println!("Apache exited with status {:?}", status.code());
            Ok(())
        } else {
            bail!("Apache exited with status {:?}", status.code())
        }
    } else {
        // Background/hidden start (existing behavior)
        Command::new(&httpd)
            .current_dir(root)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .with_context(|| format!("failed to spawn {}", httpd.display()))?;

        let pid = wait_for_apache_pid(root, STARTUP_POLL_ATTEMPTS)?.ok_or_else(|| {
            anyhow!(
                "Apache failed to start – see {}",
                root.join("apache").join("logs").join("error.log").display()
            )
        })?;

        println!("Apache started (PID {}).", pid);
        Ok(())
    }
}

fn stop_apache(root: &Path) -> Result<()> {
    let Some(pid) = current_apache_pid(root)? else {
        println!("Apache is already stopped.");
        cleanup_pid_file(root);
        return Ok(());
    };

    kill_process_tree(pid)?;
    wait_for_shutdown(root, SHUTDOWN_POLL_ATTEMPTS)?;
    cleanup_pid_file(root);

    println!("Apache stopped (PID {}).", pid);
    Ok(())
}

fn restart_apache(root: &Path) -> Result<()> {
    stop_apache(root)?;
    thread::sleep(Duration::from_millis(500));
    start_apache(root, false)
}

fn open_logs(root: &Path) -> Result<()> {
    let log_path = root.join("apache").join("logs").join("error.log");
    if !log_path.exists() {
        bail!("{} does not exist", log_path.display());
    }
    open::that(&log_path).context("failed to open Apache error log")?;
    Ok(())
}

fn open_admin() -> Result<()> {
    open::that("http://localhost/").context("failed to open http://localhost/")?;
    Ok(())
}

fn open_config(root: &Path) -> Result<()> {
    let conf = root.join("apache").join("conf").join("httpd.conf");
    if !conf.exists() {
        bail!("{} does not exist", conf.display());
    }
    open::that(&conf).context("failed to open httpd.conf")?;
    Ok(())
}

fn show_versions(root: &Path) -> Result<()> {
    println!("lampctl {}", env!("CARGO_PKG_VERSION"));
    println!("xampp root: {}", root.display());

    if let Some(line) =
        exec_and_first_line(root.join("apache").join("bin").join("httpd.exe"), ["-v"])
    {
        println!("apache: {}", line);
    }
    if let Some(line) = exec_and_first_line(root.join("php").join("php.exe"), ["-v"]) {
        println!("php: {}", line);
    }

    Ok(())
}

fn exec_and_first_line<I, S>(exe: PathBuf, args: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    if !exe.exists() {
        return None;
    }
    let output = Command::new(&exe).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().next().map(|line| line.trim().to_string())
}

fn detect_xampp_root() -> Result<PathBuf> {
    if let Ok(from_env) = env::var("LAMPCTL_XAMPP_ROOT") {
        let path = PathBuf::from(from_env);
        if is_xampp_root(&path) {
            return Ok(path);
        } else {
            bail!(
                "{} is not a XAMPP root (apache/bin/httpd.exe missing)",
                path.display()
            );
        }
    }

    let exe = env::current_exe().context("unable to resolve current executable path")?;
    let mut candidate = exe.as_path();

    while let Some(dir) = candidate.parent() {
        if is_xampp_root(dir) {
            return Ok(dir.to_path_buf());
        }
        let sibling = dir.join("xampp");
        if is_xampp_root(&sibling) {
            return Ok(sibling);
        }
        candidate = dir;
    }

    Err(anyhow!(
        "Failed to locate XAMPP root. Move lampctl next to xampp-control.exe or set LAMPCTL_XAMPP_ROOT."
    ))
}

fn is_xampp_root(path: &Path) -> bool {
    path.join("apache").join("bin").join("httpd.exe").exists()
}

fn httpd_path(root: &Path) -> Result<PathBuf> {
    let path = root.join("apache").join("bin").join("httpd.exe");
    if path.exists() {
        Ok(path)
    } else {
        bail!("{} not found", path.display());
    }
}

fn pid_file(root: &Path) -> PathBuf {
    root.join("apache").join("logs").join("httpd.pid")
}

fn cleanup_pid_file(root: &Path) {
    let pid_path = pid_file(root);
    if pid_path.exists() {
        let _ = fs::remove_file(pid_path);
    }
}

fn wait_for_apache_pid(root: &Path, attempts: usize) -> Result<Option<u32>> {
    for _ in 0..attempts {
        if let Some(pid) = read_pid(root)? {
            if process_matches_httpd(pid, root)? {
                return Ok(Some(pid));
            }
        }
        thread::sleep(Duration::from_millis(POLL_DELAY_MS));
    }
    Ok(None)
}

fn wait_for_shutdown(root: &Path, attempts: usize) -> Result<()> {
    for _ in 0..attempts {
        if current_apache_pid(root)?.is_none() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(POLL_DELAY_MS));
    }
    bail!("Apache process did not exit in time");
}

fn current_apache_pid(root: &Path) -> Result<Option<u32>> {
    let Some(pid) = read_pid(root)? else {
        return Ok(None);
    };

    if process_matches_httpd(pid, root)? {
        Ok(Some(pid))
    } else {
        Ok(None)
    }
}

fn read_pid(root: &Path) -> Result<Option<u32>> {
    let path = pid_file(root);
    if !path.exists() {
        return Ok(None);
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let pid = trimmed
        .parse::<u32>()
        .with_context(|| format!("invalid PID in {}", path.display()))?;
    Ok(Some(pid))
}

fn process_matches_httpd(pid: u32, root: &Path) -> Result<bool> {
    let expected = fs::canonicalize(httpd_path(root)?)?;
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }?;

    let image = query_process_image(handle);
    unsafe {
        let _ = CloseHandle(handle);
    }

    let actual = match image {
        Ok(path) => path,
        Err(_) => return Ok(false),
    };

    match fs::canonicalize(actual) {
        Ok(actual_path) => Ok(actual_path == expected),
        Err(_) => Ok(false),
    }
}

fn query_process_image(handle: HANDLE) -> Result<PathBuf> {
    let mut capacity: usize = 260; // Start with MAX_PATH
    loop {
        let mut buffer = vec![0u16; capacity];
        let written =
            unsafe { K32GetModuleFileNameExW(handle, HMODULE::default(), &mut buffer) } as usize;

        if written == 0 {
            return Err(anyhow!("unable to query process image"));
        }

        if written + 1 < buffer.len() {
            let os_string = OsString::from_wide(&buffer[..written]);
            return Ok(PathBuf::from(os_string));
        }

        capacity *= 2;
        if capacity > 32_768 {
            return Err(anyhow!("process image path exceeded buffer"));
        }
    }
}

fn kill_process_tree(pid: u32) -> Result<()> {
    let pid_arg = pid.to_string();
    let status = Command::new("taskkill")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["/PID", pid_arg.as_str(), "/F", "/T"])
        .status()
        .context("failed to invoke taskkill")?;

    if status.success() {
        Ok(())
    } else {
        bail!("taskkill returned exit code {:?}", status.code())
    }
}

fn status_apache(root: &Path) -> Result<()> {
    if let Some(pid) = current_apache_pid(root)? {
        println!("Apache running (PID {}).", pid);
    } else {
        println!("Apache is stopped.");
    }
    Ok(())
}
