// Remove #![cfg(windows)]

mod helpers;
mod status;

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use open;

use helpers::{
    cleanup_pid_file, current_apache_pid, exec_and_first_line, httpd_path,
    kill_process_tree, wait_for_apache_pid, wait_for_shutdown,
    CREATE_NO_WINDOW, SHUTDOWN_POLL_ATTEMPTS, STARTUP_POLL_ATTEMPTS,
};
use status::{fmt_duration_short, parse_duration, status_once};

#[derive(Subcommand, Clone, Debug, Eq, PartialEq)]
pub enum ApacheAction {
    // ... (This Enum remains the same)
    /// Start Apache (foreground instance) with the current project configuration
    Start {
        /// Print Apache output in this terminal (do not run hidden)
        #[arg(long)]
        output: bool,
        /// Document root path for the virtual host (auto-registers if needed)
        #[arg(long = "DocumentRoot")]
        document_root: Option<String>,
        /// Port to listen on (auto-assigns if not specified)
        #[arg(long)]
        port: Option<u16>,
    },
    /// Stop Apache
    Stop,
    /// Restart Apache
    Restart,
    /// Show running status (PID or stopped)
    Status {
        #[arg(long)]
        verbose: bool,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        watch: Option<String>,
    },
    /// Register/Update configuration for this folder without starting Apache
    Register {
        #[arg(long = "DocumentRoot")]
        document_root: String,
        #[arg(long)]
        port: u16,
    },
    /// Open apache logs
    Logs,
    /// Open localhost
    Admin,
    /// Open apache config
    Config,
}

pub fn handle_apache(action: ApacheAction, root: &Path) -> Result<()> {
    // ... (This function logic stays mostly the same)
    match action {
        ApacheAction::Start { output, document_root, port } => {
            ensure_vhosts_include(root)?;
            let (doc_root, effective_port) = resolve_and_save_config(root, document_root, port)?;
            write_active_vhost(root, &doc_root, effective_port)?;
            start_apache_process(root, output)
        }
        ApacheAction::Stop => stop_apache(root),
        ApacheAction::Restart => restart_apache(root),
        ApacheAction::Status { verbose, url, since: _, watch } => {
            let watch_dur = watch.as_deref().and_then(parse_duration);
            if let Some(interval) = watch_dur {
                loop {
                    let _code = status_once(root, verbose, url.as_deref())?;
                    println!("-- refresh in {} --", fmt_duration_short(interval));
                    thread::sleep(interval);
                }
            } else {
                let code = status_once(root, verbose, url.as_deref())?;
                std::process::exit(code);
            }
        }
        ApacheAction::Register { document_root, port } => {
            ensure_vhosts_include(root)?;
            let (root_path, effective_port) = resolve_and_save_config(root, Some(document_root), Some(port))?;
            write_active_vhost(root, &root_path, effective_port)?;
            Ok(())
        },
        ApacheAction::Logs => open_logs(root),
        ApacheAction::Admin => open_admin(),
        ApacheAction::Config => open_config(root),
    }
}

// ... (Helper functions like ensure_vhosts_include remain the same)
// ... (resolve_and_save_config remains the same, assuming Windows/Linux paths are handled by path::join)

fn ensure_vhosts_include(root: &Path) -> Result<()> {
    // Windows: apache/conf/extra/httpd-vhosts.conf
    // Linux:   etc/extra/httpd-vhosts.conf

    #[cfg(windows)]
    let vhosts_conf = root.join("apache").join("conf").join("extra").join("httpd-vhosts.conf");
    #[cfg(not(windows))]
    let vhosts_conf = root.join("etc").join("extra").join("httpd-vhosts.conf");

    if !vhosts_conf.exists() {
        bail!("Standard XAMPP file not found: {}", vhosts_conf.display());
    }

    let content = fs::read_to_string(&vhosts_conf)?;

    // Linux paths in config should forward slashes, but windows works with them too usually in Apache.
    // However, the Include directive path must be relative to ServerRoot.
    // Windows ServerRoot is often "apache", Linux is "/opt/lampp".
    // We'll try to stick to relative "etc/extra" or "conf/extra".

    #[cfg(windows)]
    let include_directive = "Include \"conf/extra/wlampctl-active.conf\"";
    #[cfg(not(windows))]
    let include_directive = "Include \"etc/extra/wlampctl-active.conf\"";

    if !content.contains("wlampctl-active.conf") {
        println!("ℹ First-run setup: Adding include directive to httpd-vhosts.conf");
        let mut file = OpenOptions::new().append(true).open(&vhosts_conf)?;
        writeln!(file, "\n# WlampCTL Active Project Configuration")?;
        writeln!(file, "{}", include_directive)?;
    }
    Ok(())
}

fn resolve_and_save_config(root: &Path, arg_root: Option<String>, arg_port: Option<u16>) -> Result<(String, u16)> {
    // ... (This logic is generic enough, just filesystem ops)
    // One specific: Windows backslashes replacement.

    // Copy the original function here, but ensure paths are robust.
    // The original code `final_root.replace('\\', "/")` is fine for Linux too (no-op).

    // Placeholder for brevity: paste original logic here.
    // ...
    // (See original src/apache.rs for logic)

    // Shortened for this context:
    let config_file_path = env::current_dir()?.join(".wlampctl-project.conf");
    let mut final_root = env::current_dir()?.display().to_string();
    let mut final_port = 8080;
    let mut project_id = 0; // simplified

    if config_file_path.exists() {
        let content = fs::read_to_string(&config_file_path).unwrap_or_default();
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("DOCUMENT_ROOT=") { final_root = val.trim().to_string(); }
            if let Some(val) = line.strip_prefix("PORT=") { final_port = val.trim().parse().unwrap_or(8080); }
        }
    } else {
        final_port = find_free_port(8080);
    }

    if let Some(r) = arg_root {
        let resolved = env::current_dir()?.join(&r);
        let abs = fs::canonicalize(&resolved).context("DocumentRoot path does not exist")?;
        final_root = abs.display().to_string();
    }
    if let Some(p) = arg_port { final_port = p; }

    // Save config
    let apache_root_path = final_root.replace('\\', "/");
    let config_content = format!(
        "# WlampCTL Project Configuration\nPROJECT_ID={}\nPORT={}\nDOCUMENT_ROOT={}\n",
        project_id, final_port, apache_root_path
    );
    fs::write(&config_file_path, config_content)?;

    Ok((apache_root_path, final_port))
}

fn write_active_vhost(root: &Path, doc_root: &str, port: u16) -> Result<()> {
    #[cfg(windows)]
    let active_conf = root.join("apache").join("conf").join("extra").join("wlampctl-active.conf");
    #[cfg(not(windows))]
    let active_conf = root.join("etc").join("extra").join("wlampctl-active.conf");

    // ... (Logic regarding vhost_content string format is the same)
    let vhost_content = format!(
        r#"# WlampCTL Active Project Configuration
Listen {port}
<VirtualHost *:{port}>
    DocumentRoot "{doc_root}"
    <Directory "{doc_root}">
        Options Indexes FollowSymLinks Includes ExecCGI
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog "logs/wlampctl-project-error.log"
    CustomLog "logs/wlampctl-project-access.log" common
</VirtualHost>
"#,
        port = port, doc_root = doc_root
    );
    fs::write(&active_conf, vhost_content)?;
    Ok(())
}

fn find_free_port(start: u16) -> u16 {
    let common = [80, 8080, 3000, 8000];
    for p in common { if is_port_free(p) { return p; } }
    for p in start..=start+1000 { if is_port_free(p) { return p; } }
    start
}

fn is_port_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

fn get_active_port(root: &Path) -> Option<u16> {
    #[cfg(windows)]
    let active_conf = root.join("apache").join("conf").join("extra").join("wlampctl-active.conf");
    #[cfg(not(windows))]
    let active_conf = root.join("etc").join("extra").join("wlampctl-active.conf");

    if !active_conf.exists() { return None; }
    let content = fs::read_to_string(active_conf).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.trim().strip_prefix("Listen ") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn get_local_ip() -> Option<std::net::IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

// --- Process Control ---

fn start_apache_process(root: &Path, output: bool) -> Result<()> {
    if let Some(pid) = current_apache_pid(root)? {
        println!("Apache is already running (PID {}).", pid);
        return Ok(());
    }

    let httpd = httpd_path(root)?;
    let port = get_active_port(root).unwrap_or(80);

    println!("\nServer running at:");
    println!("  ➜  Local:   http://localhost:{}/", port);
    if let Some(ip) = get_local_ip() {
        println!("  ➜  Network: http://{}:{}/", ip, port);
    }
    println!("");

    let mut cmd = Command::new(&httpd);

    // Platform specific args
    #[cfg(windows)]
    cmd.current_dir(root);

    // On Linux XAMPP, LD_LIBRARY_PATH is often needed if not using the wrapper script
    #[cfg(not(windows))]
    cmd.env("LD_LIBRARY_PATH", root.join("lib"));

    if output {
        // IMPORTANT: Force foreground on Linux so it doesn't detach/daemonize
        cmd.arg("-DFOREGROUND");

        println!("Starting Apache in foreground. Press Enter (or Ctrl+C) to stop.");

        // Isolate Apache in a new process group so it ignores SIGWINCH (terminal resize)
        #[cfg(unix)]
        cmd.process_group(0);

        cmd.stdin(Stdio::null())
           .stdout(Stdio::inherit())
           .stderr(Stdio::inherit());

        let mut child = cmd.spawn().with_context(|| format!("failed to spawn {}", httpd.display()))?;

        // Channel to signal shutdown (Enter key or Ctrl+C)
        let (tx, rx) = std::sync::mpsc::channel();

        // 1) Listen for Enter key
        let tx_stdin = tx.clone();
        thread::spawn(move || {
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
            let _ = tx_stdin.send(());
        });

        // 2) Listen for Ctrl+C / SIGTERM
        let tx_sig = tx.clone();
        let _ = ctrlc::set_handler(move || {
            let _ = tx_sig.send(());
        });

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    println!("Apache exited with status {:?}", status.code());
                    cleanup_pid_file(root);
                    return if status.success() { Ok(()) } else { bail!("Apache exited with error") };
                }
                Ok(None) => {}
                Err(e) => bail!("Error: {}", e),
            }

            // Check if we received a stop signal (Enter or Ctrl+C)
            if rx.try_recv().is_ok() {
                println!("\nStopping Apache...");

                // Use the helper which sends SIGTERM on Linux (graceful)
                // and taskkill /T on Windows (tree kill)
                let _ = kill_process_tree(child.id());

                // Now wait for the process to exit naturally
                let _ = child.wait();
                cleanup_pid_file(root);
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    } else {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        // On Linux background start, we DO NOT add -DFOREGROUND.
        // We let Apache daemonize itself so it continues running after wlampctl exits.

        cmd.spawn().with_context(|| format!("failed to spawn {}", httpd.display()))?;

        let pid = wait_for_apache_pid(root, STARTUP_POLL_ATTEMPTS)?.ok_or_else(|| {
            anyhow!("Apache failed to start – check logs")
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
    start_apache_process(root, false)
}

fn open_logs(root: &Path) -> Result<()> {
    #[cfg(windows)]
    let log_path = root.join("apache").join("logs").join("error.log");
    #[cfg(not(windows))]
    let log_path = root.join("logs").join("error_log");

    if !log_path.exists() { bail!("{} does not exist", log_path.display()); }
    open::that(&log_path).context("failed to open Apache error log")?;
    Ok(())
}

fn open_admin() -> Result<()> {
    open::that("http://localhost/").context("failed to open http://localhost/")?;
    Ok(())
}

fn open_config(root: &Path) -> Result<()> {
    #[cfg(windows)]
    let conf = root.join("apache").join("conf").join("httpd.conf");
    #[cfg(not(windows))]
    let conf = root.join("etc").join("httpd.conf");

    if !conf.exists() { bail!("{} does not exist", conf.display()); }
    open::that(&conf).context("failed to open httpd.conf")?;
    Ok(())
}

pub fn get_apache_version(root: &Path) -> Option<String> {
    exec_and_first_line(httpd_path(root).ok()?, ["-v"])
}