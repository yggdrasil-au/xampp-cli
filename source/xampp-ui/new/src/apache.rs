#![cfg(windows)]

mod helpers;
mod status;

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{TcpListener, UdpSocket};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
        /// Verbose output
        #[arg(long)]
        verbose: bool,
        /// Health probe URL (http only), e.g. http://localhost/server-status?auto
        #[arg(long)]
        url: Option<String>,
        /// Log window for future enhancements (e.g. 10m); accepted but not used yet
        #[arg(long)]
        since: Option<String>,
        /// Refresh interval, e.g. 2s, 500ms, 1m
        #[arg(long)]
        watch: Option<String>,
    },
    /// Register/Update configuration for this folder without starting Apache
    Register {
        /// Document root path for the virtual host
        #[arg(long = "DocumentRoot")]
        document_root: String,
        /// Port to listen on
        #[arg(long)]
        port: u16,
    },
    /// Open apache\logs\error.log in the default viewer
    Logs,
    /// Open http://localhost/ in the default browser
    Admin,
    /// Open apache\conf\httpd.conf in the default editor
    Config,
}

pub fn handle_apache(action: ApacheAction, root: &Path) -> Result<()> {
    match action {
        ApacheAction::Start { output, document_root, port } => {
            // 1. Ensure httpd-vhosts.conf includes our active file
            ensure_vhosts_include(root)?;

            // 2. Resolve config (args > local file > default)
            let (doc_root, effective_port) = resolve_and_save_config(root, document_root, port)?;

            // 3. Overwrite the active Apache config file
            write_active_vhost(root, &doc_root, effective_port)?;

            // 4. Start the process
            start_apache_process(root, output)
        }
        ApacheAction::Stop => stop_apache(root),
        ApacheAction::Restart => restart_apache(root),
        ApacheAction::Status { verbose, url, since: _, watch } => {
            let watch_dur = watch
                .as_deref()
                .and_then(parse_duration);
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

// --- Configuration Logic ---

/// Ensures apache/conf/extra/httpd-vhosts.conf contains the Include line for our dynamic config.
fn ensure_vhosts_include(root: &Path) -> Result<()> {
    let vhosts_conf = root.join("apache").join("conf").join("extra").join("httpd-vhosts.conf");

    if !vhosts_conf.exists() {
        // If XAMPP is standard, this should exist. If not, we might be in a weird state.
        // We'll warn but try to create it if parent dir exists.
        bail!("Standard XAMPP file not found: {}", vhosts_conf.display());
    }

    let content = fs::read_to_string(&vhosts_conf)?;
    let include_directive = "Include \"conf/extra/wlampctl-active.conf\"";

    // Simple check to avoid double appending
    if !content.contains("wlampctl-active.conf") {
        println!("ℹ First-run setup: Adding include directive to httpd-vhosts.conf");
        let mut file = OpenOptions::new()
            .append(true)
            .open(&vhosts_conf)?;
        writeln!(file, "\n# WlampCTL Active Project Configuration")?;
        writeln!(file, "{}", include_directive)?;
    }
    Ok(())
}

/// Resolves the (DocumentRoot, Port) tuple.
/// Priority: CLI Args > Existing .wlampctl-project.conf > Defaults
/// Also saves/updates the .wlampctl-project.conf file.
fn resolve_and_save_config(
    root: &Path,
    arg_root: Option<String>,
    arg_port: Option<u16>
) -> Result<(String, u16)> {
    let config_file_path = env::current_dir()?.join(".wlampctl-project.conf");

    // Default values if nothing is known
    let mut final_root = env::current_dir()?.display().to_string(); // Default to current dir
    let mut final_port = 8080;
    let mut project_id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(); // New ID by default

    // 1. Try to load existing config
    if config_file_path.exists() {
        let content = fs::read_to_string(&config_file_path).unwrap_or_default();
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("DOCUMENT_ROOT=") { final_root = val.trim().to_string(); }
            if let Some(val) = line.strip_prefix("PORT=") { final_port = val.trim().parse().unwrap_or(8080); }
            if let Some(val) = line.strip_prefix("PROJECT_ID=") { project_id = val.trim().parse().unwrap_or(project_id); }
        }
    } else {
        // If new config, try to find a free port
        final_port = find_free_port(8080);
    }

    // 2. Override with CLI args if provided
    if let Some(r) = arg_root {
        // Resolve relative path to absolute
        let resolved = env::current_dir()?.join(&r);
        let abs = fs::canonicalize(&resolved)
            .context(format!("DocumentRoot path does not exist: {}", resolved.display()))?;
        final_root = abs.display().to_string();
    }

    if let Some(p) = arg_port {
        final_port = p;
    }

    // 3. Check for System Port Conflicts (e.g. Skype, Node)
    // We only warn here because maybe the user IS running Node and wants Apache to fail,
    // or maybe they are restarting and the port is briefly held.
    loop {
        if is_port_free(final_port) {
            break;
        }

        // Check if it's OUR Apache holding it?
        if let Ok(Some(_pid)) = current_apache_pid(root) {
             // If Apache is running, this is expected behavior during a restart/reload
             break;
        }

        println!("⚠ Warning: Port {} appears to be in use by another system process.", final_port);
        print!("Enter a new port (or press Enter to exit): ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim();

        if trimmed.is_empty() {
            bail!("Operation cancelled by user.");
        }

        if let Ok(p) = trimmed.parse::<u16>() {
            final_port = p;
        } else {
            println!("Invalid port number.");
        }
    }

    // 4. Sanitize Path for Apache (Windows backslashes to forward slashes)
    let apache_root_path = final_root.replace('\\', "/");
    let apache_root_path = apache_root_path.trim_start_matches("//?/").to_string(); // Remove UNC prefix if present

    // 5. Save back to .wlampctl-project.conf
    let config_content = format!(
        "# WlampCTL Project Configuration\n# Generated: {}\n\nPROJECT_ID={}\nPORT={}\nDOCUMENT_ROOT={}\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        project_id,
        final_port,
        apache_root_path
    );
    fs::write(&config_file_path, config_content)
        .context(format!("Failed to save config to {}", config_file_path.display()))?;

    Ok((apache_root_path, final_port))
}

/// Overwrites apache/conf/extra/wlampctl-active.conf with the generated VirtualHost block.
fn write_active_vhost(root: &Path, doc_root: &str, port: u16) -> Result<()> {
    let active_conf = root.join("apache").join("conf").join("extra").join("wlampctl-active.conf");

    let vhost_content = format!(
        r#"# WlampCTL Active Project Configuration
# This file is automatically overwritten by 'wlampctl apache start'
# DO NOT EDIT MANUALLY.

Listen {port}

<VirtualHost *:{port}>
    DocumentRoot "{doc_root}"

    <Directory "{doc_root}">
        Options Indexes FollowSymLinks Includes ExecCGI
        AllowOverride All
        Require all granted
    </Directory>

    # Default error logging
    ErrorLog "logs/wlampctl-project-error.log"
    CustomLog "logs/wlampctl-project-access.log" common
</VirtualHost>
"#,
        port = port,
        doc_root = doc_root
    );

    fs::write(&active_conf, vhost_content)
        .context(format!("Failed to write active config to {}", active_conf.display()))?;

    println!("✓ Active Configuration Set:");
    println!("  Root: {}", doc_root);
    println!("  Port: {}", port);

    Ok(())
}

fn find_free_port(start: u16) -> u16 {
    let common_ports = [80, 8080, 3000, 8000, 8888, 5000, 9000];

    // Try common ports first
    for p in common_ports {
        if is_port_free(p) { return p; }
    }

    // Try sequential
    for p in start..=start+1000 {
        if is_port_free(p) { return p; }
    }

    start // Give up and return start
}

fn is_port_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

fn get_active_port(root: &Path) -> Option<u16> {
    let active_conf = root.join("apache").join("conf").join("extra").join("wlampctl-active.conf");
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


// --- Process Control (Start/Stop/Restart) ---

fn start_apache_process(root: &Path, output: bool) -> Result<()> {
    // If running, warn and exit. (We don't auto-kill because that might be rude to other projects)
    if let Some(pid) = current_apache_pid(root)? {
        println!("Apache is already running (PID {}).", pid);
        println!("Run 'lampctl apache restart' to apply new configuration.");
        return Ok(());
    }

    let httpd = httpd_path(root)?;

    // Get port from active config to display correct URLs
    let port = get_active_port(root).unwrap_or(80);

    println!("\nServer running at:");
    println!("  ➜  Local:   http://localhost:{}/", port);
    if let Some(ip) = get_local_ip() {
        println!("  ➜  Network: http://{}:{}/", ip, port);
    }
    println!("");

    if output {
        println!("Starting Apache in foreground. Press Enter to stop.");

        // Spawn httpd directly connected to stdout/stderr
        let mut child = Command::new(&httpd)
            .current_dir(root)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to spawn {}", httpd.display()))?;

        // Simple thread to catch Enter key for clean stop
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
            let _ = tx.send(());
        });

        loop {
            // Check if child crashed/exited
            match child.try_wait() {
                Ok(Some(status)) => {
                    println!("Apache exited with status {:?}", status.code());
                    cleanup_pid_file(root);
                    return if status.success() { Ok(()) } else { bail!("Apache exited with error") };
                }
                Ok(None) => {}
                Err(e) => bail!("Error waiting for Apache: {}", e),
            }

            // Check if user pressed Enter
            if rx.try_recv().is_ok() {
                println!("Stopping Apache...");
                let _ = child.kill();
                let _ = child.wait();
                cleanup_pid_file(root);
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    } else {
        // Background start (classic behavior)
        Command::new(&httpd)
            .current_dir(root)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .with_context(|| format!("failed to spawn {}", httpd.display()))?;

        let pid = wait_for_apache_pid(root, STARTUP_POLL_ATTEMPTS)?.ok_or_else(|| {
            anyhow!(
                "Apache failed to start – check logs at {}",
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
    // Note: restart does NOT re-write config from args because 'Restart' enum has no args.
    // It simply bounces the process, which re-reads the *existing* lampctl-active.conf.
    // To change config, user must run 'start' (which handles the "if running, stop" check or fails).
    // Actually, 'start' currently fails if running.
    // So 'restart' is just a process bounce.

    stop_apache(root)?;
    thread::sleep(Duration::from_millis(500));

    // We start in background mode by default for restart, or we could track previous mode?
    // Simplified: restart implies background usually, unless we want to get fancy.
    start_apache_process(root, false)
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
    // Determine port from active config if possible, else default 80
    // Simplified: just try localhost
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

pub fn get_apache_version(root: &Path) -> Option<String> {
    exec_and_first_line(root.join("apache").join("bin").join("httpd.exe"), ["-v"])
}
