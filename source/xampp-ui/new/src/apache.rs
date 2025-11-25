#![cfg(windows)]

mod helpers;
mod status;

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

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
    /// Start Apache (foreground instance)
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
    /// Register a new virtual host configuration
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
            // Auto-register if DocumentRoot is provided
            if let Some(doc_root) = document_root {
                auto_register_or_update(root, &doc_root, port)?;
            }
            
            // Ensure only the correct port is enabled in httpd-vhosts.conf
            let effective_port = if let Some(p) = port {
                Some(p)
            } else {
                // Try to read from .lampctl-project.conf
                get_project_port()
            };

            if let Some(p) = effective_port {
                 enable_only_this_port(root, p)?;
            }

            start_apache(root, output)
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
                    // Print a separator between refreshes when watching.
                    println!("-- refresh in {} --", fmt_duration_short(interval));
                    thread::sleep(interval);
                    // While watching, keep running; exit code on Ctrl-C will be 0.
                }
            } else {
                let code = status_once(root, verbose, url.as_deref())?;
                std::process::exit(code);
            }
        }
        ApacheAction::Register { document_root, port } => register_vhost(root, &document_root, port),
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
        println!("Starting Apache in foreground. Press Enter to stop.");
        
        // Run httpd in the current terminal, inheriting stdout/stderr so output appears directly.
        // We do NOT inherit stdin, so we can read it in the parent process.
        let mut child = Command::new(&httpd)
            .current_dir(root)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to spawn {}", httpd.display()))?;

        // Spawn a thread to listen for Enter key
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
            let _ = tx.send(());
        });

        loop {
            // Check if child exited on its own
            match child.try_wait() {
                Ok(Some(status)) => {
                    println!("Apache exited with status {:?}", status.code());
                    return if status.success() { Ok(()) } else { bail!("Apache exited with error") };
                }
                Ok(None) => {
                    // Still running
                }
                Err(e) => bail!("Error waiting for Apache: {}", e),
            }

            // Check if user pressed enter
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

pub fn get_apache_version(root: &Path) -> Option<String> {
    exec_and_first_line(root.join("apache").join("bin").join("httpd.exe"), ["-v"])
}

fn auto_register_or_update(root: &Path, document_root: &str, port: Option<u16>) -> Result<()> {
    let config_file_path = env::current_dir()?.join(".lampctl-project.conf");
    let vhosts_conf = root.join("apache").join("conf").join("extra").join("httpd-vhosts.conf");
    
    if !vhosts_conf.exists() {
        bail!("Virtual hosts config file not found: {}", vhosts_conf.display());
    }
    
    // Determine the port to use
    let selected_port = if let Some(p) = port {
        p
    } else if config_file_path.exists() {
        // Load port from existing config
        let config_content = fs::read_to_string(&config_file_path)
            .with_context(|| format!("Failed to read {}", config_file_path.display()))?;
        
        config_content
            .lines()
            .find(|line| line.starts_with("PORT="))
            .and_then(|line| line.strip_prefix("PORT="))
            .and_then(|port_str| port_str.parse::<u16>().ok())
            .unwrap_or_else(|| find_next_available_port(root).unwrap_or(8080))
    } else {
        // Find next available port
        find_next_available_port(root).unwrap_or(8080)
    };
    
    // Use the register_vhost function which handles both create and update
    register_vhost(root, document_root, selected_port)?;
    
    Ok(())
}

fn find_next_available_port(root: &Path) -> Option<u16> {
    let vhosts_conf = root.join("apache").join("conf").join("extra").join("httpd-vhosts.conf");
    let vhosts_content = fs::read_to_string(&vhosts_conf).ok()?;
    
    // Common ports to try in order
    let common_ports = [80, 8080, 3000, 8000, 8888, 5000, 3333, 4444, 5555, 7777, 9000, 9999];
    
    for &port in &common_ports {
        // Check if port is in use by system
        if is_port_in_use(port).unwrap_or(true) {
            continue;
        }
        
        // Check if port is defined in vhosts config
        let listen_marker = format!("Listen {}", port);
        if vhosts_content.contains(&listen_marker) {
            continue;
        }
        
        // Found available port
        return Some(port);
    }
    
    // If all common ports are taken, try random high ports
    for port in 10000..=10100 {
        if !is_port_in_use(port).unwrap_or(true) {
            let listen_marker = format!("Listen {}", port);
            if !vhosts_content.contains(&listen_marker) {
                return Some(port);
            }
        }
    }
    
    None
}

fn register_vhost(root: &Path, document_root: &str, port: u16) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let vhosts_conf = root.join("apache").join("conf").join("extra").join("httpd-vhosts.conf");
    if !vhosts_conf.exists() {
        bail!("Virtual hosts config file not found: {}", vhosts_conf.display());
    }
    
    // Check if .lampctl-project.conf exists and load existing project ID
    let config_file_path = env::current_dir()?.join(".lampctl-project.conf");
    let proj_id = if config_file_path.exists() {
        // Load existing project ID
        let config_content = fs::read_to_string(&config_file_path)
            .with_context(|| format!("Failed to read {}", config_file_path.display()))?;
        
        let id = config_content
            .lines()
            .find(|line| line.starts_with("PROJECT_ID="))
            .and_then(|line| line.strip_prefix("PROJECT_ID="))
            .and_then(|id_str| id_str.parse::<u64>().ok())
            .ok_or_else(|| anyhow!("Invalid or missing PROJECT_ID in {}", config_file_path.display()))?;
        
        println!("Using existing project ID: {}", id);
        id
    } else {
        // Generate new project ID based on timestamp
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        println!("Generated new project ID: {}", id);
        id
    };
    
    // Check if vhost with this project ID already exists
    let vhosts_content = fs::read_to_string(&vhosts_conf)
        .with_context(|| format!("Failed to read {}", vhosts_conf.display()))?;
    
    let proj_id_marker = format!("## Proj ID: {}", proj_id);
    let existing_vhost = vhosts_content.contains(&proj_id_marker);
    
    if existing_vhost {
        // Update existing vhost instead of creating a new one
        println!("Updating existing virtual host with project ID: {}", proj_id);
        return update_vhost(root, proj_id, &vhosts_conf, &vhosts_content, document_root, port);
    }
    
    // Resolve document root to absolute path
    let doc_root_path = env::current_dir()?.join(document_root);
    let doc_root_abs = fs::canonicalize(&doc_root_path)
        .with_context(|| format!("Document root does not exist: {}", doc_root_path.display()))?;
    
    // Convert to forward slashes for Apache config and remove extended-length path prefix
    let mut doc_root_str = doc_root_abs.display().to_string().replace('\\', "/");
    if doc_root_str.starts_with("//?/") {
        doc_root_str = doc_root_str[4..].to_string();
    }

    // Check if port is already in use by the system
    if is_port_in_use(port)? {
        bail!("Port {} is already in use by the system", port);
    }
    
    // Check if port is already defined in vhosts config
    let listen_marker = format!("Listen {}", port);
    let mut skip_append = false;

    if vhosts_content.contains(&listen_marker) {
        if check_vhost_match(&vhosts_content, port, &doc_root_str) {
            println!("Port {} is already configured for this path. Reusing existing configuration.", port);
            skip_append = true;
        } else {
            bail!("Port {} is already defined in {}", port, vhosts_conf.display());
        }
    }
    
    let created_date = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    if !skip_append {
        // Generate vhost configuration
        let vhost_config = format!(
            r#"
## CLI CONF
## Proj ID: {}
## Created: {}
# PORT: {}
Listen {}
#VHOST
<VirtualHost *:{}>
    ##ServerAdmin webmaster@example.com
    DocumentRoot "{}"
    ##ServerName example.com
    ##ErrorLog "logs/example.com-error.log"
    ##CustomLog "logs/example.com-access.log" common
    <Directory "{}">
        #
        # Possible values for the Options directive are "None", "All",
        # or any combination of:
        #   Indexes Includes FollowSymLinks SymLinksifOwnerMatch ExecCGI MultiViews
        #
        # Note that "MultiViews" must be named *explicitly* --- "Options All"
        # doesn't give it to you.
        #
        # The Options directive is both complicated and important.  Please see
        # http://httpd.apache.org/docs/2.4/mod/core.html#options
        # for more information.
        #
        Options Indexes FollowSymLinks Includes ExecCGI

        #
        # AllowOverride controls what directives may be placed in .htaccess files.
        # It can be "All", "None", or any combination of the keywords:
        #   AllowOverride FileInfo AuthConfig Limit
        #
        AllowOverride All

        #
        # Controls who can get stuff from this server.
        #
        Require all granted
    </Directory>
</VirtualHost>
## END
"#,
            proj_id, created_date, port, port, port, doc_root_str, doc_root_str
        );
        
        // Append to httpd-vhosts.conf
        let mut file = OpenOptions::new()
            .append(true)
            .open(&vhosts_conf)
            .with_context(|| format!("Failed to open {}", vhosts_conf.display()))?;
        
        file.write_all(vhost_config.as_bytes())
            .context("Failed to write vhost configuration")?;
        
        println!("✓ Virtual host configuration added to {}", vhosts_conf.display());
    }
    
    println!("  Project ID: {}", proj_id);
    println!("  Port: {}", port);
    println!("  Document Root: {}", doc_root_str);
    
    // Create or update local config file with project details
    let config_content = format!(
        r#"# LampCTL Project Configuration
# Created: {}
# Last Updated: {}

PROJECT_ID={}
PORT={}
DOCUMENT_ROOT={}
VHOST_CONFIG={}
"#,
        created_date,
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        proj_id,
        port,
        doc_root_str,
        vhosts_conf.display().to_string().replace('\\', "/")
    );
    
    fs::write(&config_file_path, config_content)
        .with_context(|| format!("Failed to write config file: {}", config_file_path.display()))?;
    
    println!("✓ Project config saved to {}", config_file_path.display());
    println!("\nRestart Apache to apply changes:");
    println!("  lampctl apache restart");
    
    Ok(())
}

fn check_vhost_match(content: &str, port: u16, target_root: &str) -> bool {
    let vhost_start = format!("<VirtualHost *:{}>", port);
    let lines: Vec<&str> = content.lines().collect();
    let mut inside_target_vhost = false;
    
    for line in lines {
        let trimmed = line.trim();
        if trimmed.starts_with(&vhost_start) {
            inside_target_vhost = true;
        } else if inside_target_vhost && trimmed.starts_with("</VirtualHost>") {
            inside_target_vhost = false;
        } else if inside_target_vhost {
            if trimmed.starts_with("DocumentRoot") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    let mut path = parts[1..].join(" ");
                    if path.starts_with('"') && path.ends_with('"') {
                        path = path[1..path.len()-1].to_string();
                    }
                    let path = path.replace('\\', "/");
                    if path.eq_ignore_ascii_case(target_root) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn update_vhost(_root: &Path, proj_id: u64, vhosts_conf: &Path, vhosts_content: &str, document_root: &str, new_port: u16) -> Result<()> {
    // Check if new port is already in use by the system
    if is_port_in_use(new_port)? {
        bail!("Port {} is already in use by the system", new_port);
    }
    
    // Find the existing vhost block for this project ID
    let proj_marker = format!("## Proj ID: {}", proj_id);
    let start_marker = "## CLI CONF";
    let end_marker = "## END";
    
    // Find the start and end of the vhost block
    let lines: Vec<&str> = vhosts_content.lines().collect();
    let mut block_start = None;
    let mut block_end = None;
    let mut old_port = None;
    let mut created_date = None;
    
    for (i, line) in lines.iter().enumerate() {
        if line.contains(&proj_marker) {
            // Found our project, look backwards for start
            for j in (0..=i).rev() {
                if lines[j].contains(start_marker) {
                    block_start = Some(j);
                    break;
                }
            }
            // Look forwards for end
            for j in i..lines.len() {
                if lines[j].contains(end_marker) {
                    block_end = Some(j);
                    break;
                }
                // Extract old port number
                if lines[j].trim().starts_with("Listen ") {
                    if let Some(port_str) = lines[j].trim().strip_prefix("Listen ") {
                        old_port = port_str.parse::<u16>().ok();
                    }
                }
                // Extract created date
                if lines[j].trim().starts_with("## Created: ") {
                    if let Some(date_str) = lines[j].trim().strip_prefix("## Created: ") {
                        created_date = Some(date_str.to_string());
                    }
                }
            }
            break;
        }
    }
    
    let block_start = block_start.ok_or_else(|| anyhow!("Could not find start of vhost block"))?;
    let block_end = block_end.ok_or_else(|| anyhow!("Could not find end of vhost block"))?;
    
    // Check if the new port is already defined elsewhere in the config (excluding the block we're updating)
    let listen_marker = format!("Listen {}", new_port);
    for (i, line) in lines.iter().enumerate() {
        if i < block_start || i > block_end {
            if line.contains(&listen_marker) {
                bail!("Port {} is already defined elsewhere in {}", new_port, vhosts_conf.display());
            }
        }
    }
    
    // Resolve document root to absolute path
    let doc_root_path = std::env::current_dir()?.join(document_root);
    let doc_root_abs = fs::canonicalize(&doc_root_path)
        .with_context(|| format!("Document root does not exist: {}", doc_root_path.display()))?;
    
    // Convert to forward slashes for Apache config and remove extended-length path prefix
    let mut doc_root_str = doc_root_abs.display().to_string().replace('\\', "/");
    if doc_root_str.starts_with("//?/") {
        doc_root_str = doc_root_str[4..].to_string();
    }
    
    // Generate new vhost configuration
    let created_date_str = created_date.unwrap_or_else(|| chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
    let new_vhost_block = format!(
        r#"## CLI CONF
## Proj ID: {}
## Created: {}
# PORT: {}
Listen {}
#VHOST
<VirtualHost *:{}>
    ##ServerAdmin webmaster@example.com
    DocumentRoot "{}"
    ##ServerName example.com
    ##ErrorLog "logs/example.com-error.log"
    ##CustomLog "logs/example.com-access.log" common
    <Directory "{}">
        #
        # Possible values for the Options directive are "None", "All",
        # or any combination of:
        #   Indexes Includes FollowSymLinks SymLinksifOwnerMatch ExecCGI MultiViews
        #
        # Note that "MultiViews" must be named *explicitly* --- "Options All"
        # doesn't give it to you.
        #
        # The Options directive is both complicated and important.  Please see
        # http://httpd.apache.org/docs/2.4/mod/core.html#options
        # for more information.
        #
        Options Indexes FollowSymLinks Includes ExecCGI

        #
        # AllowOverride controls what directives may be placed in .htaccess files.
        # It can be "All", "None", or any combination of the keywords:
        #   AllowOverride FileInfo AuthConfig Limit
        #
        AllowOverride All

        #
        # Controls who can get stuff from this server.
        #
        Require all granted
    </Directory>
</VirtualHost>
## END"#,
        proj_id, created_date_str, new_port, new_port, new_port, doc_root_str, doc_root_str
    );
    
    // Reconstruct the file with the updated block
    let mut new_content = String::new();
    for (i, line) in lines.iter().enumerate() {
        if i == block_start {
            new_content.push_str(&new_vhost_block);
            new_content.push('\n');
        } else if i > block_start && i <= block_end {
            // Skip old block lines
            continue;
        } else {
            new_content.push_str(line);
            new_content.push('\n');
        }
    }
    
    // Write the updated content back to the file
    fs::write(vhosts_conf, new_content)
        .with_context(|| format!("Failed to update {}", vhosts_conf.display()))?;
    
    if let Some(old) = old_port {
        println!("✓ Virtual host configuration updated (port {} → {})", old, new_port);
    } else {
        println!("✓ Virtual host configuration updated");
    }
    println!("  Project ID: {}", proj_id);
    println!("  New Port: {}", new_port);
    println!("  Document Root: {}", doc_root_str);
    
    // Update local config file
    let config_file_path = std::env::current_dir()?.join(".lampctl-project.conf");
    let config_content = format!(
        r#"# LampCTL Project Configuration
# Created: {}
# Last Updated: {}

PROJECT_ID={}
PORT={}
DOCUMENT_ROOT={}
VHOST_CONFIG={}
"#,
        created_date_str,
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        proj_id,
        new_port,
        doc_root_str,
        vhosts_conf.display().to_string().replace('\\', "/")
    );
    
    fs::write(&config_file_path, config_content)
        .with_context(|| format!("Failed to write config file: {}", config_file_path.display()))?;
    
    println!("✓ Project config updated at {}", config_file_path.display());
    println!("\nRestart Apache to apply changes:");
    println!("  lampctl apache restart");
    
    Ok(())
}

fn get_project_port() -> Option<u16> {
    let config_file_path = env::current_dir().ok()?.join(".lampctl-project.conf");
    if !config_file_path.exists() {
        return None;
    }
    
    let config_content = fs::read_to_string(&config_file_path).ok()?;
    config_content
        .lines()
        .find(|line| line.starts_with("PORT="))
        .and_then(|line| line.strip_prefix("PORT="))
        .and_then(|port_str| port_str.parse::<u16>().ok())
}

fn enable_only_this_port(root: &Path, target_port: u16) -> Result<()> {
    let vhosts_conf = root.join("apache").join("conf").join("extra").join("httpd-vhosts.conf");
    if !vhosts_conf.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(&vhosts_conf)
        .with_context(|| format!("Failed to read {}", vhosts_conf.display()))?;
    
    let mut new_lines = Vec::new();
    let mut inside_cli_conf = false;
    let mut modified = false;

    for line in content.lines() {
        let trimmed = line.trim();
        
        if trimmed == "## CLI CONF" {
            inside_cli_conf = true;
            new_lines.push(line.to_string());
            continue;
        }
        
        if trimmed == "## END" {
            inside_cli_conf = false;
            new_lines.push(line.to_string());
            continue;
        }

        if inside_cli_conf {
            // Check for Listen directive
            // It could be "Listen 8080" or "# Listen 8080" or "#Listen 8080"
            // We want to match "Listen <port>" or "#...Listen <port>"
            
            // Simple parsing: check if line contains "Listen "
            if let Some(idx) = line.find("Listen ") {
                let after_listen = &line[idx + 7..];
                // Extract port number (take until non-digit)
                let port_str: String = after_listen.chars().take_while(|c| c.is_ascii_digit()).collect();
                
                if let Ok(port) = port_str.parse::<u16>() {
                    if port == target_port {
                        // Ensure uncommented
                        if line.trim_start().starts_with('#') {
                            new_lines.push(format!("Listen {}", port));
                            modified = true;
                        } else {
                            new_lines.push(line.to_string());
                        }
                    } else {
                        // Ensure commented
                        if !line.trim_start().starts_with('#') {
                            new_lines.push(format!("# Listen {}", port));
                            modified = true;
                        } else {
                            new_lines.push(line.to_string());
                        }
                    }
                    continue;
                }
            }
        }
        
        new_lines.push(line.to_string());
    }

    if modified {
        let new_content = new_lines.join("\n");
        fs::write(&vhosts_conf, new_content)
            .with_context(|| format!("Failed to write {}", vhosts_conf.display()))?;
        println!("Updated vhosts config to listen only on port {}", target_port);
    }

    Ok(())
}

fn is_port_in_use(port: u16) -> Result<bool> {
    let out = Command::new("netstat")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-ano"])
        .output()
        .context("failed to run netstat")?;

    if !out.status.success() {
        return Ok(false);
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let port_str = format!(":{}", port);
    
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        if !(l.starts_with("TCP") || l.starts_with("UDP")) {
            continue;
        }
        
        let parts: Vec<&str> = l.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        
        // Check local address (parts[1])
        let local = parts[1];
        
        // Match patterns like 0.0.0.0:80, [::]:80, 127.0.0.1:80, *:80
        if local.ends_with(&port_str) {
            // Check if it's in LISTENING state for TCP
            if l.starts_with("TCP") {
                if parts.len() >= 4 && parts[3].to_uppercase() == "LISTENING" {
                    return Ok(true);
                }
            } else {
                // UDP doesn't have states, if port is bound it's in use
                return Ok(true);
            }
        }
    }
    
    Ok(false)
}
