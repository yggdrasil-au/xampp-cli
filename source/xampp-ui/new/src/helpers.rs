use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use anyhow::{anyhow, bail, Context, Result};

pub fn exec_and_first_line<I, S>(exe: PathBuf, args: I) -> Option<String>
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

/// Detect XAMPP root directory
pub fn detect_xampp_root() -> Result<PathBuf> {
    // 1. Check WLAMPCTL_XAMPP_ROOT env var
    if let Ok(from_env) = env::var("WLAMPCTL_XAMPP_ROOT") {
        let path = PathBuf::from(from_env);
        if is_xampp_root(&path) {
            return Ok(path);
        } else {
            bail!(
                "{} is not a XAMPP root (httpd binary missing)",
                path.display()
            );
        }
    }

    // 2. Try relative to executable
    if let Ok(exe) = env::current_exe() {
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
    }

    // 3. Try Standard Windows Path
    #[cfg(windows)]
    {
        let default_windows = PathBuf::from(r"C:\xampp");
        if is_xampp_root(&default_windows) {
            return Ok(default_windows);
        }
    }

    // 4. Try Standard Linux Path
    #[cfg(unix)]
    {
        let default_linux = PathBuf::from("/opt/lampp");
        if is_xampp_root(&default_linux) {
            return Ok(default_linux);
        }
    }

    // Failed to detect
    Err(anyhow!(
        "Failed to locate XAMPP root. Set WLAMPCTL_XAMPP_ROOT env var or install in standard location."
    ))
}

fn is_xampp_root(path: &Path) -> bool {
    // Windows: apache/bin/httpd.exe
    // Linux: bin/httpd (standard XAMPP layout)
    path.join("apache").join("bin").join("httpd.exe").exists() || 
    path.join("bin").join("httpd").exists()
}