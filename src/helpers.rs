
use std::env;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use std::process::Command;

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

pub fn detect_xampp_root() -> Result<PathBuf> {
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
