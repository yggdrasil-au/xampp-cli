
mod apache;
mod helpers;

use std::env;
use std::path::Path;

use anyhow::Result;
use clap::{Parser, Subcommand};

use helpers::exec_and_first_line;
use helpers::detect_xampp_root;


#[derive(Parser)]
#[command(
    name = "wlampctl",
    version,
    about = "CLI for controlling the XAMPP apache server"
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
        action: apache::ApacheAction,
    },
    /// Print detected XAMPP root directory
    Root,
    /// Show LampCTL, Apache, and PHP versions
    Version,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = detect_xampp_root()?;

    match cli.command {
        CommandGroup::Apache { action } => apache::handle_apache(action, &root)?,
        CommandGroup::Root => println!("{}", root.display()),
        CommandGroup::Version => show_versions(&root)?,
    }

    Ok(())
}

fn show_versions(root: &Path) -> Result<()> {
    println!("wlampctl {}", env!("CARGO_PKG_VERSION"));
    println!("xampp root: {}", root.display());

    if let Some(line) = apache::get_apache_version(root) {
        println!("apache: {}", line);
    }

    // PHP path differs on Windows vs Linux
    #[cfg(windows)]
    let php_bin = root.join("php").join("php.exe");
    #[cfg(unix)]
    let php_bin = root.join("bin").join("php");

    if let Some(line) = exec_and_first_line(php_bin, ["-v"]) {
        println!("php: {}", line);
    }

    Ok(())
}
