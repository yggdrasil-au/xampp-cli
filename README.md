# WLAP-Server-CLI

# xampp-cli-control

command line version of xampp control panel


Here's a polished **README.md** you can drop into the project root:

---

# 🧰 LampCTL — XAMPP Apache Control CLI

> A **Rust-based CLI** that re-implements the **Windows XAMPP Control Panel**'s **Apache controls** with **1:1 feature parity**, minus the GUI.

LampCTL is a lightweight command-line replacement for `xampp-control.exe` focused solely on **Apache**.
It uses the **actual XAMPP build** on disk — no external dependencies, no re-implementations — and can live **right next to the original control panel** inside your XAMPP directory.

---

## ✨ Features

* 🧭 **Apache-only control**, matching the Pascal GUI's functionality:

  * Start / Stop / Restart Apache
  * Open `httpd.conf`, `error.log`, and `http://localhost/` (Admin)
* 🪄 Works **out of the box** — just drop the binary into your XAMPP root (e.g., `C:\xampp`).
* 🧱 Uses the **real `httpd.exe`** shipped with XAMPP, exactly like the GUI.
* 🪟 Windows-only, zero external runtime dependencies.

---

## 📦 Installation

1. Download a **standard Windows XAMPP distribution** (e.g. from [apachefriends.org](https://www.apachefriends.org/)).
2. Place the compiled `lampctl.exe` binary **inside the XAMPP root folder**, next to `xampp-control.exe`:

```
C:\xampp\
├── apache\
├── php\
├── xampp-control.exe
└── lampctl.exe   ← here
```

3. Add `C:\xampp` to your system `PATH`.

---

## 🧭 Usage

LampCTL mirrors the original GUI controls, but through a clean CLI:

```pwsh
lampctl apache <action>
```

### Available Actions

| Action              | Description                                                 |
| ------------------- | ----------------------------------------------------------- |
| `start`             | Start Apache (always foreground)                            |
| `stop`              | Stop Apache                                                 |
| `restart`           | Restart Apache                                              |
| `logs`              | Open `apache\logs\error.log` in default editor/viewer       |
| `admin`             | Open [http://localhost/](http://localhost/) in your browser |
| `config`            | Open `apache\conf\httpd.conf` in default editor             |

### Examples

```pwsh
# Start Apache
lampctl apache start

# Open error log
lampctl apache logs

# Open Apache config
lampctl apache config

```

---

## 🛠️ Other Commands

```pwsh
lampctl version   # Show LampCTL, Apache, and PHP versions
lampctl root      # Print detected XAMPP root (location of the EXE)
```

---

## ⚡ Design Notes

* The tool **does not modify configs**, only invokes existing `httpd.exe` commands (`-k start|stop|install|uninstall`) exactly like the Pascal GUI.
* All paths are **relative to the binary's location**, so double-clicking or PATH invocation works reliably.
* Only **Apache** is supported. MySQL/FileZilla/Mercury/Tomcat are intentionally **ignored**.
* Service features not implemented in this tool, only forground this run instances

---

## 🧪 Building from Source

```pwsh
# Install Rust (https://rustup.rs/)
cargo build --release

# The binary will be in:
target/release/lampctl.exe
```

Copy `lampctl.exe` into your XAMPP root folder.

---

## 📝 License

MIT License © 2025
This project is not affiliated with Apache Friends or XAMPP.

---

Would you like me to add badges (build status, Rust version, etc.) to the top of the README as well?
