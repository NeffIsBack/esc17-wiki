Certipy is a Python tool that supports **Python 3.12+** and runs on both Linux and Windows. The tool is distributed via pip (Python Package Index) as `certipy-ad`. Ensure you have a suitable Python environment before installation. Below are installation instructions for common platforms:

## 🐧 Linux Installation (Debian/Ubuntu/Kali)

1. **Install Python 3.12+ and pip** if not already present. For example, on Debian-based systems:

   ```bash
   sudo apt update && sudo apt install -y python3 python3-pip
   ```

2. **Create and activate a virtual environment** (optional but recommended):

   ```bash
   python3 -m venv certipy-venv
   source certipy-venv/bin/activate
   ```

   This ensures Certipy's dependencies won't conflict with your system Python packages.
3. **Install Certipy via pip**:

   ```bash
   pip install certipy-ad
   ```

   This will download and install Certipy and its requirements (like `impacket`, `ldap3`, etc.). You should then have the `certipy` command available.

**Kali Linux Note:** Kali includes Certipy in its package repo as `certipy-ad`. It may be pre-installed on recent Kali releases. If so, you can directly run `certipy-ad` (Kali's packaged command name). If you wish to use the latest version via pip (which may be newer than Kali's package), use the pip method above. *(The Kali pre-installed version might require invoking `certipy-ad` instead of `certipy`.)*

## 🪟 Windows Installation (PowerShell)

Certipy can run on Windows as well (assuming Python 3.12+ is installed):

1. **Install Python 3.12+ for Windows** - either via the [official installer](https://www.python.org/downloads/windows/) or from the Microsoft Store.

   * If using the official installer, ensure you check "Add Python to PATH" for convenience.
   * If using Microsoft Store, search for *Python 3.12* and install it.
2. **Open PowerShell** (or Command Prompt) and create a virtual environment (optional):

   ```powershell
   py -3.12 -m venv certipy-venv
   certipy-venv\Scripts\Activate.ps1   # If execution policy allows
   # If Activate.ps1 is blocked, you may use Activate.bat in Cmd, or temporarily set execution policy
   ```

3. **Install Certipy** using pip:

   ```powershell
   pip install certipy-ad
   ```

4. Once installed, verify by running:

   ```powershell
   certipy -h
   ```

   You should see Certipy's help output, indicating a successful installation.

## 📦 Upgrading Certipy

To upgrade to the latest version of Certipy (if installed via pip), simply run:

```bash
pip install -U certipy-ad
```

This will fetch and install the latest release. It's a good idea to periodically update, as new releases may add support for newly discovered vulnerabilities (e.g., ESC9+ techniques) or improved features. At the time of writing, **Certipy v5.0.0** is the latest version (which supports ESC1 - ESC16).

## Troubleshooting Installation

* Always run Certipy using `certipy` command (not `certipy-ad`), if installed via pip. If you installed via Kali's package manager, use `certipy-ad` instead.
* If installing on Windows and you get a `'certipy' is not recognized` error, ensure Python Scripts directory is in your PATH, or invoke it via `python -m certipy`.
* Certipy depends on several libraries (impacket, cryptography, asn1crypto, etc.). Pip should handle these. If you encounter compilation issues (e.g., with cryptography on Linux), make sure build tools and OpenSSL dev libraries are installed (for Debian: `apt install build-essential libssl-dev libffi-dev python3-dev`).
* When running on Windows, if you get import errors, check that you activated the virtualenv (if used) or that Python 3.12 is being used (especially if multiple Python versions installed).
