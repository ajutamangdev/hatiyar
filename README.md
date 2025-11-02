# Hatiyar

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> Security toolkit designed for penetration testing, vulnerability assessment, and security research.

⚠️ **IMPORTANT:** Hatiyar is intended for **educational, research, and defensive security use only**.  
Do **not** use this software on systems you do not own or do not have explicit written permission to test. Misuse may result in civil or criminal liability.

---

## Quick Demo

![hatiyar demo](/docs/src/assets/hatiyar.gif)

---

## Overview

**Hatiyar** is a security toolkit designed for penetration testing, vulnerability assessment, and security research.

It provides:
- **Interactive CLI (REPL)** - Metasploit-like shell for exploring and executing security modules
- **CVE Exploit Modules** - Pre-built, tested exploits for known vulnerabilities
- **Enumeration Tools** - Cloud, network and system reconnaissance capabilities
- **Modular Architecture** - Easy extension with custom Python modules and YAML registration
- **Cloud Compliance Auditing** - (coming soon) via web dashboard

> **Future roadmap:** Additional CVE modules, enhanced security tools, web UI, automation APIs, and integration capabilities

---

## Quick Start

Get Hatiyar running in minutes:

### Prerequisites

- **[Python 3.9+](https://www.python.org/downloads/)** - Modern Python with type hints support
- **[git](https://git-scm.com/downloads)** - Version control for cloning the repository
- **[uv](https://docs.astral.sh/uv/getting-started/installation/)** - Fast Python package installer
- **build-essential** - C compiler and build tools for Makefile-based setup
  - **Linux**: `sudo apt install build-essential` (Debian/Ubuntu) or `sudo dnf install gcc make` (Fedora/RHEL)
  - **macOS**: `xcode-select --install` (Xcode Command Line Tools)

### Installation

#### 1. Clone the Repository

```bash
git clone https://github.com/ajutamangdev/hatiyar.git
cd hatiyar
```

#### 2. Set Up with Makefile (Recommended)

```bash
make setup
```

This will:
- Create a virtual environment (`.venv`)
- Install all dependencies using `uv sync`
- Activate the environment automatically for subsequent commands

#### 3. Verify Installation

```bash
make info
```

#### 4. Run the Framework

```bash
make shell           # Interactive shell
# OR
make serve           # Web server
```

> **For detailed installation instructions, alternative setup methods, and platform-specific guides, see the [Installation Guide](https://ajutamangdev.github.io/hatiyar/introduction/installation/).**

---

## 📖 Full Documentation

For comprehensive guides, tutorials, API documentation, and usage examples, visit the full documentation:

**[Hatiyar Documentation](https://ajutamangdev.github.io/hatiyar)**

---

## Security Disclaimer

This tool is provided for **educational and authorized security testing purposes only**. Users must:

- Only test systems they own or have explicit written permission to test
- Comply with all applicable local, state, and federal laws
- Use responsibly and ethically
- Never use for malicious purposes or unauthorized access

The developers assume no liability for misuse of this software.

---

## Support & Community

- **[GitHub Repository](https://github.com/ajutamangdev/hatiyar)** - Source code, issues, discussions
- **[Issue Tracker](https://github.com/ajutamangdev/hatiyar/issues)** - Report bugs, request features
- **[Discussions](https://github.com/ajutamangdev/hatiyar/discussions)** - Ask questions, share knowledge
- **[Discord Community](https://discord.gg/V9HghE8V7M)** - Join our community server

---

## License

This project is licensed under a **custom license** that allows free use, modification, and collaboration including in commercial environments like client work and training but **prohibits resale or redistribution of the tool as a standalone product**.

The original author, **Aju Tamang**, retains exclusive rights to commercialize the tool directly.

See the full [LICENSE](LICENSE) for details.

