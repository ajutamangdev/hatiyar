# Pysecfw

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> A modular Python security toolkit for penetration testing, vulnerability assessment, and security research.

⚠️ **IMPORTANT:** pysecfw is intended for **educational, research, and defensive security use only**.  
Do **not** use this software on systems you do not own or do not have explicit written permission to test. Misuse may result in civil or criminal liability.

---

## Quick Demo

![pysecfw demo](/docs/src/assets/pysecfw.gif)

---

## Overview

**pysecfw** is a python security toolkit for penetration testing.

It provides:
- **Interactive CLI (REPL)** - Metasploit-like shell for exploring and executing security modules
- **CVE Exploit Modules** - Pre-built, tested exploits for known vulnerabilities
- **Enumeration Tools** - Cloud, network and system reconnaissance capabilities
- **Modular Architecture** - Easy extension with custom Python modules and YAML registration
- **Cloud Compliance Auditing** - (coming soon) via web dashboard

> **Future roadmap:** Additional CVE modules, enhanced security tools, web UI, automation APIs, and integration capabilities

---

## Quick Start

Get pysecfw running in minutes:

### Prerequisites

- **[Python 3.9+](https://www.python.org/downloads/)** - Modern Python with type hints support
- **[git](https://git-scm.com/downloads)** - Version control for cloning the repository
- **[uv](https://docs.astral.sh/uv/getting-started/installation/)** - Fast Python package installer

### Installation

### Installation

#### 1. Clone the Repository

```bash
git clone https://github.com/ajutamangdev/pysecfw.git
cd pysecfw
```

#### 2. Create and Activate Virtual Environment

Using `uv` to create a virtual environment:

```bash
uv venv
source .venv/bin/activate  # On Linux/macOS
# OR
.venv\Scripts\activate     # On Windows
```

#### 3. Install Dependencies

```bash
uv sync
```

#### 4. Run the Framework

```bash
python3 src/pysecfw/main.py
```

---

## 📖 Full Documentation

For comprehensive guides, tutorials, API documentation, and usage examples, visit the full documentation:

**[Pysecfw Documentation](https://ajutamangdev.github.io/pysecfw)**

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

- **[GitHub Repository](https://github.com/ajutamangdev/pysecfw)** - Source code, issues, discussions
- **[Issue Tracker](https://github.com/ajutamangdev/pysecfw/issues)** - Report bugs, request features
- **[Discussions](https://github.com/ajutamangdev/pysecfw/discussions)** - Ask questions, share knowledge

---

## License

This project is licensed under a **custom license** that allows free use, modification, and collaboration including in commercial environments like client work and training but **prohibits resale or redistribution of the tool as a standalone product**.

The original author, **Aju Tamang**, retains exclusive rights to commercialize the tool directly.

See the full [LICENSE](LICENSE) for details.

