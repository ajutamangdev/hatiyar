# pysecfw — Python Security Framework

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

⚠️ **IMPORTANT:** pysecfw is intended for **educational, research, and defensive security use only**.  
Do **not** use this software on systems you do not own or do not have explicit written permission to test. Misuse may result in civil or criminal liability.

---

## Documentation

For comprehensive guides, quick start and usage examples, visit the full documentation:

**[Pysecfw Documentation](https://ajutamangdev.github.io/pysecfw)**

---

## Overview

**pysecfw** is a python security toolkit for penetration testing.

It provides :
- **Interactive CLI (REPL)** for exploring and executing security modules
- **CVE Exploit Modules** for testing known vulnerabilities
- **Enumeration Tools** for cloud, network and system reconnaissance
- **Cloud Compliance Auditing** (coming soon) via web dashboard
- **Modular plugin architecture** for easy extension

> **Future roadmap:** Additional CVE modules, enhanced security tools, web UI, automation APIs, and integration capabilities
---

## Installation

### Prerequisites

Before installing pysecfw, ensure you have the following installed on your system:

- **[Python 3.9+](https://www.python.org/downloads/)** : Required for compatibility with modern Python features
- **[git](https://git-scm.com/downloads)** : Needed to clone the repository from version control
- **[uv](https://docs.astral.sh/uv/getting-started/installation/)** : Fast Python package installer and resolver

### Installation Steps

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



## Security Disclaimer

This tool is provided for **educational and authorized security testing purposes only**. Users must:

- Only test systems they own or have explicit written permission to test
- Comply with all applicable local, state, and federal laws
- Use responsibly and ethically
- Never use for malicious purposes or unauthorized access

The developers assume no liability for misuse of this software.

---


## Support

For issues, questions, or contributions, please visit the [GitHub Issues](https://github.com/ajutamangdev/pysecfw/issues) page.

---


## License

This project is licensed under a **custom license** that allows free use, modification, and collaboration including in commercial environments like client work and training but **prohibits resale or redistribution of the tool as a standalone product**.

The original author, **Aju Tamang**, retains exclusive rights to commercialize the tool directly.

See the full [LICENSE](LICENSE) for details.

