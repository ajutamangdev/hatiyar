---
title: Installation
description: How to install and set up pysecfw
---

## Prerequisites

Before installing pysecfw, ensure you have the following:

- **Python 3.9 or higher** - [Download Python](https://www.python.org/downloads/)
- **git** - [Install git](https://git-scm.com/downloads/)
- **uv** - [Install uv](https://docs.astral.sh/uv/getting-started/installation/)
- **build-essential** (Linux only, for Makefile-based setup) - C compiler and build tools
  - **Debian/Ubuntu**: `sudo apt install build-essential`
  - **Fedora/RHEL**: `sudo dnf install gcc make`
  - **Alpine**: `apk add build-base`

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/ajutamangdev/pysecfw.git
cd pysecfw
```

### 2. Set Up the Project

Use the Makefile to set up the virtual environment and install dependencies:

```bash
make setup
```

This will:
- Create a virtual environment (`.venv`)
- Install all dependencies with `uv sync`
- Activate the environment

### 3. Verify Installation

Check the project setup:

```bash
make info
```

This displays:
- Python version (from virtual environment)
- Tool versions (uv, mypy, ruff)
- Project configuration

## Quick Start

After setup, use the Makefile to launch pysecfw:

```bash
make shell            # Launch interactive shell
make serve            # Start web server
make info             # Show project info
```

All commands automatically use the activated virtual environment.

## Alternative Setup (Manual)

If you prefer not to use Makefile, follow these steps:

### 1. Clone the Repository

```bash
git clone https://github.com/ajutamangdev/pysecfw.git
cd pysecfw
```

### 2. Create and Activate Virtual Environment

Using `uv` to create a virtual environment:

```bash
uv venv
source .venv/bin/activate  # On Linux/macOS
# OR
.venv\Scripts\activate     # On Windows
```

### 3. Install Dependencies

```bash
uv sync
```

### 4. Verify Installation

```bash
python3 src/pysecfw/main.py --version
```

### 5. Run the Framework

```bash
python3 src/pysecfw/main.py shell  # Interactive shell
# OR
python3 src/pysecfw/main.py serve  # Web server
```

## Platform-Specific Notes

### Linux

Install system dependencies:

```bash
# Debian/Ubuntu (with build tools for Makefile)
sudo apt update
sudo apt install python3 python3-pip git build-essential

# Fedora/RHEL (with build tools for Makefile)
sudo dnf install python3 python3-pip git gcc make

# Alpine (with build tools for Makefile)
apk add python3 git build-base
```

Then install uv:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### macOS

Using Homebrew:

```bash
brew install python git

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Windows

1. Install [Python](https://www.python.org/downloads/)
2. Install [git for Windows](https://git-scm.com/download/win)
3. Install uv via PowerShell:

```powershell
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

## Troubleshooting

### uv Not Found

Verify uv is installed:

```bash
uv --version
```

If not installed, follow the [uv installation guide](https://docs.astral.sh/uv/getting-started/installation/)

### Python Version Issues

Check Python version:

```bash
python3 --version
# Should show 3.9 or higher
```

## Next Steps

- **[Quick Start](/introduction/quick-start/)** - Run your first exploit
- **[Usage Guide](/guides/usage/)** - Learn all commands
- **[Configuration](/guides/configuration/)** - Customize settings

## Updating

To update to the latest version:

```bash
cd pysecfw
git pull origin main
make setup  # Update dependencies and activate environment
```

## Uninstallation

```bash
# Remove directory
cd ..
rm -rf pysecfw
```
