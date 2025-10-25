---
title: Installation
description: How to install and set up pysecfw
---

## Prerequisites

Before installing pysecfw, ensure you have the following:

- **Python 3.9 or higher** - [Download Python](https://www.python.org/downloads/)
- **git** - [Install git](https://git-scm.com/downloads/)
- **uv** - [Install uv](https://docs.astral.sh/uv/getting-started/installation/)

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/ajutamangdev/pysecfw.git
cd pysecfw
```

### 2. Install with uv

```bash
uv sync
```

This will:
- Create a virtual environment
- Install all dependencies
- Set up the project in development mode

### 3. Verify Installation

Using the full path:

```bash
python3 src/pysecfw/main.py --version
```

## Quick Start

After installation, you can immediately start using pysecfw:

```bash
# Start the interactive shell with full path
python3 src/pysecfw/main.py shell
```

## Using Makefile Commands

For convenience, use the provided Makefile shortcuts:

```bash
make shell            # Launch interactive shell
make serve            # Start web server
make info             # Show project info
```

## Platform-Specific Notes

### Linux

Install system dependencies:

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install python3 python3-pip git

# Fedora/RHEL
sudo dnf install python3 python3-pip git
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
uv sync  # Update dependencies
```

## Uninstallation

```bash
# Remove directory
cd ..
rm -rf pysecfw
```
