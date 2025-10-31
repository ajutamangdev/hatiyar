---
title: Installation
description: How to install and set up hatiyar
---

## Prerequisites

Before installing hatiyar, ensure you have the following:

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
git clone https://github.com/ajutamangdev/hatiyar.git
cd hatiyar
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

After setup, use the Makefile to launch hatiyar:

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
git clone https://github.com/ajutamangdev/hatiyar.git
cd hatiyar
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
python3 src/hatiyar/main.py --version
```

### 5. Run the Framework

```bash
python3 src/hatiyar/main.py shell  # Interactive shell
# OR
python3 src/hatiyar/main.py serve  # Web server
```

## Container Setup (Docker/Podman)

hatiyar can be containerized for consistent deployment across environments. Use either **Docker** or **Podman**.

### Prerequisites

- **Docker**: [Install Docker](https://docs.docker.com/get-docker/)
- **Podman**: [Install Podman](https://podman.io/docs/installation)

### Building the Container Image

#### Using Docker

```bash
# Build the image
docker build -t hatiyar -f Containerfile .

# Verify the image was created
docker images | grep hatiyar
```

#### Using Podman

```bash
# Build the image
podman build -t hatiyar -f Containerfile .

# Verify the image was created
podman images | grep hatiyar
```

### Running the Container

#### Interactive Shell with Docker

```bash
docker run -it --rm hatiyar shell
```

#### Interactive Shell with Podman

```bash
podman run -it --rm hatiyar shell
```

#### With AWS Credentials (Local Development)

Mount your AWS credentials into the container for cloud operations:

**Docker:**
```bash
docker run -it --rm \
  -v ~/.aws:/home/appuser/.aws:ro \
  -e AWS_PROFILE=your-profile \
  hatiyar shell
```

**Podman:**
```bash
podman run -it --rm \
  -v ~/.aws:/home/appuser/.aws:ro \
  -e AWS_PROFILE=your-profile \
  hatiyar shell
```

Replace `your-profile` with your AWS profile name.

### Troubleshooting Container Issues

#### "typer is not installed" Error

This error occurs when running a stale container image. Rebuild it:

```bash
# Docker
docker build -t hatiyar -f Containerfile . --no-cache

# Podman
podman build -t hatiyar -f Containerfile . --no-cache
```

The `--no-cache` flag forces a fresh build without using cached layers.


### Container Image Details

The Containerfile uses a multi-stage build for efficiency:

1. **Builder Stage** (`python:3.11-alpine`): Compiles dependencies with `uv`
2. **Runtime Stage** (`python:3.11-slim`): Runs the application with minimal footprint

Environment variables in the runtime:
- `PYTHONUNBUFFERED=1`: Real-time log output
- `PYTHONDONTWRITEBYTECODE=1`: No `.pyc` files in container
- Non-root `appuser` for security

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
cd hatiyar
git pull origin main
make setup  # Update dependencies and activate environment
```

## Uninstallation

```bash
# Remove directory
cd ..
rm -rf hatiyar
```
