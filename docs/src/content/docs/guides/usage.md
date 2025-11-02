---
title: Usage Guide
description: Complete command reference for hatiyar
---

hatiyar is a security toolkit designed for penetration testing, vulnerability assessment, and security research.

## Quick Start

### 1. Search for Modules

Find security modules by keyword:

```bash
# Search for Grafana vulnerabilities
hatiyar search grafana

# Find all 2021 CVEs
hatiyar search CVE-2021

# Search by vulnerability type
hatiyar search traversal
```

### 2. View Module Information

Check module details before running:

```bash
# View module info
hatiyar run cve.cve_2021_43798 --info

# Or by CVE ID
hatiyar run CVE-2021-43798 --info
```

This displays:
- Module name and description
- Author information
- Required and optional parameters
- Current option values

### 3. Run a Module

Execute a module with required options:

```bash
# Run Grafana path traversal exploit
hatiyar run cve.cve_2021_43798 \
  --set RHOST=target.example.com \
  --set PLUGIN=grafana

# Run with custom port and file
hatiyar run cve.cve_2021_43798 \
  --set RHOST=192.168.1.100 \
  --set RPORT=3000 \
  --set PLUGIN=grafana \
  --set FILE=/etc/passwd
```

### 4. Interactive Shell

Launch the interactive shell for advanced usage:

```bash
hatiyar shell
```

Shell commands:
- `ls` - List all modules
- `ls cve` - List CVE modules
- `search <query>` - Search modules
- `use <module>` - Load a module
- `show options` - Display module options
- `set <option> <value>` - Set an option
- `run` - Execute the module
- `help` - Show help
- `exit` - Exit the shell

### 5. Web Interface

Start the web dashboard:

```bash
# Default (0.0.0.0:8000)
hatiyar serve

# Custom port
hatiyar serve --port 8080

# Localhost only
hatiyar serve --host 127.0.0.1

# Development mode with auto-reload
hatiyar serve --reload
```

Access the dashboard at: http://localhost:8000

## Command Reference

### Global Options

```bash
--version, -v    Show version and exit
--help           Show help message
```

### Commands

#### `search`

Search for modules by keyword:

```bash
hatiyar search <query>
```

Searches across:
- Module names
- Descriptions
- CVE IDs
- Categories
- Authors

#### `run`

Execute a module:

```bash
hatiyar run <module> [OPTIONS]
```

Options:
- `--set KEY=VALUE` - Set module options (can be used multiple times)
- `--info` - Show module information before running
- `--help` - Show command help

Examples:
```bash
# Show info first
hatiyar run CVE-2021-43798 --info

# Run with options
hatiyar run cve.cve_2021_43798 \
  --set RHOST=example.com \
  --set PLUGIN=grafana

# Multiple options
hatiyar run cve.cve_2021_42013 \
  --set RHOST=apache.local \
  --set RPORT=8080 \
  --set FILE=/etc/passwd
```

#### `shell`

Start interactive shell:

```bash
hatiyar shell
```

#### `serve`

Start web server:

```bash
hatiyar serve [OPTIONS]
```

Options:
- `--host` - Bind host address (default: 0.0.0.0)
- `--port` - Bind port number (default: 8000)
- `--reload` - Enable auto-reload for development

#### `info`

Display system information:

```bash
hatiyar info
```

Shows:
- Version
- Module statistics by category
- Python version
- Platform information

## Module Types

### CVE Modules

Exploit modules for known vulnerabilities:

```bash
# List all CVE modules
hatiyar shell
hatiyar> ls cve

# Search for specific CVE
hatiyar search CVE-2021-43798
```

### Enumeration Modules

Information gathering and reconnaissance tools:

```bash
hatiyar search enumeration
```

### Cloud Modules

Cloud platform security assessments (AWS, Azure, GCP):

```bash
hatiyar search cloud
```

### Platform Modules

Platform-specific security tools:

```bash
hatiyar search platforms
```

## Workflow Examples

### Example 1: Running a CVE Exploit

```bash
# Step 1: Search for the vulnerability
hatiyar search grafana

# Step 2: View module details
hatiyar run cve.cve_2021_43798 --info

# Step 3: Run with required options
hatiyar run cve.cve_2021_43798 \
  --set RHOST=target.com \
  --set PLUGIN=grafana
```

### Example 2: Interactive Shell Workflow

```bash
# Start shell
hatiyar shell

# Inside shell:
hatiyar> search grafana
hatiyar> use cve.cve_2021_43798
hatiyar> show options
hatiyar> set RHOST target.example.com
hatiyar> set PLUGIN grafana
hatiyar> run
```

### Example 3: Using CVE ID Directly

```bash
# Run by CVE ID instead of module path
hatiyar run CVE-2021-43798 --info
hatiyar run CVE-2021-43798 --set RHOST=target.com --set PLUGIN=grafana
```

## Module Options

Most modules support these common options:

### Network Options
- `RHOST` - Target hostname or IP (usually required)
- `RPORT` - Target port number
- `SCHEME` - Protocol scheme (http/https)

### Request Options
- `TIMEOUT` - Request timeout in seconds
- `VERIFY_SSL` - Verify SSL certificates (True/False)
- `USER_AGENT` - Custom User-Agent string

### Module-Specific Options

Check module info to see specific options:

```bash
hatiyar run <module> --info
```

## Tips and Best Practices

1. **Always check module info first**: Use `--info` to understand required options
2. **Use CVE IDs for quick access**: `hatiyar run CVE-2021-43798` instead of full path
3. **Search before running**: Find the right module with `hatiyar search`
4. **Use shell for exploration**: Interactive shell is great for discovering modules
5. **Web interface for documentation**: Use `hatiyar serve` to browse modules visually

## Troubleshooting

### Module not found

```bash
# List available modules
hatiyar search .

# Or use shell
hatiyar shell
hatiyar> ls
```

### Missing required options

```bash
# Check required options
hatiyar run <module> --info
```

The module info shows which options are required (marked as "Yes" in the Required column).

### Command not found

Make sure hatiyar is properly installed:

```bash
# Check version
hatiyar --version

# Reinstall if needed
pip install -e .
```

## Getting Help

```bash
# Main help
hatiyar --help

# Command-specific help
hatiyar run --help
hatiyar search --help
hatiyar shell --help
hatiyar serve --help
```

## Version Information

Check your hatiyar version:

```bash
hatiyar --version
hatiyar info
```
