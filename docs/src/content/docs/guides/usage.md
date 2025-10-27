---
title: Usage Guide
description: Complete command reference for pysecfw
---

pysecfw is a modular Python security framework for vulnerability assessment, exploitation, and security testing.

## Quick Start

### 1. Search for Modules

Find security modules by keyword:

```bash
# Search for Grafana vulnerabilities
pysecfw search grafana

# Find all 2021 CVEs
pysecfw search CVE-2021

# Search by vulnerability type
pysecfw search traversal
```

### 2. View Module Information

Check module details before running:

```bash
# View module info
pysecfw run cve.cve_2021_43798 --info

# Or by CVE ID
pysecfw run CVE-2021-43798 --info
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
pysecfw run cve.cve_2021_43798 \
  --set RHOST=target.example.com \
  --set PLUGIN=grafana

# Run with custom port and file
pysecfw run cve.cve_2021_43798 \
  --set RHOST=192.168.1.100 \
  --set RPORT=3000 \
  --set PLUGIN=grafana \
  --set FILE=/etc/passwd
```

### 4. Interactive Shell

Launch the interactive shell for advanced usage:

```bash
pysecfw shell
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
pysecfw serve

# Custom port
pysecfw serve --port 8080

# Localhost only
pysecfw serve --host 127.0.0.1

# Development mode with auto-reload
pysecfw serve --reload
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
pysecfw search <query>
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
pysecfw run <module> [OPTIONS]
```

Options:
- `--set KEY=VALUE` - Set module options (can be used multiple times)
- `--info` - Show module information before running
- `--help` - Show command help

Examples:
```bash
# Show info first
pysecfw run CVE-2021-43798 --info

# Run with options
pysecfw run cve.cve_2021_43798 \
  --set RHOST=example.com \
  --set PLUGIN=grafana

# Multiple options
pysecfw run cve.cve_2021_42013 \
  --set RHOST=apache.local \
  --set RPORT=8080 \
  --set FILE=/etc/passwd
```

#### `shell`

Start interactive shell:

```bash
pysecfw shell
```

#### `serve`

Start web server:

```bash
pysecfw serve [OPTIONS]
```

Options:
- `--host` - Bind host address (default: 0.0.0.0)
- `--port` - Bind port number (default: 8000)
- `--reload` - Enable auto-reload for development

#### `info`

Display system information:

```bash
pysecfw info
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
pysecfw shell
pysecfw> ls cve

# Search for specific CVE
pysecfw search CVE-2021-43798
```

### Enumeration Modules

Information gathering and reconnaissance tools:

```bash
pysecfw search enumeration
```

### Cloud Modules

Cloud platform security assessments (AWS, Azure, GCP):

```bash
pysecfw search cloud
```

### Platform Modules

Platform-specific security tools:

```bash
pysecfw search platforms
```

## Workflow Examples

### Example 1: Running a CVE Exploit

```bash
# Step 1: Search for the vulnerability
pysecfw search grafana

# Step 2: View module details
pysecfw run cve.cve_2021_43798 --info

# Step 3: Run with required options
pysecfw run cve.cve_2021_43798 \
  --set RHOST=target.com \
  --set PLUGIN=grafana
```

### Example 2: Interactive Shell Workflow

```bash
# Start shell
pysecfw shell

# Inside shell:
pysecfw> search grafana
pysecfw> use cve.cve_2021_43798
pysecfw> show options
pysecfw> set RHOST target.example.com
pysecfw> set PLUGIN grafana
pysecfw> run
```

### Example 3: Using CVE ID Directly

```bash
# Run by CVE ID instead of module path
pysecfw run CVE-2021-43798 --info
pysecfw run CVE-2021-43798 --set RHOST=target.com --set PLUGIN=grafana
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
pysecfw run <module> --info
```

## Tips and Best Practices

1. **Always check module info first**: Use `--info` to understand required options
2. **Use CVE IDs for quick access**: `pysecfw run CVE-2021-43798` instead of full path
3. **Search before running**: Find the right module with `pysecfw search`
4. **Use shell for exploration**: Interactive shell is great for discovering modules
5. **Web interface for documentation**: Use `pysecfw serve` to browse modules visually

## Troubleshooting

### Module not found

```bash
# List available modules
pysecfw search .

# Or use shell
pysecfw shell
pysecfw> ls
```

### Missing required options

```bash
# Check required options
pysecfw run <module> --info
```

The module info shows which options are required (marked as "Yes" in the Required column).

### Command not found

Make sure pysecfw is properly installed:

```bash
# Check version
pysecfw --version

# Reinstall if needed
pip install -e .
```

## Getting Help

```bash
# Main help
pysecfw --help

# Command-specific help
pysecfw run --help
pysecfw search --help
pysecfw shell --help
pysecfw serve --help
```

## Version Information

Check your pysecfw version:

```bash
pysecfw --version
pysecfw info
```
