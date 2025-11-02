"""Command handlers for hatiyar CLI"""

from typing import Optional, List, Dict, Any
from rich.table import Table
from rich.panel import Panel
from hatiyar.core.modules import ModuleManager

# Global state
manager = ModuleManager()
active_module: Optional[Any] = None
active_module_name: Optional[str] = None
module_options: Dict[str, Any] = {}
global_options: Dict[str, Any] = {}  # Global options shared across modules
current_context: str = (
    ""  # Track current navigation context (e.g., "cloud", "cloud.aws")
)

# Constants
CATEGORIES_INFO = [
    ("cve", "CVE exploit modules"),
    ("cloud", "Cloud platform security (AWS, Azure, GCP)"),
    ("enumeration", "Reconnaissance and enumeration tools"),
    ("platforms", "Platform-specific exploits and tools"),
    ("misc", "Miscellaneous modules"),
]

SENSITIVE_KEYWORDS = ["PASSWORD", "KEY", "SECRET", "TOKEN"]


def get_current_context() -> str:
    """Get the current navigation context"""
    return current_context


def handle_command(command: str, console) -> None:
    """Route commands to appropriate handlers"""
    tokens = command.split()
    if not tokens:
        return

    cmd = tokens[0].lower()
    args = tokens[1:]

    command_handlers = {
        "help": lambda: show_help(console),
        "clear": lambda: clear_screen(console),
        "cls": lambda: clear_screen(console),
        "list": lambda: handle_list(args, console),
        "ls": lambda: handle_list(args, console),
        "cd": lambda: handle_cd(args, console),
        "reload": lambda: handle_reload(console),
        "search": lambda: handle_search(args, console),
        "info": lambda: handle_info(args, console),
        "use": lambda: handle_use(args, console),
        "select": lambda: handle_use(args, console),
        "set": lambda: handle_set(args, console),
        "show": lambda: handle_show(args, console),
        "run": lambda: handle_run(console),
        "katta": lambda: handle_run(console),
        "exploit": lambda: handle_run(console),
        "back": lambda: handle_back(console),
    }

    handler = command_handlers.get(cmd)
    if handler:
        handler()
    else:
        console.print(f"[red]Unknown command:[/red] {cmd}")
        console.print("[dim]Type [cyan]help[/cyan] for available commands[/dim]")


def show_help(console) -> None:
    """Display help information"""
    help_text = (
        "[bold cyan]Available Commands[/bold cyan]\n\n"
        "[yellow]Navigation:[/yellow]\n"
        "  ls/list                - Show categories or list modules\n"
        "  ls <category>          - List modules in category (cve, cloud, enumeration, platforms)\n"
        "  cd <path>              - Navigate to category or namespace (e.g., cd cloud, cd aws)\n"
        "  cd ..                  - Navigate up one level\n"
        "  cd                     - Return to root\n"
        "  search <query>         - Search for modules\n\n"
        "[yellow]Module Operations:[/yellow]\n"
        "  use/select <module>    - Select a module (short name works in context, e.g., 'ec2')\n"
        "  info <module?>         - Show detailed module information\n"
        "  show options           - Display current module options\n"
        "  show global            - Display global options (AWS_PROFILE, AWS_REGION, etc.)\n"
        "  set <option> <value>   - Configure module or global option\n"
        "  run/katta/exploit      - Execute the loaded module\n"
        "  back                   - Unload current module or navigate up\n\n"
        "[yellow]Utility:[/yellow]\n"
        "  reload                 - Reload modules from YAML files\n"
        "  clear                  - Clear the console\n"
        "  exit/quit              - Exit hatiyar\n\n"
    )
    console.print(Panel.fit(help_text, title="Help", border_style="cyan"))


def clear_screen(console) -> None:
    """Clear console and show welcome message"""
    console.clear()
    console.print("[bold green]Welcome to hatiyar![/bold green]")
    console.print(
        "Type [bold cyan]help[/bold cyan] for available commands or [cyan]ls[/cyan] to explore.\n"
    )


def handle_reload(console) -> None:
    """Reload module registries from YAML without restarting the CLI"""
    global manager
    manager = ModuleManager()
    stats = manager.get_stats()
    console.print(
        f"[green]Reloaded modules from YAML.[/green] Total: {stats.get('total_modules', 0)}"
    )
    console.print("[dim]Tip: run 'ls cve' to list CVE modules[/dim]")


def handle_list(args: List[str], console) -> None:
    """Handle list/ls command"""
    global current_context

    if not args:
        # If we're in a context, show that context's contents
        if current_context:
            # Check if it's a namespace (e.g., cloud.aws)
            if current_context in manager.namespaces:
                show_namespace_modules(current_context, console)
            else:
                show_category_modules(current_context, console)
        else:
            # No context, show categories
            show_categories(console)
    else:
        category_or_namespace = args[0].lower()

        # Set the current context
        current_context = category_or_namespace

        # Check if it's a namespace (e.g., cloud.aws)
        if category_or_namespace in manager.namespaces:
            show_namespace_modules(category_or_namespace, console)
        else:
            show_category_modules(category_or_namespace, console)


def handle_cd(args: List[str], console) -> None:
    """Handle cd command for navigation"""
    global current_context

    if not args:
        # cd with no args goes to root
        current_context = ""
        console.print("[cyan]Navigated to root[/cyan]")
        show_categories(console)
        return

    target = args[0].lower()

    # Handle cd ..
    if target == "..":
        if not current_context:
            console.print("[yellow]Already at root level[/yellow]")
            return

        # Navigate up one level
        if "." in current_context:
            # From cloud.aws -> cloud
            current_context = current_context.rsplit(".", 1)[0]
            console.print(f"[cyan]Navigated to {current_context}[/cyan]")

            # Show the new context
            if current_context in manager.namespaces:
                show_namespace_modules(current_context, console)
            else:
                show_category_modules(current_context, console)
        else:
            # From cloud -> root
            current_context = ""
            console.print("[cyan]Navigated to root[/cyan]")
            show_categories(console)
        return

    # Handle cd to specific location
    # If in context, try to append to current context first
    if current_context and "." not in target:
        full_path = f"{current_context}.{target}"
        if full_path in manager.namespaces:
            current_context = full_path
            console.print(f"[cyan]Navigated to {current_context}[/cyan]")
            show_namespace_modules(current_context, console)
            return

    # Try as absolute path
    if target in manager.namespaces:
        current_context = target
        console.print(f"[cyan]Navigated to {current_context}[/cyan]")
        show_namespace_modules(current_context, console)
    elif target in dict(CATEGORIES_INFO):
        current_context = target
        console.print(f"[cyan]Navigated to {current_context}[/cyan]")
        show_category_modules(target, console)
    else:
        console.print(f"[red]Invalid path:[/red] {target}")
        console.print("[dim]Use [cyan]ls[/cyan] to see available paths[/dim]")


def show_categories(console) -> None:
    """Display available module categories"""
    global current_context
    current_context = ""  # Reset context when showing categories

    table = Table(title="", show_header=True, header_style="bold magenta")
    table.add_column("Category", style="cyan bold", no_wrap=True, width=15)
    table.add_column("Description", style="dim")

    for cat, desc in CATEGORIES_INFO:
        table.add_row(cat, desc)

    console.print(table)
    console.print(
        "[dim]Use: [cyan]ls <category>[/cyan] to see modules in that category[/dim]"
    )


def show_category_modules(category: str, console) -> None:
    """Display modules in a specific category"""
    modules = manager.list_modules(category)

    if not modules:
        console.print(f"[red]No modules found in category:[/red] {category}")
        console.print("[dim]Use: [cyan]ls[/cyan] to see available categories[/dim]")
        return

    table = create_module_table(category, modules)
    console.print(table)
    console.print(
        f"\n[dim]Use: [cyan]use {modules[0]['path']}[/cyan] to load a module[/dim]"
    )


def show_namespace_modules(namespace: str, console) -> None:
    """Display modules under a namespace (e.g., cloud.aws)"""
    modules = manager.get_namespace_modules(namespace)

    if not modules:
        console.print(f"[red]No modules found in namespace:[/red] {namespace}")
        return

    # Extract the namespace name (e.g., "AWS" from "cloud.aws")
    namespace_parts = namespace.split(".")
    namespace_name = (
        namespace_parts[-1].upper() if namespace_parts else namespace.upper()
    )

    table = Table(title=f"{namespace_name} Modules ({len(modules)})")
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Module", style="cyan")  # Changed from "Module Path"
    table.add_column("Name", style="green")
    table.add_column("Description", style="dim")

    for idx, m in enumerate(modules, 1):
        desc = truncate_string(m.get("description", ""), 60)
        # Extract short name (e.g., "ec2" from "cloud.aws.ec2")
        short_name = m["path"].split(".")[-1]
        table.add_row(str(idx), short_name, m.get("name", "Unknown"), desc)

    console.print(table)
    # Show example with short name
    example_short = modules[0]["path"].split(".")[-1]
    console.print(
        f"\n[dim]Use: [cyan]select {example_short}[/cyan] to load a module[/dim]"
    )


def create_module_table(category: str, modules: List[Dict]) -> Table:
    """Create a formatted table for module listing"""
    table = Table(title=f"{category.upper()} Modules ({len(modules)})")
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Module Path", style="cyan")
    table.add_column("Name", style="green")

    if category == "cve":
        table.add_column("CVE ID", style="yellow")

    table.add_column("Description", style="dim")

    for idx, m in enumerate(modules, 1):
        desc = truncate_string(m.get("description", ""), 60)

        if category == "cve":
            table.add_row(
                str(idx), m["path"], m.get("name", "Unknown"), m.get("cve", "N/A"), desc
            )
        else:
            table.add_row(str(idx), m["path"], m.get("name", "Unknown"), desc)

    return table


def handle_search(args: List[str], console) -> None:
    """Handle search command"""
    if not args:
        console.print("[red]Usage: search <query>[/red]")
        return

    query = " ".join(args)
    results = manager.search_modules(query)

    if not results:
        console.print(f"[yellow]No modules found matching:[/yellow] {query}")
        return

    table = create_search_results_table(query, results)
    console.print(table)
    console.print("\n[dim]Use: [cyan]use <module_path>[/cyan] to load a module[/dim]")


def create_search_results_table(query: str, results: List[Dict]) -> Table:
    """Create a formatted table for search results"""
    table = Table(title=f"Search Results for '{query}' ({len(results)} found)")
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Type", style="yellow", width=12)
    table.add_column("Module Path", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Description", style="dim")

    for idx, m in enumerate(results, 1):
        desc = truncate_string(m.get("description", ""), 50)
        table.add_row(
            str(idx), m.get("type", "misc"), m["path"], m.get("name", "Unknown"), desc
        )

    return table


def handle_info(args: List[str], console) -> None:
    """Handle info command"""
    global active_module, active_module_name

    target = args[0] if args else active_module_name
    if not target:
        console.print("[red]Usage: info <module> (or load a module first)[/red]")
        return

    # Try cached metadata first
    metadata = manager.get_module_metadata(target)

    if metadata:
        display_module_info_from_metadata(metadata, console)
    else:
        display_module_info_from_load(target, console)


def display_module_info_from_metadata(metadata: Dict, console) -> None:
    """Display module info from cached metadata"""
    # Load module to get options
    mod = manager.load_module(metadata["path"])
    opts = getattr(mod, "options", {}) if mod else {}

    info_text = build_info_text(metadata)
    console.print(Panel.fit(info_text, title="Module Information", border_style="cyan"))

    if opts and mod:
        display_module_options(mod, opts, console)
    else:
        console.print("[dim]No configurable options[/dim]")


def display_module_info_from_load(target: str, console) -> None:
    """Display module info by loading the module"""
    mod = manager.load_module(target)
    if not mod:
        console.print(f"[red]Module not found:[/red] {target}")
        return

    metadata = extract_module_metadata(mod, target)
    info_text = build_info_text(metadata)

    console.print(Panel.fit(info_text, title="Module Information", border_style="cyan"))

    opts = getattr(mod, "options", {})
    if opts:
        display_module_options(mod, opts, console)
    else:
        console.print("[dim]No configurable options[/dim]")


def extract_module_metadata(module: Any, path: str) -> Dict:
    """Extract metadata from a loaded module instance"""
    return {
        "name": getattr(module, "NAME", "Unknown"),
        "description": getattr(module, "DESCRIPTION", "No description"),
        "author": getattr(module, "AUTHOR", "Unknown"),
        "version": getattr(module, "VERSION", "1.0"),
        "category": getattr(module, "CATEGORY", "misc"),
        "path": path,
        "cve": getattr(module, "CVE", None) if hasattr(module, "CVE") else None,
        "disclosure_date": getattr(module, "DISCLOSURE_DATE", "")
        if hasattr(module, "DISCLOSURE_DATE")
        else "",
    }


def build_info_text(metadata: Dict) -> str:
    """Build formatted info text from metadata"""
    info_text = (
        f"[bold cyan]{metadata.get('name', 'Unknown')}[/bold cyan]\n\n"
        f"{metadata.get('description', 'No description')}\n\n"
        f"[dim]Path:[/dim] {metadata.get('path', 'N/A')}\n"
        f"[dim]Author:[/dim] {metadata.get('author', 'Unknown')}\n"
        f"[dim]Version:[/dim] {metadata.get('version', '1.0')}\n"
        f"[dim]Category:[/dim] {metadata.get('category', 'misc')}"
    )

    if metadata.get("cve"):
        info_text += f"\n\n[bold]CVE:[/bold] [red]{metadata['cve']}[/red]\n"
        if metadata.get("disclosure_date"):
            info_text += f"[bold]Disclosed:[/bold] {metadata['disclosure_date']}"

    return info_text


def display_module_options(module: Any, opts: Dict, console) -> None:
    """Display module options in a table"""
    table = Table(title="Module Options")
    table.add_column("Option", style="yellow", no_wrap=True)
    table.add_column("Current Value", style="green")
    table.add_column("Required", style="red", justify="center", width=10)
    table.add_column("Description", style="dim")

    required_opts = getattr(module, "REQUIRED_OPTIONS", [])

    for k, v in opts.items():
        is_required = "Yes" if k in required_opts else "No"
        display_value = mask_sensitive_value(k, v)
        table.add_row(k, display_value, is_required, "")

    console.print(table)


def handle_use(args: List[str], console) -> None:
    """Handle use command"""
    global active_module, active_module_name, module_options, current_context

    if not args:
        console.print("[red]Usage: use/select <module>[/red]")
        console.print("[dim]Example: select ec2 (when in cloud.aws context)[/dim]")
        console.print(
            "[dim]Tip: Use [cyan]ls <category>[/cyan] to browse modules[/dim]"
        )
        return

    module_name = args[0]

    # Check if it's a namespace (e.g., cloud.aws)
    if module_name in manager.namespaces:
        # Update context and show submodules instead of loading
        current_context = module_name
        show_namespace_modules(module_name, console)
        return

    # If we're in a context and user provides short name, expand it
    if current_context and "." not in module_name:
        # First, try direct path in current context (e.g., cloud.ec2)
        full_path = f"{current_context}.{module_name}"
        test_module = manager.load_module(full_path, silent=True)

        if test_module:
            module_name = full_path
            active_module = test_module
        else:
            # If not found, search in all sub-namespaces
            # For example, if in "cloud" context, search cloud.aws.ec2, cloud.azure.ec2, etc.
            found = False
            for namespace in manager.namespaces:
                if namespace.startswith(current_context + "."):
                    candidate = f"{namespace}.{module_name}"
                    test_module = manager.load_module(candidate, silent=True)
                    if test_module:
                        module_name = candidate
                        active_module = test_module
                        found = True
                        break

            # If still not found, try loading as is (with error messages this time)
            if not found:
                active_module = manager.load_module(module_name)
    else:
        active_module = manager.load_module(module_name)

    if active_module:
        active_module_name = module_name
        module_options = getattr(active_module, "options", {}).copy()

        # Apply global options to module options
        for key, value in global_options.items():
            if key in module_options:
                module_options[key] = value

        console.print(f"[green]Module loaded:[/green] [bold]{module_name}[/bold]")
        display_quick_module_info(active_module, console)
    else:
        console.print(f"[red]Module not found:[/red] {module_name}")
        console.print(
            "[dim]Try: [cyan]search <keyword>[/cyan] or [cyan]ls <category>[/cyan][/dim]"
        )


def display_quick_module_info(module: Any, console) -> None:
    """Display quick module info after loading"""
    name = getattr(module, "NAME", "Unknown")
    desc = getattr(module, "DESCRIPTION", "")

    console.print(f"[dim]{name}[/dim]")
    if desc:
        console.print(f"[dim]{truncate_string(desc, 100)}[/dim]")

    console.print("\n[dim]Next steps:[/dim]")
    console.print("   [cyan]info[/cyan]         - View detailed information")
    console.print("   [cyan]show options[/cyan] - See configuration options")
    console.print("   [cyan]set <opt> <val>[/cyan] - Configure module")
    console.print("   [cyan]run[/cyan]          - Execute module")


def handle_set(args: List[str], console) -> None:
    """Handle set command - supports global options (AWS_PROFILE, AWS_REGION, etc.)"""
    global module_options, global_options

    if len(args) < 2:
        console.print("[red]Usage: set <option> <value>[/red]")
        console.print("[dim]Example: set AWS_PROFILE myprofile[/dim]")
        console.print(
            "[dim]Global options: AWS_PROFILE, AWS_REGION, ACCESS_KEY, SECRET_KEY[/dim]"
        )
        return

    key = args[0].upper()
    value = " ".join(args[1:])

    # Global options that persist across modules
    GLOBAL_OPTIONS = [
        "AWS_PROFILE",
        "AWS_REGION",
        "ACCESS_KEY",
        "SECRET_KEY",
        "SESSION_TOKEN",
    ]

    # If it's a global option, store it globally
    if key in GLOBAL_OPTIONS:
        global_options[key] = value
        # Also update current module if loaded
        if active_module and key in module_options:
            if hasattr(active_module, "set_option"):
                active_module.set_option(key, value)
            module_options[key] = value
        console.print(
            f"[green]{key} => [bold]{value}[/bold][/green] [dim](global)[/dim]"
        )
        return

    # For non-global options, require a module to be loaded
    if not active_module:
        console.print(
            "[red]No module loaded. Use [cyan]use <module>[/cyan] first.[/red]"
        )
        console.print("[dim]Or set global options: AWS_PROFILE, AWS_REGION[/dim]")
        return

    if hasattr(active_module, "set_option"):
        if active_module.set_option(key, value):
            module_options[key] = value
            console.print(f"[green]{key} => [bold]{value}[/bold][/green]")
        else:
            console.print(f"[red]Failed to set option:[/red] {key}")
            console.print(
                "[dim]Use [cyan]show options[/cyan] to see available options[/dim]"
            )
    else:
        console.print("[red]Module does not support set_option[/red]")


def handle_show(args: List[str], console) -> None:
    """Handle show command"""
    if not args:
        console.print("[red]Usage: show <what>[/red]")
        console.print(
            "[dim]Available: [cyan]show options[/cyan], [cyan]show global[/cyan][/dim]"
        )
        return

    if args[0] == "options":
        show_module_options(console)
    elif args[0] == "global":
        show_global_options(console)
    else:
        console.print(f"[red]Unknown show target:[/red] {args[0]}")
        console.print(
            "[dim]Available: [cyan]show options[/cyan], [cyan]show global[/cyan][/dim]"
        )


def show_global_options(console) -> None:
    """Display global options"""
    if not global_options:
        console.print("[yellow]No global options set[/yellow]")
        console.print(
            "[dim]Global options: AWS_PROFILE, AWS_REGION, ACCESS_KEY, SECRET_KEY[/dim]"
        )
        console.print(
            "[dim]Use: [cyan]set AWS_PROFILE myprofile[/cyan] to set global options[/dim]"
        )
        return

    table = Table(title="Global Options")
    table.add_column("Option", style="yellow", no_wrap=True)
    table.add_column("Value", style="green")

    for k, v in global_options.items():
        display_value = mask_sensitive_value(k, v)
        table.add_row(k, display_value)

    console.print(table)
    console.print(
        "\n[dim]These options are automatically applied to all AWS modules[/dim]"
    )


def show_module_options(console) -> None:
    """Display current module options"""
    if not active_module:
        console.print("[red]No module loaded.[/red]")
        return

    table = Table(title=f"Options for {active_module_name}")
    table.add_column("Option", style="yellow", no_wrap=True)
    table.add_column("Value", style="green")
    table.add_column("Required", style="red", justify="center")
    table.add_column("Type", style="cyan", justify="center")
    table.add_column("Source", style="dim", justify="center")

    required_opts = getattr(active_module, "REQUIRED_OPTIONS", [])

    for k, v in module_options.items():
        is_required = "Yes" if k in required_opts else "No"
        display_value = mask_sensitive_value(k, v)
        val_type = type(v).__name__
        # Check if this option came from global settings
        source = "global" if k in global_options else "module"

        table.add_row(k, display_value, is_required, val_type, source)

    console.print(table)
    console.print("\n[dim]Use [cyan]set <option> <value>[/cyan] to configure[/dim]")
    if any(k in global_options for k in module_options.keys()):
        console.print(
            "[dim]Options marked 'global' are inherited from global settings[/dim]"
        )


def handle_run(console) -> None:
    """Handle run/exploit command"""
    if not active_module:
        console.print(
            "[red]No module loaded. Use [cyan]use <module>[/cyan] first.[/red]"
        )
        return

    console.print(f"[bold yellow]Executing {active_module_name}...[/bold yellow]\n")

    if not hasattr(active_module, "run"):
        console.print("[red]Module does not have a run method[/red]")
        return

    try:
        # Apply all module options (including global options) to the module before running
        if hasattr(active_module, "options"):
            for key, value in module_options.items():
                if hasattr(active_module, "set_option"):
                    active_module.set_option(key, value)
                else:
                    # Directly set in module's options dict
                    active_module.options[key] = value

        result = active_module.run()
        display_run_result(result, console)
    except Exception as e:
        console.print("\n[bold red]Error during execution:[/bold red]")
        console.print(f"[red]{e}[/red]")

        import traceback

        console.print(f"\n[dim]{traceback.format_exc()}[/dim]")


def display_run_result(result: Any, console) -> None:
    """Display module execution result"""
    if isinstance(result, dict):
        if result.get("success"):
            console.print("\n[bold green]Module executed successfully[/bold green]")
            if result.get("data"):
                console.print("\n[cyan]Result:[/cyan]")
                console.print(result["data"])
        else:
            console.print("\n[bold red]Execution failed[/bold red]")
            if result.get("error"):
                console.print(f"[red]Error:[/red] {result['error']}")
    else:
        console.print("\n[yellow]Module completed[/yellow]")


def handle_back(console) -> None:
    """Handle back command - navigate up context or unload module"""
    global active_module, active_module_name, module_options, current_context

    if active_module:
        # If module is loaded, unload it
        active_module = None
        active_module_name = None
        module_options = {}
        console.print("[yellow]Module unloaded[/yellow]")
    elif current_context:
        # If in a context, navigate up
        if "." in current_context:
            # From cloud.aws -> cloud
            current_context = current_context.rsplit(".", 1)[0]
            console.print(f"[yellow]Navigated back to {current_context}[/yellow]")
        else:
            # From cloud -> root
            current_context = ""
            console.print("[yellow]Navigated back to root[/yellow]")
    else:
        console.print("[dim]Already at root level[/dim]")


# Utility functions
def truncate_string(text: str, max_length: int) -> str:
    """Truncate string with ellipsis if too long"""
    if len(text) > max_length:
        return text[:max_length] + "..."
    return text


def mask_sensitive_value(key: str, value: Any) -> str:
    """Mask sensitive values in output"""
    if any(s in key.upper() for s in SENSITIVE_KEYWORDS):
        return "***" if value else "[dim]<not set>[/dim]"
    return str(value) if value else "[dim]<not set>[/dim]"
