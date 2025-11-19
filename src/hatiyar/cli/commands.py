"""Command handlers for CLI with session-based state management."""

import re
from typing import List, Dict, Any
from rich.table import Table
from rich.panel import Panel
from hatiyar.cli.session import CLISession
from hatiyar.core.constants import (
    Context,
    SensitiveKeywords,
)

# Validation regex for option names
VALID_OPTION_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")

CATEGORIES_INFO = [
    ("cve", "CVE exploits"),
    ("cloud", "Cloud security (AWS, Azure, GCP)"),
    ("enumeration", "Recon & enumeration"),
    ("platforms", "Platforms & services"),
    ("misc", "Miscellaneous"),
]

SENSITIVE_KEYWORDS = SensitiveKeywords.KEYWORDS


def get_current_context(session: CLISession) -> str:
    return session.current_context


def handle_command(command: str, console, session: CLISession) -> None:
    tokens = command.split()
    if not tokens:
        return

    cmd = tokens[0].lower()
    args = tokens[1:]

    handlers = {
        "help": lambda: show_help(console),
        "clear": lambda: clear_screen(console),
        "cls": lambda: clear_screen(console),
        "list": lambda: handle_list(args, console, session),
        "ls": lambda: handle_list(args, console, session),
        "cd": lambda: handle_cd(args, console, session),
        "reload": lambda: handle_reload(console, session),
        "search": lambda: handle_search(args, console, session),
        "info": lambda: handle_info(args, console, session),
        "use": lambda: handle_use(args, console, session),
        "select": lambda: handle_use(args, console, session),
        "set": lambda: handle_set(args, console, session),
        "show": lambda: handle_show(args, console, session),
        "run": lambda: handle_run(console, session),
        "katta": lambda: handle_run(console, session),
        "exploit": lambda: handle_run(console, session),
        "back": lambda: handle_back(console, session),
    }

    handler = handlers.get(cmd)
    if handler:
        handler()
    else:
        console.print(f"[red]Unknown command:[/red] {cmd}")
        console.print("[dim]Type [cyan]help[/cyan] for help[/dim]")


def show_help(console) -> None:
    help_text = (
        "[bold cyan]Commands[/bold cyan]\n\n"
        "[yellow]Navigate:[/yellow]\n"
        "  ls [category]         Show modules\n"
        "  cd <path>             Navigate (cd cloud, cd aws, cd ..)\n"
        "  search <query>        Search modules\n\n"
        "[yellow]Module:[/yellow]\n"
        "  use <module>          Select module\n"
        "  info <module>         Show details\n"
        "  show options          Display options\n"
        "  set <opt> <val>       Set option\n"
        "  run                   Execute (alias: katta, exploit)\n"
        "  back                  Unload/navigate up\n\n"
        "[yellow]Util:[/yellow]\n"
        "  reload                Reload YAML\n"
        "  clear                 Clear screen\n"
        "  exit/quit             Exit\n\n"
        "[dim]Press TAB for completion[/dim]\n"
    )
    console.print(Panel.fit(help_text, title="Help", border_style="cyan"))


def clear_screen(console) -> None:
    console.clear()
    console.print("[dim]Type [cyan]help[/cyan] or press TAB[/dim]\n")


def handle_reload(console, session: CLISession) -> None:
    total = session.reload_modules()
    console.print(f"[green]✓[/green] Reloaded {total} modules")
    console.print("[dim]Use 'ls' to explore[/dim]")


def handle_list(args: List[str], console, session: CLISession) -> None:
    if not args:
        if session.current_context:
            if session.current_context in session.manager.namespaces:
                show_namespace_modules(session.current_context, console, session)
            else:
                show_category_modules(session.current_context, console, session)
        else:
            show_categories(console)
    else:
        category_or_namespace = args[0].lower()
        if session.navigate_to(category_or_namespace):
            if category_or_namespace in session.manager.namespaces:
                show_namespace_modules(category_or_namespace, console, session)
            else:
                show_category_modules(category_or_namespace, console, session)
        else:
            console.print(
                f"[red]Invalid category or namespace:[/red] {category_or_namespace}"
            )
            console.print("[dim]Use 'ls' to see available options[/dim]")


def handle_cd(args: List[str], console, session: CLISession) -> None:
    if not args:
        if session.navigate_to(""):
            console.print("[cyan]→ root[/cyan]")
            show_categories(console)
        return

    target = args[0].lower()

    if session.navigate_to(target):
        console.print(f"[cyan]→ {session.current_context or 'root'}[/cyan]")

        if not session.current_context:
            show_categories(console)
        elif session.current_context in session.manager.namespaces:
            show_namespace_modules(session.current_context, console, session)
        else:
            show_category_modules(session.current_context, console, session)
    else:
        if target == ".." and not session.current_context:
            console.print("[yellow]Already at root[/yellow]")
        else:
            console.print(f"[red]Path not found:[/red] {target}")
            console.print("[dim]Use 'ls' to see paths[/dim]")


def show_categories(console) -> None:
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Category", style="cyan bold", width=15)
    table.add_column("Description", style="dim")

    for cat, desc in CATEGORIES_INFO:
        table.add_row(cat, desc)

    console.print(table)
    console.print("[dim]→ [cyan]ls <category>[/cyan] to explore[/dim]")


def show_category_modules(category: str, console, session: CLISession) -> None:
    modules = session.manager.list_modules(category)

    if not modules:
        console.print(f"[red]No modules in:[/red] {category}")
        console.print("[dim]Use 'ls' to see categories[/dim]")
        return

    table = create_module_table(category, modules)
    console.print(table)
    example = modules[0]["path"]
    console.print(f"\n[dim]Try: [cyan]use {example}[/cyan][/dim]")


def show_namespace_modules(namespace: str, console, session: CLISession) -> None:
    modules = session.manager.get_namespace_modules(namespace)

    if not modules:
        console.print(f"[red]No modules in:[/red] {namespace}")
        return

    namespace_parts = namespace.split(".")
    namespace_name = (
        namespace_parts[-1].upper() if namespace_parts else namespace.upper()
    )

    table = Table(title=f"{namespace_name} Modules ({len(modules)})")
    table.add_column("#", style="dim", justify="right", width=6)
    table.add_column("Module", style="cyan bold", width=20)
    table.add_column("Name", style="green")

    for idx, m in enumerate(modules, 1):
        short_name = m["path"].split(".")[-1]
        table.add_row(str(idx), short_name, m.get("name", "Unknown"))

    console.print(table)
    example_short = modules[0]["path"].split(".")[-1]
    console.print(f"\n[dim]Try: [cyan]select {example_short}[/cyan][/dim]")


def create_module_table(category: str, modules: List[Dict]) -> Table:
    table = Table(title=f"{category.upper()} Modules ({len(modules)})")
    table.add_column("#", style="dim", justify="right", width=6)
    table.add_column("Module Path", style="cyan")
    table.add_column("Name", style="green")

    if category == "cve":
        table.add_column("CVE ID", style="yellow")

    for idx, m in enumerate(modules, 1):
        if category == "cve":
            table.add_row(
                str(idx), m["path"], m.get("name", "Unknown"), m.get("cve", "N/A")
            )
        else:
            table.add_row(str(idx), m["path"], m.get("name", "Unknown"))

    return table


def handle_search(args: List[str], console, session: CLISession) -> None:
    if not args:
        console.print("[red]Usage: search <query>[/red]")
        return

    query = " ".join(args)
    results = session.search_modules(query)

    if not results:
        console.print(f"[yellow]No modules found matching:[/yellow] {query}")
        return

    table = create_search_results_table(query, results)
    console.print(table)
    console.print("\n[dim]Use: [cyan]use <module_path>[/cyan] to load a module[/dim]")


def create_search_results_table(query: str, results: List[Dict]) -> Table:
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


def handle_info(args: List[str], console, session: CLISession) -> None:
    target = args[0] if args else session.active_module_name
    if not target:
        console.print("[red]Usage: info <module> (or load a module first)[/red]")
        return

    # Try cached metadata first
    metadata = session.get_module_info(target)

    if metadata:
        display_module_info_from_metadata(metadata, console, session)
    else:
        display_module_info_from_load(target, console, session)


def display_module_info_from_metadata(
    metadata: Dict, console, session: CLISession
) -> None:
    # Load module to get options
    mod = session.manager.load_module(metadata["path"])
    opts = getattr(mod, "options", {}) if mod else {}

    info_text = build_info_text(metadata)
    console.print(Panel.fit(info_text, title="Module Information", border_style="cyan"))

    if opts and mod:
        display_module_options(mod, opts, console)
    else:
        console.print("[dim]No configurable options[/dim]")


def display_module_info_from_load(target: str, console, session: CLISession) -> None:
    mod = session.manager.load_module(target)
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


def handle_use(args: List[str], console, session: CLISession) -> None:
    if not args:
        console.print("[red]Usage: use/select <module>[/red]")
        console.print("[dim]Example: select ec2 (when in cloud.aws context)[/dim]")
        console.print(
            "[dim]Tip: Use [cyan]ls <category>[/cyan] to browse modules[/dim]"
        )
        return

    module_name = args[0]

    # Check if it's a namespace (e.g., cloud.aws)
    if module_name in session.manager.namespaces:
        # Update context and show submodules instead of loading
        session.navigate_to(module_name)
        show_namespace_modules(module_name, console, session)
        return

    # Try to load the module
    if session.load_module(module_name):
        console.print(
            f"[green]Module loaded:[/green] [bold]{session.active_module_name}[/bold]"
        )
        display_quick_module_info(session.active_module, console)
    else:
        console.print(f"[red]Module not found:[/red] {module_name}")
        console.print(
            "[dim]Try: [cyan]search <keyword>[/cyan] or [cyan]ls <category>[/cyan][/dim]"
        )


def display_quick_module_info(module: Any, console) -> None:
    name = getattr(module, "NAME", "Unknown")
    desc = getattr(module, "DESCRIPTION", "")

    console.print(f"[dim]{name}[/dim]")
    if desc:
        console.print(f"[dim]{truncate_string(desc, 100)}[/dim]")

    # Quick command reference
    cmd_table = Table(show_header=True, box=None, padding=(0, 1))
    cmd_table.add_column("Command", style="cyan bold", width=22)
    cmd_table.add_column("Description", style="dim", width=35)

    cmd_table.add_row("info", "Module information")
    cmd_table.add_row("show options", "Display module options")
    cmd_table.add_row(
        "[cyan]set[/cyan] [yellow]<opt>[/yellow] [yellow]<val>[/yellow]",
        "Set option value",
    )
    cmd_table.add_row(
        "[cyan]run[/cyan] / [cyan]katta[/cyan] / [cyan]exploit[/cyan]", "Execute module"
    )

    console.print()
    console.print(cmd_table)


def handle_set(args: List[str], console, session: CLISession) -> None:
    if len(args) < 2:
        # Context-aware help
        if session.current_context and Context.K8S in session.current_context:
            console.print("\n[bold]K8s Authentication Methods[/bold]")
            console.print()
            console.print(
                "[yellow]Method 1:[/yellow] [dim]Kubeconfig (recommended)[/dim]"
            )
            console.print("  [cyan]set KUBECONFIG ~/.kube/config[/cyan]")
            console.print(
                "  [cyan]set CONTEXT prod-cluster[/cyan]      [dim]# optional[/dim]"
            )
            console.print()
            console.print("[yellow]Method 2:[/yellow] [dim]Direct API access[/dim]")
            console.print(
                "  [cyan]set API_SERVER https://k8s-api.example.com:6443[/cyan]"
            )
            console.print("  [cyan]set TOKEN eyJhbGciOiJSUzI1...[/cyan]")
            console.print()
            console.print("[dim]Quick setup:[/dim]")
            console.print("  kubectl config current-context  # check current")

        if session.current_context and Context.AWS in session.current_context:
            console.print("\n[bold]AWS Authentication Methods[/bold]")
            console.print()
            console.print(
                "[yellow]Method 1:[/yellow] [dim]AWS Profile (recommended)[/dim]"
            )
            console.print("  [cyan]set AWS_PROFILE myprofile[/cyan]")
            console.print(
                "  [cyan]set AWS_REGION us-west-2[/cyan]       [dim]# optional override[/dim]"
            )
            console.print()
            console.print("[yellow]Method 2:[/yellow] [dim]Access Keys[/dim]")
            console.print("  [cyan]set ACCESS_KEY AKIA...[/cyan]")
            console.print("  [cyan]set SECRET_KEY wJalrXUt...[/cyan]")
            console.print("  [cyan]set AWS_REGION us-east-1[/cyan]")
            console.print()
            console.print("[dim]Quick setup:[/dim]")
            console.print("  aws configure --profile dev     # create profile")
            console.print("  aws sts get-caller-identity    # test current auth")

        return

    key = args[0].upper()
    value = " ".join(args[1:])

    if session.set_option(key, value):
        is_global = (
            key in session.AWS_GLOBAL_OPTIONS or key in session.K8S_GLOBAL_OPTIONS
        )
        suffix = " [dim](global)[/dim]" if is_global else ""
        console.print(f"[green]✓[/green] {key} = {value}{suffix}")
    else:
        if not session.active_module:
            console.print("[red]No module loaded[/red]")
            console.print("[dim]Load a module first or set global options[/dim]")
        else:
            console.print(f"[red]Unknown option:[/red] {key}")
            console.print(
                "[dim]Use [cyan]show options[/cyan] to see available options[/dim]"
            )


def handle_show(args: List[str], console, session: CLISession) -> None:
    if not args:
        console.print("[red]Usage: show <what>[/red]")
        console.print(
            "[dim]Available: [cyan]show options[/cyan], [cyan]show operations[/cyan], [cyan]show global[/cyan][/dim]"
        )
        return

    if args[0] == "options":
        show_module_options(console, session)
    elif args[0] == "operations":
        show_module_operations(console, session)
    elif args[0] == "global":
        show_global_options(console, session)
    else:
        console.print(f"[red]Unknown show target:[/red] {args[0]}")
        console.print(
            "[dim]Available: [cyan]show options[/cyan], [cyan]show operations[/cyan], [cyan]show global[/cyan][/dim]"
        )


def show_global_options(console, session: CLISession) -> None:
    if not session.global_options:
        console.print("[yellow]No global options set[/yellow]")

        # Show authentication method guides
        console.print("\n[bold cyan]AWS Authentication Methods:[/bold cyan]")
        console.print("[dim]Method 1 (Profile-based):[/dim]")
        console.print("  [cyan]set AWS_PROFILE myprofile[/cyan]")
        console.print("  [cyan]set AWS_REGION us-east-1[/cyan]")
        console.print("\n[dim]Method 2 (Credentials-based):[/dim]")
        console.print("  [cyan]set ACCESS_KEY AKIA...[/cyan]")
        console.print("  [cyan]set SECRET_KEY wJalr...[/cyan]")
        console.print("  [cyan]set AWS_REGION us-east-1[/cyan]")
        console.print("  [cyan]set SESSION_TOKEN[/cyan] [dim](optional)[/dim]")

        console.print("\n[bold cyan]Kubernetes Authentication Methods:[/bold cyan]")
        console.print("[dim]Method 1 (Kubeconfig-based):[/dim]")
        console.print("  [cyan]set KUBECONFIG ~/.kube/config[/cyan]")
        console.print("  [cyan]set CONTEXT minikube[/cyan]")
        console.print("\n[dim]Method 2 (Token-based):[/dim]")
        console.print("  [cyan]set API_SERVER https://k8s.example.com[/cyan]")
        console.print("  [cyan]set TOKEN eyJhbGc...[/cyan]")
        console.print("  [cyan]set VERIFY_SSL true[/cyan] [dim](optional)[/dim]")
        console.print("\n[dim]Method 3 (Certificate-based):[/dim]")
        console.print("  [cyan]set API_SERVER https://k8s.example.com[/cyan]")
        console.print("  [cyan]set CERT_FILE /path/to/client.crt[/cyan]")
        console.print("  [cyan]set KEY_FILE /path/to/client.key[/cyan]")
        console.print(
            "  [cyan]set CA_CERT /path/to/ca.crt[/cyan] [dim](optional)[/dim]"
        )

        return

    table = Table(title="Global Options")
    table.add_column("Option", style="yellow", no_wrap=True)
    table.add_column("Value", style="green")

    for k, v in session.global_options.items():
        display_value = mask_sensitive_value(k, v)
        table.add_row(k, display_value)

    console.print(table)
    console.print("\n[dim]These options are automatically applied to all modules[/dim]")


def show_module_options(console, session: CLISession) -> None:
    if not session.active_module:
        console.print("[red]No module loaded.[/red]")
        return

    table = Table(title=f"Options for {session.active_module_name}")
    table.add_column("Option", style="yellow", no_wrap=True)
    table.add_column("Value", style="green")
    table.add_column("Required", style="red", justify="center")
    table.add_column("Type", style="cyan", justify="center")
    table.add_column("Source", style="dim", justify="center")

    required_opts = getattr(session.active_module, "REQUIRED_OPTIONS", [])

    for k, v in session.module_options.items():
        is_required = "Yes" if k in required_opts else "No"
        display_value = mask_sensitive_value(k, v)
        val_type = type(v).__name__
        # Check if this option came from global settings
        source = "global" if k in session.global_options else "module"

        table.add_row(k, display_value, is_required, val_type, source)

    console.print(table)
    console.print("\n[dim]Use [cyan]set <option> <value>[/cyan] to configure[/dim]")
    if any(k in session.global_options for k in session.module_options.keys()):
        console.print(
            "[dim]Options marked 'global' are inherited from global settings[/dim]"
        )


def show_module_operations(console, session: CLISession) -> None:
    if not session.active_module:
        console.print("[red]No module loaded.[/red]")
        return

    if hasattr(session.active_module, "show_operations"):
        session.active_module.show_operations()
    else:
        console.print("[dim]This module does not have operations to display[/dim]")


def handle_run(console, session: CLISession) -> None:
    if not session.active_module:
        console.print("[red]✗ No module loaded[/red]")
        console.print("[dim]Use: [cyan]use <module>[/cyan][/dim]")
        return

    console.print(
        f"[bold cyan]═══ Executing: {session.active_module_name} ═══[/bold cyan]\n"
    )

    try:
        result = session.execute_module()
        display_run_result(result, console)
    except RuntimeError as e:
        console.print(f"[red]✗ {e}[/red]")
    except Exception as e:
        console.print("\n[bold red]✗ Execution failed:[/bold red]")
        console.print(f"[red]{e}[/red]")

        import traceback

        console.print(f"\n[dim]{traceback.format_exc()}[/dim]")


def display_run_result(result: Any, console) -> None:
    if isinstance(result, dict):
        if result.get("success"):
            console.print("\n[bold green]✓ Success[/bold green]")
            if result.get("data"):
                console.print("\n[cyan]Data:[/cyan]")
                console.print(result["data"])
        else:
            console.print("\n[bold red]✗ Failed[/bold red]")
            if result.get("error"):
                console.print(f"[red]Error:[/red] {result['error']}")
    else:
        console.print("\n[dim]Execution complete[/dim]")


def handle_back(console, session: CLISession) -> None:
    if session.active_module:
        # Clean up and unload module
        if hasattr(session.active_module, "cleanup"):
            try:
                session.active_module.cleanup()
            except Exception as e:
                console.print(f"[yellow]Warning: Cleanup error: {e}[/yellow]")

        session.active_module = None
        session.active_module_name = None
        session.module_options.clear()
        console.print("[yellow]← Module unloaded[/yellow]")
    elif session.current_context:
        # Navigate up in context
        if session.navigate_to(".."):
            console.print(f"[yellow]← {session.current_context or 'root'}[/yellow]")
        else:
            console.print("[dim]Already at root[/dim]")
    else:
        console.print("[dim]Already at root[/dim]")


# Utility functions
def truncate_string(text: str, max_length: int) -> str:
    if len(text) > max_length:
        return text[:max_length] + "..."
    return text


def mask_sensitive_value(key: str, value: Any) -> str:
    if any(s in key.upper() for s in SENSITIVE_KEYWORDS):
        return "***" if value else "[dim]<not set>[/dim]"
    return str(value) if value else "[dim]<not set>[/dim]"
