"""
pysecfw - Modular Python Security Framework

Main entry point for Pysecfw
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

src_dir = Path(__file__).resolve().parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from pysecfw import __version__  # noqa: E402

if TYPE_CHECKING:
    import typer
    from rich.console import Console

try:
    import typer
    from rich.console import Console

    TYPER_AVAILABLE = True
except ImportError:
    TYPER_AVAILABLE = False

try:
    from fastapi import FastAPI
    from fastapi.staticfiles import StaticFiles
    from fastapi.middleware.cors import CORSMiddleware

    from pysecfw.web.routes import router as dashboard_router  # noqa: E402
    from pysecfw.web.config import config  # noqa: E402

    # Initialize application
    app = FastAPI(
        title="pysecfw",
        description="",
        version=__version__,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount static files
    static_dir = Path(__file__).parent / "web" / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Include routers
    app.include_router(dashboard_router)

except ImportError:
    app = None  # type: ignore

# ============================================================================
# CLI Application
# ============================================================================

cli: Any = None
console: Any = None

if TYPER_AVAILABLE:

    def version_callback(value: bool) -> None:
        """Show version and exit."""
        if value:
            console = Console()
            console.print(f"[cyan]pysecfw[/cyan] version [green]{__version__}[/green]")
            raise typer.Exit()

    cli = typer.Typer(
        name="pysecfw",
        help="""pysecfw - Modular Python Security Framework
        """,
        add_completion=False,
        rich_markup_mode="rich",
        no_args_is_help=True,  # Show help when no command is provided
    )
    console = Console()

    @cli.callback()
    def main_callback(
        version: bool = typer.Option(
            False,
            "--version",
            "-v",
            help="Show version and exit",
            callback=version_callback,
            is_eager=True,
        ),
    ) -> None:
        """pysecfw - Modular Python Security Framework"""
        pass

    @cli.command(name="shell")
    def shell() -> None:
        """
        Start the interactive pysecfw shell (REPL).

        The shell provides an interactive environment for exploring modules,
        setting options, and running exploits with tab completion.
        """
        try:
            from pysecfw.cli.shell import start_shell  # noqa: E402
        except Exception as e:
            print(f"Failed to start shell: {e}")
            raise typer.Exit(code=1)

        start_shell()

    @cli.command(name="serve")
    def serve(
        host: str = typer.Option("0.0.0.0", "--host", "-h", help="Bind host address"),
        port: int = typer.Option(8000, "--port", "-p", help="Bind port number"),
        reload: bool = typer.Option(
            False, "--reload", "-r", help="Enable auto-reload for development"
        ),
    ) -> None:
        """
        Audit the Cloud resources via dashboard.

        Launch a web-based interface for managing security assessments through a browser.

        Examples:
          pysecfw serve                              # Start on 0.0.0.0:8000
          pysecfw serve --port 8080                  # Custom port
          pysecfw serve --host 127.0.0.1             # Localhost only
          pysecfw serve --reload                     # Auto-reload for development
        """
        try:
            import uvicorn  # type: ignore
        except ImportError:
            console.print("[red]Error: uvicorn is not installed.[/red]")
            console.print("[yellow]Install it with:[/yellow] pip install uvicorn")
            raise typer.Exit(code=1)

        console.print(
            f"[green]Starting pysecfw web server on[/green] http://{host}:{port}"
        )
        console.print(f"[cyan]   Dashboard:[/cyan] http://{host}:{port}/")

        uvicorn.run("pysecfw.main:app", host=host, port=port, reload=reload)

    @cli.command(name="info")
    def info() -> None:
        """
        Display system and module statistics.

        Shows version information, module counts by category, and system details.
        """
        from pysecfw.core.modules import ModuleManager  # noqa: E402

        manager = ModuleManager()
        stats = manager.get_stats()

        console.print(
            "\n[bold cyan]pysecfw - Modular Python Security Framework[/bold cyan]"
        )
        console.print(f"[dim]Version:[/dim] [green]{__version__}[/green]\n")

        console.print("[bold]Module Statistics:[/bold]")
        console.print(
            f"  • Total modules: [green]{stats.get('total_modules', 0)}[/green]"
        )

        if stats.get("modules_by_category"):
            console.print("\n[bold]Modules by Category:[/bold]")
            for category, count in stats["modules_by_category"].items():
                console.print(f"  • {category}: [cyan]{count}[/cyan]")

        console.print(f"\n[dim]Python:[/dim] {sys.version.split()[0]}")
        console.print(f"[dim]Platform:[/dim] {sys.platform}\n")

    @cli.command(name="search")
    def search(
        query: str = typer.Argument(
            ..., help="Search query (name, description, CVE ID, category, author)"
        ),
    ) -> None:
        """
        Search for security modules by keyword.

        Searches across module names amd CVE IDs).

        Examples:
          pysecfw search grafana          # Search for Grafana-related modules
          pysecfw search CVE-2021         # Find all 2021 CVEs
          pysecfw search apache           # Find Apache-related exploits
          pysecfw search traversal        # Search by vulnerability type
        """
        from pysecfw.core.modules import ModuleManager  # noqa: E402
        from rich.table import Table

        manager = ModuleManager()
        results = manager.search_modules(query)

        if not results:
            console.print(f"[yellow]No modules found matching: {query}[/yellow]")
            return

        table = Table(title=f"Search Results: '{query}'")
        table.add_column("#", justify="right", style="cyan")
        table.add_column("Module Path", style="green")
        table.add_column("Name", style="yellow")
        table.add_column("CVE", style="red")
        table.add_column("Description", style="dim")

        for idx, mod in enumerate(results, 1):
            table.add_row(
                str(idx),
                mod.get("path", "N/A"),
                mod.get("name", "N/A"),
                mod.get("cve_id", "N/A"),
                mod.get("description", "N/A")[:50] + "...",
            )

        console.print(table)
        console.print(f"\n[dim]Found: {len(results)} module(s)[/dim]\n")

    @cli.command(name="run")
    def run_module(
        module_path: str = typer.Argument(
            ...,
            help="Module path (e.g., cve.cve_2021_43798) or CVE ID (e.g., CVE-2021-43798)",
        ),
        options: list[str] = typer.Option(
            [],
            "--set",
            "-s",
            help="Set option (format: KEY=VALUE)",
            metavar="KEY=VALUE",
        ),
        show_info: bool = typer.Option(
            False, "--info", "-i", help="Show module info before running"
        ),
    ) -> None:
        """
        Run a security module directly from the command line.

        Examples:
          # Run by module path
          pysecfw run cve.cve_2021_43798 --set RHOST=example.com --set PLUGIN=grafana

          # Run by CVE ID
          pysecfw run CVE-2021-43798 --set RHOST=example.com --set PLUGIN=grafana

          # Show module info before running
          pysecfw run cve.cve_2021_43798 --info

          # Search for modules first
          pysecfw search grafana

        Workflow:
          1. Search for modules: pysecfw search <keyword>
          2. View module details: pysecfw run <module> --info
          3. Run with required options: pysecfw run <module> --set OPTION=value
        """
        from pysecfw.core.modules import ModuleManager  # noqa: E402
        from rich.table import Table
        from rich.panel import Panel

        manager = ModuleManager()

        # Load the module
        console.print(f"[cyan]Loading module:[/cyan] {module_path}")
        module = manager.load_module(module_path)

        if not module:
            console.print(f"[red]Error:[/red] Module not found: {module_path}")
            raise typer.Exit(code=1)

        console.print(f"[green]✓ Module loaded:[/green] {module.NAME}")

        # Show info if requested
        if show_info:
            console.print()
            console.print(
                Panel(
                    f"[bold]{module.NAME}[/bold]\n\n"
                    f"{module.DESCRIPTION}\n\n"
                    f"[dim]Author:[/dim] {module.AUTHOR}\n"
                    f"[dim]Category:[/dim] {module.CATEGORY}",
                    title=f"Module Info: {module_path}",
                    border_style="cyan",
                )
            )

        # Parse and set options
        parsed_options = {}
        for opt in options:
            if "=" not in opt:
                console.print(f"[red]Error:[/red] Invalid option format: {opt}")
                console.print("[yellow]Use format:[/yellow] KEY=VALUE")
                raise typer.Exit(code=1)

            key, value = opt.split("=", 1)
            parsed_options[key] = value

        # Show current options
        if hasattr(module, "OPTIONS"):
            console.print()
            table = Table(title="Module Options")
            table.add_column("Option", style="cyan")
            table.add_column("Current Value", style="yellow")
            table.add_column("New Value", style="green")
            table.add_column("Required", style="red")

            for opt_name, opt_value in module.OPTIONS.items():
                new_value = parsed_options.get(opt_name, "")
                is_required = opt_name in getattr(module, "REQUIRED_OPTIONS", [])

                table.add_row(
                    opt_name,
                    str(opt_value) if opt_value else "[dim]<not set>[/dim]",
                    str(new_value) if new_value else "[dim]<unchanged>[/dim]",
                    "Yes" if is_required else "No",
                )

            console.print(table)

        # Set options
        for key, value in parsed_options.items():
            if hasattr(module, "set_option"):
                success = module.set_option(key, value)
                if success:
                    console.print(f"[dim]✓ Set {key} = {value}[/dim]")
                else:
                    console.print(f"[yellow]⚠ Unknown option: {key}[/yellow]")

        # Check required options (after setting them)
        console.print()
        if hasattr(module, "REQUIRED_OPTIONS"):
            missing = []
            for req in module.REQUIRED_OPTIONS:
                # Check self.options (runtime values) not self.OPTIONS (defaults)
                if hasattr(module, "options"):
                    val = module.options.get(req)
                    if not val or (isinstance(val, str) and not val.strip()):
                        missing.append(req)

            if missing:
                console.print(
                    f"[red]Error:[/red] Missing required options: {', '.join(missing)}"
                )
                console.print("[yellow]Set them with:[/yellow] --set OPTION=VALUE")
                console.print()
                console.print("[cyan]Example:[/cyan]")
                console.print(f"  pysec run {module_path} --set {missing[0]}=value")
                raise typer.Exit(code=1)

        # Run the module
        console.print()
        console.print("[bold cyan]═══ Executing Module ═══[/bold cyan]")
        console.print()

        try:
            result = module.run()

            console.print()
            console.print("[bold cyan]═══ Execution Complete ═══[/bold cyan]")
            console.print()

            if result:
                if isinstance(result, dict):
                    console.print("[green]✓ Result:[/green]")
                    for key, value in result.items():
                        console.print(f"  • {key}: {value}")
                else:
                    console.print(f"[green]✓ Result:[/green] {result}")
            else:
                console.print("[yellow]Module executed (no result returned)[/yellow]")

        except Exception as e:
            console.print()
            console.print(f"[red]✗ Execution failed:[/red] {e}")
            raise typer.Exit(code=1)


def main() -> int:
    """Main entry point for pysecfw CLI."""
    if not TYPER_AVAILABLE or cli is None:
        print("Error: typer is not installed.")
        print("Install it with: uv add typer")
        return 1

    cli(prog_name="pysecfw")
    return 0


if __name__ == "__main__":
    sys.exit(main())
