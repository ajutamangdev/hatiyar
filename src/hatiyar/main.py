"""
Hatiyar - security toolkit for pentesters and security researchers.

Main entry point for Hatiyar
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

src_dir = Path(__file__).resolve().parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from hatiyar import __version__  # noqa: E402

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

    from hatiyar.web.routes import router as dashboard_router  # noqa: E402
    from hatiyar.web.config import config  # noqa: E402

    # Initialize application
    app = FastAPI(
        title="hatiyar",
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
            console.print(f"[cyan]hatiyar[/cyan] version [green]{__version__}[/green]")
            raise typer.Exit()

    cli = typer.Typer(
        name="hatiyar",
        help="""hatiyar - security toolkit designed for penetration testing, vulnerability assessment, and security research
        """,
        add_completion=False,
        rich_markup_mode="rich",
        no_args_is_help=True,  # Show help when no command is provided
        context_settings={"help_option_names": ["-h", "--help"]},
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
        """hatiyar - security toolkit designed for penetration testing, vulnerability assessment, and security research."""
        pass

    @cli.command(name="shell")
    def shell() -> None:
        """Start interactive shell with tab completion"""
        banner = r"""
 _    _       _   _                  
| |  | |     | | (_)                 
| |__| | __ _| |_ _ _   _  __ _ _ __ 
|  __  |/ _` | __| | | | |/ _` | '__|
| |  | | (_| | |_| | |_| | (_| | |   
|_|  |_|\__,_|\__|_|\__, |\__,_|_|   
                     __/ |           
                    |___/             
"""
        console.print(f"[bold red]{banner}[/bold red]")

        # Show metadata centered
        try:
            metadata_version = f"Version {__version__}"
            console.print(f"[dim]{metadata_version.center(40)}[/dim]")
        except Exception:
            metadata = f"Version {__version__}"
            console.print(f"[dim]{metadata.center(40)}[/dim]")

        console.print()

        try:
            from hatiyar.cli.shell import start_shell  # noqa: E402
        except Exception as e:
            print(f"✗ Shell failed: {e}")
            raise typer.Exit(code=1)

        start_shell()

    # @cli.command(name="serve")
    # def serve(
    #     host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host"),
    #     port: int = typer.Option(8000, "--port", "-p", help="Port"),
    #     reload: bool = typer.Option(False, "--reload", "-r", help="Auto-reload"),
    # ) -> None:
    #     """Launch web dashboard for cloud auditing
    #
    #     Examples:
    #       hatiyar serve
    #       hatiyar serve --port 8080
    #       hatiyar serve --host 127.0.0.1
    #     """
    #     try:
    #         import uvicorn  # type: ignore
    #     except ImportError:
    #         console.print("[red]✗ uvicorn not installed[/red]")
    #         console.print("[dim]Install: [cyan]pip install uvicorn[/cyan][/dim]")
    #         raise typer.Exit(code=1)
    #
    #     console.print(f"[green]✓ Server starting:[/green] http://{host}:{port}")
    #     console.print(f"[cyan]  Dashboard:[/cyan] http://{host}:{port}/")
    #
    #     uvicorn.run("hatiyar.main:app", host=host, port=port, reload=reload)

    # TODO: Web dashboard coming soon!
    # The serve command will be available in a future release

    @cli.command(name="info")
    def info() -> None:
        """Show system and module statistics"""
        from hatiyar.core.modules import ModuleManager  # noqa: E402

        manager = ModuleManager()
        stats = manager.get_stats()

        console.print("\n[bold cyan]hatiyar[/bold cyan] [dim]pentesting toolkit[/dim]")
        console.print(f"[dim]Version:[/dim] [green]{__version__}[/green]\n")

        console.print("[bold]Modules:[/bold]")
        console.print(f"  Total: [green]{stats.get('total_modules', 0)}[/green]")

        if stats.get("categories"):
            for category, count in stats["categories"].items():
                console.print(f"  {category}: [cyan]{count}[/cyan]")

        console.print(
            f"\n[dim]Python {sys.version.split()[0]} • {sys.platform}[/dim]\n"
        )

    @cli.command(name="search")
    def search(
        query: str = typer.Argument(..., help="Search term"),
    ) -> None:
        """Search modules by keyword

        Examples:
          hatiyar search grafana
          hatiyar search CVE-2021
          hatiyar search apache
        """
        from hatiyar.core.modules import ModuleManager  # noqa: E402
        from rich.table import Table

        manager = ModuleManager()
        results = manager.search_modules(query)

        if not results:
            console.print(f"[yellow]✗ No results for:[/yellow] {query}")
            return

        # Check if any results have CVE IDs
        has_cve = any(mod.get("cve_id") or mod.get("cve") for mod in results)

        # Build table structure
        table = Table(title=f"[bold]Results:[/bold] {query}", title_style="cyan")
        table.add_column("#", width=4, justify="right", style="dim")
        table.add_column("Path", style="green", width=25)
        table.add_column("Name", style="cyan bold")

        if has_cve:
            table.add_column("CVE", style="red")

        # Populate table rows
        for idx, mod in enumerate(results, 1):
            row_data = [
                str(idx),
                mod.get("path", "N/A"),
                mod.get("name", "N/A"),
            ]

            if has_cve:
                cve_id = mod.get("cve_id") or mod.get("cve", "-")
                row_data.append(cve_id)

            table.add_row(*row_data)

        console.print(table)
        console.print(f"\n[dim]✓ Found {len(results)} modules[/dim]\n")

    @cli.command(name="run")
    def run_module(
        module_path: str = typer.Argument(..., help="Module path or CVE ID"),
        options: list[str] = typer.Option([], "--set", "-s", help="KEY=VALUE"),
        show_info: bool = typer.Option(False, "--info", "-i", help="Show info"),
    ) -> None:
        """Run a module directly

        Examples:
          hatiyar run cve.cve_2021_43798 --set RHOST=target.com
          hatiyar run CVE-2021-43798 --set RHOST=target.com --set PLUGIN=grafana
          hatiyar run cve.cve_2021_43798 --info
        """
        from hatiyar.core.modules import ModuleManager  # noqa: E402
        from rich.table import Table
        from rich.panel import Panel

        manager = ModuleManager()

        console.print(f"[dim]Loading:[/dim] {module_path}")
        module = manager.load_module(module_path)

        if not module:
            console.print(f"[red]✗ Module not found:[/red] {module_path}")
            raise typer.Exit(code=1)

        console.print(f"[green]✓ Loaded:[/green] {module.NAME}")

        if show_info:
            console.print()
            console.print(
                Panel(
                    f"[bold]{module.NAME}[/bold]\n\n"
                    f"{module.DESCRIPTION}\n\n"
                    f"[dim]Author:[/dim] {module.AUTHOR} | [dim]Category:[/dim] {module.CATEGORY}",
                    title="Module Info",
                    border_style="cyan",
                )
            )

        parsed_options = {}
        for opt in options:
            if "=" not in opt:
                console.print(f"[red]✗ Invalid format:[/red] {opt}")
                console.print("[dim]Use: [cyan]KEY=VALUE[/cyan][/dim]")
                raise typer.Exit(code=1)

            key, value = opt.split("=", 1)
            parsed_options[key] = value

        if hasattr(module, "OPTIONS"):
            console.print()
            table = Table(title="Options", show_header=True)
            table.add_column("Name", style="cyan bold", width=20)
            table.add_column("Current", style="dim")
            table.add_column("New", style="green")
            table.add_column("Req", justify="center", width=5)

            for opt_name, opt_value in module.OPTIONS.items():
                new_value = parsed_options.get(opt_name, "")
                is_required = opt_name in getattr(module, "REQUIRED_OPTIONS", [])

                table.add_row(
                    opt_name,
                    str(opt_value) if opt_value else "[dim]-[/dim]",
                    str(new_value) if new_value else "[dim]-[/dim]",
                    "✓" if is_required else "",
                )

            console.print(table)

        for key, value in parsed_options.items():
            if hasattr(module, "set_option"):
                success = module.set_option(key, value)
                if success:
                    console.print(f"[dim]  ✓ {key} = {value}[/dim]")
                else:
                    console.print(f"[yellow]  ⚠ Unknown: {key}[/yellow]")

        console.print()
        if hasattr(module, "REQUIRED_OPTIONS"):
            missing = []
            for req in module.REQUIRED_OPTIONS:
                if hasattr(module, "options"):
                    val = module.options.get(req)
                    if not val or (isinstance(val, str) and not val.strip()):
                        missing.append(req)

            if missing:
                console.print(f"[red]✗ Missing:[/red] {', '.join(missing)}")
                console.print(
                    f"[dim]Set with: [cyan]--set {missing[0]}=value[/cyan][/dim]"
                )
                raise typer.Exit(code=1)

        console.print("[bold cyan]═══ Executing ═══[/bold cyan]\n")

        try:
            result = module.run()

            console.print("\n[bold cyan]═══ Complete ═══[/bold cyan]\n")

            if result:
                if isinstance(result, dict):
                    console.print("[green]✓ Results:[/green]")
                    for key, value in result.items():
                        console.print(f"  {key}: {value}")
                else:
                    console.print(f"[green]✓ {result}[/green]")
            else:
                console.print("[dim]Execution finished[/dim]")

        except Exception as e:
            console.print(f"\n[red]✗ Failed:[/red] {e}")
            raise typer.Exit(code=1)


def main() -> int:
    """Main entry point for hatiyar CLI."""
    if not TYPER_AVAILABLE or cli is None:
        print("Error: typer is not installed.")
        print("Install it with: uv add typer")
        return 1

    cli(prog_name="hatiyar")
    return 0


if __name__ == "__main__":
    sys.exit(main())
