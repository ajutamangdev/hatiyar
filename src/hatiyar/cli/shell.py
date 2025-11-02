"""Interactive shell for hatiyar"""

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory
from rich.console import Console
from .commands import handle_command, get_current_context

console = Console()

# Shell configuration
COMMANDS = [
    "help",
    "list",
    "ls",
    "search",
    "use",
    "info",
    "set",
    "show",
    "run",
    "exploit",
    "back",
    "clear",
    "cls",
    "exit",
    "quit",
]

WELCOME_MESSAGE = (
    "[bold green]Welcome to Hatiyar![/bold green]\n"
    "Type [bold cyan]help[/bold cyan] for available commands or [cyan]ls[/cyan] to explore.\n"
)

EXIT_COMMANDS = ["exit", "quit", "q"]


def start_shell() -> None:
    """Start the interactive shell session"""
    completer = WordCompleter(COMMANDS, ignore_case=True)
    history = InMemoryHistory()
    session: PromptSession[str] = PromptSession(completer=completer, history=history)

    console.print(WELCOME_MESSAGE)

    while True:
        try:
            # Build prompt with context
            context = get_current_context()
            if context:
                prompt_text = f"hatiyar({context})> "
            else:
                prompt_text = "hatiyar> "
            
            user_input = session.prompt(prompt_text).strip()

            if not user_input:
                continue

            if user_input.lower() in EXIT_COMMANDS:
                console.print("[yellow]Exiting hatiyar...[/yellow]")
                break

            handle_command(user_input, console)

        except (KeyboardInterrupt, EOFError):
            console.print("\n[red]Session terminated.[/red]")
            break
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")
