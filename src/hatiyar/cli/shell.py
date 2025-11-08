"""Interactive shell for hatiyar"""

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.history import InMemoryHistory
from rich.console import Console
from .commands import handle_command, get_current_context, manager
from typing import Iterable

console = Console()

COMMANDS = [
    "help",
    "list",
    "ls",
    "cd",
    "search",
    "use",
    "select",
    "info",
    "set",
    "show",
    "run",
    "katta",
    "exploit",
    "back",
    "clear",
    "cls",
    "reload",
    "exit",
    "quit",
]

WELCOME_MESSAGE = (
    "[bold green]Welcome to Hatiyar![/bold green]\n"
    "Type [bold cyan]help[/bold cyan] for available commands or [cyan]ls[/cyan] to explore.\n"
)

EXIT_COMMANDS = ["exit", "quit", "q"]


class HatiyarCompleter(Completer):
    """Smart completer for hatiyar shell with context awareness."""

    def get_completions(
        self, document: Document, complete_event
    ) -> Iterable[Completion]:
        text = document.text_before_cursor
        tokens = text.strip().split()

        if not tokens or (len(tokens) == 1 and not text.endswith(" ")):
            # Complete command
            word = tokens[0] if tokens else ""
            for cmd in COMMANDS:
                if cmd.startswith(word.lower()):
                    yield Completion(cmd, start_position=-len(word))

        elif len(tokens) >= 1:
            cmd = tokens[0].lower()

            # Complete for specific commands
            if cmd in ["cd", "ls", "list"]:
                self._complete_path(tokens, document, complete_event)
            elif cmd in ["use", "select", "info"]:
                self._complete_module(tokens, document, complete_event)
            elif cmd == "set":
                self._complete_option(tokens, document, complete_event)
            elif cmd == "show":
                self._complete_show(tokens, document, complete_event)

    def _complete_path(self, tokens, document, complete_event):
        """Complete paths for cd/ls commands."""
        word = tokens[-1] if len(tokens) > 1 and not document.text.endswith(" ") else ""

        # Get available categories and namespaces
        categories = ["cve", "cloud", "enumeration", "platforms", "misc"]
        namespaces = list(manager.namespaces.keys())

        paths = categories + namespaces + [".."]

        for path in paths:
            if path.lower().startswith(word.lower()):
                yield Completion(path, start_position=-len(word))

    def _complete_module(self, tokens, document, complete_event):
        """Complete module names for use/select/info commands."""
        word = tokens[-1] if len(tokens) > 1 and not document.text.endswith(" ") else ""

        # Get all modules
        all_modules = manager.list_modules()
        context = get_current_context()

        # In context, prioritize short names
        if context:
            for module in all_modules:
                if context in module.get("path", ""):
                    short_name = module["path"].split(".")[-1]
                    if short_name.lower().startswith(word.lower()):
                        yield Completion(short_name, start_position=-len(word))

        # Also show full paths
        for module in all_modules:
            path = module.get("path", "")
            if path.lower().startswith(word.lower()):
                yield Completion(path, start_position=-len(word))

    def _complete_option(self, tokens, document, complete_event):
        """Complete option names for set command."""
        if len(tokens) < 2:
            return

        word = tokens[-1] if not document.text.endswith(" ") else ""

        # Common AWS options
        common_options = [
            "AWS_REGION",
            "AWS_PROFILE",
            "ACCESS_KEY",
            "SECRET_KEY",
            "SESSION_TOKEN",
            "OUTPUT_FILE",
            "ENUMERATE_INSTANCES",
            "CHECK_PUBLIC_ACCESS",
            "ENUMERATE_LAYERS",
            "ENUMERATE_APPS",
        ]

        for opt in common_options:
            if opt.lower().startswith(word.lower()):
                yield Completion(opt, start_position=-len(word))

    def _complete_show(self, tokens, document, complete_event):
        """Complete show sub-commands."""
        word = tokens[-1] if len(tokens) > 1 and not document.text.endswith(" ") else ""

        show_opts = ["options", "global"]
        for opt in show_opts:
            if opt.startswith(word.lower()):
                yield Completion(opt, start_position=-len(word))


def start_shell() -> None:
    """Start interactive shell with smart completion."""
    completer = HatiyarCompleter()
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
