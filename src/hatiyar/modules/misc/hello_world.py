from typing import Dict, Any
from rich.console import Console
from hatiyar.core.module_base import ModuleBase

console = Console()


class Module(ModuleBase):
    NAME = "Hello World"
    DESCRIPTION = "Minimal test module that prints a message"
    VERSION = "1.0"
    CATEGORY = "misc"

    OPTIONS = {
        "MESSAGE": "hello world",
        "TIMES": 1,
    }
    REQUIRED_OPTIONS = []

    def run(self) -> Dict[str, Any]:
        if not self.validate_options():
            return {"success": False, "error": "Invalid options"}

        msg = str(self.get_option("MESSAGE") or "")
        times = int(self.get_option("TIMES") or 1)
        output = "\n".join([msg] * max(times, 1))

        console.print(output)
        return {"success": True, "data": output}
