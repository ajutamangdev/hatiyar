"""Encoding/Decoding utilities"""

import base64
from urllib.parse import quote, unquote
from rich.console import Console
from hatiyar.core.module_base import ModuleBase

console = Console()


class Module(ModuleBase):
    """Encode/decode strings and generate UUIDs"""

    NAME = "Encoders"
    DESCRIPTION = "Encode and decode strings\n\nOperations: base64_encode, base64_decode, url_encode, url_decode"
    AUTHOR = "hatiyar"
    CATEGORY = "misc"

    OPTIONS = {
        "INPUT": "",
        "OPERATION": "base64_encode",  # base64_encode, base64_decode, url_encode, url_decode
    }

    REQUIRED_OPTIONS = []

    def run(self) -> dict:
        operation = self.options.get("OPERATION", "base64_encode").lower()
        input_data = self.options.get("INPUT", "")

        handlers = {
            "base64_encode": lambda: self._b64_encode(input_data),
            "base64_decode": lambda: self._b64_decode(input_data),
            "url_encode": lambda: self._url_encode(input_data),
            "url_decode": lambda: self._url_decode(input_data),
        }

        handler = handlers.get(operation)
        if not handler:
            return {"success": False, "error": f"Unknown operation: {operation}"}

        try:
            return handler()
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _b64_encode(self, data: str) -> dict:
        if not data:
            return {"success": False, "error": "INPUT required"}

        encoded = base64.b64encode(data.encode()).decode()
        console.print(f"[green]base64:[/green] {encoded}")
        return {
            "success": True,
            "operation": "base64_encode",
            "input": data,
            "output": encoded,
        }

    def _b64_decode(self, data: str) -> dict:
        if not data:
            return {"success": False, "error": "INPUT required"}

        try:
            decoded = base64.b64decode(data).decode()
            console.print(f"[green]decoded:[/green] {decoded}")
            return {
                "success": True,
                "operation": "base64_decode",
                "input": data,
                "output": decoded,
            }
        except Exception as e:
            return {"success": False, "error": f"Invalid base64: {str(e)}"}

    def _url_encode(self, data: str) -> dict:
        if not data:
            return {"success": False, "error": "INPUT required"}

        encoded = quote(data)
        console.print(f"[green]encoded:[/green] {encoded}")
        return {
            "success": True,
            "operation": "url_encode",
            "input": data,
            "output": encoded,
        }

    def _url_decode(self, data: str) -> dict:
        if not data:
            return {"success": False, "error": "INPUT required"}

        decoded = unquote(data)
        console.print(f"[green]decoded:[/green] {decoded}")
        return {
            "success": True,
            "operation": "url_decode",
            "input": data,
            "output": decoded,
        }

    def show_operations(self):
        """Display available operations"""
        from rich.table import Table

        table = Table(title="Available Operations", show_header=True)
        table.add_column("Operation", style="cyan", width=15)
        table.add_column("Description", style="dim")

        ops = [
            ("base64_encode", "Encode to base64"),
            ("base64_decode", "Decode from base64"),
            ("url_encode", "URL encode string"),
            ("url_decode", "URL decode string"),
        ]

        for op, desc in ops:
            table.add_row(op, desc)

        console.print(table)
        console.print("\n[dim]Usage: [cyan]set OPERATION <operation>[/cyan][/dim]")

    def info(self) -> dict:
        return {
            "name": self.NAME,
            "description": self.DESCRIPTION,
            "author": self.AUTHOR,
            "category": self.CATEGORY,
            "operations": {
                "base64_encode": "base64 encode",
                "base64_decode": "base64 decode",
                "url_encode": "url encode",
                "url_decode": "url decode",
            },
            "examples": [
                "set INPUT 'Hello World' && set OPERATION base64_encode && run",
                "set INPUT 'SGVsbG8gV29ybGQ=' && set OPERATION base64_decode && run",
                "set INPUT 'hello world!' && set OPERATION url_encode && run",
                "set INPUT 'hello%20world%21' && set OPERATION url_decode && run",
            ],
        }
