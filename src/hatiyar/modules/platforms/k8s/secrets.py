"""
Kubernetes Secrets Enumeration Module
Enumerate and extract Kubernetes secrets
"""

import base64
from typing import Dict, Any
from pathlib import Path
from hatiyar.core.module_base import EnumerationModule
from hatiyar.core.constants import K8sResultKeys, K8sAuthOptions, OutputDefaults
from hatiyar.utils.output import save_json_results
from .auth_base import K8sAuthMixin

try:
    from kubernetes.client.exceptions import ApiException  # type: ignore

    KUBERNETES_AVAILABLE = True
except ImportError:
    KUBERNETES_AVAILABLE = False
    ApiException = Exception

NAME = "k8s_secrets_enumeration"
DESCRIPTION = "Kubernetes secrets enumeration and extraction"
AUTHOR = "hatiyar"
CATEGORY = "platforms"
SUBCATEGORY = "k8s"


class Module(EnumerationModule, K8sAuthMixin):
    """Kubernetes secrets enumeration module with flexible authentication"""

    def __init__(self):
        super().__init__()

        # Get authentication options from mixin
        auth_options = self.get_default_auth_options()

        # Add module-specific options
        self.options = {
            **auth_options,
            "namespace": "default",
            "all_namespaces": False,
            "decode_secrets": True,
            "show_data": False,
            "output_format": "table",
            K8sAuthOptions.OUTPUT_FILE: OutputDefaults.K8S_SECRETS_RESULTS,
        }

        self.results = {
            K8sResultKeys.SECRETS: [],
            "summary": {},
            K8sResultKeys.AUTH_METHOD: "",
        }

        self.v1_api = None

    def check_requirements(self) -> tuple[bool, str]:
        """Check if kubernetes client is available"""
        if not KUBERNETES_AVAILABLE:
            return False, "Install: pip install kubernetes"
        return True, "Kubernetes client available"

    def enumerate(self) -> Dict[str, Any]:
        """Required by EnumerationModule base class"""
        return self.run()

    def run(self) -> Dict[str, Any]:
        """Execute secrets enumeration"""
        from rich.console import Console

        console = Console()

        # Check requirements
        req_ok, req_msg = self.check_requirements()
        if not req_ok:
            console.print(f"[red]✗ {req_msg}[/red]")
            return {"success": False, "error": req_msg}

        # Initialize K8s client with flexible authentication
        console.print("[cyan]Initializing Kubernetes client...[/cyan]")
        success, message, api_client = self.initialize_k8s_client(self.options)

        if not success:
            console.print(f"[red]✗ {message}[/red]")
            console.print("\n[yellow]Authentication Options (choose one):[/yellow]")
            console.print("  1. Kubeconfig + Context:")
            console.print("     set KUBECONFIG ~/.kube/config")
            console.print("     set CONTEXT my-cluster")
            console.print("  2. API Server + Token:")
            console.print("     set API_SERVER https://k8s.example.com:6443")
            console.print("     set TOKEN <bearer-token>")
            console.print("  3. API Server + Client Certificates:")
            console.print("     set API_SERVER https://k8s.example.com:6443")
            console.print("     set CLIENT_CERT ~/path/to/client.crt")
            console.print("     set CLIENT_KEY ~/path/to/client.key")
            return {"success": False, "error": message}

        console.print(f"[green]{message}[/green]\n")
        self.results["authentication_method"] = message

        # Get API clients
        api_clients = self.get_k8s_api_clients(api_client)
        self.v1_api = api_clients["v1"]

        try:
            console.print("[cyan]Enumerating Kubernetes secrets...[/cyan]\n")
            console.print(
                "[yellow]⚠ Be careful with secret data - handle responsibly[/yellow]\n"
            )

            namespace = self.options["namespace"]
            all_namespaces = self.options.get("all_namespaces", False)

            if all_namespaces:
                secrets = self.v1_api.list_secret_for_all_namespaces()
            else:
                secrets = self.v1_api.list_namespaced_secret(namespace)

            for secret in secrets.items:
                secret_data = self._extract_secret_info(secret)
                self.results["secrets"].append(secret_data)

            self.results["summary"] = self._generate_summary()
            self._display_results(console)

            # Save to JSON file
            if self.options.get("OUTPUT_FILE"):
                self._save_results(console)

            return {
                "success": True,
                "results": self.results,
                "secret_count": len(self.results["secrets"]),
            }

        except Exception as e:
            console.print(f"[red]✗ Error: {str(e)}[/red]")
            return {"success": False, "error": str(e)}

    def _extract_secret_info(self, secret) -> Dict[str, Any]:
        """Extract secret information"""
        secret_info = {
            "name": secret.metadata.name,
            "namespace": secret.metadata.namespace,
            "type": secret.type,
            "keys": list(secret.data.keys()) if secret.data else [],
            "created": secret.metadata.creation_timestamp.isoformat()
            if secret.metadata.creation_timestamp
            else None,
        }

        if self.options.get("decode_secrets") and secret.data:
            secret_info["data"] = {}
            for key, value in secret.data.items():
                try:
                    decoded = base64.b64decode(value).decode("utf-8")
                    if self.options.get("show_data"):
                        secret_info["data"][key] = decoded
                    else:
                        secret_info["data"][key] = (
                            f"***HIDDEN*** (length: {len(decoded)})"
                        )
                except Exception:
                    secret_info["data"][key] = "***DECODE_ERROR***"

        return secret_info

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        types: Dict[str, int] = {}
        for secret in self.results["secrets"]:
            secret_type = secret["type"]
            types[secret_type] = types.get(secret_type, 0) + 1

        return {
            "total_secrets": len(self.results["secrets"]),
            "types": types,
            "total_keys": sum(len(s["keys"]) for s in self.results["secrets"]),
        }

    def _display_results(self, console):
        """Display enumeration results"""
        from rich.table import Table
        from rich.panel import Panel
        from rich import box

        summary = self.results["summary"]

        types_str = "\n".join([f"  {k}: {v}" for k, v in summary["types"].items()])
        console.print(
            Panel.fit(
                f"[cyan]Total Secrets:[/cyan] {summary['total_secrets']}\n"
                f"[cyan]Total Keys:[/cyan] {summary['total_keys']}\n"
                f"[cyan]Types:[/cyan]\n{types_str}",
                title="[bold]Secrets Summary[/bold]",
                border_style="cyan",
            )
        )
        console.print()

        if self.results["secrets"]:
            table = Table(title="Secrets", box=box.ROUNDED)
            table.add_column("Name", style="cyan", overflow="fold")
            table.add_column("Namespace", style="blue")
            table.add_column("Type", style="yellow")
            table.add_column("Keys", style="green")

            for secret in self.results["secrets"]:
                keys_str = ", ".join(secret["keys"][:5])
                if len(secret["keys"]) > 5:
                    keys_str += f" ... (+{len(secret['keys']) - 5} more)"

                table.add_row(
                    secret["name"],
                    secret["namespace"],
                    secret["type"].split("/")[-1],
                    keys_str,
                )

            console.print(table)

            if not self.options.get("show_data"):
                console.print(
                    "\n[dim]💡 Use 'set show_data true' to display secret values (use with caution!)[/dim]"
                )

    def _save_results(self, console):
        """Save results to JSON file using centralized utility"""
        try:
            output_path = Path(self.options[K8sAuthOptions.OUTPUT_FILE]).expanduser()
            save_json_results(self.results, output_path)
            console.print(f"\n[green]✓ Results saved to: {output_path}[/green]")
        except (IOError, ValueError) as e:
            console.print(f"\n[red]✗ {e}[/red]")
