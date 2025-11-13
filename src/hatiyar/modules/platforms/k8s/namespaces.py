"""
Kubernetes Namespaces Enumeration Module
Enumerate namespaces with resource quotas and limits
"""

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

NAME = "k8s_namespaces_enumeration"
DESCRIPTION = "Kubernetes namespace enumeration with resource quotas and limits"
AUTHOR = "hatiyar"
CATEGORY = "platforms"
SUBCATEGORY = "k8s"


class Module(EnumerationModule, K8sAuthMixin):
    """Kubernetes namespaces enumeration module with flexible authentication"""

    def __init__(self):
        super().__init__()

        # Get authentication options from mixin
        auth_options = self.get_default_auth_options()

        # Add module-specific options
        self.options = {
            **auth_options,
            "show_quotas": True,
            "show_limits": True,
            "output_format": "table",
            K8sAuthOptions.OUTPUT_FILE: OutputDefaults.K8S_NAMESPACES_RESULTS,
        }

        self.results = {
            K8sResultKeys.NAMESPACES: [],
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
        """Execute namespaces enumeration"""
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
            console.print("[cyan]Enumerating Kubernetes namespaces...[/cyan]\n")

            # Get namespaces
            namespaces = self.v1_api.list_namespace()

            for ns in namespaces.items:
                ns_data = self._extract_namespace_info(ns, self.v1_api)
                self.results["namespaces"].append(ns_data)

            self.results["summary"] = self._generate_summary()

            console.print("[green]✓ Enumeration complete![/green]\n")
            self._display_results(console)

            # Save to JSON file
            if self.options.get("OUTPUT_FILE"):
                self._save_results(console)

            return {
                "success": True,
                "results": self.results,
                "namespace_count": len(self.results["namespaces"]),
            }

        except Exception as e:
            console.print(f"[red]✗ Error: {str(e)}[/red]")
            return {"success": False, "error": str(e)}

    def _extract_namespace_info(self, ns, v1) -> Dict[str, Any]:
        """Extract namespace information"""
        ns_name = ns.metadata.name

        ns_info = {
            "name": ns_name,
            "status": ns.status.phase,
            "created": ns.metadata.creation_timestamp.isoformat()
            if ns.metadata.creation_timestamp
            else None,
            "labels": dict(ns.metadata.labels) if ns.metadata.labels else {},
            "resource_quotas": [],
            "limit_ranges": [],
        }

        # Get resource quotas
        if self.options.get("show_quotas"):
            try:
                quotas = v1.list_namespaced_resource_quota(ns_name)
                for quota in quotas.items:
                    ns_info["resource_quotas"].append(
                        {
                            "name": quota.metadata.name,
                            "hard": dict(quota.spec.hard) if quota.spec.hard else {},
                            "used": dict(quota.status.used)
                            if quota.status.used
                            else {},
                        }
                    )
            except Exception:
                pass

        # Get limit ranges
        if self.options.get("show_limits"):
            try:
                limits = v1.list_namespaced_limit_range(ns_name)
                for limit in limits.items:
                    for item in limit.spec.limits or []:
                        ns_info["limit_ranges"].append(
                            {
                                "name": limit.metadata.name,
                                "type": item.type,
                                "max": dict(item.max) if item.max else {},
                                "min": dict(item.min) if item.min else {},
                                "default": dict(item.default) if item.default else {},
                                "default_request": dict(item.default_request)
                                if item.default_request
                                else {},
                            }
                        )
            except Exception:
                pass

        return ns_info

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        active = len(
            [ns for ns in self.results["namespaces"] if ns["status"] == "Active"]
        )
        with_quotas = len(
            [ns for ns in self.results["namespaces"] if ns["resource_quotas"]]
        )
        with_limits = len(
            [ns for ns in self.results["namespaces"] if ns["limit_ranges"]]
        )

        return {
            "total_namespaces": len(self.results["namespaces"]),
            "active": active,
            "with_quotas": with_quotas,
            "with_limits": with_limits,
        }

    def _display_results(self, console):
        """Display enumeration results"""
        from rich.table import Table
        from rich.panel import Panel
        from rich import box

        summary = self.results["summary"]

        # Summary
        console.print(
            Panel.fit(
                f"[cyan]Total Namespaces:[/cyan] {summary['total_namespaces']}\n"
                f"[green]Active:[/green] {summary['active']}\n"
                f"[cyan]With Resource Quotas:[/cyan] {summary['with_quotas']}\n"
                f"[cyan]With Limit Ranges:[/cyan] {summary['with_limits']}",
                title="[bold]Namespaces Summary[/bold]",
                border_style="cyan",
            )
        )
        console.print()

        # Namespaces table
        if self.results["namespaces"]:
            table = Table(title="Namespaces", box=box.ROUNDED)
            table.add_column("Name", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Quotas", style="yellow")
            table.add_column("Limits", style="blue")
            table.add_column("Labels", style="dim")

            for ns in self.results["namespaces"]:
                labels_str = ", ".join(
                    [f"{k}={v}" for k, v in list(ns["labels"].items())[:2]]
                )
                if len(ns["labels"]) > 2:
                    labels_str += "..."

                table.add_row(
                    ns["name"],
                    ns["status"],
                    str(len(ns["resource_quotas"])),
                    str(len(ns["limit_ranges"])),
                    labels_str or "None",
                )

            console.print(table)
            console.print()

            # Show quota details for namespaces with quotas
            ns_with_quotas = [
                ns for ns in self.results["namespaces"] if ns["resource_quotas"]
            ]
            if ns_with_quotas:
                console.print("[bold]Resource Quotas Details:[/bold]\n")
                for ns in ns_with_quotas[:5]:  # Limit to 5
                    console.print(f"[cyan]{ns['name']}:[/cyan]")
                    for quota in ns["resource_quotas"]:
                        console.print(f"  [yellow]{quota['name']}:[/yellow]")
                        for resource, limit in quota["hard"].items():
                            used = quota["used"].get(resource, "0")
                            console.print(f"    {resource}: {used}/{limit}")
                    console.print()

    def _save_results(self, console):
        """Save results to JSON file using centralized utility"""
        try:
            output_path = Path(self.options[K8sAuthOptions.OUTPUT_FILE]).expanduser()
            save_json_results(self.results, output_path)
            console.print(f"\n[green]✓ Results saved to: {output_path}[/green]")
        except (IOError, ValueError) as e:
            console.print(f"\n[red]✗ {e}[/red]")
