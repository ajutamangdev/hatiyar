"""
Kubernetes Pods Enumeration Module
Deep dive enumeration of Kubernetes pods
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
    ApiException = Exception  # Fallback for type hints

NAME = "k8s_pods_enumeration"
DESCRIPTION = "Deep enumeration of Kubernetes pods: containers, volumes, security contexts, resources"
AUTHOR = "hatiyar"
CATEGORY = "platforms"
SUBCATEGORY = "k8s"


class Module(EnumerationModule, K8sAuthMixin):
    """Kubernetes pods enumeration module with flexible authentication"""

    def __init__(self):
        super().__init__()

        # Get authentication options from mixin
        auth_options = self.get_default_auth_options()

        # Add module-specific options
        self.options = {
            **auth_options,
            "namespace": "default",
            "all_namespaces": False,
            "show_containers": True,
            "show_volumes": True,
            "output_format": "table",
            K8sAuthOptions.OUTPUT_FILE: OutputDefaults.K8S_PODS_RESULTS,
        }

        self.results = {
            K8sResultKeys.PODS: [],
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
        """Execute pods enumeration"""
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
            console.print("[cyan]Enumerating Kubernetes pods...[/cyan]\n")

            namespace = self.options["namespace"]
            all_namespaces = self.options.get("all_namespaces", False)

            if all_namespaces:
                pods = self.v1_api.list_pod_for_all_namespaces()
            else:
                pods = self.v1_api.list_namespaced_pod(namespace)

            for pod in pods.items:
                pod_data = self._extract_pod_info(pod)
                self.results["pods"].append(pod_data)

            self.results["summary"] = self._generate_summary()
            self._display_results(console)

            # Save to JSON file
            if self.options.get(K8sAuthOptions.OUTPUT_FILE):
                self._save_results(console)

            return {
                "success": True,
                "results": self.results,
                "pod_count": len(self.results[K8sResultKeys.PODS]),
            }

        except ApiException as api_err:
            error_msg = f"K8s API error: {api_err.status} - {api_err.reason}"  # type: ignore
            console.print(f"[red]✗ {error_msg}[/red]")
            return {"success": False, "error": error_msg, "status_code": api_err.status}  # type: ignore
        except Exception as e:
            console.print(f"[red]✗ Unexpected error: {str(e)}[/red]")
            import logging

            logging.exception("Error during pod enumeration")
            return {"success": False, "error": str(e)}

    def _extract_pod_info(self, pod) -> Dict[str, Any]:
        """Extract detailed pod information"""
        pod_info = {
            "name": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "status": pod.status.phase,
            "node": pod.spec.node_name,
            "ip": pod.status.pod_ip,
            "host_ip": pod.status.host_ip,
            "restart_count": sum(
                c.restart_count for c in pod.status.container_statuses or []
            ),
            "containers": [],
            "volumes": [],
            "security": {},
        }

        if self.options.get("show_containers"):
            for container in pod.spec.containers:
                container_info = {
                    "name": container.name,
                    "image": container.image,
                    "ports": [p.container_port for p in container.ports or []],
                    "resources": {
                        "requests": dict(container.resources.requests or {})
                        if container.resources
                        else {},
                        "limits": dict(container.resources.limits or {})
                        if container.resources
                        else {},
                    },
                }

                if container.security_context:
                    container_info["security_context"] = {
                        "privileged": container.security_context.privileged,
                        "run_as_user": container.security_context.run_as_user,
                        "run_as_non_root": container.security_context.run_as_non_root,
                        "read_only_root_filesystem": container.security_context.read_only_root_filesystem,
                    }

                pod_info["containers"].append(container_info)

        if self.options.get("show_volumes") and pod.spec.volumes:
            for volume in pod.spec.volumes:
                volume_info = {
                    "name": volume.name,
                    "type": self._get_volume_type(volume),
                }
                pod_info["volumes"].append(volume_info)

        if pod.spec.security_context:
            pod_info["security"]["pod_security_context"] = {
                "run_as_user": pod.spec.security_context.run_as_user,
                "run_as_group": pod.spec.security_context.run_as_group,
                "fs_group": pod.spec.security_context.fs_group,
            }

        pod_info["security"]["host_network"] = pod.spec.host_network or False
        pod_info["security"]["host_pid"] = pod.spec.host_pid or False
        pod_info["security"]["host_ipc"] = pod.spec.host_ipc or False

        return pod_info

    def _get_volume_type(self, volume) -> str:
        """Determine volume type"""
        if volume.config_map:
            return "ConfigMap"
        elif volume.secret:
            return "Secret"
        elif volume.persistent_volume_claim:
            return "PVC"
        elif volume.empty_dir:
            return "EmptyDir"
        elif volume.host_path:
            return f"HostPath: {volume.host_path.path}"
        else:
            return "Other"

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        total = len(self.results["pods"])
        running = len([p for p in self.results["pods"] if p["status"] == "Running"])
        failed = len([p for p in self.results["pods"] if p["status"] == "Failed"])
        pending = len([p for p in self.results["pods"] if p["status"] == "Pending"])

        privileged = len(
            [
                p
                for p in self.results["pods"]
                for c in p.get("containers", [])
                if c.get("security_context", {}).get("privileged")
            ]
        )

        host_network = len(
            [p for p in self.results["pods"] if p["security"].get("host_network")]
        )

        return {
            "total_pods": total,
            "running": running,
            "failed": failed,
            "pending": pending,
            "privileged_containers": privileged,
            "host_network_pods": host_network,
        }

    def _display_results(self, console):
        """Display enumeration results"""
        from rich.table import Table
        from rich.panel import Panel
        from rich import box

        summary = self.results["summary"]
        console.print(
            Panel.fit(
                f"[cyan]Total Pods:[/cyan] {summary['total_pods']}\n"
                f"[green]Running:[/green] {summary['running']}\n"
                f"[yellow]Pending:[/yellow] {summary['pending']}\n"
                f"[red]Failed:[/red] {summary['failed']}\n"
                f"[red]Privileged Containers:[/red] {summary['privileged_containers']}\n"
                f"[yellow]Host Network:[/yellow] {summary['host_network_pods']}",
                title="[bold]Pods Summary[/bold]",
                border_style="cyan",
            )
        )
        console.print()

        if self.results["pods"]:
            table = Table(title="Pods Details", box=box.ROUNDED)
            table.add_column("Name", style="cyan", overflow="fold")
            table.add_column("Namespace", style="blue")
            table.add_column("Status", style="green")
            table.add_column("IP", style="yellow")
            table.add_column("Containers", style="dim")
            table.add_column("Restarts", style="red")

            for pod in self.results["pods"][:30]:
                status_color = (
                    "green"
                    if pod["status"] == "Running"
                    else "yellow"
                    if pod["status"] == "Pending"
                    else "red"
                )
                table.add_row(
                    pod["name"],
                    pod["namespace"],
                    f"[{status_color}]{pod['status']}[/{status_color}]",
                    pod.get("ip", "N/A"),
                    str(len(pod.get("containers", []))),
                    str(pod.get("restart_count", 0)),
                )

            console.print(table)

    def _save_results(self, console):
        """Save results to JSON file using centralized utility"""
        try:
            output_path = Path(self.options[K8sAuthOptions.OUTPUT_FILE]).expanduser()
            save_json_results(self.results, output_path)
            console.print(f"\n[green]✓ Results saved to: {output_path}[/green]")
        except (IOError, ValueError) as e:
            console.print(f"\n[red]✗ {e}[/red]")
