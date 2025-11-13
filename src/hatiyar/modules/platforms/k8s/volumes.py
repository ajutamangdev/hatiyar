"""
Kubernetes Volumes Enumeration Module
Enumerate PVs, PVCs, and StorageClasses
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

NAME = "k8s_volumes_enumeration"
DESCRIPTION = "Kubernetes storage enumeration: PVs, PVCs, StorageClasses"
AUTHOR = "hatiyar"
CATEGORY = "platforms"
SUBCATEGORY = "k8s"


class Module(EnumerationModule, K8sAuthMixin):
    """Kubernetes volumes enumeration module with flexible authentication"""

    def __init__(self):
        super().__init__()

        # Get authentication options from mixin
        auth_options = self.get_default_auth_options()

        # Add module-specific options
        self.options = {
            **auth_options,
            "namespace": "default",
            "all_namespaces": False,
            "output_format": "table",
            K8sAuthOptions.OUTPUT_FILE: OutputDefaults.K8S_VOLUMES_RESULTS,
        }

        self.results = {
            K8sResultKeys.PERSISTENT_VOLUMES: [],
            K8sResultKeys.PERSISTENT_VOLUME_CLAIMS: [],
            "storage_classes": [],
            "summary": {},
        }

    def check_requirements(self) -> tuple[bool, str]:
        """Check if kubernetes client is available"""
        try:
            return True, "Kubernetes client available"
        except ImportError:
            return False, "Install: pip install kubernetes"

    def enumerate(self) -> Dict[str, Any]:
        """Required by EnumerationModule base class"""
        return self.run()

    def run(self) -> Dict[str, Any]:
        """Execute volumes enumeration"""
        from rich.console import Console

        console = Console()

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

        # Get API clients
        api_clients = self.get_k8s_api_clients(api_client)
        v1 = api_clients["v1"]
        storage_v1 = api_clients["storage_v1"]

        try:
            console.print("[cyan]Enumerating Kubernetes storage resources...[/cyan]\n")

            # Enumerate PVs
            console.print("[dim]→ Enumerating PersistentVolumes...[/dim]")
            pvs = v1.list_persistent_volume()
            for pv in pvs.items:
                self.results["persistent_volumes"].append(self._extract_pv_info(pv))

            # Enumerate PVCs
            console.print("[dim]→ Enumerating PersistentVolumeClaims...[/dim]")
            namespace = self.options["namespace"]
            all_namespaces = self.options.get("all_namespaces", False)

            if all_namespaces:
                pvcs = v1.list_persistent_volume_claim_for_all_namespaces()
            else:
                pvcs = v1.list_namespaced_persistent_volume_claim(namespace)

            for pvc in pvcs.items:
                self.results["persistent_volume_claims"].append(
                    self._extract_pvc_info(pvc)
                )

            # Enumerate StorageClasses
            console.print("[dim]→ Enumerating StorageClasses...[/dim]")
            storage_classes = storage_v1.list_storage_class()
            for sc in storage_classes.items:
                self.results["storage_classes"].append(self._extract_sc_info(sc))

            self.results["summary"] = self._generate_summary()

            console.print("[green]✓ Enumeration complete![/green]\n")
            self._display_results(console)

            # Save to JSON file
            if self.options.get("OUTPUT_FILE"):
                self._save_results(console)

            return {
                "success": True,
                "results": self.results,
            }

        except Exception as e:
            console.print(f"[red]✗ Error: {str(e)}[/red]")
            return {"success": False, "error": str(e)}

    def _extract_pv_info(self, pv) -> Dict[str, Any]:
        """Extract PV information"""
        return {
            "name": pv.metadata.name,
            "capacity": pv.spec.capacity.get("storage") if pv.spec.capacity else None,
            "access_modes": pv.spec.access_modes or [],
            "reclaim_policy": pv.spec.persistent_volume_reclaim_policy,
            "status": pv.status.phase,
            "storage_class": pv.spec.storage_class_name,
            "claim": f"{pv.spec.claim_ref.namespace}/{pv.spec.claim_ref.name}"
            if pv.spec.claim_ref
            else None,
        }

    def _extract_pvc_info(self, pvc) -> Dict[str, Any]:
        """Extract PVC information"""
        return {
            "name": pvc.metadata.name,
            "namespace": pvc.metadata.namespace,
            "status": pvc.status.phase,
            "volume": pvc.spec.volume_name,
            "capacity": pvc.status.capacity.get("storage")
            if pvc.status.capacity
            else None,
            "access_modes": pvc.spec.access_modes or [],
            "storage_class": pvc.spec.storage_class_name,
        }

    def _extract_sc_info(self, sc) -> Dict[str, Any]:
        """Extract StorageClass information"""
        return {
            "name": sc.metadata.name,
            "provisioner": sc.provisioner,
            "reclaim_policy": sc.reclaim_policy,
            "volume_binding_mode": sc.volume_binding_mode,
            "is_default": sc.metadata.annotations.get(
                "storageclass.kubernetes.io/is-default-class"
            )
            == "true"
            if sc.metadata.annotations
            else False,
        }

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        pv_bound = len(
            [pv for pv in self.results["persistent_volumes"] if pv["status"] == "Bound"]
        )
        pvc_bound = len(
            [
                pvc
                for pvc in self.results["persistent_volume_claims"]
                if pvc["status"] == "Bound"
            ]
        )

        return {
            "total_pvs": len(self.results["persistent_volumes"]),
            "pvs_bound": pv_bound,
            "pvs_available": len(self.results["persistent_volumes"]) - pv_bound,
            "total_pvcs": len(self.results["persistent_volume_claims"]),
            "pvcs_bound": pvc_bound,
            "total_storage_classes": len(self.results["storage_classes"]),
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
                f"[cyan]PersistentVolumes:[/cyan] {summary['total_pvs']} (Bound: {summary['pvs_bound']}, Available: {summary['pvs_available']})\n"
                f"[cyan]PersistentVolumeClaims:[/cyan] {summary['total_pvcs']} (Bound: {summary['pvcs_bound']})\n"
                f"[cyan]StorageClasses:[/cyan] {summary['total_storage_classes']}",
                title="[bold]Storage Summary[/bold]",
                border_style="cyan",
            )
        )
        console.print()

        # PVs table
        if self.results["persistent_volumes"]:
            table = Table(title="PersistentVolumes", box=box.ROUNDED)
            table.add_column("Name", style="cyan")
            table.add_column("Capacity", style="yellow")
            table.add_column("Status", style="green")
            table.add_column("Claim", style="blue")
            table.add_column("StorageClass", style="dim")

            for pv in self.results["persistent_volumes"]:
                status_color = "green" if pv["status"] == "Bound" else "yellow"
                table.add_row(
                    pv["name"],
                    pv.get("capacity", "N/A"),
                    f"[{status_color}]{pv['status']}[/{status_color}]",
                    pv.get("claim", "N/A"),
                    pv.get("storage_class", "N/A"),
                )

            console.print(table)
            console.print()

        # PVCs table
        if self.results["persistent_volume_claims"]:
            table = Table(title="PersistentVolumeClaims", box=box.ROUNDED)
            table.add_column("Name", style="cyan")
            table.add_column("Namespace", style="blue")
            table.add_column("Status", style="green")
            table.add_column("Volume", style="yellow")
            table.add_column("Capacity", style="dim")

            for pvc in self.results["persistent_volume_claims"]:
                status_color = "green" if pvc["status"] == "Bound" else "yellow"
                table.add_row(
                    pvc["name"],
                    pvc["namespace"],
                    f"[{status_color}]{pvc['status']}[/{status_color}]",
                    pvc.get("volume", "N/A"),
                    pvc.get("capacity", "N/A"),
                )

            console.print(table)
            console.print()

        # StorageClasses table
        if self.results["storage_classes"]:
            table = Table(title="StorageClasses", box=box.ROUNDED)
            table.add_column("Name", style="cyan")
            table.add_column("Provisioner", style="yellow")
            table.add_column("Reclaim Policy", style="blue")
            table.add_column("Default", style="green")

            for sc in self.results["storage_classes"]:
                default_icon = "✓" if sc["is_default"] else ""
                table.add_row(
                    sc["name"],
                    sc["provisioner"],
                    sc.get("reclaim_policy", "N/A"),
                    default_icon,
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
