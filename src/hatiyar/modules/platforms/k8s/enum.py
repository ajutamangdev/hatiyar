"""
Kubernetes Enumeration Orchestrator Module
Comprehensive K8s cluster enumeration with flexible authentication
"""

from typing import Dict, Any
from pathlib import Path
from hatiyar.core.module_base import EnumerationModule
from hatiyar.core.constants import K8sResultKeys, K8sAuthOptions, OutputDefaults
from hatiyar.utils.output import save_json_results
from .auth_base import K8sAuthMixin
import importlib.util

try:
    from kubernetes.client.exceptions import ApiException  # type: ignore

    KUBERNETES_AVAILABLE = importlib.util.find_spec("kubernetes") is not None
except ImportError:
    KUBERNETES_AVAILABLE = False
    ApiException = Exception  # Fallback for type hints

NAME = "k8s_enumeration"
DESCRIPTION = "Comprehensive Kubernetes cluster enumeration (orchestrator)"
AUTHOR = "hatiyar"
CATEGORY = "platforms"
SUBCATEGORY = "k8s"


class Module(EnumerationModule, K8sAuthMixin):
    """Kubernetes enumeration orchestrator with flexible authentication"""

    def __init__(self):
        super().__init__()

        # Get authentication options from mixin
        auth_options = self.get_default_auth_options()

        # Add module-specific enumeration options
        self.options = {
            **auth_options,
            "ENUMERATE_NAMESPACES": True,
            "ENUMERATE_PODS": True,
            "ENUMERATE_SECRETS": True,
            "ENUMERATE_VOLUMES": True,
            "ENUMERATE_SERVICES": True,
            "ENUMERATE_DEPLOYMENTS": True,
            "ENUMERATE_RBAC": True,
            "ENUMERATE_NETWORK_POLICIES": True,
            "NAMESPACE": "",  # Target namespace (empty = all namespaces)
            K8sAuthOptions.OUTPUT_FILE: OutputDefaults.K8S_ENUM_RESULTS,
        }

        self.v1_api = None
        self.apps_v1_api = None
        self.rbac_v1_api = None
        self.networking_v1_api = None
        self.storage_v1_api = None

        self.results = {
            K8sResultKeys.CLUSTER_INFO: {},
            K8sResultKeys.AUTH_METHOD: "",
            K8sResultKeys.NAMESPACES: [],
            K8sResultKeys.PODS: [],
            K8sResultKeys.SECRETS: [],
            K8sResultKeys.VOLUMES: {},
            K8sResultKeys.SERVICES: [],
            K8sResultKeys.DEPLOYMENTS: [],
            "rbac": {},
            "network_policies": [],
            "summary": {},
        }

    def check_requirements(self) -> tuple[bool, str]:
        """Check if kubernetes client is available"""
        if not KUBERNETES_AVAILABLE:
            return False, "Install: pip install kubernetes"
        return True, "Kubernetes client available"

    def enumerate(self) -> Dict[str, Any]:
        """Required by EnumerationModule base class"""
        return self.run()

    def run(self) -> Dict[str, Any]:
        """Execute comprehensive Kubernetes enumeration"""
        from rich.console import Console
        from rich.progress import Progress, SpinnerColumn, TextColumn

        console = Console()

        # Check requirements
        req_ok, req_msg = self.check_requirements()
        if not req_ok:
            console.print(f"[red]✗ {req_msg}[/red]")
            return {"success": False, "error": req_msg}

        # Initialize K8s client with flexible authentication
        console.print("\n[cyan]Initializing Kubernetes client...[/cyan]")
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

        # Get API clients from mixin
        api_clients = self.get_k8s_api_clients(api_client)
        self.v1_api = api_clients["v1"]
        self.apps_v1_api = api_clients["apps_v1"]
        self.rbac_v1_api = api_clients["rbac_v1"]
        self.networking_v1_api = api_clients["networking_v1"]
        self.storage_v1_api = api_clients["storage_v1"]

        # Get cluster info
        self._get_cluster_info(console)

        # Run enumeration
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            if self.options.get("ENUMERATE_NAMESPACES"):
                task = progress.add_task("[cyan]Enumerating namespaces...", total=None)
                self._enumerate_namespaces()
                progress.remove_task(task)
                console.print(
                    f"[green]✓ Found {len(self.results['namespaces'])} namespaces[/green]"
                )

            if self.options.get("ENUMERATE_PODS"):
                task = progress.add_task("[cyan]Enumerating pods...", total=None)
                self._enumerate_pods()
                progress.remove_task(task)
                console.print(
                    f"[green]✓ Found {len(self.results['pods'])} pods[/green]"
                )

            if self.options.get("ENUMERATE_SERVICES"):
                task = progress.add_task("[cyan]Enumerating services...", total=None)
                self._enumerate_services()
                progress.remove_task(task)
                console.print(
                    f"[green]✓ Found {len(self.results['services'])} services[/green]"
                )

            if self.options.get("ENUMERATE_DEPLOYMENTS"):
                task = progress.add_task("[cyan]Enumerating deployments...", total=None)
                self._enumerate_deployments()
                progress.remove_task(task)
                console.print(
                    f"[green]✓ Found {len(self.results['deployments'])} deployments[/green]"
                )

            if self.options.get("ENUMERATE_SECRETS"):
                task = progress.add_task("[cyan]Enumerating secrets...", total=None)
                self._enumerate_secrets()
                progress.remove_task(task)
                console.print(
                    f"[green]✓ Found {len(self.results['secrets'])} secrets[/green]"
                )

            if self.options.get("ENUMERATE_VOLUMES"):
                task = progress.add_task("[cyan]Enumerating storage...", total=None)
                self._enumerate_volumes()
                progress.remove_task(task)
                pv_count = len(self.results["volumes"].get("persistent_volumes", []))
                pvc_count = len(
                    self.results["volumes"].get("persistent_volume_claims", [])
                )
                console.print(
                    f"[green]✓ Found {pv_count} PVs, {pvc_count} PVCs[/green]"
                )

            if self.options.get("ENUMERATE_RBAC"):
                task = progress.add_task("[cyan]Enumerating RBAC...", total=None)
                self._enumerate_rbac()
                progress.remove_task(task)
                roles = len(self.results["rbac"].get("roles", []))
                sa = len(self.results["rbac"].get("service_accounts", []))
                console.print(
                    f"[green]✓ Found {roles} roles, {sa} service accounts[/green]"
                )

            if self.options.get("ENUMERATE_NETWORK_POLICIES"):
                task = progress.add_task(
                    "[cyan]Enumerating network policies...", total=None
                )
                self._enumerate_network_policies()
                progress.remove_task(task)
                console.print(
                    f"[green]✓ Found {len(self.results['network_policies'])} network policies[/green]"
                )

        # Generate summary
        self.results["summary"] = self._generate_summary()

        # Display results
        console.print("\n")
        self._display_summary(console)

        # Save to file if requested
        if self.options.get("OUTPUT_FILE"):
            self._save_results(console)

        return {
            "success": True,
            "results": self.results,
            "authentication_method": self.results["authentication_method"],
        }

    def _get_cluster_info(self, console):
        """Get cluster information"""
        from rich.panel import Panel
        from kubernetes import client  # type: ignore

        try:
            version_api = client.VersionApi()
            version_info = version_api.get_code()

            self.results["cluster_info"] = {
                "kubernetes_version": version_info.git_version,
                "platform": version_info.platform,
            }

            console.print(
                Panel.fit(
                    f"[cyan]Kubernetes Version:[/cyan] {version_info.git_version}\n"
                    f"[cyan]Platform:[/cyan] {version_info.platform}\n"
                    f"[cyan]Authentication:[/cyan] {self.results['authentication_method']}",
                    title="[bold cyan]Cluster Information[/bold cyan]",
                    border_style="cyan",
                )
            )
            console.print()
        except Exception as e:
            console.print(
                f"[yellow]⚠ Could not fetch cluster version: {str(e)}[/yellow]\n"
            )

    def _enumerate_namespaces(self):
        """Enumerate all namespaces"""
        try:
            namespaces = self.v1_api.list_namespace()  # type: ignore
            for ns in namespaces.items:
                self.results[K8sResultKeys.NAMESPACES].append(
                    {
                        "name": ns.metadata.name,
                        "status": ns.status.phase,
                        "created": ns.metadata.creation_timestamp.isoformat()
                        if ns.metadata.creation_timestamp
                        else None,
                        "labels": dict(ns.metadata.labels)
                        if ns.metadata.labels
                        else {},
                    }
                )
        except ApiException as api_err:
            import logging

            logging.error(
                f"K8s API error enumerating namespaces: {api_err.status} - {api_err.reason}"
            )  # type: ignore
            self.results[K8sResultKeys.NAMESPACES] = [
                {"error": str(api_err), "status": api_err.status}
            ]  # type: ignore
        except Exception as e:
            import logging

            logging.exception("Unexpected error enumerating namespaces")
            self.results[K8sResultKeys.NAMESPACES] = [{"error": str(e)}]

    def _enumerate_pods(self):
        """Enumerate all pods"""
        try:
            namespace = self.options.get("NAMESPACE")
            if namespace:
                pods = self.v1_api.list_namespaced_pod(namespace)
            else:
                pods = self.v1_api.list_pod_for_all_namespaces()

            for pod in pods.items:
                self.results["pods"].append(
                    {
                        "name": pod.metadata.name,
                        "namespace": pod.metadata.namespace,
                        "status": pod.status.phase,
                        "node": pod.spec.node_name,
                        "ip": pod.status.pod_ip,
                        "containers": len(pod.spec.containers),
                        "restart_count": sum(
                            c.restart_count for c in pod.status.container_statuses or []
                        ),
                    }
                )
        except Exception as e:
            self.results["pods"] = [{"error": str(e)}]

    def _enumerate_services(self):
        """Enumerate all services"""
        try:
            namespace = self.options.get("NAMESPACE")
            if namespace:
                services = self.v1_api.list_namespaced_service(namespace)
            else:
                services = self.v1_api.list_service_for_all_namespaces()

            for svc in services.items:
                self.results["services"].append(
                    {
                        "name": svc.metadata.name,
                        "namespace": svc.metadata.namespace,
                        "type": svc.spec.type,
                        "cluster_ip": svc.spec.cluster_ip,
                        "external_ip": svc.spec.external_i_ps or [],
                        "ports": [
                            {"port": p.port, "protocol": p.protocol}
                            for p in svc.spec.ports or []
                        ],
                    }
                )
        except Exception as e:
            self.results["services"] = [{"error": str(e)}]

    def _enumerate_deployments(self):
        """Enumerate all deployments"""
        try:
            namespace = self.options.get("NAMESPACE")
            if namespace:
                deployments = self.apps_v1_api.list_namespaced_deployment(namespace)
            else:
                deployments = self.apps_v1_api.list_deployment_for_all_namespaces()

            for deploy in deployments.items:
                self.results["deployments"].append(
                    {
                        "name": deploy.metadata.name,
                        "namespace": deploy.metadata.namespace,
                        "replicas": deploy.spec.replicas,
                        "ready_replicas": deploy.status.ready_replicas or 0,
                        "available_replicas": deploy.status.available_replicas or 0,
                    }
                )
        except Exception as e:
            self.results["deployments"] = [{"error": str(e)}]

    def _enumerate_secrets(self):
        """Enumerate all secrets"""
        try:
            namespace = self.options.get("NAMESPACE")
            if namespace:
                secrets = self.v1_api.list_namespaced_secret(namespace)
            else:
                secrets = self.v1_api.list_secret_for_all_namespaces()

            for secret in secrets.items:
                self.results["secrets"].append(
                    {
                        "name": secret.metadata.name,
                        "namespace": secret.metadata.namespace,
                        "type": secret.type,
                        "keys": list(secret.data.keys()) if secret.data else [],
                    }
                )
        except Exception as e:
            self.results["secrets"] = [{"error": str(e)}]

    def _enumerate_volumes(self):
        """Enumerate storage resources"""
        try:
            # PersistentVolumes
            pvs = self.v1_api.list_persistent_volume()
            self.results["volumes"]["persistent_volumes"] = [
                {
                    "name": pv.metadata.name,
                    "capacity": pv.spec.capacity.get("storage")
                    if pv.spec.capacity
                    else None,
                    "status": pv.status.phase,
                    "claim": f"{pv.spec.claim_ref.namespace}/{pv.spec.claim_ref.name}"
                    if pv.spec.claim_ref
                    else None,
                }
                for pv in pvs.items
            ]

            # PersistentVolumeClaims
            namespace = self.options.get("NAMESPACE")
            if namespace:
                pvcs = self.v1_api.list_namespaced_persistent_volume_claim(namespace)
            else:
                pvcs = self.v1_api.list_persistent_volume_claim_for_all_namespaces()

            self.results["volumes"]["persistent_volume_claims"] = [
                {
                    "name": pvc.metadata.name,
                    "namespace": pvc.metadata.namespace,
                    "status": pvc.status.phase,
                    "volume": pvc.spec.volume_name,
                    "capacity": pvc.status.capacity.get("storage")
                    if pvc.status.capacity
                    else None,
                }
                for pvc in pvcs.items
            ]

            # StorageClasses
            storage_classes = self.storage_v1_api.list_storage_class()
            self.results["volumes"]["storage_classes"] = [
                {
                    "name": sc.metadata.name,
                    "provisioner": sc.provisioner,
                    "reclaim_policy": sc.reclaim_policy,
                }
                for sc in storage_classes.items
            ]
        except Exception as e:
            self.results["volumes"] = {"error": str(e)}

    def _enumerate_rbac(self):
        """Enumerate RBAC resources"""
        try:
            # Roles
            namespace = self.options.get("NAMESPACE")
            if namespace:
                roles = self.rbac_v1_api.list_namespaced_role(namespace)
            else:
                roles = self.rbac_v1_api.list_role_for_all_namespaces()

            self.results["rbac"]["roles"] = [
                {
                    "name": role.metadata.name,
                    "namespace": role.metadata.namespace,
                    "rules": len(role.rules or []),
                }
                for role in roles.items
            ]

            # ClusterRoles
            cluster_roles = self.rbac_v1_api.list_cluster_role()
            self.results["rbac"]["cluster_roles"] = [
                {
                    "name": cr.metadata.name,
                    "rules": len(cr.rules or []),
                }
                for cr in cluster_roles.items
            ]

            # ServiceAccounts
            if namespace:
                service_accounts = self.v1_api.list_namespaced_service_account(
                    namespace
                )
            else:
                service_accounts = self.v1_api.list_service_account_for_all_namespaces()

            self.results["rbac"]["service_accounts"] = [
                {
                    "name": sa.metadata.name,
                    "namespace": sa.metadata.namespace,
                    "secrets": len(sa.secrets or []),
                }
                for sa in service_accounts.items
            ]
        except Exception as e:
            self.results["rbac"] = {"error": str(e)}

    def _enumerate_network_policies(self):
        """Enumerate network policies"""
        try:
            namespace = self.options.get("NAMESPACE")
            if namespace:
                policies = self.networking_v1_api.list_namespaced_network_policy(
                    namespace
                )
            else:
                policies = (
                    self.networking_v1_api.list_network_policy_for_all_namespaces()
                )

            for policy in policies.items:
                self.results["network_policies"].append(
                    {
                        "name": policy.metadata.name,
                        "namespace": policy.metadata.namespace,
                        "pod_selector": dict(policy.spec.pod_selector.match_labels)
                        if policy.spec.pod_selector
                        and policy.spec.pod_selector.match_labels
                        else {},
                    }
                )
        except Exception as e:
            self.results["network_policies"] = [{"error": str(e)}]

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        return {
            "total_namespaces": len(
                [n for n in self.results["namespaces"] if "error" not in n]
            ),
            "total_pods": len([p for p in self.results["pods"] if "error" not in p]),
            "total_services": len(
                [s for s in self.results["services"] if "error" not in s]
            ),
            "total_deployments": len(
                [d for d in self.results["deployments"] if "error" not in d]
            ),
            "total_secrets": len(
                [s for s in self.results["secrets"] if "error" not in s]
            ),
            "total_pvs": len(self.results["volumes"].get("persistent_volumes", [])),
            "total_pvcs": len(
                self.results["volumes"].get("persistent_volume_claims", [])
            ),
            "total_network_policies": len(
                [n for n in self.results["network_policies"] if "error" not in n]
            ),
        }

    def _display_summary(self, console):
        """Display enumeration summary"""
        from rich.panel import Panel
        from rich.table import Table

        summary = self.results["summary"]

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Resource", style="cyan")
        table.add_column("Count", style="green", justify="right")

        table.add_row("Namespaces", str(summary["total_namespaces"]))
        table.add_row("Pods", str(summary["total_pods"]))
        table.add_row("Services", str(summary["total_services"]))
        table.add_row("Deployments", str(summary["total_deployments"]))
        table.add_row("Secrets", str(summary["total_secrets"]))
        table.add_row("PersistentVolumes", str(summary["total_pvs"]))
        table.add_row("PersistentVolumeClaims", str(summary["total_pvcs"]))
        table.add_row("Network Policies", str(summary["total_network_policies"]))

        console.print(
            Panel(
                table,
                title="[bold green]Enumeration Summary[/bold green]",
                border_style="green",
            )
        )

    def _save_results(self, console):
        """Save results to JSON file using centralized utility"""
        try:
            output_path = Path(self.options[K8sAuthOptions.OUTPUT_FILE]).expanduser()
            save_json_results(self.results, output_path)
            console.print(f"\n[green]✓ Results saved to: {output_path}[/green]")
        except (IOError, ValueError) as e:
            console.print(f"\n[red]✗ {e}[/red]")
