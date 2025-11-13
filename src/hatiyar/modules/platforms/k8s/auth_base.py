"""K8s authentication mixin"""

import os
from typing import Dict, Any, Optional, Tuple

try:
    from kubernetes import client, config  # type: ignore

    KUBERNETES_AVAILABLE = True
except ImportError:
    KUBERNETES_AVAILABLE = False


class K8sAuthMixin:
    """
    K8s authentication mixin supporting 3 methods:
    1. Kubeconfig file
    2. API server + token
    3. API server + client certificates
    """

    def get_default_auth_options(self) -> Dict[str, Any]:
        return {
            "KUBECONFIG": "",
            "CONTEXT": "",
            "API_SERVER": "",
            "TOKEN": "",
            "CLIENT_CERT": "",
            "CLIENT_KEY": "",
            "CA_CERT": "",
            "VERIFY_SSL": True,
        }

    def initialize_k8s_client(
        self, options: Dict[str, Any]
    ) -> Tuple[bool, str, Optional[Any]]:
        if not KUBERNETES_AVAILABLE:
            return False, "Install: pip install kubernetes", None

        try:
            if options.get("API_SERVER"):
                return self._init_manual_config(options)
            elif options.get("KUBECONFIG"):
                return self._init_kubeconfig(
                    options["KUBECONFIG"], options.get("CONTEXT")
                )
            else:
                return self._init_default_kubeconfig(options.get("CONTEXT"))
        except Exception as e:
            return False, f"Authentication failed: {str(e)}", None

    def _init_manual_config(self, options: Dict[str, Any]) -> Tuple[bool, str, Any]:
        """Initialize with manual API server configuration"""
        from kubernetes.client import Configuration, ApiClient  # type: ignore

        configuration = Configuration()
        configuration.host = options["API_SERVER"]
        configuration.verify_ssl = options.get("VERIFY_SSL", True)

        # Token-based authentication
        if options.get("TOKEN"):
            configuration.api_key = {"authorization": f"Bearer {options['TOKEN']}"}
            auth_method = "API Server + Bearer Token"

        # Certificate-based authentication
        elif options.get("CLIENT_CERT") and options.get("CLIENT_KEY"):
            configuration.cert_file = os.path.expanduser(options["CLIENT_CERT"])
            configuration.key_file = os.path.expanduser(options["CLIENT_KEY"])
            auth_method = "API Server + Client Certificates"
        else:
            return (
                False,
                "API_SERVER requires either TOKEN or (CLIENT_CERT + CLIENT_KEY)",
                None,
            )

        # Optional CA certificate
        if options.get("CA_CERT"):
            configuration.ssl_ca_cert = os.path.expanduser(options["CA_CERT"])

        api_client = ApiClient(configuration)

        # Test connection
        try:
            v1 = client.CoreV1Api(api_client)
            namespaces = v1.list_namespace(limit=1)
            return (
                True,
                f"✓ Connected via {auth_method} ({len(namespaces.items)} namespaces visible)",
                api_client,
            )
        except Exception as e:
            return False, f"Connection test failed: {str(e)}", None

    def _init_kubeconfig(
        self, kubeconfig_path: str, context: Optional[str] = None
    ) -> Tuple[bool, str, None]:
        """Initialize with kubeconfig file"""
        expanded_path = os.path.expanduser(kubeconfig_path)
        if not os.path.exists(expanded_path):
            return False, f"Kubeconfig not found: {expanded_path}", None

        try:
            config.load_kube_config(config_file=expanded_path, context=context)

            auth_method = f"Kubeconfig: {expanded_path}"
            if context:
                auth_method += f" (context: {context})"

            # Test connection
            v1 = client.CoreV1Api()
            namespaces = v1.list_namespace(limit=1)
            return (
                True,
                f"✓ Connected via {auth_method} ({len(namespaces.items)} namespaces visible)",
                None,
            )
        except Exception as e:
            return False, f"Kubeconfig authentication failed: {str(e)}", None

    def _init_default_kubeconfig(
        self, context: Optional[str] = None
    ) -> Tuple[bool, str, None]:
        """Initialize with default kubeconfig (~/.kube/config)"""
        default_path = os.path.expanduser("~/.kube/config")
        if not os.path.exists(default_path):
            return False, f"Kubeconfig not found: {default_path}", None

        try:
            config.load_kube_config(context=context)

            auth_method = "Default Kubeconfig (~/.kube/config)"
            if context:
                auth_method += f" (context: {context})"

            # Test connection
            v1 = client.CoreV1Api()
            namespaces = v1.list_namespace(limit=1)
            return (
                True,
                f"✓ Connected via {auth_method} ({len(namespaces.items)} namespaces visible)",
                None,
            )
        except Exception as e:
            return False, f"Default kubeconfig failed: {str(e)}", None

    def get_k8s_api_clients(self, api_client: Optional[Any] = None) -> Dict[str, Any]:
        """
        Get initialized K8s API clients

        Args:
            api_client: Optional ApiClient instance (for manual config)

        Returns:
            Dictionary with initialized API clients
        """
        if api_client:
            return {
                "v1": client.CoreV1Api(api_client),
                "apps_v1": client.AppsV1Api(api_client),
                "rbac_v1": client.RbacAuthorizationV1Api(api_client),
                "networking_v1": client.NetworkingV1Api(api_client),
                "storage_v1": client.StorageV1Api(api_client),
            }
        else:
            return {
                "v1": client.CoreV1Api(),
                "apps_v1": client.AppsV1Api(),
                "rbac_v1": client.RbacAuthorizationV1Api(),
                "networking_v1": client.NetworkingV1Api(),
                "storage_v1": client.StorageV1Api(),
            }
