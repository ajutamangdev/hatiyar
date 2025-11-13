"""
Central constants for the Hatiyar security toolkit.

This module contains all string literals, magic values, and configuration
constants used throughout the application to improve maintainability and
reduce duplication.
"""

from typing import Final


class Context:
    """Context identifiers for different cloud and platform environments."""

    K8S: Final[str] = "k8s"
    AWS: Final[str] = "aws"
    AZURE: Final[str] = "azure"
    GCP: Final[str] = "gcp"
    CVE: Final[str] = "cve"
    ENUMERATION: Final[str] = "enumeration"
    MISC: Final[str] = "misc"


class K8sResultKeys:
    """Result dictionary keys for Kubernetes modules."""

    CLUSTER_INFO: Final[str] = "cluster_info"
    AUTH_METHOD: Final[str] = "authentication_method"
    NAMESPACES: Final[str] = "namespaces"
    PODS: Final[str] = "pods"
    SECRETS: Final[str] = "secrets"
    VOLUMES: Final[str] = "volumes"
    PERSISTENT_VOLUMES: Final[str] = "persistent_volumes"
    PERSISTENT_VOLUME_CLAIMS: Final[str] = "persistent_volume_claims"
    DEPLOYMENTS: Final[str] = "deployments"
    SERVICES: Final[str] = "services"
    NODES: Final[str] = "nodes"
    CONFIGMAPS: Final[str] = "configmaps"
    RESOURCE_QUOTAS: Final[str] = "resource_quotas"
    LIMIT_RANGES: Final[str] = "limit_ranges"
    SERVICE_ACCOUNTS: Final[str] = "service_accounts"


class K8sAuthOptions:
    """Option keys for Kubernetes authentication."""

    KUBECONFIG: Final[str] = "KUBECONFIG"
    CONTEXT: Final[str] = "CONTEXT"
    API_SERVER: Final[str] = "API_SERVER"
    TOKEN: Final[str] = "TOKEN"
    CERT_FILE: Final[str] = "CERT_FILE"
    KEY_FILE: Final[str] = "KEY_FILE"
    CA_CERT: Final[str] = "CA_CERT"
    VERIFY_SSL: Final[str] = "VERIFY_SSL"
    OUTPUT_FILE: Final[str] = "OUTPUT_FILE"


class OutputDefaults:
    """Default output file names and formats."""

    K8S_ENUM_RESULTS: Final[str] = "k8s_enum_results.json"
    K8S_PODS_RESULTS: Final[str] = "k8s_pods_results.json"
    K8S_SECRETS_RESULTS: Final[str] = "k8s_secrets_results.json"
    K8S_NAMESPACES_RESULTS: Final[str] = "k8s_namespaces_results.json"
    K8S_VOLUMES_RESULTS: Final[str] = "k8s_volumes_results.json"
    JSON_INDENT: Final[int] = 2


class ValidationLimits:
    """Validation limits for user inputs."""

    MAX_OPTION_VALUE_LENGTH: Final[int] = 1000
    MAX_COMMAND_LENGTH: Final[int] = 5000
    MAX_MODULE_NAME_LENGTH: Final[int] = 100


class Messages:
    """User-facing messages and prompts."""

    # Success messages
    SUCCESS_MODULE_LOADED: Final[str] = "[green]✓ Module loaded successfully[/green]"
    SUCCESS_OPTION_SET: Final[str] = "[green]✓ Option set: {key} = {value}[/green]"
    SUCCESS_RESULTS_SAVED: Final[str] = "[green]✓ Results saved to: {path}[/green]"

    # Error messages
    ERROR_MODULE_NOT_FOUND: Final[str] = "[red]✗ Module not found: {module}[/red]"
    ERROR_OPTION_NOT_FOUND: Final[str] = "[red]✗ Option not found: {option}[/red]"
    ERROR_INVALID_VALUE: Final[str] = "[red]✗ Invalid value: {value}[/red]"
    ERROR_SAVE_FAILED: Final[str] = "[red]✗ Failed to save results: {error}[/red]"
    ERROR_AUTH_FAILED: Final[str] = "[red]✗ Authentication failed: {error}[/red]"
    ERROR_INVALID_OPTION_NAME: Final[str] = "[red]✗ Invalid option name: {name}[/red]"
    ERROR_VALUE_TOO_LONG: Final[str] = "[red]✗ Value too long (max {limit} chars)[/red]"

    # Info messages
    INFO_NO_ACTIVE_MODULE: Final[str] = (
        "[yellow]ℹ No active module. Use 'use <module>' first[/yellow]"
    )
    INFO_RUNNING_MODULE: Final[str] = "[cyan]► Running module: {module}...[/cyan]"

    # Help messages
    HELP_USAGE: Final[str] = "[yellow]Usage: {usage}[/yellow]"


class SensitiveKeywords:
    """Keywords that indicate sensitive data."""

    KEYWORDS: Final[tuple[str, ...]] = (
        "PASSWORD",
        "PASSWD",
        "PWD",
        "SECRET",
        "KEY",
        "TOKEN",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "CREDENTIALS",
        "AUTH",
    )


# Global K8s options that apply to all K8s modules
K8S_GLOBAL_OPTIONS: Final[list[str]] = [
    K8sAuthOptions.KUBECONFIG,
    K8sAuthOptions.CONTEXT,
    K8sAuthOptions.API_SERVER,
    K8sAuthOptions.TOKEN,
    K8sAuthOptions.CERT_FILE,
    K8sAuthOptions.KEY_FILE,
    K8sAuthOptions.CA_CERT,
    K8sAuthOptions.VERIFY_SSL,
]
