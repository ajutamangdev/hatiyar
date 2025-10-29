"""Base classes for all modules"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from enum import Enum
from rich.console import Console

console = Console()


class ModuleType(Enum):
    """Enumeration of supported module types"""

    CVE = "cve"
    ENUMERATION = "enumeration"
    CLOUD = "cloud"
    AUXILIARY = "auxiliary"


class ModuleBase(ABC):
    """
    Abstract base class for all hatiyar modules.

    All modules must inherit from this class and implement the run() method.
    """

    # Module metadata (override in subclasses)
    NAME: str = "base_module"
    DESCRIPTION: str = ""
    AUTHOR: str = "Unknown"
    VERSION: str = "1.0"
    MODULE_TYPE: ModuleType = ModuleType.AUXILIARY

    # Module classification
    CATEGORY: str = "misc"
    PLATFORM: List[str] = ["all"]

    # Module configuration
    OPTIONS: Dict[str, Any] = {}
    REQUIRED_OPTIONS: List[str] = []

    def __init__(self):
        self.options = self.OPTIONS.copy()
        self.results: Dict[str, Any] = {}

    def set_option(self, key: str, value: Any) -> bool:
        """
        Set a module option with automatic type conversion.

        Args:
            key: Option name (case-insensitive)
            value: Option value

        Returns:
            True if option was set successfully, False otherwise
        """
        key_upper = key.upper()

        if key_upper not in self.options:
            return False

        try:
            converted_value = self._convert_option_value(key_upper, value)
            self.options[key_upper] = converted_value
            return True
        except (ValueError, AttributeError, TypeError) as e:
            console.print(f"[red]Invalid value type for {key}: {e}[/red]")
            return False

    def _convert_option_value(self, key: str, value: Any) -> Any:
        """Convert option value to the appropriate type"""
        current_value = self.options[key]

        if isinstance(current_value, bool):
            return str(value).lower() in ["true", "1", "yes", "y"]
        elif isinstance(current_value, int):
            return int(value)
        elif isinstance(current_value, float):
            return float(value)
        else:
            return value

    def get_option(self, key: str) -> Optional[Any]:
        """Get the value of a module option"""
        return self.options.get(key.upper())

    def validate_options(self) -> bool:
        """
        Validate that all required options are set.

        Returns:
            True if all required options are valid, False otherwise
        """
        for opt in self.REQUIRED_OPTIONS:
            value = self.options.get(opt)
            if not self._is_valid_option_value(value):
                console.print(f"[red]Required option not set: {opt}[/red]")
                return False
        return True

    def _is_valid_option_value(self, value: Any) -> bool:
        """Check if an option value is valid (not None or empty string)"""
        if value is None:
            return False
        if isinstance(value, str) and not value.strip():
            return False
        return True

    @abstractmethod
    def run(self) -> Dict[str, Any]:
        """
        Execute the module.

        Returns:
            Dictionary containing execution results with at least a 'success' key
        """
        pass

    def cleanup(self) -> None:
        """Cleanup resources after module execution (override if needed)"""
        pass


class CVEModule(ModuleBase):
    """
    Base class for CVE exploit modules.

    Provides a structured workflow: check vulnerability -> exploit
    """

    MODULE_TYPE = ModuleType.CVE

    # CVE-specific metadata (all optional)
    CVE: str = ""
    CVSS_SCORE: Optional[float] = None
    CVSS_VECTOR: Optional[str] = None
    DISCLOSURE_DATE: Optional[str] = None
    AFFECTED_VERSIONS: List[str] = []
    PATCHED_VERSIONS: List[str] = []
    RANK: Optional[str] = None  # excellent, great, good, normal, low
    REFERENCES: List[str] = []
    TAGS: List[str] = []
    CWE: Optional[str] = None

    @abstractmethod
    def check(self) -> bool:
        """
        Check if the target is vulnerable.

        Returns:
            True if target appears vulnerable, False otherwise
        """
        pass

    @abstractmethod
    def exploit(self) -> Dict[str, Any]:
        """
        Exploit the vulnerability.

        Returns:
            Dictionary containing exploitation results
        """
        pass

    def run(self) -> Dict[str, Any]:
        """Execute the CVE module: check then exploit"""
        if not self.validate_options():
            return {"success": False, "error": "Invalid options"}

        console.print(f"[cyan]Targeting {self.options.get('RHOST', 'N/A')}...[/cyan]\n")

        console.print("[bold]Exploitation[/bold]")
        return self.exploit()


class EnumerationModule(ModuleBase):
    """Base class for enumeration and reconnaissance modules"""

    MODULE_TYPE = ModuleType.ENUMERATION

    TARGET_TYPE: str = "network"

    @abstractmethod
    def enumerate(self) -> Dict[str, Any]:
        """
        Perform enumeration.

        Returns:
            Dictionary containing enumeration results
        """
        pass

    def run(self) -> Dict[str, Any]:
        """Execute the enumeration module"""
        if not self.validate_options():
            return {"success": False, "error": "Invalid options"}

        return self.enumerate()


class CloudModule(ModuleBase):
    """Base class for cloud security modules"""

    MODULE_TYPE = ModuleType.CLOUD

    CLOUD_PROVIDER: str = ""  # aws, azure, gcp
    REQUIRES_AUTH: bool = True

    @abstractmethod
    def enumerate_resources(self) -> List[Dict[str, Any]]:
        """
        Enumerate cloud resources.

        Returns:
            List of discovered resources
        """
        pass

    @abstractmethod
    def check_misconfigurations(self) -> List[Dict[str, Any]]:
        """
        Check for security misconfigurations.

        Returns:
            List of identified misconfigurations
        """
        pass

    def run(self) -> Dict[str, Any]:
        """Execute the cloud module: enumerate and check"""
        if not self.validate_options():
            return {"success": False, "error": "Invalid options"}

        resources = self.enumerate_resources()
        misconfigs = self.check_misconfigurations()

        return {
            "success": True,
            "provider": self.CLOUD_PROVIDER,
            "resources": resources,
            "misconfigurations": misconfigs,
            "total_resources": len(resources),
            "total_issues": len(misconfigs),
        }
