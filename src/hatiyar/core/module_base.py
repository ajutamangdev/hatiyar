"""Base classes for modules"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from enum import Enum
from rich.console import Console

console = Console()


class ModuleType(Enum):
    """Module types"""

    CVE = "cve"
    ENUMERATION = "enumeration"
    CLOUD = "cloud"
    AUXILIARY = "auxiliary"


class ModuleBase(ABC):
    """Base class for all modules"""

    NAME: str = "base_module"
    DESCRIPTION: str = ""
    AUTHOR: str = "Unknown"
    VERSION: str = "1.0"
    MODULE_TYPE: ModuleType = ModuleType.AUXILIARY

    CATEGORY: str = "misc"
    PLATFORM: List[str] = ["all"]

    OPTIONS: Dict[str, Any] = {}
    REQUIRED_OPTIONS: List[str] = []

    def __init__(self) -> None:
        self.options = self.OPTIONS.copy()
        self.results: Dict[str, Any] = {}

    def set_option(self, key: str, value: Any) -> bool:
        """Set module option with type conversion (case-insensitive)

        Returns:
            bool: True if option was set successfully, False otherwise
        """
        key_upper = key.upper()
        key_lower = key.lower()

        # Try uppercase first (for global options like KUBECONFIG, AWS_PROFILE)
        if key_upper in self.options:
            target_key = key_upper
        # Then try lowercase (for module-specific options like namespace)
        elif key_lower in self.options:
            target_key = key_lower
        # Try original case as fallback
        elif key in self.options:
            target_key = key
        else:
            return False

        try:
            converted_value = self._convert_option_value(target_key, value)
            self.options[target_key] = converted_value
            # Store the actual key that was used for reference
            self._last_set_key = target_key
            return True
        except (ValueError, AttributeError, TypeError) as e:
            console.print(f"[red]✗ Invalid value for {key}: {e}[/red]")
            return False

    def get_last_set_key(self) -> Optional[str]:
        """Get the actual key name that was last set (for proper display)"""
        return getattr(self, "_last_set_key", None)

    def _convert_option_value(self, key: str, value: Any) -> Any:
        """Convert option value to type"""
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
        """Get module option value"""
        return self.options.get(key.upper())

    def validate_options(self) -> bool:
        """Validate required options are set"""
        for opt in self.REQUIRED_OPTIONS:
            value = self.options.get(opt)
            if not self._is_valid_option_value(value):
                console.print(f"[red]✗ Required: {opt}[/red]")
                return False
        return True

    def _is_valid_option_value(self, value: Any) -> bool:
        """Check if option value is valid"""
        if value is None:
            return False
        if isinstance(value, str) and not value.strip():
            return False
        return True

    @abstractmethod
    def run(self) -> Dict[str, Any]:
        """Execute the module"""
        pass

    def cleanup(self) -> None:
        """Cleanup resources after execution"""
        pass


class CVEModule(ModuleBase):
    """Base class for CVE exploit modules"""

    MODULE_TYPE = ModuleType.CVE

    CVE: str = ""
    CVSS_SCORE: Optional[float] = None
    CVSS_VECTOR: Optional[str] = None
    DISCLOSURE_DATE: Optional[str] = None
    AFFECTED_VERSIONS: List[str] = []
    PATCHED_VERSIONS: List[str] = []
    RANK: Optional[str] = None
    REFERENCES: List[str] = []
    TAGS: List[str] = []
    CWE: Optional[str] = None

    @abstractmethod
    def check(self) -> bool:
        """Check if target is vulnerable"""
        pass

    @abstractmethod
    def exploit(self) -> Dict[str, Any]:
        """Exploit the vulnerability"""
        pass

    def run(self) -> Dict[str, Any]:
        """Execute CVE module"""
        if not self.validate_options():
            return {"success": False, "error": "Invalid options"}

        target = self.options.get("RHOST", "N/A")
        console.print(f"[bold cyan]→ Target:[/bold cyan] {target}\n")

        console.print("[bold]Exploiting...[/bold]")
        return self.exploit()


class EnumerationModule(ModuleBase):
    """Base class for enumeration modules"""

    MODULE_TYPE = ModuleType.ENUMERATION
    TARGET_TYPE: str = "network"

    @abstractmethod
    def enumerate(self) -> Dict[str, Any]:
        """Perform enumeration"""
        pass

    def run(self) -> Dict[str, Any]:
        """Execute enumeration"""
        if not self.validate_options():
            return {"success": False, "error": "Invalid options"}

        return self.enumerate()


class CloudModule(ModuleBase):
    """Base class for cloud security modules"""

    MODULE_TYPE = ModuleType.CLOUD
    CLOUD_PROVIDER: str = ""
    REQUIRES_AUTH: bool = True

    @abstractmethod
    def enumerate_resources(self) -> List[Dict[str, Any]]:
        """Enumerate cloud resources"""
        pass

    @abstractmethod
    def check_misconfigurations(self) -> List[Dict[str, Any]]:
        """Check for misconfigurations"""
        pass

    def run(self) -> Dict[str, Any]:
        """Execute cloud module"""
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
