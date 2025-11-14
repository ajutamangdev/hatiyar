"""CLI session management for stateful operations."""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from contextlib import contextmanager
import logging

from hatiyar.core.modules import ModuleManager
from hatiyar.core.constants import K8sAuthOptions

logger = logging.getLogger(__name__)


@dataclass
class CLISession:
    """Encapsulates CLI session state for thread-safe and testable operations.

    This class replaces global variables with proper state management,
    enabling multiple concurrent sessions and proper cleanup.

    Attributes:
        manager: Module manager instance for this session
        active_module: Currently loaded module instance
        active_module_name: Name/path of the active module
        module_options: Options for the current module
        global_options: Global options that persist across modules
        current_context: Current navigation context (e.g., 'cloud.aws')
        session_id: Unique identifier for this session
    """

    manager: ModuleManager = field(default_factory=ModuleManager)
    active_module: Optional[Any] = None
    active_module_name: Optional[str] = None
    module_options: Dict[str, Any] = field(default_factory=dict)
    global_options: Dict[str, Any] = field(default_factory=dict)
    current_context: str = ""
    session_id: str = field(default_factory=lambda: f"session_{id(object())}")

    # K8s global options that apply to all K8s modules
    K8S_GLOBAL_OPTIONS: List[str] = field(
        default_factory=lambda: [
            K8sAuthOptions.KUBECONFIG,
            K8sAuthOptions.CONTEXT,
            K8sAuthOptions.API_SERVER,
            K8sAuthOptions.TOKEN,
            K8sAuthOptions.CERT_FILE,
            K8sAuthOptions.KEY_FILE,
            K8sAuthOptions.CA_CERT,
            K8sAuthOptions.VERIFY_SSL,
        ]
    )

    # AWS global options that persist across modules
    AWS_GLOBAL_OPTIONS: List[str] = field(
        default_factory=lambda: [
            "AWS_PROFILE",
            "AWS_REGION",
            "ACCESS_KEY",
            "SECRET_KEY",
            "SESSION_TOKEN",
        ]
    )

    def __post_init__(self):
        logger.debug(f"Created CLI session: {self.session_id}")

    def reset(self) -> None:
        """Reset session state and cleanup current module."""
        if self.active_module and hasattr(self.active_module, "cleanup"):
            try:
                self.active_module.cleanup()
            except Exception as e:
                logger.warning(f"Module cleanup failed: {e}")

        self.active_module = None
        self.active_module_name = None
        self.module_options.clear()
        self.current_context = ""

    def load_module(self, module_name: str, silent: bool = False) -> bool:
        """Load a module into the session."""
        if self.active_module and hasattr(self.active_module, "cleanup"):
            try:
                self.active_module.cleanup()
            except Exception as e:
                logger.warning(f"Cleanup failed: {e}")

        if module_name in self.manager.namespaces:
            self.current_context = module_name
            return True

        expanded_name = self._expand_module_name(module_name)
        module = self.manager.load_module(expanded_name, silent=silent)

        if module:
            self.active_module = module
            self.active_module_name = expanded_name
            self.module_options = getattr(module, "options", {}).copy()
            self._apply_global_options()
            return True

        return False

    def _expand_module_name(self, module_name: str) -> str:
        """Expand short names like 'ec2' to 'cloud.aws.ec2' based on context."""
        if not self.current_context or "." in module_name:
            return module_name

        full_path = f"{self.current_context}.{module_name}"
        if self.manager.load_module(full_path, silent=True):
            return full_path

        for namespace in self.manager.namespaces:
            if namespace.startswith(self.current_context + "."):
                candidate = f"{namespace}.{module_name}"
                if self.manager.load_module(candidate, silent=True):
                    return candidate

        return module_name

    def _apply_global_options(self) -> None:
        """Apply global options to loaded module."""
        if not self.active_module:
            return

        for key, value in self.global_options.items():
            if key in self.module_options:
                self.module_options[key] = value
                if hasattr(self.active_module, "set_option"):
                    self.active_module.set_option(key, value)

    def set_option(self, key: str, value: Any) -> bool:
        """Set option value, handling global vs module-specific options."""
        key = key.upper()

        is_global = key in self.AWS_GLOBAL_OPTIONS or key in self.K8S_GLOBAL_OPTIONS

        if is_global:
            self.global_options[key] = value
            if self.active_module and key in self.module_options:
                if hasattr(self.active_module, "set_option"):
                    self.active_module.set_option(key, value)
                self.module_options[key] = value
            return True

        if not self.active_module:
            return False

        if hasattr(self.active_module, "set_option"):
            if self.active_module.set_option(key, value):
                self.module_options[key] = value
                return True
            return False
        else:
            if key in self.module_options:
                self.module_options[key] = value
                return True
            return False

    def execute_module(self) -> Optional[Dict[str, Any]]:
        """Execute the loaded module."""
        if not self.active_module:
            raise RuntimeError("No module loaded")

        if not hasattr(self.active_module, "run"):
            raise RuntimeError("Module missing run method")

        if hasattr(self.active_module, "options"):
            for key, value in self.module_options.items():
                if hasattr(self.active_module, "set_option"):
                    self.active_module.set_option(key, value)
                else:
                    self.active_module.options[key] = value

        try:
            return self.active_module.run()
        except Exception as e:
            logger.error(f"Module execution failed: {e}")
            raise

    def navigate_to(self, path: str) -> bool:
        """Navigate to context path like 'cloud.aws' or '..' or ''."""
        if path == "":
            self.current_context = ""
            return True

        if path == "..":
            if not self.current_context:
                return False

            if "." in self.current_context:
                self.current_context = self.current_context.rsplit(".", 1)[0]
            else:
                self.current_context = ""
            return True

        if self.current_context and "." not in path:
            full_path = f"{self.current_context}.{path}"
            if full_path in self.manager.namespaces:
                self.current_context = full_path
                return True

        if path in self.manager.namespaces:
            self.current_context = path
            return True

        categories = ["cve", "cloud", "enumeration", "platforms", "misc"]
        if path in categories:
            self.current_context = path
            return True

        return False

    def reload_modules(self) -> int:
        """Reload modules from YAML registry."""
        if self.active_module:
            self.reset()

        self.manager = ModuleManager()
        stats = self.manager.get_stats()
        return stats.get("total_modules", 0)

    def get_context_modules(self) -> List[Dict[str, Any]]:
        """Get modules in current context."""
        if not self.current_context:
            return []

        if self.current_context in self.manager.namespaces:
            return self.manager.get_namespace_modules(self.current_context)
        else:
            return self.manager.list_modules(self.current_context)

    def search_modules(self, query: str) -> List[Dict[str, Any]]:
        """Search modules by keyword."""
        return self.manager.search_modules(query)

    def get_module_info(
        self, module_name: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Get module info."""
        target = module_name or self.active_module_name
        if not target:
            return None

        return self.manager.get_module_metadata(target)

    @contextmanager
    def module_context(self, module_name: str):
        """Temporarily load a module, restore state after."""
        old_module = self.active_module
        old_module_name = self.active_module_name
        old_options = self.module_options.copy()

        try:
            if self.load_module(module_name):
                yield self.active_module
            else:
                yield None
        finally:
            if self.active_module and hasattr(self.active_module, "cleanup"):
                try:
                    self.active_module.cleanup()
                except Exception as e:
                    logger.warning(f"Context cleanup failed: {e}")

            self.active_module = old_module
            self.active_module_name = old_module_name
            self.module_options = old_options

    def cleanup(self) -> None:
        """Clean up session resources."""
        if self.active_module and hasattr(self.active_module, "cleanup"):
            try:
                self.active_module.cleanup()
            except Exception as e:
                logger.warning(f"Session cleanup failed: {e}")

        self.active_module = None
        self.active_module_name = None
        self.module_options.clear()
        self.global_options.clear()
        self.current_context = ""

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup()
