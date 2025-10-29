"""Enhanced module manager with category navigation"""

import importlib
import inspect
import sys
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any
from rich.console import Console

console = Console()
logger = logging.getLogger(__name__)

# Constants
MODULE_CLASS_NAME = "Module"
CVE_PREFIX = "CVE-"
MODULE_PATH_PREFIX = "hatiyar.modules."
DEFAULT_CATEGORY = "misc"
DEFAULT_MODULE_TYPE = "auxiliary"
REGISTRY_FILENAME = "*.yaml"

# YAML Schema - Required fields for module definitions
REQUIRED_MODULE_FIELDS = {"id", "name", "module_path", "category"}
OPTIONAL_MODULE_FIELDS = {
    "description",
    "author",
    "version",
    "cvss_score",
    "disclosure_date",
    "rank",
    "options",
    "references",
    "affected_versions",
}


class ModuleManager:
    """
    Manage and load security modules with YAML-based registry.

    Architecture:
    - YAML-first approach: All modules must be registered in category YAML files
    - Auto-discovery: Automatically finds all .yaml registry files
    - Clean separation: YAML for metadata, Python for implementation
    - Easy extensibility: Just add entries to YAML files
    """

    def __init__(self, verbose: bool = False):
        """
        Initialize the module manager.

        Args:
            verbose: Enable verbose output during initialization
        """
        self.verbose = verbose
        self.modules_path = Path(__file__).parent.parent / "modules"

        # Add hatiyar to Python path if not already there
        hatiyar_root = Path(__file__).parent.parent.parent
        if str(hatiyar_root) not in sys.path:
            sys.path.insert(0, str(hatiyar_root))

        # Internal state
        self._cache: Dict[str, Any] = {}
        self.cve_map: Dict[str, str] = {}
        self.metadata_cache: Dict[str, Dict[str, Any]] = {}
        self.categories: Dict[str, List[Dict[str, Any]]] = {}
        self.namespaces: Dict[str, Dict[str, Any]] = {}
        self._errors: List[str] = []

        # Load all modules from YAML registries
        self._load_all_registries()

    def _log(self, message: str, level: str = "info") -> None:
        """Internal logging with verbose mode support"""
        if self.verbose:
            if level == "error":
                console.print(f"[red]{message}[/red]")
            elif level == "warning":
                console.print(f"[yellow]{message}[/yellow]")
            elif level == "success":
                console.print(f"[green]{message}[/green]")
            else:
                console.print(f"[dim]{message}[/dim]")

    def _discover_registry_files(self) -> List[Path]:
        """
        Auto-discover all YAML registry files in the modules directory.

        Returns:
            List of paths to .yaml registry files
        """
        registry_files = []

        # Find all .yaml files in immediate subdirectories of modules/
        for category_dir in self.modules_path.iterdir():
            if not category_dir.is_dir() or category_dir.name.startswith("__"):
                continue

            # Look for .yaml files in this category directory
            for yaml_file in category_dir.glob("*.yaml"):
                registry_files.append(yaml_file)
                self._log(
                    f"Discovered registry: {yaml_file.relative_to(self.modules_path)}"
                )

            # Also look for .yaml files in nested subdirectories (for cloud/aws/, cloud/azure/, etc.)
            for subdir in category_dir.iterdir():
                if subdir.is_dir() and not subdir.name.startswith("__"):
                    for yaml_file in subdir.glob("*.yaml"):
                        registry_files.append(yaml_file)
                        self._log(
                            f"Discovered registry: {yaml_file.relative_to(self.modules_path)}"
                        )

        return registry_files

    def _validate_module_definition(
        self, mod_def: Dict[str, Any], source_file: str
    ) -> bool:
        """
        Validate that a module definition has all required fields.

        Args:
            mod_def: Module definition dictionary from YAML
            source_file: Source YAML file for error reporting

        Returns:
            True if valid, False otherwise
        """
        missing_fields = REQUIRED_MODULE_FIELDS - set(mod_def.keys())

        if missing_fields:
            self._errors.append(
                f"{source_file}: Missing required fields: {missing_fields}"
            )
            self._log(
                f"Invalid module definition in {source_file}: Missing {missing_fields}",
                "warning",
            )
            return False

        return True

    def _load_all_registries(self) -> None:
        """
        Load all module definitions from discovered YAML registry files.
        This is the main entry point for module loading.
        """
        registry_files = self._discover_registry_files()

        if not registry_files:
            self._log("No registry files found", "warning")
            return

        total_registered = 0

        for registry_file in registry_files:
            count = self._load_registry_file(registry_file)
            total_registered += count

        # Summary
        if self.verbose:
            cve_count = len(self.categories.get("cve", []))
            enum_count = len(self.categories.get("enumeration", []))
            cloud_count = len(self.categories.get("cloud", []))
            platforms_count = len(self.categories.get("platforms", []))
            misc_count = len(self.categories.get("auxiliary", []))

            console.print(
                f"\n[bold green]✓[/bold green] Loaded {total_registered} modules:"
            )
            console.print(f"  • CVE: {cve_count}")
            console.print(f"  • Enumeration: {enum_count}")
            console.print(f"  • Cloud: {cloud_count}")
            console.print(f"  • Platforms: {platforms_count}")
            console.print(f"  • Misc: {misc_count}\n")

        if self._errors and self.verbose:
            console.print(
                f"[yellow]⚠ {len(self._errors)} warnings/errors during loading[/yellow]"
            )

    def _load_registry_file(self, registry_file: Path) -> int:
        """
        Load module definitions from a single YAML registry file.

        Args:
            registry_file: Path to the YAML registry file

        Returns:
            Number of modules successfully registered
        """
        try:
            with open(registry_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data:
                self._log(f"Empty registry file: {registry_file.name}", "warning")
                return 0

            if "modules" not in data:
                self._log(f"No 'modules' key in {registry_file.name}", "warning")
                return 0

            modules = data.get("modules", [])
            registered_count = 0

            for mod_def in modules:
                if self._validate_module_definition(mod_def, registry_file.name):
                    if self._register_module(mod_def, registry_file.name):
                        registered_count += 1

            self._log(
                f"Loaded {registered_count} modules from {registry_file.name}",
                "success",
            )
            return registered_count

        except yaml.YAMLError as e:
            error_msg = f"YAML parsing error in {registry_file.name}: {e}"
            self._errors.append(error_msg)
            self._log(error_msg, "error")
            return 0
        except Exception as e:
            error_msg = f"Failed to load {registry_file.name}: {e}"
            self._errors.append(error_msg)
            self._log(error_msg, "error")
            return 0

    def _register_module(self, mod_def: Dict[str, Any], source_file: str) -> bool:
        """
        Register a single module from YAML definition.

        Args:
            mod_def: Module definition dictionary
            source_file: Source YAML file for error reporting

        Returns:
            True if successfully registered, False otherwise
        """
        try:
            module_id = mod_def.get("id", "")
            module_path = mod_def.get("module_path", "")
            category = mod_def.get("category", DEFAULT_CATEGORY)
            is_namespace = mod_def.get("is_namespace", False)

            # Build metadata
            metadata = {
                "path": module_path,
                "name": mod_def.get("name", "Unknown"),
                "description": mod_def.get("description", ""),
                "author": mod_def.get("author", "Unknown"),
                "version": mod_def.get("version", "1.0"),
                "category": category,
                "subcategory": mod_def.get("subcategory", ""),
                "type": self._infer_type_from_category(category),
                "is_namespace": is_namespace,
                "source": source_file,  # Track which YAML file this came from
            }

            # Add CVE ID if present
            if "cve_id" in mod_def:
                metadata["cve_id"] = mod_def.get("cve_id", "")
                metadata["cve"] = mod_def.get(
                    "cve_id", ""
                )  # Also store as 'cve' for backward compatibility

            # Add CVE-specific fields
            if "cvss_score" in mod_def:
                metadata.update(
                    {
                        "cvss": mod_def.get("cvss_score", 0.0),
                        "rank": mod_def.get("rank", "normal"),
                        "disclosure_date": mod_def.get("disclosure_date", ""),
                    }
                )

            # Add options if present
            if "options" in mod_def:
                metadata["options"] = mod_def.get("options", {})

            # Store metadata (avoid duplicates)
            if module_path in self.metadata_cache:
                self._log(f"Duplicate module path: {module_path} (skipping)", "warning")
                return False

            self.metadata_cache[module_path] = metadata

            # Track namespaces separately
            if is_namespace:
                self.namespaces[module_path] = metadata

            # Add to category index
            module_type = metadata["type"]
            if module_type not in self.categories:
                self.categories[module_type] = []
            self.categories[module_type].append(metadata)

            # Add to CVE map if applicable
            if module_id and module_id.upper().startswith("CVE-"):
                self.cve_map[module_id.upper()] = module_path

            self._log(f"✓ Registered: {module_path} [{category}]", "info")
            return True

        except Exception as e:
            error_msg = f"Failed to register module {mod_def.get('id', 'unknown')}: {e}"
            self._errors.append(error_msg)
            self._log(error_msg, "error")
            return False

    def _infer_type_from_category(self, category: str) -> str:
        """
        Map category name to internal module type.

        Args:
            category: Category from YAML (e.g., 'cve', 'enumeration')

        Returns:
            Internal type identifier
        """
        mapping = {
            "cve": "cve",
            "enumeration": "enumeration",
            "cloud": "cloud",
            "platforms": "platforms",
            "misc": "auxiliary",
            "auxiliary": "auxiliary",
        }
        return mapping.get(category.lower(), "auxiliary")

    def list_categories(self) -> List[str]:
        """
        List all available module categories.

        Returns:
            Sorted list of category names
        """
        return sorted(self.categories.keys())

    def list_modules(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all available modules, optionally filtered by category.

        Args:
            category: Optional category filter (e.g., 'cve', 'enumeration', 'misc', 'cloud')

        Returns:
            List of module metadata dictionaries
        """
        if category:
            # Map user-friendly categories to internal type buckets
            category_aliases = {
                "misc": "auxiliary",
                "aux": "auxiliary",
                "auxiliary": "auxiliary",
                "vuln": "cve",
            }
            canonical_type = category_aliases.get(category.lower(), category.lower())

            # Get modules from the type bucket
            modules = self.categories.get(canonical_type, [])

            # Filter modules to only include those that match the requested category
            # This prevents cross-contamination between categories
            filtered = []
            for module in modules:
                module_category = module.get("category", "").lower()

                # For misc/auxiliary, accept both 'misc' and 'auxiliary' as valid
                if canonical_type == "auxiliary":
                    if module_category in ["misc", "auxiliary"]:
                        filtered.append(module)
                # For cloud category, only show namespaces (top-level platforms)
                elif canonical_type == "cloud" and module_category == "cloud":
                    # Only include namespace modules (aws, azure, gcp) not submodules
                    if module.get("is_namespace", False):
                        filtered.append(module)
                # For other categories, require exact match
                elif module_category == category.lower():
                    filtered.append(module)

            return sorted(filtered, key=lambda x: x.get("name", ""))

        # Return all modules if no category specified
        modules = list(self.metadata_cache.values())
        return sorted(modules, key=lambda x: (x.get("type", ""), x.get("name", "")))

    def list_submodules(
        self, category: str, subcategory: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List submodules for a category (e.g., cve/2021, cloud/aws).

        Args:
            category: Main category (e.g., 'cve', 'cloud')
            subcategory: Optional subcategory filter (e.g., '2021', 'aws')

        Returns:
            List of module metadata dictionaries
        """
        modules = self.categories.get(category, [])

        if subcategory:
            filtered = [
                mod
                for mod in modules
                if subcategory in mod["path"].split(".")
                and not mod.get("is_namespace", False)  # Exclude namespaces
            ]
            return sorted(filtered, key=lambda x: x.get("name", ""))

        return sorted(modules, key=lambda x: x.get("name", ""))

    def get_namespace_modules(self, namespace_path: str) -> List[Dict[str, Any]]:
        """
        Get all modules under a specific namespace.

        Args:
            namespace_path: Namespace path (e.g., 'cloud.aws')

        Returns:
            List of module metadata dictionaries under the namespace
        """
        # Check if it's a valid namespace
        if namespace_path not in self.namespaces:
            return []

        # Get all modules that start with this namespace path
        # but are not namespaces themselves
        filtered = []
        for path, metadata in self.metadata_cache.items():
            if path.startswith(namespace_path + ".") and not metadata.get(
                "is_namespace", False
            ):
                filtered.append(metadata)

        return sorted(filtered, key=lambda x: x.get("name", ""))

    def load_module(self, path: str) -> Optional[Any]:
        """
        Load and instantiate a module by path or CVE ID.

        Args:
            path: Module path (e.g., 'cve.2021.hello') or CVE ID (e.g., 'CVE-2021-44228')

        Returns:
            Instantiated module object or None if loading failed
        """
        # Check if it's a CVE ID
        if path.upper().startswith(CVE_PREFIX):
            cve_id = path.upper()
            cve_path = self.cve_map.get(cve_id)

            if not cve_path:
                console.print(f"[red] No module found for {cve_id}[/red]")
                console.print(f"[yellow] Try: search {cve_id}[/yellow]")
                return None

            path = cve_path

        # Check if module is registered
        if path not in self.metadata_cache:
            console.print(f"[red] Module '{path}' not found in registry[/red]")
            console.print("[yellow]Use 'ls' to see available modules[/yellow]")
            return None

        # Normalize path
        module_path = (
            path
            if path.startswith(MODULE_PATH_PREFIX)
            else f"{MODULE_PATH_PREFIX}{path}"
        )

        try:
            # Reload if cached
            if module_path in self._cache:
                mod = importlib.reload(self._cache[module_path])
            else:
                mod = importlib.import_module(module_path)
                self._cache[module_path] = mod

            # Find and instantiate Module class
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if name == MODULE_CLASS_NAME:
                    return obj()

            console.print(
                f"[red]No {MODULE_CLASS_NAME} class found in {module_path}[/red]"
            )
            console.print("[yellow] Ensure your module has a 'Module' class[/yellow]")
            return None

        except ImportError as e:
            console.print(f"[red]Failed to import module: {e}[/red]")
            console.print(
                f"[yellow] Check that the Python file exists at {module_path.replace('.', '/')}.py[/yellow]"
            )
            return None
        except Exception as e:
            console.print(f"[red]Error loading module: {e}[/red]")
            if self.verbose:
                import traceback

                console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return None

    def search_modules(self, query: str) -> List[Dict[str, Any]]:
        """
        Search modules by keyword in name, description, CVE ID, or category.

        Args:
            query: Search query string

        Returns:
            List of matching module metadata dictionaries
        """
        query_lower = query.lower()
        results = []

        search_fields = ["name", "description", "cve", "category", "author"]

        for metadata in self.metadata_cache.values():
            if any(
                query_lower in str(metadata.get(field, "")).lower()
                for field in search_fields
            ):
                results.append(metadata)

        return sorted(results, key=lambda x: x.get("name", ""))

    def get_module_metadata(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Get cached metadata for a module.

        Args:
            path: Module path or CVE ID

        Returns:
            Module metadata dictionary or None if not found
        """
        # Handle CVE ID
        if path.upper().startswith(CVE_PREFIX):
            cve_id = path.upper()
            path = self.cve_map.get(cve_id, path)

        # Try direct lookup
        if path in self.metadata_cache:
            return self.metadata_cache[path]

        # Try with module prefix removed
        short_path = path.replace(MODULE_PATH_PREFIX, "")
        return self.metadata_cache.get(short_path)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about loaded modules.

        Returns:
            Dictionary with module statistics
        """
        return {
            "total_modules": len(self.metadata_cache),
            "total_cves": len(self.cve_map),
            "categories": {cat: len(mods) for cat, mods in self.categories.items()},
            "errors": len(self._errors),
        }
