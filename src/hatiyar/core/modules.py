"""Module manager with YAML registry"""

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

MODULE_CLASS_NAME = "Module"
CVE_PREFIX = "CVE-"
MODULE_PATH_PREFIX = "hatiyar.modules."
DEFAULT_CATEGORY = "misc"
DEFAULT_MODULE_TYPE = "auxiliary"
REGISTRY_FILENAME = "*.yaml"

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
    """Manage security modules with YAML registry"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.modules_path = Path(__file__).parent.parent / "modules"

        hatiyar_root = Path(__file__).parent.parent.parent
        if str(hatiyar_root) not in sys.path:
            sys.path.insert(0, str(hatiyar_root))

        self._cache: Dict[str, Any] = {}
        self.cve_map: Dict[str, str] = {}
        self.metadata_cache: Dict[str, Dict[str, Any]] = {}
        self.categories: Dict[str, List[Dict[str, Any]]] = {}
        self.namespaces: Dict[str, Dict[str, Any]] = {}
        self._errors: List[str] = []

        self._load_all_registries()

    def _log(self, message: str, level: str = "info") -> None:
        if self.verbose:
            if level == "error":
                console.print(f"[red]✗ {message}[/red]")
            elif level == "warning":
                console.print(f"[yellow]⚠ {message}[/yellow]")
            elif level == "success":
                console.print(f"[green]✓ {message}[/green]")
            else:
                console.print(f"[dim]• {message}[/dim]")

    def _discover_registry_files(self) -> List[Path]:
        """Auto-discover all YAML registry files"""
        registry_files = []

        for category_dir in self.modules_path.iterdir():
            if not category_dir.is_dir() or category_dir.name.startswith("__"):
                continue

            for yaml_file in category_dir.glob("*.yaml"):
                registry_files.append(yaml_file)
                self._log(f"Found {yaml_file.relative_to(self.modules_path)}")

            for subdir in category_dir.iterdir():
                if subdir.is_dir() and not subdir.name.startswith("__"):
                    for yaml_file in subdir.glob("*.yaml"):
                        registry_files.append(yaml_file)
                        self._log(f"Found {yaml_file.relative_to(self.modules_path)}")

        return registry_files

    def _validate_module_definition(
        self, mod_def: Dict[str, Any], source_file: str
    ) -> bool:
        """Validate module definition"""
        missing_fields = REQUIRED_MODULE_FIELDS - set(mod_def.keys())

        if missing_fields:
            self._errors.append(f"{source_file}: Missing {missing_fields}")
            self._log(
                f"{source_file}: Missing {missing_fields}",
                "warning",
            )
            return False

        return True

    def _load_all_registries(self) -> None:
        """Load all module definitions from YAML registries"""
        registry_files = self._discover_registry_files()

        if not registry_files:
            self._log("No registries found", "warning")
            return

        total_registered = 0

        for registry_file in registry_files:
            count = self._load_registry_file(registry_file)
            total_registered += count

        if self.verbose:
            cve_count = len(self.categories.get("cve", []))
            enum_count = len(self.categories.get("enumeration", []))
            cloud_count = len(self.categories.get("cloud", []))
            platforms_count = len(self.categories.get("platforms", []))
            misc_count = len(self.categories.get("auxiliary", []))

            console.print(
                f"\n[bold green]✓ {total_registered} modules loaded[/bold green]"
            )
            console.print(
                f"  CVE: [cyan]{cve_count}[/cyan] | Enum: [cyan]{enum_count}[/cyan] | Cloud: [cyan]{cloud_count}[/cyan] | Platforms: [cyan]{platforms_count}[/cyan] | Misc: [cyan]{misc_count}[/cyan]\n"
            )

        if self._errors and self.verbose:
            console.print(f"[yellow]{len(self._errors)} warnings[/yellow]")

    def _load_registry_file(self, registry_file: Path) -> int:
        """Load module definitions from YAML registry"""
        try:
            with open(registry_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data:
                self._log(f"Empty: {registry_file.name}", "warning")
                return 0

            if "modules" not in data:
                self._log(f"No modules key: {registry_file.name}", "warning")
                return 0

            modules = data.get("modules", [])
            registered_count = 0

            for mod_def in modules:
                if self._validate_module_definition(mod_def, registry_file.name):
                    if self._register_module(mod_def, registry_file.name):
                        registered_count += 1

            self._log(f"{registered_count} from {registry_file.name}", "success")
            return registered_count

        except yaml.YAMLError as e:
            error_msg = f"YAML error {registry_file.name}: {e}"
            self._errors.append(error_msg)
            self._log(error_msg, "error")
            return 0
        except Exception as e:
            error_msg = f"Load failed {registry_file.name}: {e}"
            self._errors.append(error_msg)
            self._log(error_msg, "error")
            return 0

    def _register_module(self, mod_def: Dict[str, Any], source_file: str) -> bool:
        """Register module from YAML definition"""
        try:
            module_id = mod_def.get("id", "")
            module_path = mod_def.get("module_path", "")
            category = mod_def.get("category", DEFAULT_CATEGORY)
            is_namespace = mod_def.get("is_namespace", False)

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
                "source": source_file,
            }

            if "cve_id" in mod_def:
                metadata["cve_id"] = mod_def.get("cve_id", "")
                metadata["cve"] = mod_def.get("cve_id", "")

            if "cvss_score" in mod_def:
                metadata.update(
                    {
                        "cvss": mod_def.get("cvss_score", 0.0),
                        "rank": mod_def.get("rank", "normal"),
                        "disclosure_date": mod_def.get("disclosure_date", ""),
                    }
                )

            if "options" in mod_def:
                metadata["options"] = mod_def.get("options", {})

            if module_path in self.metadata_cache:
                self._log(f"Duplicate: {module_path}", "warning")
                return False

            self.metadata_cache[module_path] = metadata

            if is_namespace:
                self.namespaces[module_path] = metadata

            module_type = metadata["type"]
            if module_type not in self.categories:
                self.categories[module_type] = []
            self.categories[module_type].append(metadata)

            if module_id and module_id.upper().startswith("CVE-"):
                self.cve_map[module_id.upper()] = module_path

            self._log(f"{module_path}", "info")
            return True

        except Exception as e:
            error_msg = f"Register failed {mod_def.get('id', 'unknown')}: {e}"
            self._errors.append(error_msg)
            self._log(error_msg, "error")
            return False

    def _infer_type_from_category(self, category: str) -> str:
        """Map category to module type"""
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
        """List all module categories"""
        return sorted(self.categories.keys())

    def list_modules(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """List modules, optionally filtered by category"""
        if category:
            category_aliases = {
                "misc": "auxiliary",
                "aux": "auxiliary",
                "auxiliary": "auxiliary",
                "vuln": "cve",
            }
            canonical_type = category_aliases.get(category.lower(), category.lower())

            modules = self.categories.get(canonical_type, [])

            filtered = []
            for module in modules:
                module_category = module.get("category", "").lower()
                module_path = module.get("path", "")

                if canonical_type == "auxiliary":
                    if module_category in ["misc", "auxiliary"]:
                        filtered.append(module)
                elif canonical_type == "cloud" and module_category == "cloud":
                    if module.get("is_namespace", False):
                        filtered.append(module)
                elif module_category == category.lower():
                    # Only show top-level items for this category
                    # Filter out nested modules (e.g., show platforms.k8s but not platforms.k8s.enum)
                    path_parts = module_path.split(".")

                    # For top-level category listing, only show:
                    # 1. Namespaces at category.xxx level (e.g., platforms.k8s)
                    # 2. Direct modules at category.xxx level (e.g., platforms.docker_scan)
                    # But NOT nested modules like platforms.k8s.enum (3+ parts)
                    if len(path_parts) <= 2:
                        filtered.append(module)
                    elif module.get("is_namespace", False):
                        # Always show namespaces (e.g., cloud.aws.ec2 if it's a namespace)
                        filtered.append(module)

            return sorted(filtered, key=lambda x: x.get("name", ""))

        modules = list(self.metadata_cache.values())
        return sorted(modules, key=lambda x: (x.get("type", ""), x.get("name", "")))

    def list_submodules(
        self, category: str, subcategory: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List submodules for category"""
        modules = self.categories.get(category, [])

        if subcategory:
            filtered = [
                mod
                for mod in modules
                if subcategory in mod["path"].split(".")
                and not mod.get("is_namespace", False)
            ]
            return sorted(filtered, key=lambda x: x.get("name", ""))

        return sorted(modules, key=lambda x: x.get("name", ""))

    def get_namespace_modules(self, namespace_path: str) -> List[Dict[str, Any]]:
        """Get all modules under namespace"""
        if namespace_path not in self.namespaces:
            return []

        filtered = []
        for path, metadata in self.metadata_cache.items():
            if path.startswith(namespace_path + ".") and not metadata.get(
                "is_namespace", False
            ):
                filtered.append(metadata)

        return sorted(filtered, key=lambda x: x.get("name", ""))

    def load_module(self, path: str, silent: bool = False) -> Optional[Any]:
        """Load and instantiate module by path or CVE ID"""
        if path.upper().startswith(CVE_PREFIX):
            cve_id = path.upper()
            cve_path = self.cve_map.get(cve_id)

            if not cve_path:
                if not silent:
                    console.print(f"[red]✗ {cve_id} not found[/red]")
                    console.print(f"[dim]Try: [cyan]search {cve_id}[/cyan][/dim]")
                return None

            path = cve_path

        if path not in self.metadata_cache:
            if not silent:
                console.print(f"[red]✗ Module not found: [/red][yellow]{path}[/yellow]")
                console.print("[dim]Use [cyan]ls[/cyan] to see modules[/dim]")
            return None

        module_path = (
            path
            if path.startswith(MODULE_PATH_PREFIX)
            else f"{MODULE_PATH_PREFIX}{path}"
        )

        try:
            if module_path in self._cache:
                mod = importlib.reload(self._cache[module_path])
            else:
                mod = importlib.import_module(module_path)
                self._cache[module_path] = mod

            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if name == MODULE_CLASS_NAME:
                    return obj()

            if not silent:
                console.print(f"[red]✗ No Module class in {module_path}[/red]")
            return None

        except ImportError as e:
            if not silent:
                console.print(f"[red]✗ Import failed:[/red] {e}")
                console.print(
                    f"[dim]Check: [cyan]{module_path.replace('.', '/')}.py[/cyan][/dim]"
                )
            return None
        except Exception as e:
            console.print(f"[red]✗ Load error:[/red] {e}")
            if self.verbose:
                import traceback

                console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return None

    def search_modules(self, query: str) -> List[Dict[str, Any]]:
        """Search modules by keyword"""
        query_lower = query.lower()
        results = []

        search_fields = ["path", "name", "description", "cve", "category", "author"]

        for metadata in self.metadata_cache.values():
            if any(
                query_lower in str(metadata.get(field, "")).lower()
                for field in search_fields
            ):
                results.append(metadata)

        return sorted(results, key=lambda x: x.get("name", ""))

    def get_module_metadata(self, path: str) -> Optional[Dict[str, Any]]:
        """Get module metadata"""
        if path.upper().startswith(CVE_PREFIX):
            cve_id = path.upper()
            path = self.cve_map.get(cve_id, path)

        if path in self.metadata_cache:
            return self.metadata_cache[path]

        short_path = path.replace(MODULE_PATH_PREFIX, "")
        return self.metadata_cache.get(short_path)

    def get_stats(self) -> Dict[str, Any]:
        """Get module statistics"""
        return {
            "total_modules": len(self.metadata_cache),
            "total_cves": len(self.cve_map),
            "categories": {cat: len(mods) for cat, mods in self.categories.items()},
            "errors": len(self._errors),
        }
