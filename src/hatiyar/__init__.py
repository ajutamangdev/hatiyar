import importlib.metadata
import tomllib
from pathlib import Path


def _get_version() -> str:
    """
    Get version dynamically from multiple sources.

    Priority:
    1. Installed package metadata (if installed)
    2. pyproject.toml (for development)
    3. Fallback to "unknown"
    """
    try:
        return importlib.metadata.version("hatiyar")
    except importlib.metadata.PackageNotFoundError:
        pass

    try:
        project_root = Path(__file__).parent.parent.parent
        pyproject_path = project_root / "pyproject.toml"

        if pyproject_path.exists():
            with open(pyproject_path, "rb") as f:
                pyproject_data = tomllib.load(f)
                return pyproject_data.get("project", {}).get("version", "unknown")
    except Exception:
        pass

    return "unknown"


__version__ = _get_version()


__all__ = ["__version__"]
