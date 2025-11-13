"""Output utilities for saving results."""

import json
import logging
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)


def save_json_results(
    results: Dict[str, Any],
    output_path: Path | str,
    indent: int = 2,
) -> None:
    """Save results to JSON file."""
    if isinstance(output_path, str):
        output_path = Path(output_path).expanduser().resolve()

    # Validate path is safe
    try:
        # Create parent directories if they don't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write JSON file
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(results, f, indent=indent, default=str, ensure_ascii=False)

        logger.info(f"Results saved to: {output_path}")

    except PermissionError as e:
        logger.error(f"Permission denied writing to {output_path}")
        raise IOError(f"No write permission for {output_path}") from e
    except OSError as e:
        logger.error(f"OS error writing to {output_path}: {e}")
        raise IOError(f"Failed to save results: {e}") from e
    except (TypeError, ValueError) as e:
        logger.error(f"JSON serialization error: {e}")
        raise ValueError(f"Cannot serialize results to JSON: {e}") from e


def validate_output_path(path_str: str, allow_absolute: bool = True) -> Path:
    """Validate and resolve output file path."""
    if not path_str:
        raise ValueError("Output path cannot be empty")

    path = Path(path_str).expanduser().resolve()

    # Check if path is absolute when not allowed
    if not allow_absolute and path.is_absolute():
        raise ValueError(f"Absolute paths not allowed: {path}")

    # Check for directory traversal attempts
    try:
        # Ensure the path doesn't try to escape current directory
        if not allow_absolute:
            cwd = Path.cwd()
            path.relative_to(cwd)
    except ValueError as e:
        raise ValueError(f"Path traversal detected: {path}") from e

    return path


def get_timestamped_output_path(
    module_name: str,
    extension: str = "json",
    output_dir: Path | str | None = None,
) -> Path:
    """Generate timestamped output file path."""
    from datetime import datetime

    if output_dir is None:
        output_dir = Path.cwd() / "results"
    elif isinstance(output_dir, str):
        output_dir = Path(output_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{module_name}_{timestamp}.{extension}"

    return output_dir / filename


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"
