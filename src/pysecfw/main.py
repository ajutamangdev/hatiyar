import sys
from pathlib import Path

src_path = Path(__file__).parent.parent
sys.path.insert(0, str(src_path))

from pysecfw.cli.shell import start_shell  # noqa: E402


def main() -> None:
    """Start the pysecfw interactive shell"""
    start_shell()


if __name__ == "__main__":
    main()
