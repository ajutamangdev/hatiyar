import sys
from pathlib import Path
from pysecfw.cli.shell import start_shell

# Add src directory to path to allow absolute imports
src_path = Path(__file__).parent.parent
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))


def main():
    start_shell()


if __name__ == "__main__":
    main()
