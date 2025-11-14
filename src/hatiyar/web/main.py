import sys
from pathlib import Path

# Ensure src is in path
src_path = Path(__file__).resolve().parents[2]
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from hatiyar.main import app  # noqa: E402
from hatiyar.web.config import config  # noqa: E402

# For backwards compatibility and uvicorn support
__all__ = ["app", "config"]

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.HOST, port=config.PORT, reload=config.RELOAD)
