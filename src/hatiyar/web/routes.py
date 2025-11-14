"""Web dashboard routes for hatiyar."""

from pathlib import Path
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

try:
    from ..core.modules import ModuleManager
except ImportError:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from hatiyar.core.modules import ModuleManager

router = APIRouter(tags=["dashboard"])
base_dir = Path(__file__).parent
templates = Jinja2Templates(directory=str(base_dir / "templates"))
manager = ModuleManager()


@router.get("/", response_class=HTMLResponse, summary="Dashboard home")
async def dashboard(request: Request):
    """Render the main dashboard page."""
    stats = manager.get_stats()
    return templates.TemplateResponse(
        "index.html", {"request": request, "stats": stats}
    )
