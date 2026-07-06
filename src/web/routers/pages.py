"""Route page d'accueil."""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from starlette.templating import Jinja2Templates

from ..template_utils import render_template

router = APIRouter()
_static_dir = Path(__file__).parent.parent / "static"
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Favicon (SVG)."""
    svg = _static_dir / "favicon.svg"
    if svg.exists():
        return FileResponse(svg, media_type="image/svg+xml")
    return Response(status_code=404)


@router.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Page d'accueil."""
    return render_template(templates, "index.html", {"request": request})
