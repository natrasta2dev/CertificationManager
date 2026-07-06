"""Route page d'accueil."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from starlette.templating import Jinja2Templates
from pathlib import Path

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Page d'accueil."""
    return templates.TemplateResponse("index.html", {"request": request})
