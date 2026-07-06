"""Rendu HTML compatible Python 3.14 (contournement cache Jinja2/Starlette)."""

from fastapi.responses import HTMLResponse
from starlette.templating import Jinja2Templates


def render_template(
    templates: Jinja2Templates,
    template_name: str,
    context: dict,
) -> HTMLResponse:
    """Rend un template Jinja2 sans passer par TemplateResponse de Starlette."""
    template = templates.env.get_template(template_name)
    return HTMLResponse(template.render(context))
