"""Commande CLI pour lancer l'interface web."""

import click
import uvicorn
from pathlib import Path


@click.command()
@click.option(
    "--host",
    default="127.0.0.1",
    help="Adresse IP du serveur"
)
@click.option(
    "--port",
    default=8000,
    type=int,
    help="Port du serveur"
)
@click.option(
    "--reload",
    is_flag=True,
    help="Activer le rechargement automatique (développement)"
)
def web(host: str, port: int, reload: bool):
    """Lance l'interface web de CertificationManager."""
    click.echo(f"🚀 Démarrage de l'interface web sur http://{host}:{port}")
    click.echo("📝 Appuyez sur Ctrl+C pour arrêter le serveur")
    
    from ..web.app import create_app
    
    app = create_app()
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )

