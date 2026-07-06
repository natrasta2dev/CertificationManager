"""Commande CLI pour lancer l'interface web."""

import click
import uvicorn


@click.command()
@click.option("--host", default="127.0.0.1", help="Adresse IP du serveur")
@click.option("--port", default=8000, type=int, help="Port du serveur")
@click.option("--reload", is_flag=True, help="Rechargement automatique (développement)")
@click.option("--ssl-keyfile", default=None, help="Chemin vers la clé privée TLS")
@click.option("--ssl-certfile", default=None, help="Chemin vers le certificat TLS")
def web(host: str, port: int, reload: bool, ssl_keyfile: str, ssl_certfile: str):
    """Lance l'interface web de CertificationManager."""
    scheme = "https" if ssl_certfile and ssl_keyfile else "http"
    click.echo(f"🚀 Démarrage sur {scheme}://{host}:{port}")
    if ssl_certfile:
        click.echo("🔒 TLS activé")
    click.echo("📝 Ctrl+C pour arrêter")

    from ..web.app import create_app

    app = create_app()

    ssl_kwargs = {}
    if ssl_certfile and ssl_keyfile:
        ssl_kwargs["ssl_keyfile"] = ssl_keyfile
        ssl_kwargs["ssl_certfile"] = ssl_certfile
    elif ssl_certfile or ssl_keyfile:
        raise click.UsageError("--ssl-keyfile et --ssl-certfile doivent être fournis ensemble")

    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=reload,
        log_level="info",
        **ssl_kwargs,
    )
