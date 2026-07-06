"""Version du package."""

from importlib.metadata import PackageNotFoundError, version


def get_version() -> str:
    """Retourne la version installée du package."""
    try:
        return version("certification-manager")
    except PackageNotFoundError:
        return "0.2.0"
