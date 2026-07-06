"""Routers FastAPI pour l'interface web."""

from . import (
    alerts,
    audit,
    auth,
    backup,
    automation,
    ca,
    certificates,
    client_certificates,
    csr,
    letsencrypt,
    pages,
    statistics,
)

__all__ = [
    "alerts",
    "audit",
    "auth",
    "backup",
    "automation",
    "ca",
    "certificates",
    "client_certificates",
    "csr",
    "letsencrypt",
    "pages",
    "statistics",
]
