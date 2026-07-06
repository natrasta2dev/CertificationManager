"""Utilitaires pour les réponses d'export de certificats."""

import base64
from typing import Any, Dict


def encode_file_payload(
    file_data: bytes,
    filename: str,
    mime_type: str,
    format_name: str,
) -> Dict[str, Any]:
    """Encode un fichier en base64 avec les champs unifiés file_data et content."""
    encoded = base64.b64encode(file_data).decode("utf-8")
    return {
        "format": format_name,
        "filename": filename,
        "file_data": encoded,
        "content": encoded,
        "mime_type": mime_type,
    }


def encode_named_file(file_data: bytes, filename: str, mime_type: str) -> Dict[str, str]:
    """Encode un fichier nommé (certificat ou clé) pour les exports multi-fichiers."""
    encoded = base64.b64encode(file_data).decode("utf-8")
    return {
        "filename": filename,
        "content": encoded,
        "file_data": encoded,
        "mime_type": mime_type,
    }
