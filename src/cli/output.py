"""Formatage de sortie CLI (table, json, yaml, csv)."""

import csv
import io
import json
from typing import Any, Callable, Dict, List, Optional, Sequence

import click

OUTPUT_FORMATS = ("table", "json", "yaml", "csv")


def emit_data(
    data: Any,
    fmt: str,
    table_renderer: Optional[Callable[[], None]] = None,
    csv_rows: Optional[Sequence[Dict[str, Any]]] = None,
) -> None:
    """Affiche des données selon le format demandé."""
    fmt = fmt.lower()
    if fmt == "json":
        click.echo(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    elif fmt == "yaml":
        try:
            import yaml
        except ImportError:
            click.echo(json.dumps(data, indent=2, ensure_ascii=False, default=str))
            click.echo(
                "# PyYAML non installé — sortie JSON utilisée",
                err=True,
            )
            return
        click.echo(yaml.dump(data, allow_unicode=True, default_flow_style=False))
    elif fmt == "csv":
        if not csv_rows:
            if isinstance(data, list) and data and isinstance(data[0], dict):
                csv_rows = data
            else:
                click.echo(json.dumps(data, default=str))
                return
        if not csv_rows:
            click.echo("")
            return
        output = io.StringIO()
        fieldnames = list(csv_rows[0].keys())
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)
        click.echo(output.getvalue().rstrip())
    elif fmt == "table":
        if table_renderer:
            table_renderer()
        elif isinstance(data, list):
            _default_table(data)
        else:
            click.echo(json.dumps(data, indent=2, default=str))
    else:
        click.echo(json.dumps(data, indent=2, default=str))


def _default_table(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        click.echo("(vide)")
        return
    keys = list(rows[0].keys())
    widths = {k: max(len(k), max(len(str(r.get(k, ""))) for r in rows)) for k in keys}
    header = " ".join(k.ljust(widths[k]) for k in keys)
    click.echo(header)
    click.echo("-" * len(header))
    for row in rows:
        click.echo(" ".join(str(row.get(k, "")).ljust(widths[k]) for k in keys))


def certificates_table(certs: List[Dict[str, Any]]) -> None:
    click.echo(f"\n{'ID':<36} {'CN':<30} {'Expire le':<12} {'Statut':<10}")
    click.echo("-" * 90)
    for cert in certs:
        cert_id = str(cert.get("id", "N/A"))[:36]
        cn = str(cert.get("common_name", "N/A"))[:30]
        expires = cert.get("not_valid_after", "N/A")
        if isinstance(expires, str) and "T" in expires:
            expires = expires.split("T")[0]
        status = "Valide" if not cert.get("is_expired", False) else "Expire"
        days = cert.get("days_until_expiry", 0)
        if days and days > 0 and days <= 30:
            status = f"{days}j"
        click.echo(f"{cert_id:<36} {cn:<30} {str(expires):<12} {status:<10}")


def alerts_table(alerts: List[Dict[str, Any]]) -> None:
    click.echo(f"\n{'Niveau':<10} {'CN':<30} {'Jours':<8} {'Message'}")
    click.echo("-" * 80)
    for a in alerts:
        click.echo(
            f"{a.get('level', ''):<10} "
            f"{str(a.get('common_name', ''))[:30]:<30} "
            f"{str(a.get('days_until_expiry', '')):<8} "
            f"{a.get('message', '')}"
        )
