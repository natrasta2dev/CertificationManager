"""Tests formatage sortie CLI."""

import json

from src.cli.output import emit_data, OUTPUT_FORMATS


def test_output_formats_constant():
    assert "json" in OUTPUT_FORMATS
    assert "yaml" in OUTPUT_FORMATS
    assert "csv" in OUTPUT_FORMATS
    assert "table" in OUTPUT_FORMATS


def test_emit_json(capsys):
    emit_data({"ok": True}, "json")
    out = capsys.readouterr().out
    assert json.loads(out)["ok"] is True


def test_emit_csv(capsys):
    rows = [{"id": "a", "name": "test"}]
    emit_data(rows, "csv", csv_rows=rows)
    out = capsys.readouterr().out
    assert "test" in out
