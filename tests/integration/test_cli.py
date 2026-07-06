"""Tests d'intégration CLI (Click CliRunner)."""

import json


class TestCLIIntegration:
    """Tests pour les commandes CLI principales."""

    def test_generate_and_list(self, cli_runner):
        runner, cli = cli_runner
        result = runner.invoke(cli, ["generate", "-n", "cli.example.com", "-d", "90"])
        assert result.exit_code == 0, result.output
        assert "cli.example.com" in result.output

        result = runner.invoke(cli, ["list", "--format", "json"])
        assert result.exit_code == 0
        certs = json.loads(result.output)
        assert len(certs) == 1
        assert certs[0]["common_name"] == "cli.example.com"

    def test_generate_csr(self, cli_runner, tmp_path):
        runner, cli = cli_runner
        out = tmp_path / "test.csr"
        result = runner.invoke(
            cli,
            ["csr", "generate", "-n", "csr.example.com", "-o", str(out)],
        )
        assert result.exit_code == 0, result.output
        assert out.exists()

    def test_status_command(self, cli_runner):
        runner, cli = cli_runner
        runner.invoke(cli, ["generate", "-n", "status.example.com"])
        result = runner.invoke(cli, ["status", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total"] >= 1

    def test_expiring_command(self, cli_runner):
        runner, cli = cli_runner
        runner.invoke(cli, ["generate", "-n", "exp.example.com", "-d", "5"])
        result = runner.invoke(cli, ["expiring", "--days", "30", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) >= 1

    def test_alerts_command(self, cli_runner):
        runner, cli = cli_runner
        runner.invoke(cli, ["generate", "-n", "alertcli.example.com", "-d", "3"])
        result = runner.invoke(cli, ["alerts", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) >= 1

    def test_delete_certificate(self, cli_runner):
        runner, cli = cli_runner
        gen = runner.invoke(cli, ["generate", "-n", "del.example.com"])
        assert gen.exit_code == 0

        list_result = runner.invoke(cli, ["list", "--format", "json"])
        cert_id = json.loads(list_result.output)[0]["id"]

        result = runner.invoke(cli, ["delete", "--yes", "--id", cert_id])
        assert result.exit_code == 0

        list_after = runner.invoke(cli, ["list", "--format", "json"])
        assert "Aucun certificat" in list_after.output

    def test_user_create_and_list(self, cli_runner):
        runner, cli = cli_runner
        result = runner.invoke(
            cli,
            ["user", "create", "-u", "testuser", "-p", "password123", "--role", "viewer"],
        )
        assert result.exit_code == 0, result.output
        assert "testuser" in result.output

        result = runner.invoke(cli, ["user", "list"])
        assert result.exit_code == 0
        assert "testuser" in result.output

    def test_config_show(self, cli_runner):
        runner, cli = cli_runner
        result = runner.invoke(cli, ["config", "show"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "storage_path" in data
