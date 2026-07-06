"""Tests pour le module import_export."""

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from src.core.certificate import CertificateManager
from src.core.import_export import CertificateExporter, CertificateImporter


class TestCertificateImporter:
    """Tests pour CertificateImporter."""

    def test_import_from_pem_with_key(self, temp_storage, tmp_path):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("import.example.com")
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

        importer = CertificateImporter(temp_storage)
        cert_id = importer.import_from_pem(str(cert_path), key_path=str(key_path))
        loaded, loaded_meta = temp_storage.load_certificate(cert_id)
        assert loaded_meta["common_name"] == "import.example.com"
        assert temp_storage.load_private_key(cert_id) is not None

    def test_import_from_pem_cert_only(self, temp_storage, tmp_path):
        manager = CertificateManager()
        cert, _, _ = manager.generate_self_signed_cert("certonly.example.com")
        cert_path = tmp_path / "cert.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        cert_id = CertificateImporter(temp_storage).import_from_pem(str(cert_path))
        loaded, _ = temp_storage.load_certificate(cert_id)
        assert isinstance(loaded, x509.Certificate)

    def test_import_missing_file_raises(self, temp_storage):
        with pytest.raises(FileNotFoundError):
            CertificateImporter(temp_storage).import_from_pem("/nonexistent/cert.pem")

    def test_import_from_der(self, temp_storage, tmp_path):
        manager = CertificateManager()
        cert, key, _ = manager.generate_self_signed_cert("der.example.com")
        cert_path = tmp_path / "cert.der"
        key_path = tmp_path / "key.der"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

        cert_id = CertificateImporter(temp_storage).import_from_der(
            str(cert_path), key_path=str(key_path)
        )
        loaded, meta = temp_storage.load_certificate(cert_id)
        assert meta["common_name"] == "der.example.com"

    def test_import_from_pkcs12(self, temp_storage, tmp_path):
        manager = CertificateManager()
        cert, key, _ = manager.generate_self_signed_cert("p12.example.com")
        exporter = CertificateExporter(temp_storage)
        cert_id = temp_storage.save_certificate(cert, key, {"common_name": "p12.example.com", "id": "x"})
        # Re-save properly
        cert, key, meta = manager.generate_self_signed_cert("p12.example.com")
        cert_id = temp_storage.save_certificate(cert, key, meta)
        p12_path = tmp_path / "cert.p12"
        exporter.export_to_pkcs12(cert_id, str(p12_path))

        new_id = CertificateImporter(temp_storage).import_from_pkcs12(str(p12_path))
        _, imported_meta = temp_storage.load_certificate(new_id)
        assert imported_meta["common_name"] == "p12.example.com"


class TestCertificateExporter:
    """Tests pour CertificateExporter."""

    def test_export_to_pem(self, temp_storage, tmp_path):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("export.example.com")
        cert_id = temp_storage.save_certificate(cert, key, meta)

        out = tmp_path / "out.pem"
        cert_path, key_path = CertificateExporter(temp_storage).export_to_pem(
            cert_id, str(out), include_key=True
        )
        assert Path(cert_path).exists()
        assert key_path and Path(key_path).exists()

    def test_export_to_der(self, temp_storage, tmp_path):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("derout.example.com")
        cert_id = temp_storage.save_certificate(cert, key, meta)

        out = tmp_path / "out.der"
        cert_path, _ = CertificateExporter(temp_storage).export_to_der(cert_id, str(out))
        data = Path(cert_path).read_bytes()
        loaded = x509.load_der_x509_certificate(data, default_backend())
        assert loaded.subject == cert.subject

    def test_export_to_pkcs12(self, temp_storage, tmp_path):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("p12out.example.com")
        cert_id = temp_storage.save_certificate(cert, key, meta)

        p12_path = tmp_path / "out.p12"
        result = CertificateExporter(temp_storage).export_to_pkcs12(
            cert_id, str(p12_path), password=b"secret"
        )
        assert Path(result).exists()
        assert Path(result).stat().st_size > 0

    def test_pem_roundtrip(self, temp_storage, tmp_path):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("roundtrip.example.com")
        cert_id = temp_storage.save_certificate(cert, key, meta)

        out = tmp_path / "round.pem"
        CertificateExporter(temp_storage).export_to_pem(cert_id, str(out), include_key=True)
        new_id = CertificateImporter(temp_storage).import_from_pem(
            str(out), key_path=str(out.with_suffix(".key"))
        )
        _, new_meta = temp_storage.load_certificate(new_id)
        assert new_meta["common_name"] == "roundtrip.example.com"
