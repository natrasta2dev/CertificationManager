"""Commandes CLI pour CertificationManager."""

import sys
from pathlib import Path
from typing import Optional
import click
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from ..core import (
    CertificateManager,
    ClientCertificateManager,
    SecureStorage,
    CertificateValidator,
    DomainValidator,
    CertificateLifecycle,
    AlertManager,
    CertificateRenewal,
    CertificateImporter,
    CertificateExporter,
    CAManager,
    LetsEncryptManager,
)
from .web_command import web


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """CertificationManager - Gestionnaire de certificats cryptographiques."""
    pass


@cli.command()
@click.option(
    "--common-name", "-n",
    required=True,
    help="Nom commun (CN) du certificat"
)
@click.option(
    "--validity-days", "-d",
    default=365,
    type=int,
    help="Nombre de jours de validité (défaut: 365)"
)
@click.option(
    "--key-type",
    type=click.Choice(["RSA", "ECDSA"], case_sensitive=False),
    default="RSA",
    help="Type de clé (défaut: RSA)"
)
@click.option(
    "--key-size", "-s",
    type=click.Choice(["2048", "3072", "4096"]),
    default="2048",
    help="Taille de la clé en bits (défaut: 2048, uniquement pour RSA)"
)
@click.option(
    "--country", "-C",
    help="Code pays (ex: FR)"
)
@click.option(
    "--state", "-ST",
    help="État ou province"
)
@click.option(
    "--locality", "-L",
    help="Ville"
)
@click.option(
    "--organization", "-O",
    help="Organisation"
)
@click.option(
    "--organizational-unit", "-OU",
    help="Unité organisationnelle"
)
@click.option(
    "--email", "-E",
    help="Adresse email"
)
@click.option(
    "--san-dns",
    multiple=True,
    help="Subject Alternative Name DNS (peut être utilisé plusieurs fois)"
)
@click.option(
    "--output", "-o",
    help="Fichier de sortie pour le certificat (optionnel, sinon sauvegardé dans le stockage)"
)
def generate(
    common_name: str,
    validity_days: int,
    key_type: str,
    key_size: str,
    country: Optional[str],
    state: Optional[str],
    locality: Optional[str],
    organization: Optional[str],
    organizational_unit: Optional[str],
    email: Optional[str],
    san_dns: tuple,
    output: Optional[str],
):
    """Génère un certificat auto-signé."""
    try:
        cert_manager = CertificateManager()
        
        # Convertir san_dns tuple en liste
        san_dns_list = list(san_dns) if san_dns else None

        cert, private_key, metadata = cert_manager.generate_self_signed_cert(
            common_name=common_name,
            key_type=key_type,
            key_size=int(key_size) if key_type.upper() == "RSA" else 2048,
            validity_days=validity_days,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            organizational_unit=organizational_unit,
            email=email,
            san_dns=san_dns_list,
        )

        if output:
            # Sauvegarder dans le fichier spécifié
            cert_pem = cert_manager.cert_to_pem(cert)
            Path(output).write_bytes(cert_pem)
            click.echo(f"✅ Certificat généré et sauvegardé dans: {output}")
        else:
            # Sauvegarder dans le stockage
            storage = SecureStorage()
            cert_id = storage.save_certificate(cert, private_key, metadata)
            click.echo(f"✅ Certificat généré avec succès!")
            click.echo(f"   ID: {cert_id}")
            click.echo(f"   CN: {common_name}")
            click.echo(f"   Valide jusqu'au: {cert.not_valid_after_utc.strftime('%Y-%m-%d')}")

    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--common-name", "-n",
    required=True,
    help="Nom commun (CN) du certificat"
)
@click.option(
    "--key-type",
    type=click.Choice(["RSA", "ECDSA"], case_sensitive=False),
    default="RSA",
    help="Type de clé (défaut: RSA)"
)
@click.option(
    "--key-size", "-s",
    type=click.Choice(["2048", "3072", "4096"]),
    default="2048",
    help="Taille de la clé en bits (défaut: 2048, uniquement pour RSA)"
)
@click.option(
    "--country", "-C",
    help="Code pays"
)
@click.option(
    "--state", "-ST",
    help="État ou province"
)
@click.option(
    "--locality", "-L",
    help="Ville"
)
@click.option(
    "--organization", "-O",
    help="Organisation"
)
@click.option(
    "--organizational-unit", "-OU",
    help="Unité organisationnelle"
)
@click.option(
    "--email", "-E",
    help="Adresse email"
)
@click.option(
    "--san-dns",
    multiple=True,
    help="Subject Alternative Name DNS"
)
@click.option(
    "--output", "-o",
    help="Fichier de sortie pour la CSR"
)
def csr(
    common_name: str,
    key_type: str,
    key_size: str,
    country: Optional[str],
    state: Optional[str],
    locality: Optional[str],
    organization: Optional[str],
    organizational_unit: Optional[str],
    email: Optional[str],
    san_dns: tuple,
    output: Optional[str],
):
    """Génère une Certificate Signing Request (CSR)."""
    try:
        cert_manager = CertificateManager()
        
        san_dns_list = list(san_dns) if san_dns else None

        csr, private_key, metadata = cert_manager.generate_csr(
            common_name=common_name,
            key_type=key_type,
            key_size=int(key_size) if key_type.upper() == "RSA" else 2048,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            organizational_unit=organizational_unit,
            email=email,
            san_dns=san_dns_list,
        )

        if output:
            csr_pem = csr.public_bytes(serialization.Encoding.PEM)
            Path(output).write_bytes(csr_pem)
            click.echo(f"✅ CSR générée et sauvegardée dans: {output}")
        else:
            storage = SecureStorage()
            csr_id = storage.save_csr(csr, private_key, metadata)
            click.echo(f"✅ CSR générée avec succès!")
            click.echo(f"   ID: {csr_id}")
            click.echo(f"   CN: {common_name}")

    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Format de sortie"
)
def list(format: str):
    """Liste tous les certificats stockés."""
    try:
        storage = SecureStorage()
        certificates = storage.list_certificates()

        if not certificates:
            click.echo("Aucun certificat trouvé.")
            return

        if format == "json":
            import json
            click.echo(json.dumps(certificates, indent=2))
        else:
            click.echo(f"\n{'ID':<36} {'CN':<30} {'Expire le':<12} {'Statut':<10}")
            click.echo("-" * 90)
            for cert in certificates:
                cert_id = cert.get("id", "N/A")[:36]
                cn = cert.get("common_name", "N/A")[:30]
                expires = cert.get("not_valid_after", "N/A")
                if isinstance(expires, str) and "T" in expires:
                    expires = expires.split("T")[0]
                
                status = "✅ Valide" if not cert.get("is_expired", False) else "❌ Expiré"
                days = cert.get("days_until_expiry", 0)
                if days > 0 and days <= 30:
                    status = f"⚠️  {days}j"
                
                click.echo(f"{cert_id:<36} {cn:<30} {expires:<12} {status:<10}")

    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--certificate", "-c",
    help="Chemin vers le fichier certificat (PEM)"
)
@click.option(
    "--id",
    help="ID du certificat stocké"
)
@click.option(
    "--format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Format de sortie"
)
def info(certificate: Optional[str], id: Optional[str], format: str):
    """Affiche les informations détaillées d'un certificat."""
    try:
        if not certificate and not id:
            click.echo("❌ Vous devez spécifier --certificate ou --id", err=True)
            sys.exit(1)

        if certificate:
            # Charger depuis fichier
            cert_pem = Path(certificate).read_bytes()
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        else:
            # Charger depuis stockage
            storage = SecureStorage()
            cert, _ = storage.load_certificate(id)

        validator = CertificateValidator()
        info_dict = validator.get_certificate_info(cert)

        if format == "json":
            import json
            click.echo(json.dumps(info_dict, indent=2))
        else:
            click.echo("\n📋 Informations du certificat:")
            click.echo("=" * 60)
            subject_dict = {attr.oid._name: attr.value for attr in cert.subject}
            issuer_dict = {attr.oid._name: attr.value for attr in cert.issuer}
            click.echo(f"Sujet: {subject_dict}")
            click.echo(f"Émetteur: {issuer_dict}")
            click.echo(f"Numéro de série: {info_dict['serial_number']}")
            click.echo(f"Valide du: {info_dict['not_valid_before']}")
            click.echo(f"Valide jusqu'au: {info_dict['not_valid_after']}")
            click.echo(f"Statut: {'❌ Expiré' if info_dict['is_expired'] else '✅ Valide'}")
            if not info_dict['is_expired']:
                click.echo(f"Jours restants: {info_dict['days_until_expiry']}")
            if info_dict.get('subject_alternative_names'):
                click.echo(f"SAN: {', '.join(info_dict['subject_alternative_names'])}")

    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--certificate", "-c",
    help="Chemin vers le fichier certificat (PEM)"
)
@click.option(
    "--id",
    help="ID du certificat stocké"
)
def verify(certificate: Optional[str], id: Optional[str]):
    """Vérifie la validité d'un certificat."""
    try:
        if not certificate and not id:
            click.echo("❌ Vous devez spécifier --certificate ou --id", err=True)
            sys.exit(1)

        if certificate:
            cert_pem = Path(certificate).read_bytes()
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        else:
            storage = SecureStorage()
            cert, _ = storage.load_certificate(id)

        validator = CertificateValidator()
        is_valid, errors = validator.validate_certificate(cert)

        if is_valid:
            click.echo("✅ Le certificat est valide")
        else:
            click.echo("❌ Le certificat n'est pas valide:")
            for error in errors:
                click.echo(f"   - {error}")
            sys.exit(1)

    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--id",
    required=True,
    help="ID du certificat à supprimer"
)
@click.confirmation_option(
    prompt="Êtes-vous sûr de vouloir supprimer ce certificat?"
)
def delete(id: str):
    """Supprime un certificat et sa clé privée."""
    try:
        storage = SecureStorage()
        storage.delete_certificate(id)
        click.echo(f"✅ Certificat {id} supprimé avec succès")

    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--days", "-d",
    default=30,
    type=int,
    help="Nombre de jours avant expiration (défaut: 30)"
)
@click.option(
    "--include-expired",
    is_flag=True,
    help="Inclure les certificats déjà expirés"
)
@click.option(
    "--format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Format de sortie"
)
def expiring(days: int, include_expired: bool, format: str):
    """Liste les certificats expirant bientôt."""
    try:
        lifecycle = CertificateLifecycle()
        expiring_certs = lifecycle.get_expiring_certificates(
            days_threshold=days,
            include_expired=include_expired
        )

        if format == "json":
            import json
            click.echo(json.dumps(expiring_certs, indent=2))
        else:
            if not expiring_certs:
                click.echo(f"✅ Aucun certificat n'expire dans les {days} prochains jours.")
                return

            click.echo(f"\n⚠️  Certificats expirant dans les {days} jours:")
            click.echo(f"{'ID':<36} {'CN':<30} {'Expire le':<12} {'Jours':<8} {'Statut':<10}")
            click.echo("-" * 100)
            
            for cert in expiring_certs:
                cert_id = cert.get("id", "N/A")[:36]
                cn = cert.get("common_name", "N/A")[:30]
                expires = cert.get("not_valid_after", "N/A")
                if isinstance(expires, str) and "T" in expires:
                    expires = expires.split("T")[0]
                
                days_left = cert.get("days_until_expiry", 0)
                is_expired = cert.get("is_expired", False)
                
                if is_expired:
                    status = "❌ Expiré"
                elif days_left <= 7:
                    status = f"🔴 {days_left}j"
                else:
                    status = f"⚠️  {days_left}j"
                
                click.echo(f"{cert_id:<36} {cn:<30} {expires:<12} {days_left:<8} {status:<10}")

    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--id",
    help="ID du certificat (optionnel, sinon affiche les stats globales)"
)
@click.option(
    "--format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Format de sortie"
)
def status(id: Optional[str], format: str):
    """Affiche le statut d'un certificat ou les statistiques globales."""
    try:
        lifecycle = CertificateLifecycle()

        if id:
            # Statut d'un certificat spécifique
            status_data = lifecycle.get_certificate_status(id)
            
            if format == "json":
                import json
                click.echo(json.dumps(status_data, indent=2))
            else:
                click.echo(f"\n📊 Statut du certificat: {id}")
                click.echo("=" * 60)
                click.echo(f"Nom commun: {status_data.get('common_name', 'N/A')}")
                click.echo(f"Statut: {status_data.get('status_label', 'N/A')}")
                click.echo(f"Jours restants: {status_data.get('days_until_expiry', 'N/A')}")
                click.echo(f"Expire le: {status_data.get('expires_at', 'N/A')}")
                click.echo(f"Valide: {'✅ Oui' if status_data.get('is_valid') else '❌ Non'}")
                if status_data.get('validation_errors'):
                    click.echo("Erreurs de validation:")
                    for error in status_data['validation_errors']:
                        click.echo(f"  - {error}")
        else:
            # Statistiques globales
            stats = lifecycle.get_statistics()
            
            if format == "json":
                import json
                click.echo(json.dumps(stats, indent=2))
            else:
                click.echo("\n📊 Statistiques des certificats:")
                click.echo("=" * 60)
                click.echo(f"Total: {stats['total']}")
                click.echo(f"✅ Valides: {stats['valid']}")
                click.echo(f"⚠️  Expirant bientôt (≤30j): {stats['expiring_soon']}")
                click.echo(f"🔴 Critique (≤7j): {stats['critical']}")
                click.echo(f"❌ Expirés: {stats['expired']}")

    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--threshold",
    multiple=True,
    type=(int, str),
    help="Seuil d'alerte (jours, niveau). Ex: --threshold 7 critical --threshold 30 warning"
)
@click.option(
    "--include-expired",
    is_flag=True,
    help="Inclure les certificats expirés"
)
@click.option(
    "--format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Format de sortie"
)
def alerts(threshold: tuple, include_expired: bool, format: str):
    """Vérifie et affiche les alertes pour les certificats."""
    try:
        from ..core.alerts import AlertLevel
        
        # Configurer les seuils
        thresholds = {}
        if threshold:
            for days, level_str in threshold:
                try:
                    level = AlertLevel[level_str.upper()]
                    thresholds[days] = level
                except KeyError:
                    click.echo(f"⚠️  Niveau d'alerte invalide: {level_str}. Utilisez: info, warning, critical, error", err=True)
        else:
            # Seuils par défaut
            thresholds = {
                7: AlertLevel.CRITICAL,
                30: AlertLevel.WARNING,
                60: AlertLevel.INFO,
            }

        alert_manager = AlertManager(thresholds=thresholds)
        alerts_list = alert_manager.check_certificates(include_expired=include_expired)

        if format == "json":
            import json
            click.echo(json.dumps([alert.to_dict() for alert in alerts_list], indent=2))
        else:
            if not alerts_list:
                click.echo("✅ Aucune alerte.")
                return

            click.echo(f"\n🔔 Alertes ({len(alerts_list)}):")
            click.echo("=" * 80)
            
            for alert in alerts_list:
                level_icon = {
                    "info": "ℹ️",
                    "warning": "⚠️",
                    "critical": "🔴",
                    "error": "❌",
                }.get(alert.level.value, "•")
                
                click.echo(f"{level_icon} [{alert.level.value.upper()}] {alert.message}")
                click.echo(f"   Certificat: {alert.common_name} (ID: {alert.cert_id[:8]}...)")
                if alert.days_until_expiry > 0:
                    click.echo(f"   Jours restants: {alert.days_until_expiry}")
                click.echo()

    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--id",
    required=True,
    help="ID du certificat à renouveler"
)
@click.option(
    "--validity-days", "-d",
    type=int,
    help="Nombre de jours de validité pour le nouveau certificat (défaut: même durée que l'original)"
)
@click.option(
    "--no-archive",
    is_flag=True,
    help="Ne pas archiver l'ancien certificat"
)
def renew(id: str, validity_days: Optional[int], no_archive: bool):
    """Renouvelle un certificat avec les mêmes paramètres."""
    try:
        renewal = CertificateRenewal()
        
        # Vérifier si le certificat peut être renouvelé
        can_renew, error_msg = renewal.can_renew(id)
        if not can_renew:
            click.echo(f"❌ {error_msg}", err=True)
            sys.exit(1)
        
        # Charger l'ancien certificat pour afficher les infos
        storage = SecureStorage()
        old_cert, old_metadata = storage.load_certificate(id)
        common_name = old_metadata.get('common_name', 'N/A')
        
        click.echo(f"🔄 Renouvellement du certificat: {common_name}")
        click.echo(f"   ID: {id}")
        
        # Renouveler
        new_cert_id, new_metadata = renewal.renew_certificate(
            id,
            validity_days=validity_days,
            archive_old=not no_archive
        )
        
        click.echo(f"✅ Certificat renouvelé avec succès!")
        click.echo(f"   Nouveau ID: {new_cert_id}")
        click.echo(f"   Valide jusqu'au: {new_metadata.get('not_valid_after', 'N/A')}")
        if not no_archive:
            click.echo(f"   Ancien certificat archivé")

    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command(name="import")
@click.option(
    "--cert", "-c",
    required=True,
    help="Chemin vers le fichier certificat (PEM ou DER)"
)
@click.option(
    "--key", "-k",
    help="Chemin vers le fichier clé privée (optionnel)"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["pem", "der", "p12", "pfx"], case_sensitive=False),
    default="pem",
    help="Format du fichier (défaut: pem)"
)
@click.option(
    "--password",
    help="Mot de passe pour déchiffrer le fichier (optionnel)"
)
@click.option(
    "--no-validate",
    is_flag=True,
    help="Ne pas valider le certificat après import"
)
def import_cert(cert: str, key: Optional[str], format: str, password: Optional[str], no_validate: bool):
    """Importe un certificat depuis un fichier."""
    try:
        importer = CertificateImporter()
        
        password_bytes = password.encode("utf-8") if password else None
        
        if format.lower() in ["p12", "pfx"]:
            cert_id = importer.import_from_pkcs12(
                cert,
                password=password_bytes,
                validate=not no_validate
            )
        elif format.lower() == "der":
            cert_id = importer.import_from_der(
                cert,
                key_path=key,
                password=password_bytes,
                validate=not no_validate
            )
        else:  # PEM par défaut
            cert_id = importer.import_from_pem(
                cert,
                key_path=key,
                password=password_bytes,
                validate=not no_validate
            )
        
        click.echo(f"✅ Certificat importé avec succès!")
        click.echo(f"   ID: {cert_id}")
        
        # Afficher les infos
        storage = SecureStorage()
        cert_obj, metadata = storage.load_certificate(cert_id)
        click.echo(f"   CN: {metadata.get('common_name', 'N/A')}")
        click.echo(f"   Valide jusqu'au: {metadata.get('not_valid_after', 'N/A')}")

    except FileNotFoundError as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command(name="export")
@click.option(
    "--id",
    required=True,
    help="ID du certificat à exporter"
)
@click.option(
    "--output", "-o",
    required=True,
    help="Chemin de sortie pour le fichier"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["pem", "der", "p12", "pfx"], case_sensitive=False),
    default="pem",
    help="Format d'export (défaut: pem)"
)
@click.option(
    "--include-key",
    is_flag=True,
    help="Inclure la clé privée dans l'export"
)
@click.option(
    "--password",
    help="Mot de passe pour protéger la clé privée (optionnel)"
)
def export_cert(id: str, output: str, format: str, include_key: bool, password: Optional[str]):
    """Exporte un certificat vers un fichier."""
    try:
        exporter = CertificateExporter()
        
        password_bytes = password.encode("utf-8") if password else None
        
        if format.lower() in ["p12", "pfx"]:
            if not include_key:
                click.echo("⚠️  Le format PKCS#12 nécessite la clé privée. --include-key sera activé.", err=True)
            output_path = exporter.export_to_pkcs12(
                id,
                output,
                password=password_bytes
            )
            click.echo(f"✅ Certificat exporté en PKCS#12: {output_path}")
        elif format.lower() == "der":
            cert_path, key_path = exporter.export_to_der(
                id,
                output,
                include_key=include_key,
                key_password=password_bytes
            )
            click.echo(f"✅ Certificat exporté en DER: {cert_path}")
            if key_path:
                click.echo(f"   Clé privée: {key_path}")
        else:  # PEM par défaut
            cert_path, key_path = exporter.export_to_pem(
                id,
                output,
                include_key=include_key,
                key_password=password_bytes
            )
            click.echo(f"✅ Certificat exporté en PEM: {cert_path}")
            if key_path:
                click.echo(f"   Clé privée: {key_path}")

    except FileNotFoundError:
        click.echo(f"❌ Certificat non trouvé: {id}", err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.group()
def ca():
    """Gestion des autorités de certification (CA)."""
    pass


@ca.command("list")
@click.option(
    "--format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Format de sortie"
)
def ca_list(format: str):
    """Liste toutes les CA stockées."""
    try:
        ca_manager = CAManager()
        cas = ca_manager.list_ca_certificates()

        if format == "json":
            import json
            click.echo(json.dumps(cas, indent=2))
        else:
            if not cas:
                click.echo("Aucune CA stockée.")
                return

            click.echo("\n📜 Autorités de Certification:")
            click.echo("=" * 80)
            headers = ["ID", "Nom", "CN", "Type", "Confiance", "Expire le"]
            rows = []
            for ca_data in cas:
                ca_type = "Racine" if ca_data.get("is_root") else "Intermediaire"
                trusted = "✅" if ca_data.get("is_trusted") else "❌"
                expires = ca_data.get("not_valid_after", "N/A")
                if expires != "N/A":
                    expires = expires.split("T")[0]
                
                rows.append([
                    ca_data["id"][:8] + "...",
                    ca_data.get("name", "N/A"),
                    ca_data.get("common_name", "N/A"),
                    ca_type,
                    trusted,
                    expires,
                ])
            
            # Simple table formatting
            col_widths = [max(len(str(item)) for item in col) for col in zip(*([headers] + rows))]
            header_line = " ".join(f"{h:<{w}}" for h, w in zip(headers, col_widths))
            click.echo(header_line)
            click.echo("-" * len(header_line))
            for row in rows:
                click.echo(" ".join(f"{str(item):<{w}}" for item, w in zip(row, col_widths)))

    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@ca.command("import")
@click.option(
    "--file", "-f",
    required=True,
    help="Chemin vers le fichier certificat CA (PEM ou DER)"
)
@click.option(
    "--name", "-n",
    help="Nom personnalisé pour la CA"
)
@click.option(
    "--root",
    is_flag=True,
    default=True,
    help="Marquer comme CA racine (défaut: True)"
)
@click.option(
    "--no-trust",
    is_flag=True,
    help="Ne pas marquer comme CA de confiance"
)
def ca_import(file: str, name: Optional[str], root: bool, no_trust: bool):
    """Importe une CA depuis un fichier."""
    try:
        ca_manager = CAManager()
        ca_id = ca_manager.import_ca_from_file(
            file,
            name=name,
            is_root=root,
            is_trusted=not no_trust
        )
        
        ca_cert, metadata = ca_manager.get_ca_certificate(ca_id)
        
        click.echo(f"✅ CA importée avec succès!")
        click.echo(f"   ID: {ca_id}")
        click.echo(f"   Nom: {metadata.get('name', 'N/A')}")
        click.echo(f"   CN: {metadata.get('common_name', 'N/A')}")
        click.echo(f"   Type: {'Racine' if metadata.get('is_root') else 'Intermediaire'}")
        click.echo(f"   Confiance: {'✅ Oui' if metadata.get('is_trusted') else '❌ Non'}")

    except FileNotFoundError as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@ca.command("delete")
@click.option(
    "--id",
    required=True,
    help="ID de la CA à supprimer"
)
def ca_delete(id: str):
    """Supprime une CA."""
    try:
        ca_manager = CAManager()
        ca_cert, metadata = ca_manager.get_ca_certificate(id)
        
        if not click.confirm(f"Êtes-vous sûr de vouloir supprimer la CA '{metadata.get('name', id)}' ?"):
            return
        
        ca_manager.delete_ca_certificate(id)
        click.echo(f"✅ CA supprimée avec succès!")

    except FileNotFoundError:
        click.echo(f"❌ CA non trouvée: {id}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@ca.command("verify")
@click.option(
    "--cert-id",
    required=True,
    help="ID du certificat à vérifier"
)
@click.option(
    "--ca-ids",
    help="IDs des CA à utiliser (séparés par des virgules). Si non spécifié, utilise toutes les CA de confiance."
)
def ca_verify(cert_id: str, ca_ids: Optional[str]):
    """Vérifie un certificat avec les CA stockées."""
    try:
        storage = SecureStorage()
        ca_manager = CAManager()
        
        cert, _ = storage.load_certificate(cert_id)
        
        ca_id_list = None
        if ca_ids:
            ca_id_list = [ca_id.strip() for ca_id in ca_ids.split(",")]
        
        is_valid, errors = ca_manager.verify_certificate_chain(cert, ca_cert_ids=ca_id_list)
        
        if is_valid:
            click.echo("✅ Le certificat est valide et signé par une CA de confiance")
        else:
            click.echo("❌ Le certificat n'est pas valide:")
            for error in errors:
                click.echo(f"   - {error}")

    except FileNotFoundError as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.group()
def letsencrypt():
    """Gestion des certificats Let's Encrypt."""
    pass


@letsencrypt.command("obtain")
@click.option(
    "--domains", "-d",
    required=True,
    multiple=True,
    help="Domaines pour le certificat (peut être répété)"
)
@click.option(
    "--email", "-e",
    help="Email pour les notifications Let's Encrypt"
)
@click.option(
    "--staging",
    is_flag=True,
    help="Utiliser l'environnement de staging (pour tests)"
)
@click.option(
    "--webroot",
    help="Chemin du webroot pour la validation HTTP-01"
)
@click.option(
    "--standalone",
    is_flag=True,
    help="Utiliser le mode standalone (nécessite que le port 80 soit libre)"
)
def letsencrypt_obtain(domains: tuple, email: Optional[str], staging: bool, webroot: Optional[str], standalone: bool):
    """Obtient un certificat Let's Encrypt."""
    try:
        le_manager = LetsEncryptManager()
        
        if not le_manager.check_certbot_available():
            click.echo("❌ certbot n'est pas installé.", err=True)
            click.echo("   Installez-le avec:", err=True)
            click.echo("   - Debian/Ubuntu: sudo apt-get install certbot", err=True)
            click.echo("   - macOS: brew install certbot", err=True)
            click.echo("   - Ou visitez: https://certbot.eff.org/", err=True)
            sys.exit(1)
        
        domains_list = list(domains)
        click.echo(f"🔐 Obtention d'un certificat Let's Encrypt pour: {', '.join(domains_list)}")
        
        if staging:
            click.echo("   ⚠️  Mode staging activé (certificats de test)")
        
        cert_id = le_manager.obtain_certificate(
            domains=domains_list,
            email=email,
            staging=staging,
            webroot=webroot,
            standalone=standalone or not webroot
        )
        
        click.echo(f"✅ Certificat obtenu avec succès!")
        click.echo(f"   ID: {cert_id}")
        
        # Afficher les infos
        storage = SecureStorage()
        cert_obj, metadata = storage.load_certificate(cert_id)
        click.echo(f"   CN: {metadata.get('common_name', 'N/A')}")
        click.echo(f"   Valide jusqu'au: {metadata.get('not_valid_after', 'N/A')}")

    except RuntimeError as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@letsencrypt.command("renew")
@click.option(
    "--id",
    help="ID du certificat à renouveler. Si non spécifié, renouvelle tous les certificats expirant bientôt."
)
@click.option(
    "--days", "-d",
    type=int,
    default=30,
    help="Nombre de jours avant expiration pour renouveler automatiquement (défaut: 30)"
)
def letsencrypt_renew(id: Optional[str], days: int):
    """Renouvelle un certificat Let's Encrypt."""
    try:
        le_manager = LetsEncryptManager()
        
        if not le_manager.check_certbot_available():
            click.echo("❌ certbot n'est pas installé.", err=True)
            sys.exit(1)
        
        if id:
            click.echo(f"🔄 Renouvellement du certificat: {id}")
            new_cert_id = le_manager.renew_certificate(id)
            click.echo(f"✅ Certificat renouvelé avec succès!")
            click.echo(f"   Nouveau ID: {new_cert_id}")
        else:
            click.echo(f"🔄 Renouvellement automatique des certificats expirant dans {days} jours...")
            renewed = le_manager.renew_all_expiring(days_threshold=days)
            
            if renewed:
                click.echo(f"✅ {len(renewed)} certificat(s) renouvelé(s):")
                for old_id, new_id in renewed:
                    click.echo(f"   {old_id[:8]}... -> {new_id[:8]}...")
            else:
                click.echo("ℹ️  Aucun certificat à renouveler.")

    except ValueError as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@letsencrypt.command("list")
@click.option(
    "--format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Format de sortie"
)
def letsencrypt_list(format: str):
    """Liste tous les certificats Let's Encrypt."""
    try:
        le_manager = LetsEncryptManager()
        certs = le_manager.list_letsencrypt_certificates()

        if format == "json":
            import json
            click.echo(json.dumps(certs, indent=2))
        else:
            if not certs:
                click.echo("Aucun certificat Let's Encrypt stocké.")
                return

            click.echo("\n🔐 Certificats Let's Encrypt:")
            click.echo("=" * 80)
            headers = ["ID", "CN", "Domaines", "Expire le", "Staging"]
            rows = []
            for cert in certs:
                domains = ", ".join(cert.get("letsencrypt_domains", []))
                expires = cert.get("not_valid_after", "N/A")
                if expires != "N/A":
                    expires = expires.split("T")[0]
                staging = "✅" if cert.get("letsencrypt_staging") else "❌"
                
                rows.append([
                    cert["id"][:8] + "...",
                    cert.get("common_name", "N/A"),
                    domains[:40] + "..." if len(domains) > 40 else domains,
                    expires,
                    staging,
                ])
            
            # Simple table formatting
            col_widths = [max(len(str(item)) for item in col) for col in zip(*([headers] + rows))]
            header_line = " ".join(f"{h:<{w}}" for h, w in zip(headers, col_widths))
            click.echo(header_line)
            click.echo("-" * len(header_line))
            for row in rows:
                click.echo(" ".join(f"{str(item):<{w}}" for item, w in zip(row, col_widths)))

    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.group()
def client():
    """Gestion des certificats client (mutual TLS)."""
    pass


@client.command("generate")
@click.option(
    "--common-name", "-n",
    required=True,
    help="Nom commun (CN) du certificat client"
)
@click.option(
    "--validity-days", "-d",
    default=365,
    type=int,
    help="Nombre de jours de validité (défaut: 365)"
)
@click.option(
    "--key-type",
    type=click.Choice(["RSA", "ECDSA"], case_sensitive=False),
    default="RSA",
    help="Type de clé (défaut: RSA)"
)
@click.option(
    "--key-size", "-s",
    type=click.Choice(["2048", "3072", "4096"]),
    default="2048",
    help="Taille de la clé en bits (défaut: 2048, uniquement pour RSA)"
)
@click.option(
    "--country", "-C",
    help="Code pays (ex: FR)"
)
@click.option(
    "--state", "-ST",
    help="État ou province"
)
@click.option(
    "--locality", "-L",
    help="Ville"
)
@click.option(
    "--organization", "-O",
    help="Organisation"
)
@click.option(
    "--organizational-unit", "-OU",
    help="Unité organisationnelle"
)
@click.option(
    "--email", "-E",
    help="Adresse email"
)
@click.option(
    "--ca-cert",
    help="Chemin vers le certificat CA pour signer (optionnel, sinon auto-signé)"
)
@click.option(
    "--ca-key",
    help="Chemin vers la clé privée CA (requis si --ca-cert est fourni)"
)
@click.option(
    "--output", "-o",
    help="Fichier de sortie pour le certificat (optionnel, sinon sauvegardé dans le stockage)"
)
def client_generate(
    common_name: str,
    validity_days: int,
    key_type: str,
    key_size: str,
    country: Optional[str],
    state: Optional[str],
    locality: Optional[str],
    organization: Optional[str],
    organizational_unit: Optional[str],
    email: Optional[str],
    ca_cert: Optional[str],
    ca_key: Optional[str],
    output: Optional[str],
):
    """Génère un certificat client pour mutual TLS."""
    try:
        client_manager = ClientCertificateManager()
        
        # Charger CA si fournie
        ca_cert_obj = None
        ca_key_obj = None
        if ca_cert:
            if not ca_key:
                click.echo("❌ --ca-key est requis si --ca-cert est fourni", err=True)
                sys.exit(1)
            
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            ca_cert_pem = Path(ca_cert).read_bytes()
            ca_cert_obj = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
            
            ca_key_pem = Path(ca_key).read_bytes()
            # Essayer de charger sans mot de passe d'abord
            try:
                ca_key_obj = serialization.load_pem_private_key(ca_key_pem, password=None, backend=default_backend())
            except ValueError:
                # Essayer avec un mot de passe
                password = click.prompt("Mot de passe pour la clé CA", hide_input=True)
                ca_key_obj = serialization.load_pem_private_key(
                    ca_key_pem, 
                    password=password.encode('utf-8'), 
                    backend=default_backend()
                )

        cert, private_key, metadata = client_manager.generate_client_cert(
            common_name=common_name,
            key_type=key_type,
            key_size=int(key_size) if key_type.upper() == "RSA" else 2048,
            validity_days=validity_days,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            organizational_unit=organizational_unit,
            email=email,
            ca_cert=ca_cert_obj,
            ca_key=ca_key_obj,
        )

        if output:
            # Sauvegarder dans le fichier spécifié
            cert_pem = CertificateManager.cert_to_pem(cert)
            Path(output).write_bytes(cert_pem)
            click.echo(f"✅ Certificat client généré et sauvegardé dans: {output}")
        else:
            # Sauvegarder dans le stockage
            storage = SecureStorage()
            cert_id = storage.save_certificate(cert, private_key, metadata)
            click.echo(f"✅ Certificat client généré avec succès!")
            click.echo(f"   ID: {cert_id}")
            click.echo(f"   CN: {common_name}")
            click.echo(f"   Type: Client (mutual TLS)")
            click.echo(f"   Valide jusqu'au: {metadata.get('not_valid_after', 'N/A')}")

    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@client.command("export-browser")
@click.option(
    "--id",
    required=True,
    help="ID du certificat client à exporter"
)
@click.option(
    "--output", "-o",
    required=True,
    help="Chemin de sortie pour le fichier PKCS#12 (.p12)"
)
@click.option(
    "--password",
    help="Mot de passe pour protéger le fichier PKCS#12 (optionnel)"
)
def client_export_browser(id: str, output: str, password: Optional[str]):
    """Exporte un certificat client au format PKCS#12 pour import dans les navigateurs."""
    try:
        storage = SecureStorage()
        cert, private_key = storage.load_certificate(id)
        
        client_manager = ClientCertificateManager()
        p12_data = client_manager.export_for_browser(
            cert,
            private_key,
            password=password
        )
        
        Path(output).write_bytes(p12_data)
        click.echo(f"✅ Certificat client exporté pour navigateur: {output}")
        click.echo(f"   Format: PKCS#12 (.p12)")
        click.echo(f"   Vous pouvez maintenant l'importer dans votre navigateur:")
        click.echo(f"   - Chrome/Edge: Paramètres > Sécurité > Gérer les certificats > Autorités")
        click.echo(f"   - Firefox: Options > Vie privée et sécurité > Certificats > Afficher les certificats")

    except FileNotFoundError:
        click.echo(f"❌ Certificat non trouvé: {id}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


# Ajouter la commande web
cli.add_command(web)
cli.add_command(ca)
cli.add_command(letsencrypt)
cli.add_command(client)


if __name__ == "__main__":
    cli()

