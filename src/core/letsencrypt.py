"""Intégration avec Let's Encrypt (ACME)."""

import os
import subprocess
import json
import uuid
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .storage import SecureStorage
from .import_export import CertificateImporter


class LetsEncryptManager:
    """Gestionnaire d'intégration avec Let's Encrypt."""

    def __init__(self, storage: Optional[SecureStorage] = None):
        """
        Initialise le gestionnaire Let's Encrypt.

        Args:
            storage: Instance de SecureStorage. Si None, crée une nouvelle instance.
        """
        self.storage = storage or SecureStorage()
        self.importer = CertificateImporter(self.storage)
        
        # Répertoire pour les certificats Let's Encrypt
        self.letsencrypt_dir = self.storage.storage_path / "letsencrypt"
        self.letsencrypt_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuration
        self.staging_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
        self.production_url = "https://acme-v02.api.letsencrypt.org/directory"

    def check_certbot_available(self) -> bool:
        """
        Vérifie si certbot est disponible.

        Returns:
            True si certbot est installé
        """
        try:
            result = subprocess.run(
                ["certbot", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def obtain_certificate(
        self,
        domains: List[str],
        email: Optional[str] = None,
        staging: bool = False,
        webroot: Optional[str] = None,
        standalone: bool = False
    ) -> str:
        """
        Obtient un certificat Let's Encrypt.

        Args:
            domains: Liste des domaines pour le certificat
            email: Email pour les notifications Let's Encrypt
            staging: Utiliser l'environnement de staging (pour tests)
            webroot: Chemin du webroot pour la validation HTTP-01
            standalone: Utiliser le mode standalone (nécessite que le port 80 soit libre)

        Returns:
            ID du certificat importé
        """
        if not self.check_certbot_available():
            raise RuntimeError(
                "certbot n'est pas installé. "
                "Installez-le avec: sudo apt-get install certbot (Debian/Ubuntu) "
                "ou brew install certbot (macOS)"
            )

        if not domains:
            raise ValueError("Au moins un domaine doit être spécifié")

        # Créer un répertoire temporaire pour certbot
        certbot_dir = self.letsencrypt_dir / f"certbot_{uuid.uuid4().hex[:8]}"
        certbot_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Construire la commande certbot
            cmd = ["certbot", "certonly"]
            
            if staging:
                cmd.append("--staging")
                cmd.extend(["--server", self.staging_url])
            
            # Mode de validation
            if standalone:
                cmd.append("--standalone")
                cmd.append("--preferred-challenges")
                cmd.append("http")
            elif webroot:
                cmd.extend(["--webroot", "--webroot-path", webroot])
            else:
                # Par défaut, utiliser standalone
                cmd.append("--standalone")
                cmd.append("--preferred-challenges")
                cmd.append("http")
            
            # Domaines
            for domain in domains:
                cmd.extend(["-d", domain])
            
            # Email (optionnel mais recommandé)
            if email:
                cmd.extend(["--email", email])
            else:
                cmd.append("--register-unsafely-without-email")
            
            # Options supplémentaires
            cmd.extend([
                "--agree-tos",
                "--non-interactive",
            ])

            # Exécuter certbot
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes max
            )

            if result.returncode != 0:
                raise RuntimeError(
                    f"Erreur lors de l'obtention du certificat Let's Encrypt:\n"
                    f"{result.stderr}\n{result.stdout}"
                )

            # Trouver les fichiers générés par certbot
            # Certbot stocke généralement dans /etc/letsencrypt/live/<domain>/
            standard_path = Path(f"/etc/letsencrypt/live/{domains[0]}")
            
            if not standard_path.exists():
                raise FileNotFoundError(
                    f"Les fichiers de certificat n'ont pas été trouvés dans {standard_path}. "
                    "Certbot a peut-être échoué. Vérifiez les logs."
                )
            
            cert_file = standard_path / "cert.pem"
            key_file = standard_path / "privkey.pem"
            
            if not cert_file.exists():
                raise FileNotFoundError(f"Fichier certificat non trouvé: {cert_file}")
            if not key_file.exists():
                raise FileNotFoundError(f"Fichier clé privée non trouvé: {key_file}")

            # Importer le certificat
            cert_id = self.importer.import_from_pem(
                str(cert_file),
                key_path=str(key_file) if key_file.exists() else None,
                validate=True
            )

            # Ajouter les métadonnées Let's Encrypt
            all_metadata = self.storage._load_metadata()
            if cert_id in all_metadata:
                all_metadata[cert_id]["letsencrypt"] = True
                all_metadata[cert_id]["letsencrypt_domains"] = domains
                all_metadata[cert_id]["letsencrypt_staging"] = staging
                all_metadata[cert_id]["letsencrypt_obtained_at"] = datetime.now(timezone.utc).isoformat()
                self.storage._save_metadata(all_metadata)

            return cert_id

        finally:
            # Nettoyer le répertoire temporaire (garder les certificats)
            pass

    def renew_certificate(self, cert_id: str) -> str:
        """
        Renouvelle un certificat Let's Encrypt.

        Args:
            cert_id: ID du certificat à renouveler

        Returns:
            ID du nouveau certificat
        """
        if not self.check_certbot_available():
            raise RuntimeError("certbot n'est pas installé")

        # Récupérer les métadonnées du certificat
        cert, metadata = self.storage.load_certificate(cert_id)
        
        if not metadata.get("letsencrypt"):
            raise ValueError("Ce certificat n'est pas un certificat Let's Encrypt")

        domains = metadata.get("letsencrypt_domains", [])
        if not domains:
            # Extraire le domaine du CN
            for attr in cert.subject:
                if attr.oid._name == "commonName":
                    domains = [attr.value]
                    break

        if not domains:
            raise ValueError("Impossible de déterminer les domaines du certificat")

        # Obtenir un nouveau certificat
        staging = metadata.get("letsencrypt_staging", False)
        email = metadata.get("email")
        
        new_cert_id = self.obtain_certificate(
            domains=domains,
            email=email,
            staging=staging,
            standalone=True  # Par défaut, utiliser standalone
        )

        return new_cert_id

    def list_letsencrypt_certificates(self) -> List[Dict]:
        """
        Liste tous les certificats Let's Encrypt.

        Returns:
            Liste des métadonnées des certificats Let's Encrypt
        """
        all_certs = self.storage.list_certificates()
        letsencrypt_certs = [
            cert for cert in all_certs
            if cert.get("letsencrypt", False)
        ]
        return letsencrypt_certs

    def renew_all_expiring(self, days_threshold: int = 30) -> List[Tuple[str, str]]:
        """
        Renouvelle tous les certificats Let's Encrypt expirant bientôt.

        Args:
            days_threshold: Nombre de jours avant expiration pour renouveler

        Returns:
            Liste de tuples (ancien_cert_id, nouveau_cert_id)
        """
        from .lifecycle import CertificateLifecycle
        
        lifecycle = CertificateLifecycle(self.storage)
        expiring = lifecycle.get_expiring_certificates(
            days_threshold=days_threshold,
            include_expired=False
        )

        renewed = []
        for cert_data in expiring:
            cert_id = cert_data.get("id")
            if cert_id and cert_data.get("letsencrypt"):
                try:
                    new_cert_id = self.renew_certificate(cert_id)
                    renewed.append((cert_id, new_cert_id))
                except Exception as e:
                    # Logger l'erreur mais continuer
                    print(f"Erreur lors du renouvellement de {cert_id}: {e}")
                    continue

        return renewed

