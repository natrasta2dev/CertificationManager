#!/usr/bin/env python3
"""Script pour générer des certificats de test avec différentes durées de validité."""

import random
import sys
from src.core import CertificateManager, SecureStorage

def generate_test_certificates(count=100):
    """Génère des certificats de test avec différentes durées."""
    
    cert_manager = CertificateManager()
    storage = SecureStorage()
    
    # Distribution des durées pour créer différents types d'alertes
    # - Expirés (négatifs ou 0 jours)
    # - Critique (1-7 jours)
    # - Warning (8-30 jours)
    # - Info (31-60 jours)
    # - Valides (61-365 jours)
    # - Long terme (366-730 jours)
    
    durations = []
    
    # 10 certificats expirés (0-1 jour - seront expirés immédiatement ou presque)
    durations.extend([random.randint(0, 1) for _ in range(10)])
    
    # 15 certificats critiques (2-7 jours)
    durations.extend([random.randint(2, 7) for _ in range(15)])
    
    # 20 certificats warning (8-30 jours)
    durations.extend([random.randint(8, 30) for _ in range(20)])
    
    # 15 certificats info (31-60 jours)
    durations.extend([random.randint(31, 60) for _ in range(15)])
    
    # 25 certificats valides (61-365 jours)
    durations.extend([random.randint(61, 365) for _ in range(25)])
    
    # 15 certificats long terme (366-730 jours)
    durations.extend([random.randint(366, 730) for _ in range(15)])
    
    # Mélanger pour plus de réalisme
    random.shuffle(durations)
    
    print(f"🔐 Génération de {len(durations)} certificats de test...\n")
    
    organizations = [
        "Acme Corp", "Tech Solutions", "Digital Services", "Cloud Systems",
        "Security Inc", "Network Pro", "Data Center", "Web Services",
        "IT Solutions", "Enterprise Systems", "Global Tech", "Secure Corp"
    ]
    
    domains = [
        "example.com", "test.com", "demo.org", "sample.net", "dev.io",
        "prod.com", "staging.net", "api.example.com", "www.test.com"
    ]
    
    created = 0
    errors = 0
    
    for i, days in enumerate(durations, 1):
        try:
            # Générer un nom unique
            org = random.choice(organizations)
            domain = random.choice(domains)
            subdomain = f"cert-{i:03d}"
            common_name = f"{subdomain}.{domain}"
            
            # Générer le certificat
            cert, private_key, metadata = cert_manager.generate_self_signed_cert(
                common_name=common_name,
                validity_days=days,
                organization=org,
                country="FR",
                state=random.choice(["Ile-de-France", "Auvergne-Rhône-Alpes", "Provence-Alpes-Côte d'Azur", None]),
                locality=random.choice(["Paris", "Lyon", "Marseille", None]),
                key_size=random.choice([2048, 3072, 4096]),
            )
            
            # Sauvegarder
            cert_id = storage.save_certificate(cert, private_key, metadata)
            
            # Afficher le statut
            status_icon = "❌" if days <= 0 else "🔴" if days <= 7 else "⚠️" if days <= 30 else "ℹ️" if days <= 60 else "✅"
            print(f"{status_icon} [{i:3d}/{len(durations)}] {common_name:<30} {days:>4} jours - {org}")
            
            created += 1
            
        except Exception as e:
            print(f"❌ Erreur pour certificat {i}: {e}")
            errors += 1
    
    print(f"\n{'='*70}")
    print(f"✅ {created} certificats créés avec succès")
    if errors > 0:
        print(f"❌ {errors} erreurs")
    print(f"\n📊 Répartition:")
    print(f"   - Expirés: {sum(1 for d in durations if d <= 0)}")
    print(f"   - Critique (1-7j): {sum(1 for d in durations if 1 <= d <= 7)}")
    print(f"   - Warning (8-30j): {sum(1 for d in durations if 8 <= d <= 30)}")
    print(f"   - Info (31-60j): {sum(1 for d in durations if 31 <= d <= 60)}")
    print(f"   - Valides (61-365j): {sum(1 for d in durations if 61 <= d <= 365)}")
    print(f"   - Long terme (366-730j): {sum(1 for d in durations if 366 <= d <= 730)}")

if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    generate_test_certificates(count)

