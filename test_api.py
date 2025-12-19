#!/usr/bin/env python3
"""Script de test pour vérifier les endpoints API."""

import requests
import sys

BASE_URL = "http://127.0.0.1:8000"

def test_endpoint(path):
    """Teste un endpoint."""
    url = f"{BASE_URL}{path}"
    try:
        response = requests.get(url, timeout=5)
        print(f"✅ {path}: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Réponse: {str(data)[:100]}...")
        else:
            print(f"   Erreur: {response.text[:100]}")
        return response.status_code == 200
    except requests.exceptions.ConnectionError:
        print(f"❌ {path}: Serveur non accessible (est-il démarré ?)")
        return False
    except Exception as e:
        print(f"❌ {path}: Erreur - {e}")
        return False

if __name__ == "__main__":
    print("🧪 Test des endpoints API...\n")
    
    endpoints = [
        "/api/statistics",
        "/api/alerts?include_expired=true",
        "/api/certificates",
    ]
    
    results = []
    for endpoint in endpoints:
        results.append(test_endpoint(endpoint))
        print()
    
    if all(results):
        print("✅ Tous les endpoints fonctionnent !")
        sys.exit(0)
    else:
        print("❌ Certains endpoints ont échoué")
        sys.exit(1)


