#!/bin/bash
# Script pour redémarrer le serveur web proprement

echo "🛑 Arrêt des processus uvicorn existants..."
pkill -f "uvicorn.*certmanager" || pkill -f "certmanager web" || echo "Aucun processus trouvé"

sleep 2

echo "🚀 Démarrage du serveur web..."
source venv/bin/activate
certmanager web --reload


