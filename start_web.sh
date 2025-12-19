#!/bin/bash
# Script pour démarrer l'interface web

source venv/bin/activate
certmanager web --host 127.0.0.1 --port 8000

