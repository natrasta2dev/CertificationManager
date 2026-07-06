.PHONY: install test lint format clean help ci docker-build docker-run

help:
	@echo "Commandes disponibles:"
	@echo "  make install      - Installer les dépendances"
	@echo "  make test         - Lancer les tests"
	@echo "  make test-cov     - Tests avec couverture"
	@echo "  make ci           - Pipeline locale (lint + tests)"
	@echo "  make lint         - Vérifier le code avec flake8"
	@echo "  make format       - Formater le code avec black"
	@echo "  make docker-build - Construire l'image Docker"
	@echo "  make docker-run   - Lancer via docker-compose"
	@echo "  make clean        - Nettoyer les fichiers temporaires"

install:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	pip install -e .

test:
	pytest tests/ -v

test-cov:
	pytest tests/ --cov=src --cov-report=html --cov-report=term

lint:
	flake8 src/ tests/
	mypy src/

format:
	black src/ tests/
	isort src/ tests/

clean:
	find . -type d -name __pycache__ -exec rm -r {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -r {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -r {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -r {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage dist/ build/

ci: lint test

docker-build:
	docker build -t certification-manager:latest .

docker-run:
	docker compose up --build

