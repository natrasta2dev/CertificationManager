.PHONY: install test lint format clean help

help:
	@echo "Commandes disponibles:"
	@echo "  make install    - Installer les dépendances"
	@echo "  make test       - Lancer les tests"
	@echo "  make lint       - Vérifier le code avec flake8"
	@echo "  make format     - Formater le code avec black"
	@echo "  make clean      - Nettoyer les fichiers temporaires"

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

