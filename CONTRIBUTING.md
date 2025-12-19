# 🤝 Guide de contribution

Merci de votre intérêt pour contribuer à CertificationManager ! Ce document fournit des directives pour contribuer au projet.

## 📋 Table des matières

- [Code de conduite](#code-de-conduite)
- [Comment contribuer](#comment-contribuer)
- [Processus de développement](#processus-de-développement)
- [Standards de code](#standards-de-code)
- [Tests](#tests)
- [Documentation](#documentation)
- [Soumission de Pull Requests](#soumission-de-pull-requests)

## 📜 Code de conduite

Ce projet adhère à un code de conduite. En participant, vous êtes tenu de maintenir ce code. Veuillez signaler tout comportement inacceptable.

## 🚀 Comment contribuer

### Signaler un bug

Si vous trouvez un bug, veuillez créer une issue avec :
- Description claire du bug
- Étapes pour reproduire
- Comportement attendu vs comportement actuel
- Version de Python et OS
- Logs d'erreur si disponibles

### Proposer une fonctionnalité

Pour proposer une nouvelle fonctionnalité :
- Vérifiez d'abord si elle n'existe pas déjà dans les issues
- Créez une issue avec le label "enhancement"
- Décrivez clairement la fonctionnalité et son utilité
- Attendez la discussion avant de commencer le développement

### Corriger un bug

1. Vérifiez les issues existantes
2. Assignez-vous l'issue ou créez-en une nouvelle
3. Créez une branche depuis `main`
4. Faites vos modifications
5. Ajoutez des tests
6. Soumettez une Pull Request

## 🔧 Processus de développement

### 1. Fork et clone

```bash
# Fork le projet sur GitHub
# Puis clonez votre fork
git clone https://github.com/votre-username/CertificationManager.git
cd CertificationManager
```

### 2. Créer une branche

```bash
# Créer une branche pour votre travail
git checkout -b feature/ma-fonctionnalite
# ou
git checkout -b fix/mon-bug
```

### 3. Configuration de l'environnement

```bash
# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installer en mode développement
pip install -e ".[dev]"
```

### 4. Faire vos modifications

- Suivez les standards de code
- Écrivez des tests pour votre code
- Mettez à jour la documentation si nécessaire
- Vérifiez que tous les tests passent

### 5. Commit

```bash
# Ajouter vos fichiers
git add .

# Commit avec un message clair
git commit -m "feat: ajouter fonctionnalité X"
# ou
git commit -m "fix: corriger bug Y"
```

**Convention de commit** : Utilisez les préfixes suivants :
- `feat:` pour une nouvelle fonctionnalité
- `fix:` pour une correction de bug
- `docs:` pour la documentation
- `test:` pour les tests
- `refactor:` pour le refactoring
- `style:` pour le formatage
- `chore:` pour les tâches de maintenance

### 6. Push et Pull Request

```bash
# Push vers votre fork
git push origin feature/ma-fonctionnalite

# Créer une Pull Request sur GitHub
```

## 📝 Standards de code

### Python

- **Style** : Suivez PEP 8
- **Formatage** : Utilisez `black` pour le formatage automatique
- **Linting** : Utilisez `flake8` pour le linting
- **Type hints** : Utilisez les type hints Python 3.9+

```bash
# Formater le code
black src/ tests/

# Vérifier le style
flake8 src/ tests/
```

### Structure du code

- Une fonction = une responsabilité
- Noms de variables et fonctions clairs et descriptifs
- Commentaires pour expliquer le "pourquoi", pas le "quoi"
- Docstrings pour toutes les fonctions publiques

### Exemple

```python
def generate_certificate(
    common_name: str,
    validity_days: int = 365,
    key_size: int = 2048
) -> Certificate:
    """
    Génère un certificat auto-signé.
    
    Args:
        common_name: Le nom commun (CN) du certificat
        validity_days: Nombre de jours de validité (défaut: 365)
        key_size: Taille de la clé en bits (défaut: 2048)
    
    Returns:
        Un objet Certificate
    
    Raises:
        ValueError: Si les paramètres sont invalides
    """
    # Implémentation...
```

## 🧪 Tests

### Écrire des tests

- Écrivez des tests pour toute nouvelle fonctionnalité
- Les tests doivent être indépendants et reproductibles
- Utilisez des fixtures pour les données de test
- Testez les cas limites et les erreurs

### Exécuter les tests

```bash
# Tous les tests
pytest

# Tests avec couverture
pytest --cov=src --cov-report=html

# Tests spécifiques
pytest tests/test_certificate.py

# Tests en mode verbose
pytest -v
```

### Couverture de code

Maintenez une couverture de code d'au moins 80%.

## 📚 Documentation

### Docstrings

Utilisez le format Google pour les docstrings :

```python
def ma_fonction(param1: str, param2: int) -> bool:
    """Brève description.
    
    Description plus détaillée si nécessaire.
    
    Args:
        param1: Description du paramètre 1
        param2: Description du paramètre 2
    
    Returns:
        Description de la valeur de retour
    
    Raises:
        ValueError: Quand et pourquoi cette exception est levée
    """
    pass
```

### Documentation du projet

- Mettez à jour le README si vous ajoutez des fonctionnalités
- Ajoutez des exemples d'utilisation
- Documentez les changements breaking dans CHANGELOG.md

## 🔍 Soumission de Pull Requests

### Avant de soumettre

- [ ] Tous les tests passent
- [ ] Le code est formaté avec `black`
- [ ] Pas d'erreurs de linting
- [ ] La documentation est à jour
- [ ] Les commits suivent la convention
- [ ] La branche est à jour avec `main`

### Template de Pull Request

```markdown
## Description
Brève description des changements

## Type de changement
- [ ] Bug fix
- [ ] Nouvelle fonctionnalité
- [ ] Breaking change
- [ ] Documentation

## Comment tester
Étapes pour tester les changements

## Checklist
- [ ] Tests ajoutés/mis à jour
- [ ] Documentation mise à jour
- [ ] Code formaté
- [ ] Pas d'erreurs de linting
```

### Processus de review

1. Un mainteneur examinera votre PR
2. Des commentaires peuvent être laissés
3. Faites les modifications demandées
4. Une fois approuvée, la PR sera mergée

## 🎯 Zones où l'aide est la bienvenue

- Correction de bugs
- Amélioration de la documentation
- Ajout de tests
- Nouvelles fonctionnalités (vérifiez d'abord avec les mainteneurs)
- Optimisations de performance
- Amélioration de l'interface utilisateur

## ❓ Questions ?

Si vous avez des questions, n'hésitez pas à :
- Créer une issue avec le label "question"
- Contacter les mainteneurs

Merci de contribuer à CertificationManager ! 🎉

