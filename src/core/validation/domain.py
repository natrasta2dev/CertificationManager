"""Validation des noms de domaine et support wildcard."""

import re
from typing import List, Tuple


class DomainValidator:
    """Validateur de noms de domaine avec support wildcard."""

    # Pattern pour un nom de domaine valide
    DOMAIN_PATTERN = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    # Pattern pour un wildcard valide (*.example.com)
    WILDCARD_PATTERN = re.compile(
        r'^\*\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )

    @classmethod
    def is_valid_domain(cls, domain: str) -> bool:
        """
        Vérifie si un nom de domaine est valide.
        
        Args:
            domain: Nom de domaine à valider
            
        Returns:
            True si le domaine est valide, False sinon
        """
        if not domain or len(domain) > 253:
            return False
        
        # Vérifier si c'est un wildcard
        if domain.startswith('*.'):
            return cls.WILDCARD_PATTERN.match(domain) is not None
        
        # Vérifier si c'est un domaine normal
        return cls.DOMAIN_PATTERN.match(domain) is not None

    @classmethod
    def is_wildcard(cls, domain: str) -> bool:
        """
        Vérifie si un nom de domaine est un wildcard.
        
        Args:
            domain: Nom de domaine à vérifier
            
        Returns:
            True si c'est un wildcard, False sinon
        """
        return domain.startswith('*.') and cls.WILDCARD_PATTERN.match(domain) is not None

    @classmethod
    def validate_domains(cls, domains: List[str]) -> Tuple[bool, List[str]]:
        """
        Valide une liste de noms de domaine.
        
        Args:
            domains: Liste de noms de domaine à valider
            
        Returns:
            Tuple (is_valid, errors) où errors contient les domaines invalides
        """
        errors = []
        for domain in domains:
            if not cls.is_valid_domain(domain):
                errors.append(domain)
        
        return len(errors) == 0, errors

    @classmethod
    def extract_base_domain(cls, wildcard: str) -> str:
        """
        Extrait le domaine de base d'un wildcard.
        
        Args:
            wildcard: Nom de domaine wildcard (ex: *.example.com)
            
        Returns:
            Domaine de base (ex: example.com)
        """
        if cls.is_wildcard(wildcard):
            return wildcard[2:]  # Enlever "*."
        return wildcard

    @classmethod
    def matches_wildcard(cls, wildcard: str, domain: str) -> bool:
        """
        Vérifie si un domaine correspond à un wildcard.
        
        Args:
            wildcard: Nom de domaine wildcard (ex: *.example.com)
            domain: Nom de domaine à vérifier (ex: api.example.com)
            
        Returns:
            True si le domaine correspond au wildcard, False sinon
        """
        if not cls.is_wildcard(wildcard):
            return False
        
        base_domain = cls.extract_base_domain(wildcard)
        return domain.endswith('.' + base_domain) or domain == base_domain

