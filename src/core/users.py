"""Gestion des utilisateurs."""

import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from .auth import hash_password, verify_password


class UserRole(str, Enum):
    """Rôles utilisateur."""

    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


@dataclass
class User:
    """Utilisateur authentifié."""

    id: str
    username: str
    role: UserRole
    password_hash: str = ""
    created_at: str = ""

    def to_dict(self, include_hash: bool = False) -> Dict:
        data = {
            "id": self.id,
            "username": self.username,
            "role": self.role.value,
            "created_at": self.created_at,
        }
        if include_hash:
            data["password_hash"] = self.password_hash
        return data


class UserManager:
    """Gestionnaire de comptes utilisateurs (stockage JSON local)."""

    def __init__(self, storage_path: Optional[str] = None):
        if storage_path is None:
            from ..config import get_settings
            storage_path = get_settings().storage_path

        self.users_file = Path(storage_path) / "users.json"
        self.users_file.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> Dict[str, Dict]:
        if not self.users_file.exists():
            return {}
        try:
            with open(self.users_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("users", {})
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self, users: Dict[str, Dict]) -> None:
        tmp_path = self.users_file.with_suffix(".json.tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump({"users": users}, f, indent=2, ensure_ascii=False)
        os.chmod(tmp_path, 0o600)
        tmp_path.replace(self.users_file)
        os.chmod(self.users_file, 0o600)

    def list_users(self) -> List[Dict]:
        """Liste les utilisateurs (sans hash)."""
        return [self._to_user(data).to_dict() for data in self._load().values()]

    def get_by_username(self, username: str) -> Optional[User]:
        """Récupère un utilisateur par nom."""
        for data in self._load().values():
            if data.get("username") == username:
                return self._to_user(data)
        return None

    def get_by_id(self, user_id: str) -> Optional[User]:
        """Récupère un utilisateur par ID."""
        data = self._load().get(user_id)
        return self._to_user(data) if data else None

    def create_user(
        self,
        username: str,
        password: str,
        role: UserRole = UserRole.VIEWER,
    ) -> User:
        """Crée un nouvel utilisateur."""
        if self.get_by_username(username):
            raise ValueError(f"L'utilisateur '{username}' existe déjà")

        user_id = str(uuid.uuid4())
        user_data = {
            "id": user_id,
            "username": username,
            "password_hash": hash_password(password),
            "role": role.value,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        users = self._load()
        users[user_id] = user_data
        self._save(users)
        return self._to_user(user_data)

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authentifie un utilisateur."""
        user = self.get_by_username(username)
        if not user or not verify_password(password, user.password_hash):
            return None
        return user

    def delete_user(self, user_id: str) -> None:
        """Supprime un utilisateur."""
        users = self._load()
        if user_id not in users:
            raise KeyError(f"Utilisateur {user_id} introuvable")
        del users[user_id]
        self._save(users)

    def ensure_default_admin(self, password: str) -> Optional[User]:
        """Crée l'admin par défaut si aucun utilisateur n'existe."""
        if self._load():
            return None
        return self.create_user("admin", password, UserRole.ADMIN)

    @staticmethod
    def _to_user(data: Dict) -> User:
        return User(
            id=data["id"],
            username=data["username"],
            role=UserRole(data["role"]),
            password_hash=data.get("password_hash", ""),
            created_at=data.get("created_at", ""),
        )
