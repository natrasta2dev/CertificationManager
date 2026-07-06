"""Modèles Pydantic pour l'API REST."""

from typing import List, Optional

from pydantic import BaseModel, Field


class CertificateCreate(BaseModel):
    common_name: str
    validity_days: int = 365
    key_type: str = "RSA"
    key_size: int = 2048
    country: Optional[str] = None
    state: Optional[str] = None
    locality: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    email: Optional[str] = None
    san_dns: Optional[List[str]] = None
    san_ip: Optional[List[str]] = None


class CSRCreate(BaseModel):
    common_name: str
    key_type: str = "RSA"
    key_size: int = 2048
    country: Optional[str] = None
    state: Optional[str] = None
    locality: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    email: Optional[str] = None
    san_dns: Optional[List[str]] = None
    san_ip: Optional[List[str]] = None


class LetsEncryptObtain(BaseModel):
    domains: List[str] = Field(..., min_length=1)
    email: Optional[str] = None
    staging: bool = False
    webroot: Optional[str] = None
    standalone: bool = True


class CAGenerate(BaseModel):
    common_name: str
    name: Optional[str] = None
    is_root: bool = True
    parent_ca_id: Optional[str] = None
    key_type: str = "RSA"
    key_size: int = 2048
    validity_days: int = 3650
    country: Optional[str] = None
    state: Optional[str] = None
    locality: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    email: Optional[str] = None


class CASignCSR(BaseModel):
    csr_id: str
    validity_days: int = 365


class CASignServer(BaseModel):
    common_name: str
    validity_days: int = 365
    key_type: str = "RSA"
    key_size: int = 2048
    country: Optional[str] = None
    state: Optional[str] = None
    locality: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    email: Optional[str] = None
    san_dns: Optional[List[str]] = None
    san_ip: Optional[List[str]] = None
