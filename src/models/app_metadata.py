# src/models/app_metadata.py
"""
Módulo `app_metadata`

Este módulo define a classe `AppMetadata`, que representa a estrutura padronizada
para os metadados de uma aplicação web distribuída na rede P2P SkyNet.

A classe `AppMetadata` encapsula informações essenciais sobre a aplicação,
como nome, descrição, tags, versão, autor e um timestamp. Crucialmente,
ela também integra funcionalidades para serialização/deserialização
(garantindo uma representação canônica para fins criptográficos) e métodos
para assinar e verificar a autenticidade dos metadados, utilizando as
ferramentas criptográficas do projeto.

Isso garante a integridade e a proveniência das informações das aplicações
na rede, um requisito fundamental para a confiança e segurança do sistema.
"""
import json
import logging
import datetime
from typing import List, Dict, Any, Optional

from crypto.keys import sign_data, verify_signature

class AppMetadata:
    """
    Representa os metadados de uma aplicação web P2P.

    Estes metadados incluem informações descritivas e de controle, além de
    funcionalidades para garantir sua autenticidade através de assinaturas digitais.
    """
    def __init__(
        self,
        name: str,
        description: str,
        tags: List[str],
        version: str,
        author_public_key: str, # Chave pública PEM (string) do autor da aplicação
        timestamp: int, # Unix timestamp da publicação/última atualização
        active: bool = True, # Indica se esta versão da aplicação está ativa na rede
        app_hash: Optional[str] = None # Hash SHA-256 do conteúdo compactado da aplicação
    ):
        if not all([name, description, version, author_public_key, timestamp is not None]):
            raise ValueError("Campos obrigatórios de metadados (name, description, version, author_public_key, timestamp) não podem ser vazios ou nulos.")
        if not isinstance(tags, list):
            raise TypeError("O campo 'tags' deve ser uma lista de strings.")

        self.name = name
        self.description = description
        self.tags = tags
        self.version = version
        self.author_public_key = author_public_key
        self.timestamp = timestamp
        self.active = active
        self.app_hash = app_hash # O hash real do conteúdo é preenchido após a compactação

    def to_dict(self) -> Dict[str, Any]:
        """
        Converte o objeto AppMetadata para um dicionário Python.
        Útil para serialização JSON.
        """
        return {
            "name": self.name,
            "description": self.description,
            "tags": self.tags,
            "version": self.version,
            "author_public_key": self.author_public_key,
            "timestamp": self.timestamp,
            "active": self.active,
            "app_hash": self.app_hash
        }

    def to_json(self) -> str:
        """
        Serializa o objeto AppMetadata para uma string JSON canônica.
        Esta representação é usada como base para a assinatura digital,
        garantindo que a mesma entrada sempre produza a mesma string JSON.
        """
        # Garante uma representação JSON consistente para assinatura:
        # sort_keys=True para ordem consistente das chaves.
        # indent=None e separators=(',', ':') para JSON compacto e sem quebras de linha/espaços adicionais.
        return json.dumps(self.to_dict(), sort_keys=True, indent=None, separators=(',', ':'))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """
        Cria uma instância de AppMetadata a partir de um dicionário.
        """
        return cls(
            name=data["name"],
            description=data["description"],
            tags=data.get("tags", []), # Garante que tags seja uma lista vazia se ausente
            version=data["version"],
            author_public_key=data["author_public_key"],
            timestamp=data["timestamp"],
            active=data.get("active", True), # Assume ativo por padrão se ausente
            app_hash=data.get("app_hash")
        )

    @classmethod
    def from_json(cls, json_string: str):
        """
        Cria uma instância de AppMetadata a partir de uma string JSON.
        """
        data = json.loads(json_string)
        return cls.from_dict(data)

    def sign(self, private_key_pem: bytes) -> bytes:
        """
        Assina os metadados usando a chave privada PEM do autor.
        A assinatura é gerada sobre a representação JSON canônica dos metadados.

        Args:
            private_key_pem (bytes): A chave privada do autor no formato PEM (bytes).

        Returns:
            bytes: A assinatura digital resultante em bytes.
        """
        data_to_sign = self.to_json().encode('utf-8')
        return sign_data(private_key_pem, data_to_sign)

    def verify_signature(self, signature: bytes) -> bool:
        """
        Verifica a assinatura dos metadados usando a chave pública PEM do autor.

        Args:
            signature (bytes): A assinatura digital em bytes a ser verificada.

        Returns:
            bool: True se a assinatura for válida e corresponder aos metadados, False caso contrário.
        """
        data_to_verify = self.to_json().encode('utf-8')
        # A chave pública do autor é parte dos metadados (self.author_public_key)
        return verify_signature(self.author_public_key.encode('utf-8'), data_to_verify, signature)

    def __str__(self):
        """Representação em string do objeto AppMetadata."""
        return f"AppMetadata(name='{self.name}', version='{self.version}', author='{self.author_public_key[:10]}...', hash='{self.app_hash[:10] if self.app_hash else 'N/A'}', active={self.active})"

    def __repr__(self):
        """Representação de debug do objeto AppMetadata."""
        return self.__str__()
