# src/storage/app_storage.py
"""
Módulo `app_storage`

Este módulo define a classe `AppStorage`, responsável por gerenciar
o armazenamento local de aplicações web distribuídas na rede P2P SkyNet.

Cada aplicação é armazenada em uma estrutura de diretórios específica,
onde o nome do diretório raiz é o `app_hash` da aplicação. Dentro deste
diretório, são guardados o arquivo `metadata.json` (contendo os metadados
da aplicação), `signature.sig` (a assinatura digital dos metadados) e
`content.zip` (o conteúdo compactado da aplicação).

A `AppStorage` fornece uma interface para:
- Criar e remover diretórios de aplicações.
- Salvar e carregar metadados, assinaturas e conteúdo compactado.
- Verificar a existência local de uma aplicação.

Esta abordagem de armazenamento baseado em hash garante a imutabilidade
e a rastreabilidade do conteúdo das aplicações.
"""
import json
import logging
from pathlib import Path
import shutil
from typing import Dict, Any, Optional

# Diretório base padrão para todas as aplicações, localizado na raiz do projeto.
# Cada aplicação terá um subdiretório aqui, nomeado com seu app_hash.
APP_BASE_DIR = Path.cwd() / "apps"

class AppStorage:
    """
    Gerencia a estrutura de diretórios e o armazenamento local de aplicações P2P.
    As aplicações são armazenadas em subdiretórios baseados em seu hash.
    """
    def __init__(self, base_dir: Path = APP_BASE_DIR):
        """
        Inicializa o gerenciador de armazenamento de aplicações.
        Cria o diretório base se ele não existir.

        Args:
            base_dir (Path): O diretório raiz onde as aplicações serão armazenadas.
        """
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True) # Garante que o diretório base exista
        logging.info(f"Diretório base de armazenamento de aplicações: {self.base_dir}")

    def get_app_dir(self, app_hash: str) -> Path:
        """
        Retorna o caminho completo para o diretório de uma aplicação específica.

        Args:
            app_hash (str): O hash SHA-256 da aplicação.

        Returns:
            Path: O objeto Path para o diretório da aplicação.

        Raises:
            ValueError: Se o app_hash for vazio.
        """
        if not app_hash:
            raise ValueError("app_hash não pode ser vazio.")
        return self.base_dir / app_hash

    def create_app_dir(self, app_hash: str):
        """
        Cria o diretório para uma aplicação específica se ele não existir.
        Os diretórios pai também são criados, se necessário.

        Args:
            app_hash (str): O hash SHA-256 da aplicação.
        """
        app_dir = self.get_app_dir(app_hash)
        app_dir.mkdir(parents=True, exist_ok=True)
        logging.debug(f"Diretório da aplicação '{app_hash}' criado em: {app_dir}")

    def save_app_metadata(self, app_hash: str, metadata: Dict[str, Any]):
        """
        Salva o arquivo `metadata.json` para uma aplicação específica.

        Args:
            app_hash (str): O hash SHA-256 da aplicação.
            metadata (Dict[str, Any]): Um dicionário contendo os metadados da aplicação.

        Raises:
            Exception: Se ocorrer um erro durante a escrita do arquivo.
        """
        self.create_app_dir(app_hash)
        metadata_path = self.get_app_dir(app_hash) / "metadata.json"
        try:
            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=4) # Indentação para legibilidade
            logging.debug(f"Metadados da aplicação '{app_hash}' salvos em: {metadata_path}")
        except Exception as e:
            logging.error(f"Erro ao salvar metadados da aplicação '{app_hash}': {e}")
            raise

    def save_app_signature(self, app_hash: str, signature: bytes):
        """
        Salva o arquivo `signature.sig` (assinatura dos metadados) para uma aplicação específica.

        Args:
            app_hash (str): O hash SHA-256 da aplicação.
            signature (bytes): A assinatura digital em bytes.

        Raises:
            Exception: Se ocorrer um erro durante a escrita do arquivo.
        """
        self.create_app_dir(app_hash)
        signature_path = self.get_app_dir(app_hash) / "signature.sig"
        try:
            with open(signature_path, "wb") as f:
                f.write(signature)
            logging.debug(f"Assinatura da aplicação '{app_hash}' salva em: {signature_path}")
        except Exception as e:
            logging.error(f"Erro ao salvar assinatura da aplicação '{app_hash}': {e}")
            raise

    def save_app_content(self, app_hash: str, content: bytes):
        """
        Salva o arquivo `content.zip` (conteúdo compactado da aplicação) para uma aplicação específica.

        Args:
            app_hash (str): O hash SHA-256 da aplicação.
            content (bytes): O conteúdo da aplicação compactado em bytes.

        Raises:
            Exception: Se ocorrer um erro durante a escrita do arquivo.
        """
        self.create_app_dir(app_hash)
        content_path = self.get_app_dir(app_hash) / "content.zip"
        try:
            with open(content_path, "wb") as f:
                f.write(content)
            logging.debug(f"Conteúdo da aplicação '{app_hash}' salvo em: {content_path}")
        except Exception as e:
            logging.error(f"Erro ao salvar conteúdo da aplicação '{app_hash}': {e}")
            raise

    def load_app_metadata(self, app_hash: str) -> Optional[Dict[str, Any]]:
        """
        Carrega o arquivo `metadata.json` de uma aplicação.

        Args:
            app_hash (str): O hash SHA-256 da aplicação.

        Returns:
            Optional[Dict[str, Any]]: Um dicionário contendo os metadados, ou None se o arquivo não existir ou houver erro.
        """
        metadata_path = self.get_app_dir(app_hash) / "metadata.json"
        if metadata_path.exists():
            try:
                with open(metadata_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logging.error(f"Erro ao carregar metadados da aplicação '{app_hash}': {e}")
        return None

    def load_app_signature(self, app_hash: str) -> Optional[bytes]:
        """
        Carrega o arquivo `signature.sig` de uma aplicação.

        Args:
            app_hash (str): O hash SHA-256 da aplicação.

        Returns:
            Optional[bytes]: A assinatura digital em bytes, ou None se o arquivo não existir ou houver erro.
        """
        signature_path = self.get_app_dir(app_hash) / "signature.sig"
        if signature_path.exists():
            try:
                with open(signature_path, "rb") as f:
                    return f.read()
            except Exception as e:
                logging.error(f"Erro ao carregar assinatura da aplicação '{app_hash}': {e}")
        return None

    def load_app_content(self, app_hash: str) -> Optional[bytes]:
        """
        Carrega o arquivo `content.zip` de uma aplicação.

        Args:
            app_hash (str): O hash SHA-256 da aplicação.

        Returns:
            Optional[bytes]: O conteúdo compactado da aplicação em bytes, ou None se o arquivo não existir ou houver erro.
        """
        content_path = self.get_app_dir(app_hash) / "content.zip"
        if content_path.exists():
            try:
                with open(content_path, "rb") as f:
                    return f.read()
            except Exception as e:
                logging.error(f"Erro ao carregar conteúdo da aplicação '{app_hash}': {e}")
        return None

    def app_exists_locally(self, app_hash: str) -> bool:
        """
        Verifica se o diretório de uma aplicação existe localmente.

        Args:
            app_hash (str): O hash SHA-256 da aplicação.

        Returns:
            bool: True se o diretório da aplicação existir, False caso contrário.
        """
        return self.get_app_dir(app_hash).is_dir()

    def delete_app(self, app_hash: str):
        """
        Exclui o diretório completo de uma aplicação e todo o seu conteúdo.

        Args:
            app_hash (str): O hash SHA-256 da aplicação a ser excluída.

        Raises:
            Exception: Se ocorrer um erro durante a exclusão do diretório.
        """
        app_dir = self.get_app_dir(app_hash)
        if app_dir.is_dir():
            try:
                shutil.rmtree(app_dir) # Remove o diretório e todo o seu conteúdo recursivamente
                logging.info(f"Diretório da aplicação '{app_hash}' excluído: {app_dir}")
            except Exception as e:
                logging.error(f"Erro ao excluir diretório da aplicação '{app_hash}': {e}")
                raise
        else:
            logging.warning(f"Tentativa de excluir aplicação '{app_hash}' que não existe localmente em {app_dir}.")
