# src/storage/app_index.py
"""
Módulo `app_index`

Este módulo implementa a classe `AppIndex`, que atua como um gerenciador de índice
para os metadados das aplicações web distribuídas na rede P2P SkyNet.

O índice armazena objetos `AppMetadata` e é persistido em um arquivo JSON
(`index.json`) no disco, garantindo que o estado das aplicações conhecidas
seja mantido entre as sessões do nó.

As funcionalidades incluem:
- Carregar e salvar o índice do/para o disco.
- Adicionar, recuperar e remover metadados de aplicações.
- Realizar buscas básicas por nome, descrição ou tags.
- Gerenciar o status 'active' das aplicações, crucial para o sistema de
  atualização automática e para garantir a regra de "versão única ativa".
"""
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from models.app_metadata import AppMetadata

class AppIndex:
    """
    Gerencia um índice local de metadados de aplicações (`AppMetadata`).
    O índice é persistido em um arquivo JSON.
    """
    def __init__(self, index_dir: Path):
        """
        Inicializa o índice de aplicações.
        Cria o diretório de índice e carrega o estado persistido, se existir.

        Args:
            index_dir (Path): O diretório onde o arquivo de índice JSON será armazenado.
        """
        self.index_dir = index_dir
        self.index_file = self.index_dir / "index.json"
        self.index: Dict[str, AppMetadata] = {} # Mapeia app_hash para AppMetadata
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self.load_index()
        logging.info(f"AppIndex inicializado. Carregado de: {self.index_file} com {len(self.index)} entradas.")

    def load_index(self):
        """
        Carrega o índice de aplicações de um arquivo JSON.
        Em caso de erro, o índice é inicializado como vazio.
        """
        if self.index_file.exists():
            try:
                with open(self.index_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for app_hash, metadata_dict in data.items():
                        try:
                            # Reconstroi o objeto AppMetadata a partir do dicionário
                            self.index[app_hash] = AppMetadata.from_dict(metadata_dict)
                        except Exception as e:
                            logging.error(f"Erro ao carregar metadados para app_hash {app_hash} do índice: {e}")
                logging.info(f"Índice de aplicações carregado com {len(self.index)} entradas.")
            except Exception as e:
                logging.error(f"Erro ao carregar o índice de aplicações de {self.index_file}: {e}")
                self.index = {} # Reinicia o índice em caso de erro de leitura/parsing
        else:
            logging.info("Arquivo de índice não encontrado. Iniciando com índice vazio.")

    def save_index(self):
        """
        Salva o estado atual do índice de aplicações em um arquivo JSON.
        """
        try:
            # Converte objetos AppMetadata para dicionários para serialização JSON
            data = {app_hash: metadata.to_dict() for app_hash, metadata in self.index.items()}
            with open(self.index_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4) # Indentação para legibilidade
            logging.debug(f"Índice de aplicações salvo em: {self.index_file}")
        except Exception as e:
            logging.error(f"Erro ao salvar o índice de aplicações em {self.index_file}: {e}")

    def add_application(self, app_hash: str, metadata: AppMetadata):
        """
        Adiciona ou atualiza os metadados de uma aplicação no índice.
        Se uma aplicação com o mesmo nome e autor já existir e for ativa,
        sua versão antiga é marcada como inativa. Isso garante a regra de
        "versão única ativa" por aplicação (identificada por nome e autor).

        Args:
            app_hash (str): O hash SHA-256 do conteúdo da aplicação.
            metadata (AppMetadata): O objeto AppMetadata da aplicação.

        Raises:
            TypeError: Se metadata não for uma instância de AppMetadata.
        """
        if not isinstance(metadata, AppMetadata):
            raise TypeError("metadata deve ser uma instância de AppMetadata.")
        
        # Implementa a lógica de "versão única ativa"
        if metadata.active:
            for existing_hash, existing_metadata in list(self.index.items()):
                # Verifica se é a mesma aplicação (mesmo nome e autor)
                if existing_metadata.name == metadata.name and \
                   existing_metadata.author_public_key == metadata.author_public_key and \
                   existing_metadata.active and \
                   existing_hash != app_hash: # E não é o mesmo hash (ou seja, é uma versão diferente)
                    
                    # Desativa a versão antiga
                    existing_metadata.active = False
                    self.index[existing_hash] = existing_metadata # Atualiza no índice
                    logging.info(f"Versão antiga de '{existing_metadata.name}' ({existing_hash[:8]}) desativada em favor de uma nova versão.")

        self.index[app_hash] = metadata # Adiciona a nova versão (que é ativa por padrão)
        self.save_index()
        logging.info(f"Aplicação '{metadata.name}' ({app_hash[:8]}...) adicionada/atualizada no índice.")

    def get_application(self, app_hash: str) -> Optional[AppMetadata]:
        """
        Recupera os metadados de uma aplicação pelo seu hash.

        Args:
            app_hash (str): O hash SHA-256 da aplicação.

        Returns:
            Optional[AppMetadata]: O objeto AppMetadata, ou None se não encontrado.
        """
        return self.index.get(app_hash)

    def remove_application(self, app_hash: str):
        """
        Remove uma aplicação do índice e salva as alterações.

        Args:
            app_hash (str): O hash SHA-256 da aplicação a ser removida.
        """
        if app_hash in self.index:
            del self.index[app_hash]
            self.save_index()
            logging.info(f"Aplicação {app_hash[:8]}... removida do índice.")

    def get_all_applications(self, active_only: bool = True) -> List[AppMetadata]:
        """
        Retorna todos os metadados de aplicações no índice.

        Args:
            active_only (bool): Se True, retorna apenas aplicações marcadas como ativas.

        Returns:
            List[AppMetadata]: Uma lista de objetos AppMetadata.
        """
        if active_only:
            return [metadata for metadata in self.index.values() if metadata.active]
        return list(self.index.values())

    def search_applications(self, query: str, active_only: bool = True) -> List[AppMetadata]:
        """
        Implementa uma busca básica por nome, descrição ou tags.

        Args:
            query (str): Termo de busca.
            active_only (bool): Se True, busca apenas entre aplicações ativas.

        Returns:
            List[AppMetadata]: Uma lista de objetos AppMetadata que correspondem à busca.
        """
        query_lower = query.lower()
        results = []
        for metadata in self.get_all_applications(active_only=active_only):
            if query_lower in metadata.name.lower() or \
               query_lower in metadata.description.lower() or \
               any(query_lower in tag.lower() for tag in metadata.tags):
                results.append(metadata)
        return results

    def update_application_status(self, app_hash: str, active: bool):
        """
        Atualiza o status 'active' de uma aplicação no índice e salva.

        Args:
            app_hash (str): O hash SHA-256 da aplicação.
            active (bool): O novo status 'active' (True/False).
        """
        if app_hash in self.index:
            self.index[app_hash].active = active
            self.save_index()
            logging.info(f"Status 'active' da aplicação {app_hash[:8]}... atualizado para {active}.")
