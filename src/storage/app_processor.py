# src/storage/app_processor.py
"""
Módulo `app_processor`

Este módulo fornece a classe `AppProcessor`, que contém utilitários essenciais
para o processamento de aplicações distribuídas na rede P2P SkyNet.

As funcionalidades principais incluem:
- Geração de hashes SHA-256 para o conteúdo de aplicações, garantindo a
  identificação única e a verificação de integridade.
- Compactação de diretórios de aplicações em formato ZIP para otimização
  de armazenamento e transmissão.
- Descompactação do conteúdo ZIP de aplicações para torná-las prontas para serem servidas.

A consistência na compactação (especialmente a ordem dos arquivos) é crucial
para que o hash SHA-256 de um mesmo conteúdo seja sempre idêntico,
independentemente de onde a operação é realizada.
"""
import hashlib
import zipfile
import io
import logging
from pathlib import Path
import os # Para listdir e path.join em zipping
import shutil # Para o exemplo de uso, mas será removido

# Definir o diretório base das aplicações, como em app_storage
# É importante que este BASE_DIR seja consistente com AppStorage
APP_BASE_DIR = Path.cwd() / "apps"

class AppProcessor:
    """
    Gerencia o processamento de aplicações, incluindo compactação, descompactação
    e geração de hashes SHA-256.
    """
    def __init__(self):
        logging.info("AppProcessor inicializado.")

    def generate_app_hash(self, content: bytes) -> str:
        """
        Gera o hash SHA-256 do conteúdo fornecido.
        Este hash é usado como identificador único para a aplicação.

        Args:
            content (bytes): O conteúdo (geralmente compactado) em bytes.

        Returns:
            str: O hash SHA-256 como uma string hexadecimal.
        """
        if not isinstance(content, bytes):
            raise TypeError("O conteúdo deve ser do tipo bytes.")
        return hashlib.sha256(content).hexdigest()

    def zip_app_directory(self, app_dir: Path) -> bytes:
        """
        Compacta um diretório de aplicação em um arquivo ZIP na memória.
        A ordem dos arquivos dentro do ZIP é garantida (alfabética) para
        produzir hashes consistentes para o mesmo conteúdo.

        Args:
            app_dir (Path): O caminho para o diretório da aplicação a ser compactada.

        Returns:
            bytes: Os dados do arquivo ZIP em bytes.

        Raises:
            ValueError: Se o caminho fornecido não for um diretório válido.
        """
        if not app_dir.is_dir():
            raise ValueError(f"O caminho fornecido não é um diretório: {app_dir}")

        in_memory_zip = io.BytesIO()
        # Nível de compressão 9 (máximo) para otimização
        with zipfile.ZipFile(in_memory_zip, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            # Percorre o diretório recursivamente
            for root, _, files in os.walk(app_dir):
                for file in sorted(files): # Ordena os arquivos para garantir hashes consistentes
                    file_path = Path(root) / file
                    # Calcula o caminho relativo dentro do ZIP (ex: 'index.html', 'css/style.css')
                    arcname = file_path.relative_to(app_dir)
                    zf.write(file_path, arcname=arcname)
        
        in_memory_zip.seek(0) # Retorna ao início do stream para leitura
        return in_memory_zip.read()

    def unzip_app_content(self, zipped_content: bytes, destination_dir: Path):
        """
        Descompacta o conteúdo ZIP de uma aplicação para um diretório de destino.

        Args:
            zipped_content (bytes): O conteúdo compactado da aplicação em bytes.
            destination_dir (Path): O caminho para o diretório onde os arquivos serão extraídos.

        Raises:
            TypeError: Se o conteúdo zipado não for do tipo bytes.
            zipfile.BadZipFile: Se o conteúdo não for um arquivo ZIP válido.
            Exception: Para outros erros durante a descompactação.
        """
        if not isinstance(zipped_content, bytes):
            raise TypeError("O conteúdo zipado deve ser do tipo bytes.")
        
        destination_dir.mkdir(parents=True, exist_ok=True) # Garante que o diretório de destino exista
        try:
            with zipfile.ZipFile(io.BytesIO(zipped_content), 'r') as zf:
                zf.extractall(destination_dir)
            logging.debug(f"Conteúdo descompactado para: {destination_dir}")
        except zipfile.BadZipFile as e:
            logging.error(f"Erro: Conteúdo não é um arquivo ZIP válido. {e}")
            raise
        except Exception as e:
            logging.error(f"Erro ao descompactar conteúdo para {destination_dir}: {e}")
            raise

    def get_decompressed_app_path(self, app_hash: str, base_dir: Path = APP_BASE_DIR) -> Path:
        """
        Retorna o caminho completo do diretório onde os arquivos descompactados
        de uma aplicação (prontos para serem servidos pelo web server) devem residir.

        Args:
            app_hash (str): O hash da aplicação.
            base_dir (Path): O diretório base de armazenamento das aplicações.

        Returns:
            Path: O caminho completo para o diretório de conteúdo descompactado.
        """
        return base_dir / app_hash / "unzipped_content"
