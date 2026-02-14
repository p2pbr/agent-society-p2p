# src/crypto/keys.py
"""
Módulo para operações criptográficas de chave RSA, como geração de pares de chaves,
assinatura digital e verificação de assinaturas.
"""
import os
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_rsa_key_pair():
    """
    Gera um novo par de chaves RSA (privada e pública).
    Retorna:
        tuple: (private_key, public_key) no formato PEM serializado.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def save_key_pair(private_pem: bytes, public_pem: bytes, key_dir: Path):
    """
    Salva o par de chaves RSA (privada e pública) para arquivos no diretório especificado.
    Args:
        private_pem (bytes): A chave privada no formato PEM.
        public_pem (bytes): A chave pública no formato PEM.
        key_dir (Path): O diretório onde os arquivos de chave serão salvos.
    """
    key_dir.mkdir(parents=True, exist_ok=True)
    with open(key_dir / "private_key.pem", "wb") as f:
        f.write(private_pem)
    with open(key_dir / "public_key.pem", "wb") as f:
        f.write(public_pem)

def load_key_pair(key_dir: Path) -> tuple[bytes, bytes]:
    """
    Carrega o par de chaves RSA (privada e pública) de arquivos no diretório especificado.
    Args:
        key_dir (Path): O diretório de onde os arquivos de chave serão carregados.
    Returns:
        tuple: (private_key, public_key) no formato PEM serializado.
    Raises:
        FileNotFoundError: Se os arquivos de chave não existirem.
    """
    private_key_path = key_dir / "private_key.pem"
    public_key_path = key_dir / "public_key.pem"
    if not private_key_path.exists() or not public_key_path.exists():
        raise FileNotFoundError(f"Chaves não encontradas em {key_dir}")
    with open(private_key_path, "rb") as f:
        private_pem = f.read()
    with open(public_key_path, "rb") as f:
        public_pem = f.read()
    return private_pem, public_pem

def get_or_generate_key_pair(key_dir: Path) -> tuple[bytes, bytes]:
    """
    Tenta carregar um par de chaves RSA existente do diretório especificado.
    Se não encontrar as chaves, gera um novo par e as salva.
    Args:
        key_dir (Path): O diretório onde as chaves serão procuradas ou salvas.
    Returns:
        tuple: (private_key, public_key) no formato PEM serializado.
    """
    try:
        logging.info(f"Tentando carregar chaves RSA de {key_dir}...")
        private_pem, public_pem = load_key_pair(key_dir)
        logging.info("Chaves RSA carregadas com sucesso.")
        return private_pem, public_pem
    except FileNotFoundError:
        logging.info(f"Chaves RSA não encontradas em {key_dir}. Gerando novo par de chaves...")
        private_pem, public_pem = generate_rsa_key_pair()
        save_key_pair(private_pem, public_pem, key_dir)
        logging.info(f"Novo par de chaves RSA gerado e salvo em {key_dir}.")
        return private_pem, public_pem

def sign_data(private_pem: bytes, data: bytes) -> bytes:
    """
    Assina os dados fornecidos usando a chave privada RSA.
    Args:
        private_pem (bytes): A chave privada no formato PEM.
        data (bytes): Os dados a serem assinados.
    Returns:
        bytes: A assinatura.
    """
    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None,
        backend=default_backend()
    )
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_pem: bytes, data: bytes, signature: bytes) -> bool:
    """
    Verifica a assinatura dos dados fornecidos usando a chave pública RSA.
    Args:
        public_pem (bytes): A chave pública no formato PEM.
        data (bytes): Os dados originais.
        signature (bytes): A assinatura a ser verificada.
    Returns:
        bool: True se a assinatura for válida, False caso contrário.
    """
    public_key = serialization.load_pem_public_key(
        public_pem,
        backend=default_backend()
    )
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        # Qualquer exceção durante a verificação (e.g., assinatura inválida) significa falha
        return False

def public_key_to_node_id(public_pem: bytes) -> str:
    """
    Gera um NodeID a partir de uma chave pública usando hash SHA256.
    Args:
        public_pem (bytes): A chave pública no formato PEM.
    Returns:
        str: O hash SHA256 da chave pública, representando o NodeID.
    """
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(public_pem)
    return hasher.finalize().hex()
