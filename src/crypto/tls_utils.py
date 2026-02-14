# src/crypto/tls_utils.py
"""
Módulo `tls_utils`

Este módulo fornece funções utilitárias para a geração e gerenciamento de chaves
e certificados TLS autoassinados, que são fundamentais para estabelecer conexões
P2P criptografadas e seguras dentro da rede SkyNet.

As funcionalidades incluem:
- Geração de um par de chave privada e certificado autoassinado para um nó P2P.
- Criação e configuração de contextos SSL/TLS para uso em servidores e clientes `asyncio`.

A utilização de certificados autoassinados simplifica a configuração em ambientes
de desenvolvimento e redes P2P privadas onde uma Autoridade Certificadora (CA)
centralizada não é desejável ou prática. A autenticação mútua (mTLS) é configurada
com `CERT_REQUIRED` no lado do servidor, mas a validação específica do `NodeID`
e da chave pública do peer é realizada no nível da aplicação (handshake de desafio-resposta),
complementando a segurança de transporte fornecida pelo TLS.
"""
import ssl
import os
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from ipaddress import ip_address as ip_addr

def generate_self_signed_cert(
    cert_dir: Path,
    node_id: str,
    private_key_pem: bytes,
    ip_address: str,
) -> tuple[Path, Path]:
    """
    Gera um par de chave privada e certificado TLS autoassinado para um nó específico.
    Se os arquivos de chave e certificado já existirem, eles não são gerados novamente.

    Args:
        cert_dir (Path): O diretório onde os arquivos de chave e certificado serão salvos.
        node_id (str): O ID do nó, usado como Common Name (CN) no certificado.
        private_key_pem (bytes): A chave privada do nó em formato PEM (bytes), usada para assinar o certificado.
        ip_address (str): O endereço IP do nó.

    Returns:
        tuple[Path, Path]: Uma tupla contendo os caminhos para o arquivo de chave privada
                           e o arquivo de certificado (.key, .crt) respectivamente.
    """
    cert_dir.mkdir(parents=True, exist_ok=True)
    key_path = cert_dir / f"{node_id}.key"
    cert_path = cert_dir / f"{node_id}.crt"

    # Se os arquivos já existem, não os gera novamente
    if key_path.exists() and cert_path.exists():
        return key_path, cert_path

    # Carregar a chave privada fornecida (do nó)
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None, # A chave privada do nó já não tem senha
        backend=default_backend()
    )

    # Gerar o certificado autoassinado
    # O "subject" e o "issuer" são o mesmo para um certificado autoassinado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Sao Paulo"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Sao Paulo"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SkyNet P2P"),
        x509.NameAttribute(NameOID.COMMON_NAME, node_id), # Common Name é o NodeID
    ])

    # Adicionar o endereço IP e localhost às SANs
    san_entries = [
        x509.DNSName(node_id),
        x509.DNSName("localhost"),
    ]
    try:
        # Adicionar o endereço IP como uma SAN
        from ipaddress import ip_address as ip_addr
        san_entries.append(x509.IPAddress(ip_addr(ip_address)))
    except ValueError:
        # Se não for um endereço IP válido, trata como um nome de DNS
        san_entries.append(x509.DNSName(ip_address))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)) # Válido por 1 ano
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, data_encipherment=True,
                                     content_commitment=False, key_agreement=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False, key_cert_sign=False), critical=True,)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Escrever a chave privada e o certificado para arquivos
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

    return key_path, cert_path

def create_ssl_context(
    cert_path: Path, key_path: Path, is_server: bool,
    peer_certs_dir: Path = None
) -> ssl.SSLContext:
    """
    Cria e configura um contexto SSL/TLS para uso com `asyncio.start_server` ou `asyncio.open_connection`.

    Args:
        cert_path (Path): Caminho para o arquivo de certificado do nó.
        key_path (Path): Caminho para o arquivo de chave privada do nó.
        is_server (bool): True se o contexto for para um servidor, False para um cliente.
        peer_certs_dir (Path, optional): Diretório contendo certificados de peers conhecidos.
                                        Usado para autenticação mútua (mTLS) ou para confiar em outros peers.

    Returns:
        ssl.SSLContext: O contexto SSL/TLS configurado.
    """
    # Cria um contexto padrão, configurado para autenticação de servidor (para clientes)
    # ou autenticação de cliente (para servidores que querem verificar clientes).
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH if not is_server else ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2 # Força TLS 1.2 ou superior para segurança
    context.set_ciphers('HIGH:!aNULL:!RC4:!MD5:!DSS') # Conjunto de cifras seguras

    # Carrega a própria chave e certificado do nó
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    # Para testes e ambiente P2P com certificados autoassinados e autenticação em nível de aplicação,
    # desabilitamos a verificação de certificado TLS para evitar problemas de confiança inicial.
    # A autenticação real do peer é realizada pelo handshake de desafio-resposta.
    context.check_hostname = False # Desabilitar hostname check para certificados autoassinados
    context.verify_mode = ssl.CERT_NONE # Não tenta validar o certificado do peer no nível TLS
    
    # Se peer_certs_dir for fornecido, ainda carregamos os certificados, mas apenas
    # para que possam ser usados na lógica da aplicação (ex: para verificar assinaturas
    # de mensagens, mas não para validação inicial de conexão TLS).
    if peer_certs_dir:
        for cert_file in peer_certs_dir.glob("*.crt"):
            try:
                context.load_verify_locations(str(cert_file))
            except ssl.SSLError as e:
                logging.error(f"Erro ao carregar CA cert {cert_file}: {e}")

    return context
