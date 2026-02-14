# core/node.py
"""
Módulo `node`

Este módulo define a classe `Node`, que representa um participante individual
na rede P2P SkyNet. O `Node` é a entidade central que orquestra todas as
operações da rede, incluindo:

- Gerenciamento de identidade criptográfica (pares de chaves RSA e `NodeID`).
- Estabelecimento de conexões seguras com outros peers via TLS e handshake
  de autenticação de desafio-resposta.
- Descoberta de peers através de nós de bootstrap.
- Envio e recebimento de mensagens P2P.
- Gerenciamento do ciclo de vida de aplicações (armazenamento, indexação,
  processamento, solicitação e anúncio de aplicações).
- Execução de um servidor web local para servir e interagir com as aplicações
  distribuídas.
"""
import asyncio
import logging
import os
import json # Adiciona importação do módulo json
from pathlib import Path # Importar Path para manipulação de caminhos
from cryptography.hazmat.primitives.hashes import SHA256
from protocol.message import (
    Message,
    MESSAGE_TYPE_HELLO,
    MESSAGE_TYPE_PEER_LIST,
    MESSAGE_TYPE_PUBLIC_KEY_EXCHANGE,
    MESSAGE_TYPE_CHALLENGE,
    MESSAGE_TYPE_CHALLENGE_RESPONSE,
    MESSAGE_TYPE_APP_ANNOUNCE,
    MESSAGE_TYPE_APP_REQUEST,
    MESSAGE_TYPE_APP_RESPONSE # Importar todos os tipos de mensagem relevantes
)
from protocol.factory import MessageHandlerFactory
from bootstrap.client import BootstrapClient
from crypto.keys import get_or_generate_key_pair, public_key_to_node_id, sign_data, verify_signature
from crypto.tls_utils import generate_self_signed_cert, create_ssl_context
from storage.app_storage import AppStorage
from storage.app_index import AppIndex
from storage.app_processor import AppProcessor
from web.server import WebServer # Importa a classe do servidor web
from models.app_metadata import AppMetadata # Importa AppMetadata para type hinting

class Node:
    """
    Representa um único nó na rede P2P SkyNet.
    Gerencia sua identidade, conexões, processamento de mensagens e serviços de aplicação.
    """
    def __init__(self, host='127.0.0.1', port=0, cli=None, bootstrap_nodes=None, web_port=8080):
        """
        Inicializa um novo nó.

        Args:
            host (str): O endereço do host para vincular (ex: '127.0.0.1' para localhost).
            port (int): A porta para ouvir as conexões P2P. 0 significa que o SO atribuirá uma porta livre.
            cli: Instância CLI opcional para exibir mensagens (usado para interação com o usuário).
            bootstrap_nodes (list): Uma lista de tuplas (host, porta) para nós de bootstrap iniciais.
            web_port (int): A porta para o servidor web local.
        """
        self.host = host
        self.port = port # A porta pode ser 0 inicialmente, será atualizada após o server.serve_forever()
        self.web_port = web_port
        
        self.peers = {} # Armazena {node_id: (reader, writer, peer_public_key_pem)}
        self.server = None # Servidor P2P asyncio
        self.cli = cli # Referência para a interface CLI
        
        # Clientes de Bootstrap para descoberta inicial de peers (inicializado após a identidade)
        self.bootstrap_nodes = bootstrap_nodes if bootstrap_nodes is not None else []
        self.bootstrap_client = None

        # Gerenciamento de Aplicações Distribuídas
        self.app_storage = AppStorage() # Gerencia o armazenamento local de arquivos de aplicações
        self.app_processor = AppProcessor() # Utilitários para compactar/descompactar/hashear apps

        # Sincronização de Downloads de Aplicações
        self.app_download_events = {} # Armazena asyncio.Event para sincronização de downloads de apps

        # Variáveis de identidade do nó e TLS (inicializadas em _initialize_identity)
        self.node_id = None
        self.private_key = None
        self.public_key = None
        self.node_data_dir = None
        self.cert_dir = None
        self.tls_key_path = None
        self.tls_cert_path = None
        self.ssl_server_context = None
        self.ssl_client_context = None
        self.app_index = None # Inicializado em _initialize_identity

        logging.info(f"Node inicializado em {self.host}:{self.port} (Web: {self.web_port}). A identidade do nó será inicializada após a porta ser definida.")

        # Inicializa o servidor web local, passando a si mesmo (o nó)
        self.web_server = WebServer(host=self.host, port=self.web_port, node_instance=self)

    def _get_public_key_pem(self) -> bytes:
        """
        Retorna a chave pública do nó em formato PEM (Privacy-Enhanced Mail).
        Esta chave é usada para identificação e verificação de assinaturas.
        """
        return self.public_key

    def _get_private_key_pem(self) -> bytes:
        """
        Retorna a chave privada do nó em formato PEM.
        Esta chave é usada para assinar dados e desafios criptográficos.
        """
        return self.private_key

    async def _initialize_identity(self):
        """
        Inicializa a identidade criptográfica do nó, incluindo chaves RSA e certificados TLS,
        após a porta P2P real ter sido atribuída.
        """
        # Define o diretório de dados persistente para este nó, usando um identificador estável.
        # Se a porta for 0, usa um ID persistente para o diretório de dados do nó.
        # Isso garante que o nó mantenha sua identidade mesmo se receber uma porta aleatória.
        # Define o diretório de dados persistente para este nó como o diretório ".node_data" na raiz do projeto.
        # Todos os nós compartilharão este mesmo diretório para chaves e outros dados persistentes.
        self.node_data_dir = Path.cwd() / ".node_data"
        self.node_data_dir.mkdir(parents=True, exist_ok=True) # Garante que o diretório exista.

        
        # Identidade do Nó: Carrega ou gera o par de chaves RSA
        self.private_key, self.public_key = get_or_generate_key_pair(self.node_data_dir)
        self.node_id = public_key_to_node_id(self.public_key)
        
        # Configuração TLS para comunicação P2P criptografada
        # O diretório de certificados agora é um subdiretório do node_data_dir
        self.cert_dir = self.node_data_dir / "certs" 
        self.tls_key_path, self.tls_cert_path = generate_self_signed_cert(
            self.cert_dir, self.node_id, self._get_private_key_pem(), self.host
        )
        # Contexto SSL para o servidor P2P (escuta conexões)
        self.ssl_server_context = create_ssl_context(
            self.tls_cert_path, self.tls_key_path, is_server=True, peer_certs_dir=self.cert_dir
        )
        # Contexto SSL para o cliente P2P (inicia conexões)
        self.ssl_client_context = create_ssl_context(
            self.tls_cert_path, self.tls_key_path, is_server=False, peer_certs_dir=self.cert_dir
        )
        
        # Inicializa o índice de metadados de aplicações, usando o diretório de dados do nó
        self.app_index = AppIndex(self.node_data_dir / ".index")

        # Inicializa o BootstrapClient agora que a identidade do nó está definida
        self.bootstrap_client = BootstrapClient(self, self.bootstrap_nodes)

        logging.info(f"Node {self.node_id} identidade inicializada em {self.host}:{self.port} (Web: {self.web_port}) com chaves RSA e certificados TLS persistentes. Componentes de aplicação inicializados.")
        
    async def _send_protocol_message(self, writer: asyncio.StreamWriter, message: Message):
        """
        Envia uma mensagem de protocolo para um StreamWriter específico.
        Utilizado para mensagens de handshake e de controle interno da rede.

        Args:
            writer (asyncio.StreamWriter): O escritor da conexão para o peer de destino.
            message (Message): O objeto Message a ser enviado.
        """
        try:
            message_json = message.to_json() + '\n' # Adiciona delimitador de mensagem
            writer.write(message_json.encode())
            await writer.drain() # Garante que os dados foram enviados para o buffer do sistema operacional
            peer_address = writer.get_extra_info('peername')
            logging.debug(f"[{self.node_id}] Enviado {message.type} para {peer_address}")
        except Exception as e:
            logging.error(f"[{self.node_id}] Erro ao enviar mensagem de protocolo para {peer_address}: {e}")
            raise # Re-lança para ser capturado e tratado no nível superior (e.g., fechamento da conexão)
    
    async def _receive_protocol_message(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Message:
        """
        Recebe e decodifica uma única mensagem de protocolo de um StreamReader específico.
        Utilizado para mensagens de handshake e de controle interno da rede.

        Args:
            reader (asyncio.StreamReader): O leitor da conexão do peer.
            writer (asyncio.StreamWriter): O escritor da conexão do peer.

        Returns:
            Message: Um objeto Message construído a partir dos dados recebidos.

        Raises:
            asyncio.IncompleteReadError: Se a conexão for fechada inesperadamente pelo peer.
            ValueError, json.JSONDecodeError: Se a mensagem recebida estiver mal formatada.
            Exception: Para outros erros inesperados.
        """
        try:
            # Lê até o delimitador de nova linha, garantindo que a mensagem seja completa
            data = await reader.readuntil(b'\n')
            message_str = data.decode().strip()
            message = Message.from_json(message_str)
            peer_address = writer.get_extra_info('peername')
            logging.debug(f"[{self.node_id}] Recebido {message.type} de {peer_address}")
            return message
        except asyncio.IncompleteReadError:
            logging.warning(f"[{self.node_id}] Conexão fechada pelo peer durante leitura de mensagem de protocolo.")
            raise
        except (ValueError, json.JSONDecodeError) as ve:
            logging.error(f"[{self.node_id}] Erro de formato de mensagem durante leitura de protocolo: {ve}")
            raise
        except Exception as e:
            logging.error(f"[{self.node_id}] Erro inesperado ao receber mensagem de protocolo: {e}")
            raise
    
    async def start(self):
        """
        Inicia o servidor P2P do nó para escutar conexões de entrada,
        utilizando TLS para criptografia, e também inicia o servidor web local.
        """
        # Inicia um servidor temporário para descobrir a porta real que será usada.
        temp_server = await asyncio.start_server(self._handle_new_connection, self.host, self.port)
        self.host, self.port = temp_server.sockets[0].getsockname()
        temp_server.close() # Fecha o servidor temporário, pois não será mais necessário.
        await temp_server.wait_closed() # Garante que o servidor temporário foi completamente fechado.

        # Agora que a porta real é conhecida, inicializa a identidade do nó e os contextos SSL.
        # Isso garante que as chaves e certificados TLS sejam gerados/carregados para a porta correta.
        await self._initialize_identity()

        # Inicia o servidor P2P principal, agora com o contexto SSL corretamente configurado.
        self.server = await asyncio.start_server(
            self._handle_new_connection, self.host, self.port, ssl=self.ssl_server_context
        )
        logging.info(f"Node {self.node_id} escutando (com TLS) em {self.host}:{self.port}")

        # Inicia a descoberta de bootstrap após o servidor P2P estar pronto
        await self.bootstrap_client.start_discovery()

        # Inicia a tarefa de envio periódico da lista de peers para manter a rede atualizada
        asyncio.create_task(self._send_peer_list_periodically())

        # Inicia o servidor web local como uma tarefa em segundo plano
        asyncio.create_task(self.web_server.start())
        
        # Mantém o servidor P2P ativo indefinidamente
        async with self.server:
            await self.server.serve_forever()

    async def _handle_new_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        """
        Gerencia uma nova conexão de entrada, realizando um handshake seguro
        baseado em troca de chaves públicas e autenticação de desafio-resposta.

        Args:
            reader (asyncio.StreamReader): O leitor da nova conexão.
            writer (asyncio.StreamWriter): O escritor da nova conexão.

        Returns:
            bool: True se o handshake for bem-sucedido, False caso contrário.
        """
        peer_node_id = None # Inicializa peer_node_id para garantir que esteja sempre associado a um valor
        peer_address = writer.get_extra_info('peername')
        peer_host, peer_port = peer_address[0], peer_address[1]
        logging.info(f"[{self.node_id}] Tentando handshake seguro com {peer_host}:{peer_port} (conexão de entrada).")

        try:
            # 1. Receber PUBLIC_KEY_EXCHANGE do peer
            pk_exchange_msg = await self._receive_protocol_message(reader, writer)
            if pk_exchange_msg.type != MESSAGE_TYPE_PUBLIC_KEY_EXCHANGE:
                logging.warning(f"[{self.node_id}] Recebido tipo de mensagem inesperado '{pk_exchange_msg.type}' de {peer_address} durante o handshake. Esperava PUBLIC_KEY_EXCHANGE.")
                return False

            peer_public_key_pem = pk_exchange_msg.payload.get("public_key")
            if not peer_public_key_pem:
                logging.warning(f"[{self.node_id}] PUBLIC_KEY_EXCHANGE do peer {peer_address} não contém chave pública.")
                return False

            # Deriva o NodeID do peer a partir da chave pública recebida
            peer_node_id = public_key_to_node_id(peer_public_key_pem.encode())
            logging.debug(f"[{self.node_id}] Recebida chave pública de {peer_node_id} ({peer_address}).")

            # 2. Gerar um desafio aleatório, assinar com nossa chave privada e enviar CHALLENGE
            challenge = os.urandom(32) # 32 bytes de dados aleatórios para o desafio
            signed_challenge = sign_data(self._get_private_key_pem(), challenge)

            challenge_msg = Message(
                message_type=MESSAGE_TYPE_CHALLENGE,
                node_id=self.node_id,
                payload={
                    "challenge": challenge.hex(), # Desafio em formato hexadecimal
                    "signature": signed_challenge.hex(), # Assinatura do desafio
                    "public_key": self._get_public_key_pem().decode() # Envia nossa chave pública novamente para o peer verificar
                }
            )
            await self._send_protocol_message(writer, challenge_msg)
            logging.debug(f"[{self.node_id}] Enviado CHALLENGE para {peer_node_id} ({peer_address}).")

            # 3. Receber CHALLENGE_RESPONSE do peer
            challenge_response_msg = await self._receive_protocol_message(reader, writer)
            if challenge_response_msg.type != MESSAGE_TYPE_CHALLENGE_RESPONSE:
                logging.warning(f"[{self.node_id}] Recebido tipo de mensagem inesperado '{challenge_response_msg.type}' de {peer_address}. Esperava CHALLENGE_RESPONSE.")
                return False

            peer_signed_challenge_response = challenge_response_msg.payload.get("signature")
            if not peer_signed_challenge_response:
                logging.warning(f"[{self.node_id}] CHALLENGE_RESPONSE do peer {peer_address} não contém assinatura.")
                return False

            # Verifica se o peer assinou o desafio *original* que nós enviamos
            original_challenge_from_peer = challenge_response_msg.payload.get("original_challenge")
            if original_challenge_from_peer is None or original_challenge_from_peer != challenge.hex():
                logging.warning(f"[{self.node_id}] Desafio original inválido no CHALLENGE_RESPONSE de {peer_node_id} ({peer_address}).")
                return False

            # Valida a assinatura do peer usando sua chave pública
            is_valid = verify_signature(
                peer_public_key_pem.encode(),
                bytes.fromhex(original_challenge_from_peer),
                bytes.fromhex(peer_signed_challenge_response)
            )

            if not is_valid:
                logging.warning(f"[{self.node_id}] Assinatura inválida no CHALLENGE_RESPONSE de {peer_node_id} ({peer_address}). Handshake falhou.")
                return False

            logging.info(f"[{self.node_id}] Handshake seguro COMPLETO com {peer_node_id} ({peer_address}).")
            # Armazena o peer autenticado, incluindo sua chave pública
            self.peers[peer_node_id] = (reader, writer, peer_public_key_pem.encode())
            # Inicia a escuta de mensagens regulares deste peer em uma nova tarefa
            asyncio.create_task(self._listen_to_peer(reader, writer, peer_node_id))
            return True

        except asyncio.IncompleteReadError:
            logging.warning(f"[{self.node_id}] Peer {peer_address} desconectado durante o handshake seguro.")
        except Exception as e:
            logging.error(f"[{self.node_id}] Erro durante o handshake seguro com {peer_address}: {e}")
        finally:
            # Garante que a conexão seja fechada se o handshake falhar ou o peer não for adicionado
            if writer and not (peer_node_id in self.peers and self.peers[peer_node_id][1] == writer):
                logging.debug(f"[{self.node_id}] Fechando conexão com {peer_address} devido a falha no handshake.")
                writer.close()
                await writer.wait_closed()
        return False # Handshake falhou

    async def connect_to_peer(self, peer_host: str, peer_port: int) -> bool:
        """
        Conecta a um peer no host e porta fornecidos e realiza um handshake seguro
        baseado em troca de chaves públicas e autenticação de desafio-resposta.

        Args:
            peer_host (str): O endereço IP ou hostname do peer.
            peer_port (int): A porta do peer.

        Returns:
            bool: True se a conexão e o handshake forem bem-sucedidos, False caso contrário.
        """
        writer = None # Inicializa writer para garantir que seja fechado em caso de exceção
        peer_node_id = None # Inicializa peer_node_id para uso no bloco finally
        try:
            # Tenta abrir uma conexão com TLS usando o contexto de cliente
            reader, writer = await asyncio.open_connection(peer_host, peer_port, ssl=self.ssl_client_context)
            peer_address = writer.get_extra_info('peername')
            logging.info(f"[{self.node_id}] Tentando handshake seguro (com TLS) com {peer_host}:{peer_port} (conexão de saída).")

            # 1. Enviar nossa chave pública (PUBLIC_KEY_EXCHANGE)
            our_pk_exchange_msg = Message(
                message_type=MESSAGE_TYPE_PUBLIC_KEY_EXCHANGE,
                node_id=self.node_id,
                payload={"public_key": self._get_public_key_pem().decode()}
            )
            await self._send_protocol_message(writer, our_pk_exchange_msg)
            logging.debug(f"[{self.node_id}] Enviado PUBLIC_KEY_EXCHANGE para {peer_host}:{peer_port}.")

            # 2. Receber CHALLENGE do peer
            challenge_msg = await self._receive_protocol_message(reader, writer)
            if challenge_msg.type != MESSAGE_TYPE_CHALLENGE:
                logging.warning(f"[{self.node_id}] Recebido tipo de mensagem inesperado '{challenge_msg.type}' de {peer_host}:{peer_port}. Esperava CHALLENGE.")
                return False

            peer_public_key_pem = challenge_msg.payload.get("public_key")
            peer_challenge = challenge_msg.payload.get("challenge")
            peer_signed_challenge = challenge_msg.payload.get("signature")

            if not all([peer_public_key_pem, peer_challenge, peer_signed_challenge]):
                logging.warning(f"[{self.node_id}] CHALLENGE do peer {peer_host}:{peer_port} está incompleto.")
                return False

            # Deriva o NodeID do peer a partir da chave pública recebida
            peer_node_id = public_key_to_node_id(peer_public_key_pem.encode())
            logging.debug(f"[{self.node_id}] Recebido CHALLENGE de {peer_node_id} ({peer_host}:{peer_port}).")

            # Verificar a assinatura do desafio do peer usando a chave pública do peer
            is_valid_peer_signature = verify_signature(
                peer_public_key_pem.encode(),
                bytes.fromhex(peer_challenge),
                bytes.fromhex(peer_signed_challenge)
            )
            if not is_valid_peer_signature:
                logging.warning(f"[{self.node_id}] Assinatura inválida no CHALLENGE de {peer_node_id} ({peer_host}:{peer_port}). Handshake falhou.")
                return False

            # 3. Assinar o desafio do peer com nossa chave privada e enviar CHALLENGE_RESPONSE
            our_signed_response_to_challenge = sign_data(self._get_private_key_pem(), bytes.fromhex(peer_challenge))
            
            our_challenge_response_msg = Message(
                message_type=MESSAGE_TYPE_CHALLENGE_RESPONSE,
                node_id=self.node_id,
                payload={
                    "original_challenge": peer_challenge, # O desafio original que o peer nos enviou
                    "signature": our_signed_response_to_challenge.hex()
                }
            )
            await self._send_protocol_message(writer, our_challenge_response_msg)
            logging.debug(f"[{self.node_id}] Enviado CHALLENGE_RESPONSE para {peer_node_id} ({peer_host}:{peer_port}).")

            logging.info(f"[{self.node_id}] Handshake seguro COMPLETO com {peer_node_id} ({peer_host}:{peer_port}).")
            # Armazena o peer autenticado, incluindo sua chave pública
            self.peers[peer_node_id] = (reader, writer, peer_public_key_pem.encode())
            # Inicia a escuta de mensagens regulares deste peer em uma nova tarefa
            asyncio.create_task(self._listen_to_peer(reader, writer, peer_node_id))
            return True

        except ConnectionRefusedError:
            logging.warning(f"[{self.node_id}] Conexão recusada por {peer_host}:{peer_port}")
            return False
        except asyncio.IncompleteReadError:
            logging.warning(f"[{self.node_id}] Peer {peer_host}:{peer_port} desconectado durante o handshake seguro.")
            return False
        except Exception as e:
            logging.error(f"[{self.node_id}] Erro durante o handshake seguro com {peer_host}:{peer_port}: {e}")
            return False
        finally:
            # Garante que a conexão seja fechada se o handshake falhar ou o peer não for adicionado
            if writer and not (peer_node_id in self.peers and self.peers[peer_node_id][1] == writer):
                logging.debug(f"[{self.node_id}] Fechando conexão com {peer_host}:{peer_port} devido a falha no handshake.")
                writer.close()
                await writer.wait_closed()

    async def _listen_to_peer(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer_node_id: str):
        """
        Escuta mensagens de um peer conectado.

        Args:
            reader (asyncio.StreamReader): O leitor da conexão do peer.
            writer (asyncio.StreamWriter): O escritor da conexão do peer.
            peer_node_id (str): O NodeID do peer conectado.
        """
        try:
            while True:
                # Use _receive_protocol_message para ler mensagens completas
                message = await self._receive_protocol_message(reader, writer)
                logging.info(f"[{self.node_id}] Recebido {message.type} message de {peer_node_id}")
                
                # Despacha a mensagem para o manipulador apropriado
                handler = MessageHandlerFactory.get_handler(message.type)
                await handler.handle_message(self, message, writer)

        except asyncio.IncompleteReadError:
            logging.info(f"[{self.node_id}] Peer {peer_node_id} desconectado (conexão fechada).")
        except Exception as e:
            logging.error(f"[{self.node_id}] Erro ao escutar peer {peer_node_id}: {e}")
        finally:
            logging.info(f"[{self.node_id}] Peer {peer_node_id} desconectado.")
            if peer_node_id in self.peers:
                del self.peers[peer_node_id]
            writer.close()
            await writer.wait_closed()

    async def send_message(self, peer_node_id: str, message: Message):
        """
        Envia uma mensagem para um peer conectado específico.

        Args:
            peer_node_id (str): O ID do nó do peer destinatário.
            message (Message): O objeto Message a ser enviado.
        """
        if peer_node_id in self.peers:
            reader, writer, _ = self.peers[peer_node_id] # Desempacota a tupla, ignorando a chave pública por enquanto
            try:
                # Adiciona um caractere de nova linha para delimitar mensagens
                message_json = message.to_json() + '\n'
                writer.write(message_json.encode())
                await writer.drain()
                logging.info(f"[{self.node_id}] Enviado {message.type} para {peer_node_id}")
            except Exception as e:
                logging.error(f"[{self.node_id}] Erro ao enviar mensagem para {peer_node_id}: {e}")
                # Opcionalmente, limpa a conexão se o envio falhar
                writer.close()
                await writer.wait_closed()
                if peer_node_id in self.peers:
                    del self.peers[peer_node_id]
        else:
            logging.warning(f"[{self.node_id}] Peer {peer_node_id} não encontrado. Mensagem não enviada.")

    async def _send_peer_list_periodically(self):
        """
        Envia periodicamente uma mensagem 'peer_list' para todos os peers conectados,
        informando-os sobre os peers conhecidos do nó.
        """
        while True:
            await asyncio.sleep(30) # Envia a cada 30 segundos

            if not self.peers:
                logging.debug(f"[{self.node_id}] Nenhum peer para enviar peer_list.")
                continue

            known_peers_info = []
            for peer_node_id, (reader, writer, peer_public_key_pem) in self.peers.items():
                try:
                    peername = writer.get_extra_info('peername')
                    known_peers_info.append({
                        "node_id": peer_node_id,
                        "host": peername[0],
                        "port": peername[1],
                        "public_key": peer_public_key_pem.decode() # Inclui a chave pública do peer
                    })
                except Exception as e:
                    logging.warning(f"[{self.node_id}] Erro ao obter informações do peer {peer_node_id}: {e}")

            peer_list_message = Message(
                message_type=MESSAGE_TYPE_PEER_LIST,
                node_id=self.node_id,
                payload={"peers": known_peers_info}
            )

            logging.info(f"[{self.node_id}] Enviando peer_list para {len(self.peers)} peers.")
            for peer_node_id in list(self.peers.keys()):
                await self.send_message(peer_node_id, peer_list_message)

    async def request_app_content(self, app_hash: str, timeout: int = 60) -> bool:
        """
        Solicita o conteúdo de uma aplicação específica a peers conectados.
        Bloqueia até que o conteúdo seja baixado ou o tempo limite seja atingido.

        Args:
            app_hash (str): O hash da aplicação a ser solicitada.
            timeout (int): Tempo em segundos para aguardar o download.

        Returns:
            bool: True se o download for bem-sucedido, False caso contrário.
        """
        if self.app_storage.app_exists_locally(app_hash):
            logging.info(f"[{self.node_id}] Aplicação {app_hash[:8]}... já existe localmente.")
            return True

        # Prepara o evento de download
        if app_hash in self.app_download_events:
            logging.info(f"[{self.node_id}] Download para {app_hash[:8]}... já em andamento. Aguardando evento existente.")
            event = self.app_download_events[app_hash]
        else:
            event = asyncio.Event()
            self.app_download_events[app_hash] = event
            logging.info(f"[{self.node_id}] Iniciando solicitação P2P para aplicação {app_hash[:8]}...")

            request_message = Message(
                message_type=MESSAGE_TYPE_APP_REQUEST,
                node_id=self.node_id,
                payload={"app_hash": app_hash}
            )

            # Envia a solicitação para todos os peers conectados
            if not self.peers:
                logging.warning(f"[{self.node_id}] Não há peers conectados para solicitar {app_hash[:8]}...")
                del self.app_download_events[app_hash]
                return False

            send_tasks = [self.send_message(peer_id, request_message) for peer_id in self.peers.keys()]
            # Não precisamos aguardar a conclusão do envio, apenas que a solicitação seja feita
            asyncio.gather(*send_tasks)

        try:
            logging.info(f"[{self.node_id}] Aguardando download de {app_hash[:8]}... (timeout: {timeout}s)")
            await asyncio.wait_for(event.wait(), timeout=timeout)
            logging.info(f"[{self.node_id}] Download de {app_hash[:8]}... concluído via P2P.")
            return True
        except asyncio.TimeoutError:
            logging.warning(f"[{self.node_id}] Tempo limite ({timeout}s) excedido para download de {app_hash[:8]}...")
            return False
        finally:
            # Garante que o evento seja limpo, mesmo se o download falhar ou for bem-sucedido
            if app_hash in self.app_download_events:
                del self.app_download_events[app_hash]

    async def announce_app_to_p2p(self, app_hash: str, app_meta: AppMetadata, signature_hex: str):
        """
        Anuncia uma aplicação (nova ou atualizada) para todos os peers conectados.

        Args:
            app_hash (str): O hash SHA-256 do conteúdo da aplicação.
            app_meta (AppMetadata): O objeto AppMetadata da aplicação.
            signature_hex (str): A assinatura hexadecimal dos metadados da aplicação pelo autor.
        """
        logging.info(f"[{self.node_id}] Anunciando aplicação '{app_meta.name}' ({app_hash[:8]}...) para a rede P2P.")

        announce_message = Message(
            message_type=MESSAGE_TYPE_APP_ANNOUNCE,
            node_id=self.node_id,
            payload={
                "app_hash": app_hash,
                "metadata": app_meta.to_dict(),
                "signature": signature_hex
            }
        )

        if not self.peers:
            logging.warning(f"[{self.node_id}] Não há peers conectados para anunciar a aplicação '{app_meta.name}'.")
            return

        send_tasks = [self.send_message(peer_id, announce_message) for peer_id in self.peers.keys()]
        # Agrupar e enviar as tarefas de envio em paralelo
        await asyncio.gather(*send_tasks)
        logging.info(f"[{self.node_id}] Anúncio da aplicação '{app_meta.name}' enviado para {len(self.peers)} peers.")

    def get_address(self):
        """
        Retorna o host e a porta do nó para conexões P2P.

        Returns:
            tuple[str, int]: Uma tupla contendo (host, port).
        """
        return self.host, self.port

    def get_id(self):
        """
        Retorna o identificador único (NodeID) do nó.

        Returns:
            str: O NodeID do nó.
        """
        return self.node_id
