# protocol/handler.py
"""
Módulo `handler`

Este módulo define a arquitetura de manipuladores de mensagens para a rede P2P SkyNet.
Utiliza o padrão Strategy para processar diferentes tipos de mensagens recebidas
pelos nós, desacoplando a lógica de processamento do mecanismo de transporte.

Cada classe que herda de `MessageHandler` é responsável por processar um
tipo específico de mensagem P2P, como mensagens de saudação, listas de peers,
chat ou, mais recentemente, mensagens relacionadas ao ciclo de vida de aplicações
(anúncios, requisições e respostas de conteúdo).
"""
from abc import ABC, abstractmethod
import logging
import asyncio # Para tasks e sleeps
from typing import Dict, Any # Para tipagem de payloads

from protocol.message import Message, MESSAGE_TYPE_HELLO, MESSAGE_TYPE_PEER_LIST, MESSAGE_TYPE_CHAT, MESSAGE_TYPE_APP_ANNOUNCE, MESSAGE_TYPE_APP_REQUEST, MESSAGE_TYPE_APP_RESPONSE
from models.app_metadata import AppMetadata
from storage.app_storage import AppStorage
from storage.app_processor import AppProcessor
from crypto.keys import public_key_to_node_id # Adicionado importação para public_key_to_node_id

class MessageHandler(ABC):
    """
    Classe base abstrata para todos os manipuladores de mensagens.
    Define a interface comum para processar diferentes tipos de mensagens.
    """
    @abstractmethod
    async def handle_message(self, node, message: Message, writer):
        """
        Processa uma dada mensagem.
        Este método deve ser implementado por todas as classes de manipuladores concretas.

        Args:
            node: A instância do nó P2P que recebeu a mensagem.
            message (Message): O objeto Message a ser manipulado.
            writer: O asyncio.StreamWriter conectado ao remetente da mensagem,
                    usado para enviar respostas diretas.
        """
        pass

class HelloMessageHandler(MessageHandler):
    """
    Manipula mensagens do tipo 'hello'.

    Atualmente, esta mensagem é considerada legada devido à introdução
    do handshake seguro com TLS e desafio-resposta. Ela serve principalmente
    para fins de logging ou compatibilidade com versões antigas, mas não
    participa mais do processo de estabelecimento de conexão.
    """
    async def handle_message(self, node, message: Message, writer):
        logging.info(f"[{node.node_id}] Recebido 'hello' (legado) de {message.node_id}. Este tipo de mensagem deve ser descontinuado.")
        # O handshake seguro agora gerencia a conexão e a adição de peers.
        # Esta mensagem é tratada apenas para compatibilidade ou para logging de mensagens antigas.
        pass

class PeerListMessageHandler(MessageHandler):
    """
    Manipula mensagens do tipo 'peer_list'.

    Extrai informações sobre peers conhecidos de uma mensagem e tenta
    se conectar a novos peers descobertos, usando o handshake seguro.
    Também verifica a consistência entre o `peer_id` e a chave pública anunciada.
    """
    async def handle_message(self, node, message: Message, writer):
        logging.info(f"[{node.node_id}] Recebido peer_list de {message.node_id}")
        peers_data = message.payload.get("peers", [])
        for peer_info in peers_data:
            peer_id = peer_info.get("node_id")
            peer_host = peer_info.get("host")
            peer_port = peer_info.get("port")
            peer_public_key = peer_info.get("public_key") # Chave pública incluída agora para validação

            if peer_id and peer_host and peer_port and peer_public_key:
                # Verificar se o peer_id corresponde à chave pública fornecida
                expected_peer_id = public_key_to_node_id(peer_public_key.encode())
                if expected_peer_id != peer_id:
                    logging.warning(f"[{node.node_id}] Peer na lista {peer_id} com chave pública inconsistente. Ignorando.")
                    continue

                if peer_id == node.node_id:
                    continue # Um nó não deve tentar se conectar a si mesmo
                
                # Verifica se o nó já está conectado a este peer ou se uma conexão já está sendo tentada
                if peer_id not in node.peers:
                    logging.info(f"[{node.node_id}] Novo peer {peer_id} descoberto em {peer_host}:{peer_port}. Tentando conectar...")
                    # A conexão agora usará o handshake seguro com TLS
                    asyncio.create_task(node.connect_to_peer(peer_host, peer_port))
                else:
                    logging.debug(f"[{node.node_id}] Já conectado ou processando peer {peer_id}.")
            else:
                logging.warning(f"[{node.node_id}] Informação de peer inválida em peer_list: {peer_info}")

class ChatMessageHandler(MessageHandler):
    """
    Manipula mensagens do tipo 'chat'.
    Exibe a mensagem de chat para o usuário (via CLI, se disponível no nó).
    """
    async def handle_message(self, node, message: Message, writer):
        chat_text = message.payload.get("text", "")
        if chat_text:
            full_message = f"[{message.node_id}]: {chat_text}"
            logging.info(f"[{node.node_id}] Recebido chat: {full_message}")
            if hasattr(node, 'cli') and node.cli: # Verifica se o nó tem uma interface CLI para exibir a mensagem
                node.cli.display_message(full_message)
        else:
            logging.warning(f"[{node.node_id}] Recebida mensagem de chat vazia de {message.node_id}")

class AppAnnounceMessageHandler(MessageHandler):
    """
    Manipula mensagens de anúncio de aplicação (APP_ANNOUNCE).
    Esta é a lógica central para o gerenciamento e atualização automática de aplicações.
    Valida a assinatura dos metadados, gerencia versões e aciona downloads se necessário.
    """
    def __init__(self):
        # Os serviços de armazenamento, índice e processamento de apps são acessados via a instância do nó.
        pass

    async def handle_message(self, node, message: Message, writer):
        logging.info(f"[{node.node_id}] Recebido APP_ANNOUNCE de {message.node_id} para app_hash: {message.payload.get('app_hash')}")
        
        try:
            metadata_dict = message.payload.get("metadata")
            signature_hex = message.payload.get("signature")
            app_hash = message.payload.get("app_hash")

            # Validação inicial do payload
            if not all([metadata_dict, signature_hex, app_hash]):
                logging.warning(f"[{node.node_id}] APP_ANNOUNCE incompleto de {message.node_id}. Ignorando.")
                return

            # 1. Reconstruir AppMetadata e verificar assinatura
            metadata = AppMetadata.from_dict(metadata_dict)
            if metadata.app_hash is None:
                metadata.app_hash = app_hash # Garante que a metadata tenha o hash correto
            elif metadata.app_hash != app_hash:
                logging.warning(f"[{node.node_id}] APP_ANNOUNCE de {message.node_id} com app_hash inconsistente na metadata. Ignorando.")
                return

            # Verifica a autenticidade do anúncio usando a chave pública do autor
            if not metadata.verify_signature(bytes.fromhex(signature_hex)):
                logging.warning(f"[{node.node_id}] Assinatura inválida para APP_ANNOUNCE de {message.node_id}. Ignorando.")
                return

            logging.info(f"[{node.node_id}] Anúncio válido para '{metadata.name}' ({app_hash[:8]}) de {metadata.author_public_key[:8]}...")

            # 2. Lógica de atualização automática e controle de "versão única ativa"
            existing_active_app = None
            # Procura por uma versão ativa existente da mesma aplicação (mesmo nome/autor)
            for existing_hash, existing_meta in node.app_index.index.items():
                if existing_meta.name == metadata.name and \
                   existing_meta.author_public_key == metadata.author_public_key and \
                   existing_meta.active:
                    existing_active_app = existing_meta
                    break
            
            is_new_app_family = True # Assume que é uma app completamente nova ou a primeira versão ativa da família
            if existing_active_app:
                is_new_app_family = False
                # Se o hash do anúncio for o mesmo da versão ativa local, é redundante
                if existing_active_app.app_hash == app_hash:
                    logging.info(f"[{node.node_id}] Já possuímos a versão ativa mais recente de '{metadata.name}' ({app_hash[:8]}). Ignorando anúncio redundante.")
                    return # Não faz nada se já tem a versão ativa mais recente
                # Se o anúncio for de uma versão mais nova (baseado no timestamp)
                elif metadata.timestamp > existing_active_app.timestamp:
                    logging.info(f"[{node.node_id}] Nova versão de '{metadata.name}' ({app_hash[:8]}) encontrada. Versão antiga ({existing_active_app.app_hash[:8]}) será desativada.")
                    
                    # Desativa a versão antiga no índice
                    node.app_index.update_application_status(existing_active_app.app_hash, False)
                    # O conteúdo da versão antiga será removido *após* o download da nova para evitar interrupções

                    # Salva os metadados da nova versão e a adiciona ao índice (já ativa por padrão)
                    node.app_storage.save_app_metadata(app_hash, metadata.to_dict())
                    node.app_storage.save_app_signature(app_hash, bytes.fromhex(signature_hex))
                    node.app_index.add_application(app_hash, metadata) # Isso já marca como ativa

                    # Solicita o download do conteúdo da nova versão via P2P
                    download_success = await node.request_app_content(app_hash)
                    if download_success:
                        logging.info(f"[{node.node_id}] Nova versão de '{metadata.name}' ({app_hash[:8]}) baixada e ativada.")
                        # Remove o conteúdo da versão antiga para liberar espaço
                        node.app_storage.delete_app(existing_active_app.app_hash)
                        logging.info(f"[{node.node_id}] Conteúdo da versão antiga {existing_active_app.app_hash[:8]}... de '{metadata.name}' removido.")
                    else:
                        logging.warning(f"[{node.node_id}] Falha ao baixar a nova versão {app_hash[:8]}... de '{metadata.name}'. Tentando reativar versão antiga.")
                        # Tenta reativar a versão antiga se o download da nova falhar
                        node.app_index.update_application_status(existing_active_app.app_hash, True)
                        node.app_storage.delete_app(app_hash) # Limpa metadados e assinatura da nova versão incompleta
                        return # Aborta o processamento deste anúncio
                else:
                    logging.info(f"[{node.node_id}] Anúncio de '{metadata.name}' ({app_hash[:8]}) é uma versão mais antiga ou igual. Ignorando.")
                    return # Ignora anúncios de versões mais antigas ou redundantes
            
            # Se é uma app completamente nova ou uma atualização de uma versão inativa/removida
            if is_new_app_family and metadata.active: 
                # Salva os metadados e a assinatura
                node.app_storage.save_app_metadata(app_hash, metadata.to_dict())
                node.app_storage.save_app_signature(app_hash, bytes.fromhex(signature_hex))
                node.app_index.add_application(app_hash, metadata) # Adiciona e marca como ativa

                # Solicita o download do conteúdo
                download_success = await node.request_app_content(app_hash)
                if download_success:
                    logging.info(f"[{node.node_id}] Nova aplicação '{metadata.name}' ({app_hash[:8]}) baixada e ativada.")
                else:
                    logging.warning(f"[{node.node_id}] Falha ao baixar a nova aplicação {app_hash[:8]}... de '{metadata.name}'. Removendo do índice.")
                    node.app_index.remove_application(app_hash) # Remove do índice se o download falhar
                    node.app_storage.delete_app(app_hash) # Limpa arquivos associados
                    return # Aborta o processamento

            # TODO: Considerar propagar este anúncio para outros peers para acelerar a disseminação.

        except Exception as e:
            logging.error(f"[{node.node_id}] Erro ao processar APP_ANNOUNCE de {message.node_id}: {e}")

class AppRequestMessageHandler(MessageHandler):
    """
    Manipula mensagens de solicitação de aplicação (APP_REQUEST).
    Verifica o armazenamento local e envia o conteúdo da aplicação se disponível
    de volta ao solicitante.
    """
    def __init__(self):
        # Os serviços de armazenamento e processamento de apps são acessados via a instância do nó.
        pass

    async def handle_message(self, node, message: Message, writer):
        logging.info(f"[{node.node_id}] Recebido APP_REQUEST de {message.node_id} para app_hash: {message.payload.get('app_hash')}")

        requested_app_hash = message.payload.get("app_hash")
        if not requested_app_hash:
            logging.warning(f"[{node.node_id}] APP_REQUEST incompleto de {message.node_id}. Ignorando.")
            return

        # Verifica se o conteúdo da aplicação está disponível localmente
        app_content = node.app_storage.load_app_content(requested_app_hash)

        if app_content:
            logging.info(f"[{node.node_id}] Conteúdo da aplicação {requested_app_hash[:8]}... encontrado localmente. Enviando APP_RESPONSE.")
            response_message = Message(
                message_type=MESSAGE_TYPE_APP_RESPONSE,
                node_id=node.node_id,
                payload={
                    "app_hash": requested_app_hash,
                    "content": app_content.hex() # Envia conteúdo em formato hexadecimal para evitar problemas de codificação
                }
            )
            # Usa _send_protocol_message para enviar a resposta ao writer específico
            await node._send_protocol_message(writer, response_message)
        else:
            logging.info(f"[{node.node_id}] Conteúdo da aplicação {requested_app_hash[:8]}... NÃO encontrado localmente. Não foi possível responder.")
            # Opcional: Enviar uma resposta negativa específica ou simplesmente não responder (o cliente eventualmente fará timeout)

class AppResponseMessageHandler(MessageHandler):
    """
    Manipula mensagens de resposta de aplicação (APP_RESPONSE).
    Salva o conteúdo da aplicação recebido e verifica seu hash para integridade.
    Sinaliza a conclusão do download para tarefas que estavam aguardando.
    """
    def __init__(self):
        # Os serviços de armazenamento e processamento de apps são acessados via a instância do nó.
        pass

    async def handle_message(self, node, message: Message, writer):
        logging.info(f"[{node.node_id}] Recebido APP_RESPONSE de {message.node_id} para app_hash: {message.payload.get('app_hash')}")

        app_hash = message.payload.get("app_hash")
        content_hex = message.payload.get("content")

        # Validação inicial do payload
        if not all([app_hash, content_hex]):
            logging.warning(f"[{node.node_id}] APP_RESPONSE incompleto de {message.node_id}. Ignorando.")
            return

        app_content = bytes.fromhex(content_hex)
        
        # 1. Verificar o hash do conteúdo recebido para garantir integridade
        generated_hash = node.app_processor.generate_app_hash(app_content)
        if generated_hash != app_hash:
            logging.warning(f"[{node.node_id}] Hash do conteúdo recebido ({generated_hash[:8]}...) NÃO corresponde ao app_hash esperado ({app_hash[:8]}...). Possível corrupção ou adulteração. Ignorando.")
            return

        # 2. Salvar o conteúdo no armazenamento local
        node.app_storage.save_app_content(app_hash, app_content)
        logging.info(f"[{node.node_id}] Conteúdo da aplicação {app_hash[:8]}... salvo localmente e hash verificado.")

        # Notificar o nó de que o download foi concluído, sinalizando o asyncio.Event
        if app_hash in node.app_download_events:
            event = node.app_download_events[app_hash]
            event.set() # Sinaliza que o download foi concluído
            logging.info(f"[{node.node_id}] Evento de download para {app_hash[:8]}... setado.")
        else:
            logging.warning(f"[{node.node_id}] Evento de download para {app_hash[:8]}... não encontrado no Node. Pode ser uma resposta para uma requisição não iniciada.")

        # O conteúdo descompactado para servir será feito sob demanda pelo WebServer (Task 13),
        # ou pela lógica de atualização que descompacta para verificar integridade antes de servir.