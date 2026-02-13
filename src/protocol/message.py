# protocol/message.py
"""
Módulo `message`

Este módulo define a estrutura padrão para mensagens trocadas dentro da rede P2P SkyNet.
Todas as comunicações entre nós são encapsuladas nesta estrutura `Message`,
que suporta serialização e desserialização para o formato JSON.

A padronização das mensagens é crucial para a interoperabilidade e para
facilitar o roteamento e o processamento de diferentes tipos de informações
na rede.
"""
import json
import logging

# Define os tipos de mensagem como constantes para consistência e clareza
MESSAGE_TYPE_HELLO = "hello" # Mensagem de saudação (legada do handshake simples)
MESSAGE_TYPE_PEER_LIST = "peer_list" # Compartilhamento de lista de peers conhecidos
MESSAGE_TYPE_CHAT = "chat" # Mensagem de chat genérica
MESSAGE_TYPE_PUBLIC_KEY_EXCHANGE = "public_key_exchange" # Troca de chave pública durante o handshake seguro
MESSAGE_TYPE_CHALLENGE = "challenge" # Envio de desafio criptográfico durante o handshake
MESSAGE_TYPE_CHALLENGE_RESPONSE = "challenge_response" # Resposta a um desafio criptográfico

# Novos tipos de mensagem para gerenciamento de aplicações
MESSAGE_TYPE_APP_ANNOUNCE = "app_announce" # Anúncio de uma nova aplicação ou atualização
MESSAGE_TYPE_APP_REQUEST = "app_request"   # Solicitação de conteúdo de aplicação por hash
MESSAGE_TYPE_APP_RESPONSE = "app_response" # Resposta contendo o conteúdo de uma aplicação

class Message:
    """
    Representa uma mensagem padronizada na rede P2P SkyNet.

    Mensagens são estruturadas em formato JSON e contêm um tipo (`type`),
    um identificador do nó remetente (`node_id`) e um payload (`payload`)
    que carrega os dados específicos da mensagem.
    """
    def __init__(self, message_type: str, node_id: str, payload: dict = None):
        """
        Inicializa um objeto Message.

        Args:
            message_type (str): O tipo da mensagem (ex: 'hello', 'peer_list', 'chat', 'app_announce').
            node_id (str): O ID do nó remetente da mensagem.
            payload (dict, optional): Um dicionário contendo o conteúdo específico da mensagem.
                                     Padrão para um dicionário vazio se não for fornecido.

        Raises:
            ValueError: Se message_type ou node_id forem strings vazias.
            TypeError: Se payload não for um dicionário ou None.
        """
        if not isinstance(message_type, str) or not message_type:
            raise ValueError("message_type deve ser uma string não vazia.")
        if not isinstance(node_id, str) or not node_id:
            raise ValueError("node_id deve ser uma string não vazia.")
        if payload is not None and not isinstance(payload, dict):
            raise TypeError("payload deve ser um dicionário ou None.")

        self.type = message_type
        self.node_id = node_id
        self.payload = payload if payload is not None else {}

    def to_json(self) -> str:
        """
        Serializa o objeto Message para uma string JSON.

        Returns:
            str: A representação JSON da mensagem.

        Raises:
            TypeError: Se houver um erro durante a serialização para JSON.
        """
        try:
            return json.dumps({
                "type": self.type,
                "node_id": self.node_id,
                "payload": self.payload
            })
        except TypeError as e:
            logging.error(f"Erro ao serializar mensagem para JSON: {e}")
            raise

    @staticmethod
    def from_json(json_string: str):
        """
        Desserializa uma string JSON para um objeto Message.

        Args:
            json_string (str): A string JSON a ser desserializada.

        Returns:
            Message: Um objeto Message construído a partir da string JSON.

        Raises:
            json.JSONDecodeError: Se a string não for um JSON válido.
            KeyError, ValueError: Se a string JSON não contiver os campos esperados ou estiver mal formatada.
        """
        try:
            data = json.loads(json_string)
            message_type = data.get("type")
            node_id = data.get("node_id")
            payload = data.get("payload")
            return Message(message_type, node_id, payload)
        except json.JSONDecodeError as e:
            logging.error(f"Erro ao decodificar mensagem JSON: {e}")
            raise
        except (KeyError, ValueError) as e:
            logging.error(f"Formato de mensagem inválido: {e}, dados: {json_string}")
            raise

    def __str__(self):
        """
        Retorna uma representação em string legível da mensagem.
        """
        return f"Message(type={self.type}, node_id={self.node_id}, payload={self.payload})"

    def __repr__(self):
        """
        Retorna uma representação de debug da mensagem.
        """
        return self.__str__()
