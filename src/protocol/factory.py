# protocol/factory.py
"""
Módulo `factory`

Este módulo implementa o padrão Factory (`MessageHandlerFactory`) para criar
e fornecer instâncias apropriadas de manipuladores de mensagens (`MessageHandler`)
com base no tipo de mensagem recebida na rede P2P SkyNet.

A centralização da lógica de criação de manipuladores aqui garante que cada
tipo de mensagem seja direcionado ao seu processador específico de forma
organizada e extensível.
"""
from protocol.handler import (
    HelloMessageHandler,
    PeerListMessageHandler,
    ChatMessageHandler,
    AppAnnounceMessageHandler,
    AppRequestMessageHandler,
    AppResponseMessageHandler,
    MessageHandler # Importação da classe base abstrata
)
from protocol.message import (
    MESSAGE_TYPE_HELLO,
    MESSAGE_TYPE_PEER_LIST,
    MESSAGE_TYPE_CHAT,
    MESSAGE_TYPE_APP_ANNOUNCE,
    MESSAGE_TYPE_APP_REQUEST,
    MESSAGE_TYPE_APP_RESPONSE
)
import logging

class MessageHandlerFactory:
    """
    Classe Factory para criar instâncias apropriadas de MessageHandler
    com base no tipo de mensagem.

    Mantém um registro de todos os manipuladores disponíveis e retorna
    o manipulador correto para um dado tipo de mensagem.
    """
    _handlers = {
        MESSAGE_TYPE_HELLO: HelloMessageHandler(),
        MESSAGE_TYPE_PEER_LIST: PeerListMessageHandler(),
        MESSAGE_TYPE_CHAT: ChatMessageHandler(),
        MESSAGE_TYPE_APP_ANNOUNCE: AppAnnounceMessageHandler(),
        MESSAGE_TYPE_APP_REQUEST: AppRequestMessageHandler(),
        MESSAGE_TYPE_APP_RESPONSE: AppResponseMessageHandler(),
    }

    @classmethod
    def get_handler(cls, message_type: str) -> MessageHandler:
        """
        Retorna uma instância de MessageHandler para o tipo de mensagem fornecido.

        Args:
            message_type (str): O tipo da mensagem para a qual um manipulador é solicitado.

        Returns:
            MessageHandler: Uma instância do manipulador de mensagens correspondente.

        Raises:
            ValueError: Se nenhum manipulador estiver registrado para o tipo de mensagem fornecido.
        """
        handler = cls._handlers.get(message_type)
        if not handler:
            logging.error(f"[{cls.__name__}] Nenhum manipulador registrado para o tipo de mensagem: {message_type}")
            raise ValueError(f"Nenhum manipulador registrado para o tipo de mensagem: {message_type}")
        return handler
