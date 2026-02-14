# Plano de Implementação de Recursos da Rede P2P

Este documento detalha o plano de implementação dos novos recursos para a rede P2P, baseando-se nas funcionalidades e requisitos definidos nos documentos "artigo-funcionalidades.txt" e "requisitos.txt".

## 1. Visão Geral

O objetivo principal é expandir as capacidades de comunicação da rede P2P, introduzindo comunicação de broadcast e ponto-a-ponto aprimorada, juntamente com um gerenciamento mais robusto de mensagens e peers, e fortalecendo a segurança geral do sistema.

## 2. Requisitos Prioritários

As funcionalidades de **Broadcast**, **Envio Direto (Send)**, **Manipulação de Mensagens (Handler)** e **Segurança e Identidade** são classificadas com **Prioridade Alta**. A funcionalidade de **Lista de Peers Dinâmica** tem **Prioridade Média**, mas será integrada aos demais para garantir um sistema coeso.

## 3. Plano Detalhado de Implementação

### 3.1. Refatoração e Melhorias de Base (Pronto para iniciar)

*   **Revisão do `protocol/message.py`:** Adicionar novos tipos de mensagem conforme necessário (ex: `MESSAGE_TYPE_BROADCAST`, `MESSAGE_TYPE_DIRECT_SEND`, `MESSAGE_TYPE_ACK`).
*   **Aprimoramento do `Node` (`core/node.py`):**
    *   Métodos auxiliares para gerenciamento de peers (adicionar, remover, buscar por ID).
    *   Mecanismo para armazenar IDs de mensagens de broadcast já processadas (`self.processed_broadcast_messages`).

### 3.2. Implementação do Handler de Mensagens (RF5, RF6, RNF3, RF9)

**Objetivo:** Criar um sistema flexível e robusto para processar todos os tipos de mensagens recebidas, com validação de segurança integrada.

*   **`protocol/handler.py`:**
    *   **Atualizar `MessageHandlerFactory`:** Adicionar novos manipuladores para os tipos de mensagem Broadcast, Direct Send, Acknowledge, etc.
    *   **`BaseMessageHandler` (ou similar):** Implementar lógica comum de validação de assinatura e verificação de `Node ID` antes de despachar para manipuladores específicos.
    *   **`BroadcastMessageHandler`:**
        *   Verificar assinatura do emissor.
        *   Checar `self.processed_broadcast_messages` para evitar loops (RF2).
        *   Propagar a mensagem para peers não processados (RF2).
        *   Disparar callback para a aplicação do nó.
    *   **`DirectSendMessageHandler`:**
        *   Verificar assinatura do emissor.
        *   Disparar callback para a aplicação do nó.
        *   Enviar `MESSAGE_TYPE_ACK` de volta ao emissor (RF4).
    *   **`AcknowledgeMessageHandler`:**
        *   Processar confirmação de recebimento para `Direct Send`.
        *   Limpar estado de mensagem pendente de `ACK`.

### 3.3. Implementação do Broadcast de Mensagem (RF1, RF2, RNF1)

**Objetivo:** Permitir que um nó envie eficientemente uma mensagem para todos os nós da rede.

*   **`Node` (`core/node.py`):**
    *   **`broadcast(self, message: Message)` método:**
        *   Gerar `ID` único para a mensagem.
        *   Assinar a mensagem com a chave privada do nó.
        *   Enviar a mensagem para todos os peers conectados do nó.
        *   Integrar com `BroadcastMessageHandler` para propagação eficiente.

### 3.4. Implementação do Envio Direto (Send) (RF3, RF4, RNF2)

**Objetivo:** Fornecer um mecanismo seguro e confiável para comunicação ponto-a-ponto.

*   **`Node` (`core/node.py`):**
    *   **`send_direct_message(self, target_node_id: str, message: Message)` método:**
        *   Localizar `reader/writer` para `target_node_id` ou estabelecer nova conexão.
        *   Assinar a mensagem.
        *   Enviar `MESSAGE_TYPE_DIRECT_SEND`.
        *   Implementar mecanismo de retransmissão e espera por `ACK` (RF4).
    *   **`_send_with_ack(self, writer, message: Message, timeout=5)` método auxiliar:**
        *   Enviar mensagem e esperar por `ACK` ou retransmitir.

### 3.5. Aprimoramento da Lista de Peers Dinâmica (RF7, RF8, RNF4)

**Objetivo:** Manter uma lista de peers ativos e atualizada para otimizar a conectividade.

*   **`Node` (`core/node.py`):**
    *   **Atualizar `_send_peer_list_periodically`:** Incluir o próprio `Node ID` e endereço no `payload`.
    *   **Atualizar `PeerListMessageHandler`:**
        *   Ao receber `peer_list`, mesclar com a lista local.
        *   Usar `TLS` para validar peers (RF9, RNF4).
    *   **Mecanismo de detecção de inatividade:**
        *   Monitorar conexões (ex: se `writer.write()` falha, marcar peer como inativo).
        *   Remover peers inativos periodicamente (RF8).

### 3.6. Fortalecimento da Segurança e Identidade (RF9, RF10, RNF5)

**Objetivo:** Garantir a autenticidade, integridade e confidencialidade das comunicações.

*   **`Node` (`core/node.py`) e `protocol/handler.py`:**
    *   Garantir que todas as mensagens (Broadcast, Direct Send) sejam assinadas pelo emissor e verificadas pelo receptor usando a chave pública do `Node ID` do emissor (RF9).
    *   **Mecanismo de Blacklist/Whitelist (RF10):**
        *   Adicionar uma lista `self.blacklist` ao `Node`.
        *   `MessageHandler` deve consultar a blacklist para rejeitar mensagens.
    *   Confidencialidade: Já coberta por `TLS/RSA` para todas as conexões P2P (RNF5).

## 4. Próximos Passos (Iteração 1)

1.  **Refatorar `protocol/message.py`:** Adicionar novos tipos de mensagem.
2.  **Criar `BroadcastMessageHandler` e `DirectSendMessageHandler`** em `protocol/handler.py` com validação de assinatura inicial.
3.  **Implementar `Node.broadcast()`:** Foco no envio e propagação inicial.
4.  **Ajustar `PeerListMessageHandler`:** Para usar `public_key_to_node_id` e mesclar com lógica de detecção de peers.

## 5. Considerações Finais

*   **Testes:** Cada funcionalidade implementada deve ser acompanhada de testes unitários e de integração.
*   **Logging:** Manter logging detalhado para facilitar depuração.
*   **Modularidade:** Manter a estrutura modular, separando responsabilidades.
