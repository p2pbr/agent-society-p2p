# src/web/server.py
"""
Módulo `server`

Este módulo implementa o servidor HTTP local (`WebServer`) que atua como
a interface para o usuário final interagir com a rede P2P SkyNet.
Ele é responsável por servir aplicações web estáticas diretamente no navegador,
garantindo que o acesso ocorra exclusivamente via `localhost` por razões de segurança.

O `WebServer` integra-se com a funcionalidade do nó P2P para:
- Listar aplicações disponíveis no índice local.
- Buscar aplicações por metadados.
- Servir o conteúdo de aplicações (baixando-o via P2P sob demanda, se necessário).
- Receber requisições para publicação de novas aplicações na rede.

A segurança das aplicações servidas é aprimorada com a inclusão de
Content Security Policies (CSP) em todas as respostas HTTP.
"""
import asyncio
import logging
from typing import Dict, Any, Tuple, List
from urllib.parse import urlparse, parse_qs
from pathlib import Path # Para manipular caminhos de arquivos estáticos
import mimetypes # Para determinar o tipo de conteúdo de arquivos estáticos
import json # Para lidar com corpos POST JSON

# Importações para funcionalidades que o servidor precisará, acessadas via a instância do Node
from storage.app_storage import AppStorage
from storage.app_index import AppIndex
from storage.app_processor import AppProcessor
from models.app_metadata import AppMetadata # Para renderizar informações da app

# Política de Segurança de Conteúdo (CSP) padrão
# Restritiva: permite recursos apenas da mesma origem ('self'),
# sem scripts ou estilos inline, e sem eval().
# 'unsafe-inline' para style-src é incluído para flexibilidade com aplicações estáticas básicas.
# 'unsafe-eval' é propositalmente omitido para segurança.
# connect-src 'self' permite requisições AJAX/websockets apenas para a própria origem.
DEFAULT_CSP_HEADER = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self';"


class WebServer:
    """
    Implementa o servidor HTTP local para servir aplicações P2P.
    Escuta apenas em '127.0.0.1' para segurança e interage com a instância do nó P2P.
    """
    def __init__(self, host='127.0.0.1', port=8080, node_instance=None):
        """
        Inicializa o servidor Web.

        Args:
            host (str): O host para vincular. Deve ser '127.0.0.1' por segurança.
            port (int): A porta TCP para o servidor HTTP escutar.
            node_instance: Referência para a instância do nó P2P principal,
                           através da qual o WebServer acessa os serviços de app.
        """
        # Garante que o servidor sempre se vincule a localhost por segurança
        if host != '127.0.0.1':
            logging.warning(f"Host '{host}' especificado para WebServer. Forçando vínculo para '127.0.0.1' por razões de segurança.")
            self.host = '127.0.0.1'
        else:
            self.host = host
        self.port = port
        self.server = None # Instância do servidor asyncio HTTP

        self.node = node_instance # Armazena a instância do nó P2P
        # Os serviços de app são acessados via a instância do nó
        if self.node:
            self.app_storage = self.node.app_storage
            self.app_index = self.node.app_index
            self.app_processor = self.node.app_processor
        else:
            logging.warning("WebServer inicializado sem uma instância de nó. Funcionalidades P2P e de gerenciamento de aplicações estarão limitadas.")
            # Fallback para instâncias locais se o nó não for fornecido, para permitir testar partes do WebServer
            self.app_storage = AppStorage()
            self.app_index = AppIndex(Path.cwd() / ".index") # Usar caminho padrão para o índice
            self.app_processor = AppProcessor()

        logging.info(f"WebServer inicializado em http://{self.host}:{self.port}")

    async def start(self):
        """
        Inicia o servidor HTTP.
        O servidor será executado indefinidamente, manipulando requisições HTTP.
        """
        try:
            self.server = await asyncio.start_server(
                self._handle_request, self.host, self.port
            )
            logging.info(f"WebServer escutando em http://{self.host}:{self.port}")
            async with self.server:
                await self.server.serve_forever()
        except Exception as e:
            logging.error(f"Erro ao iniciar WebServer em {self.host}:{self.port}: {e}")
            raise

    async def _handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Manipula uma requisição HTTP de entrada.
        Realiza a leitura da requisição, o parsing e o roteamento para o manipulador apropriado.
        """
        addr = writer.get_extra_info('peername')
        logging.debug(f"Recebida conexão HTTP de {addr}")

        try:
            # Lê a linha de requisição (ex: GET /index.html HTTP/1.1)
            request_line = await reader.readline()
            if not request_line:
                return # Conexão fechada

            method, path, http_version = request_line.decode().strip().split(None, 2)
            logging.info(f"[{method}] {path} HTTP/{http_version} de {addr}")

            # Lê os cabeçalhos da requisição
            headers = {}
            while True:
                header_line = await reader.readline()
                if not header_line or header_line == b'\r\n': # Fim dos cabeçalhos
                    break
                key, value = header_line.decode().strip().split(':', 1)
                headers[key.lower()] = value.strip()
            
            # Lidar com o corpo da requisição para POST (se houver)
            body = b''
            if method == 'POST':
                content_length = int(headers.get('content-length', 0))
                if content_length > 0:
                    body = await reader.readexactly(content_length)
                    logging.debug(f"Corpo da requisição POST recebido ({len(body)} bytes): {body.decode()[:100]}...")

            # Rotear a requisição com base no path
            parsed_url = urlparse(path)
            request_path = parsed_url.path
            query_params = parse_qs(parsed_url.query)

            if request_path == '/':
                await self._serve_root(writer)
            elif request_path.startswith('/app/'):
                # Extrai o hash da URL (garante que pega só o hash base, ex: de /app/HASH/file.html)
                app_hash = request_path[5:].split('/')[0]
                await self._serve_app(writer, app_hash, request_path)
            elif request_path == '/search':
                await self._handle_search(writer, query_params)
            elif request_path == '/publish' and method == 'POST':
                await self._handle_publish(writer, headers, body)
            else:
                await self._serve_404(writer)

        except asyncio.IncompleteReadError:
            logging.warning(f"Conexão de {addr} encerrada inesperadamente durante a leitura HTTP.")
        except Exception as e:
            logging.error(f"Erro ao manipular requisição HTTP de {addr}: {e}")
            await self._serve_500(writer, str(e)) # Envia uma resposta de erro 500
        finally:
            writer.close() # Garante que o writer seja sempre fechado
            await writer.wait_closed()

    async def _send_response(self, writer: asyncio.StreamWriter, status_code: int, status_message: str, headers: Dict[str, str], body: bytes = b''):
        """
        Envia uma resposta HTTP completa, incluindo o cabeçalho Content-Security-Policy.

        Args:
            writer (asyncio.StreamWriter): O escritor da conexão para o cliente.
            status_code (int): O código de status HTTP (ex: 200, 404).
            status_message (str): A mensagem de status HTTP (ex: "OK", "Not Found").
            headers (Dict[str, str]): Um dicionário de cabeçalhos HTTP adicionais.
            body (bytes): O corpo da resposta HTTP em bytes.
        """
        # Adiciona o cabeçalho CSP padrão se não estiver explicitamente definido
        if "content-security-policy" not in {k.lower() for k in headers.keys()}:
            headers["Content-security-policy"] = DEFAULT_CSP_HEADER # Note a capitalização de s e p aqui, conforme padrão

        response_line = f"HTTP/1.1 {status_code} {status_message}\r\n"
        header_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        
        full_response = (
            response_line.encode('utf-8') +
            header_lines.encode('utf-8') +
            b"Content-Length: " + str(len(body)).encode('utf-8') + b"\r\n" +
            b"\r\n" + # Linha em branco separando cabeçalhos do corpo
            body
        )
        writer.write(full_response)
        await writer.drain() # Garante que os dados sejam enviados ao cliente

    async def _serve_root(self, writer: asyncio.StreamWriter):
        """
        Serve a página inicial de boas-vindas do servidor web.
        Inclui informações sobre o SkyNet, como acessar e publicar aplicações,
        além de listar as aplicações disponíveis e um formulário de busca.
        """
        headers = {"Content-Type": "text/html; charset=utf-8"}
        
        # Obtém todas as aplicações ativas do índice
        applications = self.app_index.get_all_applications(active_only=True)
        
        # --- Seção de Boas-Vindas e Introdução ---
        body_html = """
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Bem-vindo ao SkyNet P2P Web Service</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f7f6; color: #333; line-height: 1.6; }
                .container { max-width: 900px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
                h1, h2, h3 { color: #0056b3; margin-bottom: 15px; border-bottom: 1px solid #eee; padding-bottom: 10px; }
                ul { list-style-type: disc; margin-left: 20px; }
                li { margin-bottom: 8px; }
                a { color: #007bff; text-decoration: none; }
                a:hover { text-decoration: underline; }
                .instruction-box { background-color: #e9ecef; border-left: 5px solid #0056b3; padding: 15px; margin-top: 20px; border-radius: 4px; }
                pre { background-color: #e9ecef; padding: 10px; border-radius: 4px; overflow-x: auto; font-family: 'Courier New', Courier, monospace; font-size: 0.9em; }
                code { background-color: #e9ecef; padding: 2px 4px; border-radius: 3px; font-size: 0.9em; }
                .app-list { margin-top: 30px; }
                .search-form { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; }
                input[type="text"], button { padding: 10px; margin-right: 10px; border-radius: 4px; border: 1px solid #ccc; }
                button { background-color: #007bff; color: white; border: none; cursor: pointer; }
                button:hover { background-color: #0056b3; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Bem-vindo ao SkyNet P2P Web Service!</h1>
                <p>Esta é a sua porta de entrada para um ecossistema de aplicações web distribuídas e descentralizadas. No SkyNet, cada nó contribui para o armazenamento e distribuição de conteúdo, garantindo resiliência e autonomia.</p>
                
                <div class="instruction-box">
                    <h3>Como Acessar Aplicações</h3>
                    <p>Abaixo você encontrará uma lista das aplicações web que estão disponíveis no momento em sua rede local. Clique em qualquer uma delas para acessá-las diretamente em seu navegador.</p>
                    <p>Você também pode usar a barra de busca para encontrar aplicações específicas.</p>
                </div>

                <div class="app-list">
                    <h2>Aplicações Disponíveis</h2>
                    <ul>
        """
        if applications:
            for app_meta in applications:
                body_html += f"<li><a href='/app/{app_meta.app_hash}'>{app_meta.name} ({app_meta.version}) por {app_meta.author_public_key[:8]}...</a> - {app_meta.description}</li>"
        else:
            body_html += "<li>Nenhuma aplicação ativa encontrada.</li>"
        body_html += """
                    </ul>
                </div>

                <div class="search-form">
                    <h2>Buscar Aplicações</h2>
                    <form action="/search" method="GET">
                        <input type="text" name="q" placeholder="Buscar por nome, tag, descrição">
                        <button type="submit">Buscar</button>
                    </form>
                </div>

                <div class="instruction-box">
                    <h3>Como Publicar sua Aplicação Web</h3>
                    <p>Você pode contribuir para o SkyNet publicando suas próprias aplicações web estáticas. Siga estes passos:</p>
                    <ol>
                        <li><strong>Prepare sua Aplicação:</strong> Crie um diretório contendo seus arquivos HTML, CSS, JavaScript e outros recursos estáticos.</li>
                        <li><strong>Gere o Conteúdo e os Metadados:</strong> A partir do diretório da sua aplicação, você precisará gerar o conteúdo zipado, seu hash SHA-256, e um objeto JSON de metadados.</li>
                        <li><strong>Assine os Metadados:</strong> Use sua chave privada RSA para assinar digitalmente os metadados. Isso garante a autoria e a integridade.</li>
                        <li><strong>Envie para o Servidor Local:</strong> Faça uma requisição HTTP POST para o endpoint <code>/publish</code> do seu nó local.</li>
                    </ol>
                    <p>O payload da requisição POST deve ser um JSON com a seguinte estrutura:</p>
                    <pre><code>
{
  "metadata": {
    "name": "Nome da Sua App",
    "description": "Uma breve descrição da sua aplicação.",
    "tags": ["tag1", "tag2"],
    "version": "1.0.0",
    "author_public_key": "SUA_CHAVE_PUBLICA_RSA_PEM_AQUI",
    "timestamp": 1678886400, // Unix timestamp
    "active": true
  },
  "content": "CONTEUDO_ZIPADO_DA_APP_EM_FORMATO_HEXADECIMAL",
  "signature": "ASSINATURA_DOS_METADADOS_EM_FORMATO_HEXADECIMAL"
}
                    </code></pre>
                    <p>Para gerar o <code>author_public_key</code> (formato PEM), o <code>content</code> (hex do zip) e a <code>signature</code> (hex), você pode usar utilitários fornecidos pelo projeto ou scripts auxiliares.</p>
                    <p>Após a publicação, sua aplicação será distribuída na rede P2P e visível para outros nós.</p>
                </div>

                <footer>
                    <p>SkyNet P2P Web Service - Conectando aplicações de forma descentralizada.</p>
                </footer>
            </div>
        </body>
        </html>
        """
        
        body = body_html.encode('utf-8')
        await self._send_response(writer, 200, "OK", headers, body)

    async def _serve_static_file(self, writer: asyncio.StreamWriter, file_path: Path, content_type: str = None):
        """
        Serve um arquivo estático do sistema de arquivos para o cliente.

        Args:
            writer (asyncio.StreamWriter): O escritor da conexão para o cliente.
            file_path (Path): O caminho para o arquivo estático a ser servido.
            content_type (str, optional): O tipo de conteúdo MIME do arquivo.
                                         Se None, será adivinhado a partir da extensão do arquivo.
        """
        if not file_path.is_file():
            await self._serve_404(writer) # Arquivo não encontrado
            return

        if content_type is None:
            # Tenta adivinhar o tipo MIME a partir da extensão do arquivo
            content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        
        try:
            with open(file_path, "rb") as f:
                content = f.read() # Lê o conteúdo binário do arquivo
            
            headers = {"Content-Type": content_type}
            await self._send_response(writer, 200, "OK", headers, content)
        except Exception as e:
            logging.error(f"Erro ao servir arquivo estático {file_path}: {e}")
            await self._serve_500(writer, f"Erro ao carregar arquivo: {file_path.name}")

    async def _serve_app(self, writer: asyncio.StreamWriter, app_hash: str, request_full_path: str):
        """
        Serve uma aplicação P2P web pelo seu `app_hash`.
        Gerencia o download P2P sob demanda e a descompactação do conteúdo.

        Args:
            writer (asyncio.StreamWriter): O escritor da conexão para o cliente.
            app_hash (str): O hash SHA-256 da aplicação a ser servida.
            request_full_path (str): O caminho completo da requisição HTTP (ex: /app/<hash>/index.html).
        """
        logging.info(f"Requisição para servir aplicação com hash: {app_hash}, path: {request_full_path}")
        
        app_meta = self.app_index.get_application(app_hash)
        if not app_meta or not app_meta.active:
            logging.warning(f"Aplicação {app_hash[:8]}... não encontrada ou inativa no índice.")
            await self._serve_404(writer) # Responde com 404 se a app não for encontrada ou estiver inativa
            return
        
        # Se o conteúdo da aplicação não estiver disponível localmente, tenta baixar via P2P
        if not self.app_storage.app_exists_locally(app_hash):
            logging.info(f"Conteúdo da aplicação {app_hash[:8]}... não encontrado localmente. Tentando baixar via P2P.")
            if not self.node:
                logging.error(f"WebServer não tem instância de nó para solicitar {app_hash[:8]}... via P2P. Funcionalidade de download P2P indisponível.")
                await self._serve_500(writer, "Servidor não configurado para P2P. Conteúdo não disponível.")
                return

            # Inicia a requisição P2P para baixar a aplicação e aguarda.
            # O timeout aqui é para a espera da resposta P2P, não para a requisição HTTP completa.
            download_successful = await self.node.request_app_content(app_hash, timeout=60) 
            
            if not download_successful:
                logging.warning(f"Falha ao baixar aplicação {app_hash[:8]}... via P2P ou tempo limite excedido.")
                await self._send_response(writer, 503, "Service Unavailable", {"Content-Type": "text/html; charset=utf-8"}, "<h1>503 Indisponível</h1><p>Conteúdo da aplicação não pôde ser baixado via P2P.</p>".encode('utf-8'))
                return
            
            # Se o download foi bem-sucedido, o código continua para servir a aplicação.
            logging.info(f"Download da aplicação {app_hash[:8]}... concluído. Prosseguindo para servir.")

        # Verifica se o conteúdo já está descompactado para ser servido
        decompressed_path = self.app_processor.get_decompressed_app_path(app_hash, base_dir=self.app_storage.base_dir)
        if not decompressed_path.is_dir():
            logging.info(f"Descompactando conteúdo da aplicação {app_hash[:8]}...")
            try:
                zipped_content = self.app_storage.load_app_content(app_hash)
                if zipped_content:
                    self.app_processor.unzip_app_content(zipped_content, decompressed_path)
                    logging.info(f"Aplicação {app_hash[:8]}... descompactada para {decompressed_path}")
                else:
                    logging.error(f"Conteúdo zipado não encontrado para {app_hash[:8]}... apesar de app_exists_locally ser True. Erro de estado.")
                    await self._serve_500(writer, "Erro interno: conteúdo da app faltando.")
                    return
            except Exception as e:
                logging.error(f"Erro ao descompactar aplicação {app_hash[:8]}...: {e}")
                await self._serve_500(writer, "Erro ao descompactar aplicação.")
                return

        # Servir os arquivos estáticos da aplicação descompactada
        # Converte o caminho da requisição HTTP (ex: /app/HASH/css/style.css)
        # para um caminho relativo dentro do diretório descompactado (ex: css/style.css)
        if request_full_path.startswith(f'/app/{app_hash}'):
            relative_file_path_str = request_full_path[len(f'/app/{app_hash}'):]
            if not relative_file_path_str or relative_file_path_str == '/': # Se a URL for /app/HASH ou /app/HASH/, servir index.html
                relative_file_path_str = '/index.html'
        else:
            logging.error(f"Erro ao parsear URL para servir app: {request_full_path} com hash {app_hash}. Caminho inconsistente.")
            await self._serve_500(writer, "Erro interno ao rotear a aplicação.")
            return

        # Caminho completo do arquivo no sistema de arquivos local
        file_to_serve_path = decompressed_path / relative_file_path_str.lstrip('/')
        
        await self._serve_static_file(writer, file_to_serve_path)

    async def _handle_search(self, writer: asyncio.StreamWriter, query_params: Dict[str, List[str]]):
        """
        Manipula requisições de busca por aplicações.
        Busca no índice local e renderiza os resultados em HTML.

        Args:
            writer (asyncio.StreamWriter): O escritor da conexão para o cliente.
            query_params (Dict[str, List[str]]): Dicionário de parâmetros de query da URL.
        """
        query = query_params.get('q', [''])[0]
        logging.info(f"Requisição de busca recebida: '{query}'")

        if not query:
            headers = {"Content-Type": "text/html; charset=utf-8"}
            body = "<h1>Buscar Aplicações</h1><p>Por favor, forneça um termo de busca.</p>".encode('utf-8')
            await self._send_response(writer, 200, "OK", headers, body)
            return

        results = self.app_index.search_applications(query)

        body_html = f"<h1>Resultados da Busca para '{query}'</h1>"
        if results:
            body_html += "<p>Aplicações encontradas:</p><ul>"
            for app_meta in results:
                body_html += f"<li><a href='/app/{app_meta.app_hash}'>{app_meta.name} ({app_meta.version}) por {app_meta.author_public_key[:8]}...</a> - {app_meta.description}</li>"
            body_html += "</ul>"
        else:
            body_html += "<p>Nenhuma aplicação encontrada com o termo de busca.</p>"
        
        body_html += """
        <hr>
        <p><a href="/">Voltar para a página inicial</a></p>
        """

        headers = {"Content-Type": "text/html; charset=utf-8"}
        body = body_html.encode('utf-8')
        await self._send_response(writer, 200, "OK", headers, body)

    async def _handle_publish(self, writer: asyncio.StreamWriter, headers: Dict[str, str], body: bytes):
        """
        Manipula requisições POST para publicação de novas aplicações ou atualizações.
        Espera um corpo JSON com 'metadata', 'content' (zip em hexadecimal) e 'signature'.

        Args:
            writer (asyncio.StreamWriter): O escritor da conexão para o cliente.
            headers (Dict[str, str]): Cabeçalhos da requisição HTTP.
            body (bytes): O corpo da requisição HTTP em bytes.
        """
        logging.info("Requisição POST /publish recebida.")
        
        try:
            request_data = json.loads(body.decode('utf-8'))
            metadata_dict = request_data.get("metadata")
            content_hex = request_data.get("content")
            signature_hex = request_data.get("signature")
            
            if not all([metadata_dict, content_hex, signature_hex]):
                await self._send_response(writer, 400, "Bad Request", {"Content-Type": "text/plain"}, "Corpo da requisição incompleto. Esperava 'metadata', 'content' e 'signature'.".encode('utf-8'))
                return

            app_content = bytes.fromhex(content_hex)
            
            # 1. Gerar o hash da aplicação a partir do conteúdo
            app_hash = self.app_processor.generate_app_hash(app_content)

            # 2. Validar metadados e assinatura
            app_meta = AppMetadata.from_dict(metadata_dict)
            if app_meta.app_hash is None:
                app_meta.app_hash = app_hash # Atualiza o app_hash na metadata se não definido
            elif app_meta.app_hash != app_hash:
                await self._send_response(writer, 400, "Bad Request", {"Content-Type": "text/plain"}, "Hash da aplicação na metadata não corresponde ao hash do conteúdo fornecido.".encode('utf-8'))
                return

            if not app_meta.verify_signature(bytes.fromhex(signature_hex)):
                await self._send_response(writer, 401, "Unauthorized", {"Content-Type": "text/plain"}, "Assinatura de metadados inválida.".encode('utf-8'))
                return
            
            # 3. Salvar aplicação localmente
            self.app_storage.save_app_content(app_hash, app_content)
            self.app_storage.save_app_metadata(app_hash, app_meta.to_dict())
            self.app_storage.save_app_signature(app_hash, bytes.fromhex(signature_hex))
            
            # 4. Adicionar ao índice local (a lógica de "única versão ativa" é tratada em app_index)
            self.app_index.add_application(app_hash, app_meta)

            logging.info(f"Aplicação '{app_meta.name}' ({app_hash[:8]}...) publicada localmente com sucesso.")

            # Anunciar a nova aplicação para a rede P2P
            if self.node:
                await self.node.announce_app_to_p2p(app_hash, app_meta, signature_hex)
            else:
                logging.warning("WebServer não tem instância de nó. Não foi possível anunciar a aplicação na rede P2P.")

            response_body = json.dumps({"status": "success", "app_hash": app_hash, "message": f"Aplicação '{app_meta.name}' publicada com sucesso."}).encode('utf-8')
            headers = {"Content-Type": "application/json; charset=utf-8"}
            await self._send_response(writer, 201, "Created", headers, response_body)

        except json.JSONDecodeError:
            await self._send_response(writer, 400, "Bad Request", {"Content-Type": "text/plain"}, "Corpo da requisição inválido: esperado JSON.".encode('utf-8'))
        except Exception as e:
            logging.error(f"Erro ao processar requisicao /publish: {e}")
            await self._serve_500(writer, f"Erro interno: {e}") # Resposta de erro 500

    async def _serve_404(self, writer: asyncio.StreamWriter):
        """
        Serve uma página de erro 404 (Not Found).
        """
        headers = {"Content-Type": "text/html; charset=utf-8"}
        body = "<h1>404 Not Found</h1><p>A página solicitada não foi encontrada.</p>".encode('utf-8')
        await self._send_response(writer, 404, "Not Found", headers, body)

    async def _serve_500(self, writer: asyncio.StreamWriter, error_message: str = "Internal Server Error"):
        """
        Serve uma página de erro 500 (Internal Server Error).
        """
        headers = {"Content-Type": "text/html; charset=utf-8"}
        body = f"<h1>500 Internal Server Error</h1><p>{error_message}</p>".encode('utf-8')
        await self._send_response(writer, 500, "Internal Server Error", headers, body)