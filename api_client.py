import requests
import logging
import websocket
import json
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger("SerialApp")

class APIClient:
    """
    Cliente para interagir com o backend de gerenciamento.
    Agora usa API Key para autenticação e WebSocket para comunicação em tempo real.
    """
    def __init__(self, base_url: str):
        if not base_url.startswith("http"):
            self.base_url = f"http://{base_url}"
        else:
            self.base_url = base_url
        
        self.timeout = 15
        self.api_key = None  # Armazenará a API Key
        self.ws = None  # WebSocket connection
        self.ws_thread = None
        self.heartbeat_thread = None
        self.is_connected = False
        self.on_message_callback: Optional[Callable] = None
        self.on_status_callback: Optional[Callable] = None

    def _get_auth_header(self) -> dict:
        """ Monta o cabeçalho de autorização se a API Key existir. """
        if not self.api_key:
            raise ValueError("API Key não foi definida.")
        return {"X-API-Key": self.api_key}

    def autenticar_api_key(self, api_key: str) -> tuple[bool, str]:
        """
        Autentica usando API Key.

        Returns:
            tuple[bool, str]: (True, "Mensagem de sucesso") se a autenticação for bem-sucedida.
                              (False, "Mensagem de erro") se falhar.
        """
        url = f"{self.base_url}/api/v1/agent-credentials/authenticate"
        logger.info(f"Autenticando API Key em {url}")

        try:
            data = {"api_key": api_key}
            response = requests.post(url, json=data, timeout=self.timeout)

            if response.status_code == 200:
                self.api_key = api_key
                credential_data = response.json()
                logger.info(f"API Key autenticada com sucesso para agente '{credential_data.get('agent', {}).get('name', 'N/A')}'.")
                return True, f"Autenticação realizada com sucesso. Agente: {credential_data.get('agent', {}).get('name', 'N/A')}"
            
            error_msg = response.json().get("detail", "API Key inválida.")
            logger.warning(f"Falha na autenticação da API Key: {error_msg}")
            return False, f"Falha na autenticação: {error_msg}"

        except requests.exceptions.RequestException as e:
            logger.critical(f"Erro de conexão ao autenticar API Key: {e}")
            return False, "Não foi possível conectar ao servidor de autenticação."

    def conectar_websocket(self, on_message_callback: Callable = None, on_status_callback: Callable = None) -> tuple[bool, str]:
        """
        Conecta ao WebSocket do backend para comunicação em tempo real.
        
        Returns:
            tuple[bool, str]: (True, "Mensagem de sucesso") se a conexão for bem-sucedida.
                              (False, "Mensagem de erro") se falhar.
        """
        if not self.api_key:
            return False, "API Key não foi definida. Faça a autenticação primeiro."

        self.on_message_callback = on_message_callback
        self.on_status_callback = on_status_callback
        
        ws_url = self.base_url.replace("http", "ws") + f"/ws/agent?api_key={self.api_key}"
        logger.info(f"Conectando ao WebSocket: {ws_url}")

        try:
            self.ws = websocket.WebSocketApp(
                ws_url,
                on_open=self._on_ws_open,
                on_message=self._on_ws_message,
                on_error=self._on_ws_error,
                on_close=self._on_ws_close
            )
            
            self.ws_thread = threading.Thread(target=self.ws.run_forever)
            self.ws_thread.daemon = True
            self.ws_thread.start()
            
            # Aguardar um pouco para verificar se a conexão foi estabelecida
            time.sleep(2)
            
            if self.is_connected:
                self._start_heartbeat()
                return True, "Conexão WebSocket estabelecida com sucesso."
            else:
                return False, "Falha ao estabelecer conexão WebSocket."
                
        except Exception as e:
            logger.critical(f"Erro ao conectar WebSocket: {e}")
            return False, f"Erro na conexão WebSocket: {str(e)}"
    
    def _on_ws_open(self, ws):
        """Callback chamado quando WebSocket é aberto."""
        logger.info("Conexão WebSocket estabelecida")
        self.is_connected = True
        if self.on_status_callback:
            self.on_status_callback("connected", "Conectado ao servidor")
    
    def _on_ws_message(self, ws, message):
        """Callback chamado quando uma mensagem é recebida."""
        try:
            data = json.loads(message)
            logger.info(f"Mensagem recebida via WebSocket: {data}")
            if self.on_message_callback:
                self.on_message_callback(data)
        except json.JSONDecodeError as e:
            logger.error(f"Erro ao decodificar mensagem WebSocket: {e}")
    
    def _on_ws_error(self, ws, error):
        """Callback chamado quando há erro no WebSocket."""
        logger.error(f"Erro no WebSocket: {error}")
        if self.on_status_callback:
            self.on_status_callback("error", f"Erro na conexão: {str(error)}")
    
    def _on_ws_close(self, ws, close_status_code, close_msg):
        """Callback chamado quando WebSocket é fechado."""
        logger.info(f"Conexão WebSocket fechada: {close_status_code} - {close_msg}")
        self.is_connected = False
        if self.on_status_callback:
            self.on_status_callback("disconnected", "Desconectado do servidor")
    
    def _start_heartbeat(self):
        """Inicia o thread de heartbeat."""
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            return
            
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop)
        self.heartbeat_thread.daemon = True
        self.heartbeat_thread.start()
    
    def _heartbeat_loop(self):
        """Loop de heartbeat para manter a conexão ativa."""
        while self.is_connected and self.ws:
            try:
                heartbeat_msg = {
                    "type": "heartbeat",
                    "timestamp": time.time()
                }
                self.ws.send(json.dumps(heartbeat_msg))
                logger.debug("Heartbeat enviado")
                time.sleep(30)  # Enviar heartbeat a cada 30 segundos
            except Exception as e:
                logger.error(f"Erro ao enviar heartbeat: {e}")
                break
    
    def enviar_dados_serial(self, dados: str):
        """Envia dados seriais via WebSocket."""
        if not self.is_connected or not self.ws:
            logger.warning("WebSocket não está conectado")
            return False
            
        try:
            message = {
                "type": "serial_data",
                "data": dados,
                "timestamp": time.time()
            }
            self.ws.send(json.dumps(message))
            logger.debug(f"Dados seriais enviados: {dados}")
            return True
        except Exception as e:
            logger.error(f"Erro ao enviar dados seriais: {e}")
            return False
    
    def desconectar(self):
        """Desconecta do WebSocket."""
        self.is_connected = False
        if self.ws:
            self.ws.close()
        if self.ws_thread and self.ws_thread.is_alive():
            self.ws_thread.join(timeout=5)
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=5)
        logger.info("Desconectado do WebSocket")