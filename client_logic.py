import socket
import struct
import logging
import time
import serial # Importa serial aqui
from PySide6.QtCore import QThread, Signal, QSemaphore

APP_LOGGER_NAME = "SerialApp"

class ClientThread(QThread):
    status_update_signal = Signal(str, str) # (tipo_de_status, mensagem_de_status)
    # log_signal passado no __init__

    def __init__(self, server_url: str, serial_port_name: str,
                 serial_semaphore: QSemaphore, serial_params: dict, log_signal: Signal):
        super().__init__()
        self.server_url = server_url
        self.serial_port_name = serial_port_name
        self.serial_semaphore = serial_semaphore
        self.serial_params = serial_params
        self.log_signal = log_signal
        self.logger = logging.getLogger(f"{APP_LOGGER_NAME}.ClientThread")

        self._is_running = True
        self.client_socket: socket.socket = None
        self.serial_port: serial.Serial = None

    def _log(self, message: str, level=logging.INFO, to_gui=True):
        self.logger.log(level, message)
        if to_gui and self.log_signal:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            level_name = logging.getLevelName(level)
            self.log_signal.emit(f"{timestamp} - {level_name} - CLI: {message}")

    def stop_client(self):
        self._log("Solicitação para parar o cliente...", to_gui=False)
        self.status_update_signal.emit("client_status", "Desconectando...")
        self._is_running = False
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR) # Notifica o outro lado
            except: pass # Ignora erros se o socket já estiver problemático
            try:
                self.client_socket.close()
            except Exception as e:
                self._log(f"Erro ao fechar socket cliente: {e}", logging.ERROR, to_gui=False)
        self.client_socket = None

    def run(self):
        self._is_running = True
        try:
            if not self.open_serial_port():
                return

            url_parts = self.server_url.split(':')
            host = url_parts[0]
            try:
                port = int(url_parts[1]) if len(url_parts) > 1 and url_parts[1] else 80
            except ValueError:
                self._log(f"Porta inválida na URL do servidor: {self.server_url}", logging.ERROR)
                self.status_update_signal.emit("client_status", "URL Inválida")
                self.status_update_signal.emit("error", "Porta na URL inválida.")
                return

            self.status_update_signal.emit("client_status", "Conectando...")
            self.status_update_signal.emit("connection_detail", f"Cliente para: {host}:{port}")
            
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10.0) # Timeout para conexão
            self.client_socket.connect((host, port))
            self.client_socket.settimeout(1.0) # Timeout para operações de recv/send

            self._log(f"Conectado ao servidor em {self.server_url}")
            self.status_update_signal.emit("client_status", "Conectado")

            while self._is_running:
                serial_data = self.read_from_serial_port() # Pode bloquear por timeout da serial
                if serial_data: # Se leu algo da serial
                    # A linha original `data_from_serial = "".join(data.split(" ")[:-5])`
                    # é muito específica. Se for um protocolo, precisa ser robusto.
                    # Por ora, vamos enviar o dado bruto como recebido da serial.
                    # Se uma transformação específica é necessária, ela deve ser feita aqui.
                    # Exemplo: data_to_send = serial_data.strip() # Simples strip
                    data_to_send_str = serial_data.strip() # Exemplo
                    
                    # Se precisar da lógica original exata (remover as últimas 5 "palavras" separadas por espaço):
                    # parts = serial_data.split(" ")
                    # if len(parts) > 5:
                    #    data_to_send_str = " ".join(parts[:-5])
                    # else:
                    #    data_to_send_str = "" # ou serial_data, dependendo do que se espera
                    
                    if not data_to_send_str: # Não envia strings vazias
                        time.sleep(0.05) # Pequena pausa para não ocupar CPU se não houver dados
                        continue

                    try:
                        data_bytes = data_to_send_str.encode('cp850') # Ou outra codificação conforme o servidor espera
                    except Exception as e_enc:
                        self._log(f"Erro ao codificar dados da serial: {e_enc}. Dados: '{data_to_send_str}'", logging.ERROR)
                        continue # Pula este envio

                    try:
                        # Envia tamanho primeiro
                        self.client_socket.sendall(struct.pack("!Q", len(data_bytes)))
                        # Envia dados
                        self.client_socket.sendall(data_bytes)
                        self._log(f"Enviado para servidor: '{data_to_send_str}' ({len(data_bytes)} bytes)")
                    except socket.error as e_sock:
                        self._log(f"Erro de socket ao enviar dados para o servidor: {e_sock}", logging.ERROR)
                        self.status_update_signal.emit("client_status", "Erro de Envio")
                        self.status_update_signal.emit("error", f"Socket: {e_sock}")
                        self._is_running = False # Para a thread em caso de erro de envio
                        break # Sai do loop de envio/leitura
                    except Exception as e_send:
                        self._log(f"Erro inesperado ao enviar dados: {e_send}", logging.ERROR)
                        self.status_update_signal.emit("client_status", "Erro Desconhecido")
                        self_is_running = False
                        break
                else: # serial_data é None ou vazio (timeout da serial sem dados)
                    if not self._is_running:
                        break
                    time.sleep(0.05) # Pequena pausa para não ocupar CPU no loop
            
        except socket.timeout:
            self._log(f"Timeout ao conectar/comunicar com o servidor {self.server_url}.", logging.ERROR)
            self.status_update_signal.emit("client_status", "Timeout Servidor")
            self.status_update_signal.emit("error", "Timeout na conexão com servidor.")
        except ConnectionRefusedError:
            self._log(f"Conexão recusada pelo servidor em {self.server_url}.", logging.ERROR)
            self.status_update_signal.emit("client_status", "Conexão Recusada")
            self.status_update_signal.emit("error", "Servidor recusou a conexão.")
        except socket.gaierror: # Erro de resolução de nome
            self._log(f"Nome do servidor ou endereço inválido: {self.server_url}", logging.ERROR)
            self.status_update_signal.emit("client_status", "Host Inválido")
            self.status_update_signal.emit("error", "Endereço do servidor inválido.")
        except Exception as e:
            self._log(f"Erro na thread Cliente: {e}", logging.CRITICAL)
            self.status_update_signal.emit("client_status", f"Erro Crítico: {type(e).__name__}")
            self.status_update_signal.emit("error", f"Cliente: {e}")
        finally:
            self.close_serial_port()
            if self.client_socket:
                try:
                    self.client_socket.close()
                except: pass
            
            if self._is_running : # Se saiu por erro e não por stop_client()
                self._is_running = False

            self.status_update_signal.emit("client_status", "Desconectado")
            self._log("Thread Cliente finalizada.", to_gui=False)

    def open_serial_port(self) -> bool:
        # Similar ao ServerThread.open_serial_port
        if self.serial_port and self.serial_port.is_open:
            return True
        try:
            self._log(f"Abrindo porta serial {self.serial_port_name} com params: {self.serial_params}")
            self.serial_port = serial.Serial(
                port=self.serial_port_name,
                baudrate=self.serial_params.get("baudrate", 9600),
                bytesize=self.serial_params.get("bytesize", serial.EIGHTBITS),
                parity=self.serial_params.get("parity", serial.PARITY_NONE),
                stopbits=self.serial_params.get("stopbits", serial.STOPBITS_ONE),
                timeout=self.serial_params.get("timeout", 1), # Timeout para leituras
                xonxoff=False,
                rtscts=self.serial_params.get("rtscts", False),
                dsrdtr=self.serial_params.get("dsrdtr", False)
            )
            self._log(f"Porta serial {self.serial_port_name} (cliente) aberta.")
            self.status_update_signal.emit("client_status", "Serial Conectada")
            return True
        except serial.SerialException as e:
            self._log(f"Falha ao abrir porta serial {self.serial_port_name} (cliente): {e}", logging.ERROR)
            self.status_update_signal.emit("client_status", "Erro na Serial")
            self.status_update_signal.emit("error", f"Serial (Cli): {e}")
            return False
        except Exception as e_gen:
            self._log(f"Erro inesperado ao abrir porta serial {self.serial_port_name} (cliente): {e_gen}", logging.ERROR)
            self.status_update_signal.emit("client_status", "Erro Conf Serial (Cli)")
            self.status_update_signal.emit("error", f"Conf Serial (Cli): {e_gen}")
            return False


    def close_serial_port(self):
        # Similar ao ServerThread.close_serial_port
        if self.serial_port and self.serial_port.is_open:
            try:
                self.serial_port.close()
                self._log(f"Porta serial {self.serial_port_name} (cliente) fechada.")
            except Exception as e:
                self._log(f"Erro ao fechar porta serial {self.serial_port_name} (cliente): {e}", logging.ERROR)
        self.serial_port = None

    def read_from_serial_port(self) -> str:
        if not self.serial_port or not self.serial_port.is_open:
            self._log("Porta serial (cliente) não está aberta para leitura.", logging.WARNING)
            # self.status_update_signal.emit("warning", "Serial (Cli) desconectada ao ler.") # Pode poluir
            return None

        data = None
        try:
            if self.serial_semaphore.tryAcquire(1, 200): # Tenta adquirir por 200ms
                try:
                    # read_until espera até encontrar o terminador ou timeout.
                    # Se o dispositivo serial não envia '\n', isso pode não funcionar bem.
                    # Alternativa: self.serial_port.read(self.serial_port.in_waiting or 1)
                    if self.serial_port.in_waiting > 0:
                        # Tenta ler uma linha, comum para dispositivos baseados em texto.
                        # O timeout da porta serial (definido na abertura) controla o bloqueio máximo aqui.
                        line = self.serial_port.readline() # read_until(b'\n') é similar
                        if line:
                            # Tenta decodificar com cp850, mas seja flexível
                            try:
                                data = line.decode('cp850').strip()
                            except UnicodeDecodeError:
                                try:
                                    data = line.decode('ascii', errors='replace').strip()
                                    self._log(f"Dados da serial decodificados como ASCII (com perdas): '{data}'", logging.DEBUG)
                                except Exception:
                                    data = str(line) # Fallback
                                    self._log(f"Falha ao decodificar dados da serial. Bruto: {line}", logging.WARNING)

                            if data:
                                self._log(f"Recebido da serial (cliente): '{data}'", logging.DEBUG)
                except serial.SerialException as e: # Ex: porta desconectada
                    self._log(f"Erro SerialException ao ler da porta (cliente): {e}", logging.ERROR)
                    self.status_update_signal.emit("client_status", "Erro Leitura Serial")
                    self.status_update_signal.emit("error", f"Leitura Serial (Cli): {e}")
                    self._is_running = False # Para a thread se a serial falhar catastroficamente
                    return None
                except Exception as e:
                    self._log(f"Erro desconhecido ao ler da porta serial (cliente): {e}", logging.ERROR)
                    return None # Não para a thread por qualquer erro, apenas loga
                finally:
                    self.serial_semaphore.release()
            # else: # Não conseguiu adquirir semáforo - não logar para não poluir se for frequente
            #    self._log("Timeout ao adquirir semáforo para leitura serial (cliente).", logging.DEBUG)
            #    pass

        except Exception as e_sem:
             self._log(f"Erro relacionado ao semáforo na leitura serial (cliente): {e_sem}", logging.ERROR)

        return data