import socket
import struct
import logging
import time
import serial # Importa serial aqui
from PySide6.QtCore import QThread, Signal, QSemaphore

APP_LOGGER_NAME = "SerialApp"

class ClientThread(QThread):
    status_update_signal = Signal(str, str)
    data_transmitted_signal = Signal(int)
    data_received_signal = Signal(int)
    uptime_signal = Signal(str)

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

        self.start_time = 0
        self.bytes_sent = 0
        self.bytes_received = 0

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
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except: pass
            try:
                self.client_socket.close()
            except Exception as e:
                self._log(f"Erro ao fechar socket cliente: {e}", logging.ERROR, to_gui=False)
        self.client_socket = None

    def run(self):
        self._is_running = True
        self.start_time = time.time()
        self.bytes_sent = 0
        self.bytes_received = 0
        
        try:
            if not self.open_serial_port():
                return

            url_parts = self.server_url.split(':')
            host = url_parts[0]
            try:
                port = int(url_parts[1]) if len(url_parts) > 1 and url_parts[1] else 80
            except ValueError:
                self._log(f"Porta inválida na URL: {self.server_url}", logging.ERROR)
                self.status_update_signal.emit("client_status", "URL Inválida")
                return

            self.status_update_signal.emit("client_status", "Conectando...")
            self.status_update_signal.emit("connection_detail", f"Cliente para: {host}:{port}")
            
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10.0)
            self.client_socket.connect((host, port))
            self.client_socket.settimeout(1.0)

            self._log(f"Conectado ao servidor em {self.server_url}")
            self.status_update_signal.emit("client_status", "Conectado")

            while self._is_running:
                self.update_uptime()
                serial_data = self.read_from_serial_port()
                if serial_data:
                    data_to_send_str = "".join(serial_data.strip().split(" ")[:10])
                    
                    if not data_to_send_str:
                        time.sleep(0.05)
                        continue
                    
                    data_bytes = b''
                    try:
                        data_bytes = data_to_send_str.encode('cp850')
                    except Exception as e_enc:
                        self._log(f"Erro ao codificar dados: {e_enc}. Dados: '{data_to_send_str}'", logging.ERROR)
                        continue

                    try:
                        self.client_socket.sendall(struct.pack("!Q", len(data_bytes)))
                        self.client_socket.sendall(data_bytes)
                        
                        self.bytes_sent += len(data_bytes) + 8 # 8 bytes do cabeçalho de tamanho
                        self.data_transmitted_signal.emit(self.bytes_sent)
                        
                        self._log(f"Enviado para servidor: '{data_to_send_str}' ({len(data_bytes)} bytes)")
                    except socket.error as e_sock:
                        self._log(f"Erro de socket ao enviar dados: {e_sock}", logging.ERROR)
                        self.status_update_signal.emit("client_status", "Erro de Envio")
                        self._is_running = False
                        break
                    except Exception as e_send:
                        self._log(f"Erro inesperado ao enviar dados: {e_send}", logging.ERROR)
                        self.status_update_signal.emit("client_status", "Erro Desconhecido")
                        self._is_running = False
                        break
                else:
                    if not self._is_running:
                        break
                    time.sleep(0.05)
            
        except socket.timeout:
            self._log(f"Timeout ao conectar com o servidor {self.server_url}.", logging.ERROR)
            self.status_update_signal.emit("client_status", "Timeout Servidor")
        except ConnectionRefusedError:
            self._log(f"Conexão recusada pelo servidor em {self.server_url}.", logging.ERROR)
            self.status_update_signal.emit("client_status", "Conexão Recusada")
        except socket.gaierror:
            self._log(f"Endereço do servidor inválido: {self.server_url}", logging.ERROR)
            self.status_update_signal.emit("client_status", "Host Inválido")
        except Exception as e:
            self._log(f"Erro na thread Cliente: {e}", logging.CRITICAL)
            self.status_update_signal.emit("client_status", f"Erro Crítico: {type(e).__name__}")
        finally:
            self.close_serial_port()
            if self.client_socket:
                try:
                    self.client_socket.close()
                except: pass
            
            if self._is_running :
                self._is_running = False

            self.status_update_signal.emit("client_status", "Desconectado")
            self._log("Thread Cliente finalizada.", to_gui=False)

    def update_uptime(self):
        uptime_seconds = int(time.time() - self.start_time)
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        self.uptime_signal.emit(f"{hours:02}:{minutes:02}:{seconds:02}")

    def open_serial_port(self) -> bool:
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
                timeout=self.serial_params.get("timeout", 1),
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
            return None

        data = None
        try:
            if self.serial_semaphore.tryAcquire():
                try:
                    if self.serial_port.in_waiting > 0:
                        line = self.serial_port.read_until(b'\n')
                        if not line:
                            line = self.serial_port.read_until(b' ')
                        if line:
                            try:
                                data = line.decode('cp850').strip()
                                self.serial_port.reset_input_buffer()
                                self.serial_port.reset_output_buffer()
                            except UnicodeDecodeError:
                                try:
                                    data = line.decode('ascii', errors='replace').strip()
                                    self._log(f"Decodificado como ASCII (com perdas): '{data}'", logging.DEBUG)
                                except Exception:
                                    data = str(line)
                                    self._log(f"Falha ao decodificar. Bruto: {line}", logging.WARNING)

                            if data:
                                self._log(f"Recebido da serial (cliente): '{data}'", logging.DEBUG)
                except serial.SerialException as e:
                    self._log(f"Erro SerialException ao ler (cliente): {e}", logging.ERROR)
                    self.status_update_signal.emit("client_status", "Erro Leitura Serial")
                    self._is_running = False
                    return None
                except Exception as e:
                    self._log(f"Erro desconhecido ao ler da serial (cliente): {e}", logging.ERROR)
                    return None
                finally:
                    self.serial_semaphore.release()
        except Exception as e_sem:
             self._log(f"Erro no semáforo (leitura): {e_sem}", logging.ERROR)

        return data