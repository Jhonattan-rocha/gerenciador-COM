import socket
import struct
import threading
import logging
import time
import serial # Importa serial aqui
from PySide6.QtCore import QThread, Signal, QSemaphore

APP_LOGGER_NAME = "SerialApp" # Mesmo nome do logger principal

class ServerThread(QThread):
    status_update_signal = Signal(str, str)
    client_list_signal = Signal(list)
    data_transmitted_signal = Signal(int)
    data_received_signal = Signal(int)
    uptime_signal = Signal(str)

    def __init__(self, ip: str, port: int, serial_port_name: str,
                 serial_semaphore: QSemaphore, serial_params: dict, log_signal: Signal):
        super().__init__()
        self.ip = ip
        self.port = port
        self.serial_port_name = serial_port_name
        self.serial_semaphore = serial_semaphore
        self.serial_params = serial_params
        self.log_signal = log_signal
        self.logger = logging.getLogger(f"{APP_LOGGER_NAME}.ServerThread")

        self._is_running = True
        self.server_socket: socket.socket = None
        self.serial_port: serial.Serial = None
        self.connected_clients = {} # client_socket: address
        self.client_handler_threads: list[threading.Thread] = []
        
        self.start_time = 0
        self.bytes_sent = 0
        self.bytes_received = 0


    def _log(self, message: str, level=logging.INFO, to_gui=True):
        self.logger.log(level, message) # Log para arquivo
        if to_gui and self.log_signal:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            level_name = logging.getLevelName(level)
            self.log_signal.emit(f"{timestamp} - {level_name} - SRV: {message}")


    def stop_server(self):
        self._log("Solicitação para parar o servidor...", to_gui=False) # Log interno
        self.status_update_signal.emit("server_status", "Parando...")
        self._is_running = False

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                 self._log(f"Erro ao fechar o socket principal do servidor: {e}", logging.ERROR, to_gui=False)
        
        for client_socket in list(self.connected_clients.keys()):
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
            except Exception as e:
                self._log(f"Erro ao fechar socket do cliente: {e}", logging.ERROR, to_gui=False)
        
        self.connected_clients.clear()
        self.update_client_list_signal()


    def run(self):
        self._is_running = True
        self.start_time = time.time()
        self.bytes_sent = 0
        self.bytes_received = 0
        
        try:
            if not self.open_serial_port():
                return

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.ip, self.port))
            self.server_socket.listen(5)
            self._log(f"Servidor ouvindo em {self.ip}:{self.port}")
            self.status_update_signal.emit("server_status", "Ouvindo")
            self.status_update_signal.emit("connection_detail", f"Servidor: {self.ip}:{self.port}")

            while self._is_running:
                try:
                    self.server_socket.settimeout(1.0)
                    client_socket, addr = self.server_socket.accept()
                    
                    if not self._is_running:
                        client_socket.close()
                        break

                    self._log(f"Cliente conectado de {addr}")
                    self.connected_clients[client_socket] = addr
                    self.update_client_list_signal()

                    client_handler = threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True)
                    self.client_handler_threads.append(client_handler)
                    client_handler.start()

                except socket.timeout:
                    self.update_uptime()
                    continue
                except OSError as e:
                    if self._is_running:
                        self._log(f"Erro de socket no loop principal: {e}", logging.ERROR)
                        self.status_update_signal.emit("server_status", "Erro de Socket")
                    break
                except Exception as e:
                    if self._is_running:
                        self._log(f"Erro inesperado no loop do servidor: {e}", logging.ERROR)
                        self.status_update_signal.emit("server_status", f"Erro: {e}")
                    break
        
        except Exception as e:
            self._log(f"Erro crítico na thread do servidor: {e}", logging.CRITICAL)
            self.status_update_signal.emit("server_status", f"Erro Crítico: {e}")
        finally:
            self.close_serial_port()
            if self.server_socket:
                try:
                    self.server_socket.close()
                except: pass
            
            if self._is_running:
                self._is_running = False 
            
            self.status_update_signal.emit("server_status", "Parado")
            self._log("Thread Servidor finalizada.", to_gui=False)

    def update_uptime(self):
        uptime_seconds = int(time.time() - self.start_time)
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        self.uptime_signal.emit(f"{hours:02}:{minutes:02}:{seconds:02}")

    def update_client_list_signal(self):
        client_list = [f"{addr[0]}:{addr[1]}" for addr in self.connected_clients.values()]
        self.client_list_signal.emit(client_list)

    def handle_client(self, client_socket: socket.socket, addr):
        client_ip_addr = f"{addr[0]}:{addr[1]}"
        self._log(f"Handler iniciado para cliente {client_ip_addr}")
        try:
            while self._is_running:
                data_len_packed = client_socket.recv(8)
                if not data_len_packed:
                    self._log(f"Cliente {client_ip_addr} desconectou (sem enviar tamanho).")
                    break
                
                data_len = struct.unpack("!Q", data_len_packed)[0]
                if data_len == 0:
                    self._log(f"Cliente {client_ip_addr} enviou tamanho de dados 0.", logging.DEBUG)
                    continue

                data = b''
                while len(data) < data_len:
                    chunk = client_socket.recv(data_len - len(data))
                    if not chunk:
                        self._log(f"Cliente {client_ip_addr} desconectou durante transmissão.", logging.WARNING)
                        return
                    data += chunk
                
                self.bytes_received += len(data)
                self.data_received_signal.emit(self.bytes_received)

                try:
                    decoded_data_for_log = data.decode('cp850', errors='replace').strip()
                    self._log(f"Recebido de {client_ip_addr} para serial: '{decoded_data_for_log}' ({len(data)} bytes)")
                except Exception as e:
                    self._log(f"Recebido de {client_ip_addr}: {len(data)} bytes (erro ao decodificar: {e})")

                self.write_to_serial_port(data)

        except ConnectionResetError:
            self._log(f"Cliente {client_ip_addr} resetou a conexão.", logging.WARNING)
        except socket.error as e:
            if self._is_running:
                 self._log(f"Erro de socket com {client_ip_addr}: {e}", logging.ERROR)
        except Exception as e:
            if self._is_running:
                self._log(f"Erro ao lidar com {client_ip_addr}: {e}", logging.ERROR)
        finally:
            if client_socket in self.connected_clients:
                del self.connected_clients[client_socket]
                self.update_client_list_signal()
            try:
                client_socket.close()
            except: pass
            self._log(f"Conexão com cliente {client_ip_addr} encerrada.")


    def open_serial_port(self) -> bool:
        if self.serial_port and self.serial_port.is_open:
            self._log("Porta serial já está aberta.", logging.DEBUG)
            return True
        try:
            self._log(f"Tentando abrir porta serial {self.serial_port_name} com params: {self.serial_params}")
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
            self._log(f"Porta serial {self.serial_port_name} aberta com sucesso.")
            self.status_update_signal.emit("server_status", "Serial Conectada")
            return True
        except serial.SerialException as e:
            self._log(f"Falha ao abrir porta serial {self.serial_port_name}: {e}", logging.ERROR)
            self.status_update_signal.emit("server_status", "Erro na Serial")
            self.status_update_signal.emit("error", f"Serial: {e}")
            return False
        except Exception as e_gen:
            self._log(f"Erro inesperado ao configurar porta serial {self.serial_port_name}: {e_gen}", logging.ERROR)
            self.status_update_signal.emit("server_status", "Erro Config Serial")
            self.status_update_signal.emit("error", f"Config Serial: {e_gen}")
            return False


    def close_serial_port(self):
        if self.serial_port and self.serial_port.is_open:
            try:
                self.serial_port.close()
                self._log(f"Porta serial {self.serial_port_name} fechada.")
            except Exception as e:
                self._log(f"Erro ao fechar porta serial {self.serial_port_name}: {e}", logging.ERROR)
        self.serial_port = None


    def write_to_serial_port(self, data: bytes):
        if not self.serial_port or not self.serial_port.is_open:
            self._log("Tentativa de escrita em porta serial fechada.", logging.WARNING)
            self.status_update_signal.emit("error", "Serial desconectada ao escrever.")
            return

        try:
            if self.serial_semaphore.tryAcquire():
                try:
                    self.serial_port.reset_input_buffer()
                    self.serial_port.reset_output_buffer()

                    bytes_written = self.serial_port.write(data)
                    self.serial_port.flush()
                    

                    
                    self._log(f"Enviado {bytes_written} bytes para serial: '{data.decode('cp850', 'replace')}'", logging.DEBUG)
                except serial.SerialTimeoutException:
                    self._log("Timeout ao escrever na porta serial.", logging.WARNING)
                    self.status_update_signal.emit("error", "Timeout na escrita serial.")
                except Exception as e:
                    self._log(f"Erro ao escrever na porta serial: {e}", logging.ERROR)
                    self.status_update_signal.emit("error", f"Erro escrita serial: {e}")
                finally:
                    self.serial_semaphore.release()
            else:
                self._log("Não foi possível adquirir semáforo para escrita serial.", logging.WARNING)
                self.status_update_signal.emit("warning", "Semáforo serial ocupado.")
        except Exception as e_sem:
             self._log(f"Erro no semáforo: {e_sem}", logging.ERROR)