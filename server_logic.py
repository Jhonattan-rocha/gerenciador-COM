import socket
import struct
import threading
import logging
import time
import serial # Importa serial aqui
from PySide6.QtCore import QThread, Signal, QSemaphore

APP_LOGGER_NAME = "SerialApp" # Mesmo nome do logger principal

class ServerThread(QThread):
    # Sinais: (tipo_de_status, mensagem_de_status)
    status_update_signal = Signal(str, str) # ex: ("server_status", "Ouvindo"), ("error", "Falha ao abrir serial")
    client_count_signal = Signal(int)
    # log_signal já é passado no __init__ para logs diretos na GUI

    def __init__(self, ip: str, port: int, serial_port_name: str,
                 serial_semaphore: QSemaphore, serial_params: dict, log_signal: Signal):
        super().__init__()
        self.ip = ip
        self.port = port
        self.serial_port_name = serial_port_name
        self.serial_semaphore = serial_semaphore
        self.serial_params = serial_params
        self.log_signal = log_signal # Para logs que devem ir para a GUI
        self.logger = logging.getLogger(f"{APP_LOGGER_NAME}.ServerThread") # Logger específico do Modulo/Thread

        self._is_running = True
        self.server_socket: socket.socket = None
        self.serial_port: serial.Serial = None
        self.connected_clients = {} # client_socket: address
        self.client_handler_threads: list[QThread] = []


    def _log(self, message: str, level=logging.INFO, to_gui=True):
        self.logger.log(level, message) # Log para arquivo
        if to_gui and self.log_signal:
            # Formato simples, QtHandler na GUI principal adicionará timestamp/level
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            level_name = logging.getLevelName(level)
            self.log_signal.emit(f"{timestamp} - {level_name} - SRV: {message}")


    def stop_server(self):
        self._log("Solicitação para parar o servidor...", to_gui=False) # Log interno
        self.status_update_signal.emit("server_status", "Parando...")
        self._is_running = False

        # Fechar sockets dos clientes
        for client_socket in list(self.connected_clients.keys()): # Itera sobre uma cópia
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
            except Exception as e:
                self._log(f"Erro ao fechar socket do cliente: {e}", logging.ERROR, to_gui=False)
        self.connected_clients.clear()
        self.client_count_signal.emit(0)

        # Fechar socket do servidor
        if self.server_socket:
            try:
                # Truque para desbloquear o accept
                socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((self.ip, self.port))
            except:
                pass # Ignora se não conseguir conectar (servidor já pode estar fechando)
            finally:
                try:
                    self.server_socket.close()
                except Exception as e:
                     self._log(f"Erro ao fechar o socket principal do servidor: {e}", logging.ERROR, to_gui=False)
        self.server_socket = None
        
        # Esperar threads de handle_client terminarem
        for t in self.client_handler_threads:
            if t.is_alive():
                t.join(timeout=1.0) # Dá 1 segundo para cada thread de cliente terminar
        self.client_handler_threads = []


    def run(self):
        self._is_running = True # Garante que está True ao iniciar
        try:
            if not self.open_serial_port():
                # open_serial_port já emite status e loga
                return # Sai se a porta serial não puder ser aberta

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Permite reuso rápido do endereço
            self.server_socket.bind((self.ip, self.port))
            self.server_socket.listen(5)
            self._log(f"Servidor ouvindo em {self.ip}:{self.port}")
            self.status_update_signal.emit("server_status", "Ouvindo")
            self.status_update_signal.emit("connection_detail", f"Servidor: {self.ip}:{self.port}")


            while self._is_running:
                try:
                    self.server_socket.settimeout(1.0) # Timeout para verificar _is_running
                    client_socket, addr = self.server_socket.accept()
                    
                    if not self._is_running: # Verifica novamente após o accept desbloquear
                        client_socket.close()
                        break

                    self._log(f"Cliente conectado de {addr}")
                    self.connected_clients[client_socket] = addr
                    self.client_count_signal.emit(len(self.connected_clients))

                    client_handler = threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True)
                    self.client_handler_threads.append(client_handler)
                    client_handler.start()

                except socket.timeout:
                    continue # Loop normal para checar _is_running
                except OSError as e: # Ex: socket fechado
                    if self._is_running: # Se não era esperado o fechamento
                        self._log(f"Erro de socket no loop principal: {e}", logging.ERROR)
                        self.status_update_signal.emit("server_status", "Erro de Socket")
                    break # Sai do loop se o socket foi fechado
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
            if self.server_socket: # Garante que o socket do servidor seja fechado
                try:
                    self.server_socket.close()
                except: pass # Ignora erros no fechamento final
            
            # Limpeza final de threads de cliente, se alguma ainda estiver na lista
            for t in self.client_handler_threads:
                if t.is_alive():
                    t.join(timeout=0.1)
            self.client_handler_threads = []

            # Garante que o estado final seja "Parado" se ainda estiver rodando no final
            if self._is_running: # Se saiu por erro, mas _is_running não foi setado para False
                self._is_running = False 
            
            self.status_update_signal.emit("server_status", "Parado")
            self._log("Thread Servidor finalizada.", to_gui=False)


    def handle_client(self, client_socket: socket.socket, addr):
        client_ip_addr = f"{addr[0]}:{addr[1]}"
        self._log(f"Handler iniciado para cliente {client_ip_addr}")
        try:
            while self._is_running: # Verifica a flag global do servidor
                # Protocolo: 8 bytes para tamanho (unsigned long long, network byte order)
                # seguido pelos dados.
                data_len_packed = client_socket.recv(8)
                if not data_len_packed:
                    self._log(f"Cliente {client_ip_addr} desconectou (sem enviar tamanho).")
                    break
                
                data_len = struct.unpack("!Q", data_len_packed)[0]
                if data_len == 0: # Pode ser um keep-alive ou fim de transmissão planejada
                    self._log(f"Cliente {client_ip_addr} enviou tamanho de dados 0.", logging.DEBUG)
                    continue

                data = b''
                while len(data) < data_len:
                    chunk = client_socket.recv(data_len - len(data))
                    if not chunk:
                        self._log(f"Cliente {client_ip_addr} desconectou durante transmissão de dados.", logging.WARNING)
                        return # Sai do handler
                    data += chunk
                
                # Assume-se que os dados recebidos do cliente são para a porta serial
                # Tentar decodificar para log, mas enviar bytes crus para a serial
                try:
                    decoded_data_for_log = data.decode('cp850', errors='replace').strip()
                    self._log(f"Recebido de {client_ip_addr} para serial: '{decoded_data_for_log}' ({len(data)} bytes)")
                except Exception as e:
                    self._log(f"Recebido de {client_ip_addr} para serial: {len(data)} bytes (erro ao decodificar para log: {e})")

                self.write_to_serial_port(data)

                # Resposta da serial para o cliente (se houver)
                # Esta parte precisa ser bem definida: o servidor espera uma resposta da serial?
                # Se sim, como e quando ler? Por agora, é unidirecional: cliente -> serial.
                # Para comunicação bidirecional, seria necessário um loop de leitura da serial aqui
                # e envio de volta para client_socket.

        except ConnectionResetError:
            self._log(f"Cliente {client_ip_addr} resetou a conexão.", logging.WARNING)
        except socket.error as e:
            if self._is_running: # Só loga como erro se o servidor não estiver parando
                 self._log(f"Erro de socket com cliente {client_ip_addr}: {e}", logging.ERROR)
        except Exception as e:
            if self._is_running:
                self._log(f"Erro ao lidar com cliente {client_ip_addr}: {e}", logging.ERROR)
        finally:
            if client_socket in self.connected_clients:
                del self.connected_clients[client_socket]
                self.client_count_signal.emit(len(self.connected_clients))
            try:
                client_socket.close()
            except: pass # Ignora erros ao fechar
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
                timeout=self.serial_params.get("timeout", 1), # Timeout para leituras
                xonxoff=False, # Geralmente False para hardware
                rtscts=self.serial_params.get("rtscts", False),
                dsrdtr=self.serial_params.get("dsrdtr", False)
            )
            # Pyserial >= 3.0 levanta SerialException em falha de abertura
            self._log(f"Porta serial {self.serial_port_name} aberta com sucesso.")
            self.status_update_signal.emit("server_status", "Serial Conectada")
            return True
        except serial.SerialException as e:
            self._log(f"Falha ao abrir porta serial {self.serial_port_name}: {e}", logging.ERROR)
            self.status_update_signal.emit("server_status", "Erro na Serial")
            self.status_update_signal.emit("error", f"Serial: {e}") # Sinal específico de erro
            return False
        except Exception as e_gen: # Outras exceções (ex: ValueError em parâmetros)
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
            self._log("Tentativa de escrita em porta serial fechada ou indisponível.", logging.WARNING)
            self.status_update_signal.emit("error", "Serial desconectada ao escrever.")
            return

        try:
            if self.serial_semaphore.tryAcquire(): # Tenta adquirir por 500ms
                try:
                    # Limpar buffers antes de escrever pode ser útil em alguns casos,
                    # mas pode descartar dados importantes em outros. Avaliar necessidade.
                    self.serial_port.reset_input_buffer()
                    self.serial_port.reset_output_buffer()

                    bytes_written = self.serial_port.write(data)
                    self.serial_port.flush() # Garante que os dados sejam enviados
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
                self._log("Não foi possível adquirir semáforo para escrita serial (timeout).", logging.WARNING)
                self.status_update_signal.emit("warning", "Semáforo serial ocupado (escrita).")
        except Exception as e_sem:
             self._log(f"Erro relacionado ao semáforo: {e_sem}", logging.ERROR)