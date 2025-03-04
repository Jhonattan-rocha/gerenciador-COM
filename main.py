import sys
import json
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QTabWidget, QLabel, QGroupBox, QGridLayout,
                             QLineEdit, QPushButton, QComboBox, QTextEdit,
                             QFileDialog, QMessageBox) # Import QMessageBox for error dialogs
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtCore import QTimer, QThread, Signal, QSemaphore
import serial, logging
import serial.tools.list_ports
import socket
import threading

class SerealConWindow(QWidget):
    log_signal = Signal(str)
    status_signal = Signal(str) # Signal for status updates

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gerenciador de porta sereal")
        self.setWindowIcon(QIcon("./icon.png"))
        self.serial_port = None
        self.server_socket = None
        self.client_thread = None
        self.server_thread = None
        self.connected_clients = {}
        self.serial_port_semaphore = QSemaphore(1)
        self.log_file_path = ""
        self.log_file_name = "app_log.txt"

        self.tab_widget = QTabWidget()
        self.config_tab = QWidget()
        self.status_tab = QWidget()
        self.log_tab = QWidget()
        self.credits_tab = QWidget()

        self.tab_widget.addTab(self.config_tab, "Configuração")
        self.tab_widget.addTab(self.status_tab, "Status da Conexão")
        self.tab_widget.addTab(self.log_tab, "Log")
        self.tab_widget.addTab(self.credits_tab, "Créditos")

        self.setup_config_tab()
        self.setup_status_tab()
        self.setup_log_tab()
        self.setup_credits_tab()

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(self.tab_widget)
        self.setLayout(main_layout)

        self.load_config()
        self.setup_logging()
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.update_log_content)
        self.log_timer.start(5000)
        self.log_signal.connect(self.append_log_text)
        self.status_signal.connect(self.update_status_text) # Connect status signal

        self.log_message("Aplicativo Iniciado.")

    def setup_status_tab(self):
        status_layout = QVBoxLayout(self.status_tab)

        # Grupo Status da Conexão
        connection_status_group = QGroupBox("Status da Conexão")
        connection_status_layout = QGridLayout()

        self.status_label_value = QLabel("Desconectado")
        self.connection_details_value = QLabel("N/A")
        self.focused_port_value = QLabel("N/A")
        self.connected_clients_value = QLabel("0")
        self.server_status_value = QLabel("Parado") # Server mode specific status
        self.client_status_value = QLabel("Desconectado") # Client mode specific status

        connection_status_layout.addWidget(QLabel("Status Geral:"), 0, 0)
        connection_status_layout.addWidget(self.status_label_value, 0, 1)
        connection_status_layout.addWidget(QLabel("Detalhes da Conexão:"), 1, 0)
        connection_status_layout.addWidget(self.connection_details_value, 1, 1)
        connection_status_layout.addWidget(QLabel("Porta Serial Focada:"), 2, 0)
        connection_status_layout.addWidget(self.focused_port_value, 2, 1)
        connection_status_layout.addWidget(QLabel("Clientes Conectados (Servidor):"), 3, 0)
        connection_status_layout.addWidget(self.connected_clients_value, 3, 1)
        connection_status_layout.addWidget(QLabel("Status Servidor:"), 4, 0) # Server status label
        connection_status_layout.addWidget(self.server_status_value, 4, 1) # Server status value
        connection_status_layout.addWidget(QLabel("Status Cliente:"), 5, 0) # Client status label
        connection_status_layout.addWidget(self.client_status_value, 5, 1) # Client status value

        connection_status_group.setLayout(connection_status_layout)

        status_layout.addWidget(connection_status_group)
        self.status_tab.setLayout(status_layout)

    def update_status_text(self, status_message):
        """Updates status label in GUI thread."""
        status_data = json.loads(status_message)
        if 'status_label' in status_data:
            self.status_label_value.setText(status_data['status_label'])
        if 'connection_details' in status_data:
            self.connection_details_value.setText(status_data['connection_details'])
        if 'focused_port' in status_data:
            self.focused_port_value.setText(status_data['focused_port'])
        if 'server_status' in status_data:
            self.server_status_value.setText(status_data['server_status'])
        if 'client_status' in status_data:
            self.client_status_value.setText(status_data['client_status'])

    def handle_connect_button(self):
        """Function to execute on Connect button click."""
        modo = self.mode_combo.currentText()
        if modo == "Servidor":
            if not self.server_thread or not self.server_thread.isRunning():
                self.start_server_mode()
            else:
                self.stop_server_mode() # Stop if already running
        elif modo == "Cliente":
            if not self.client_thread or not self.client_thread.isRunning():
                self.start_client_mode()
            else:
                self.stop_client_mode() # Stop if already running
        else:
            self.log_message("Modo inválido selecionado.")

        self.save_config()
        self.update_log_content()
        self.update_connect_button_text() # Update button text after action

    def update_connect_button_text(self):
        """Updates the connect button text based on current mode and thread status."""
        modo = self.mode_combo.currentText()
        if modo == "Servidor":
            if self.server_thread and self.server_thread.isRunning():
                self.connect_button.setText("Parar Servidor")
            else:
                self.connect_button.setText("Iniciar Servidor")
        elif modo == "Cliente":
            if self.client_thread and self.client_thread.isRunning():
                self.connect_button.setText("Desconectar Cliente")
            else:
                self.connect_button.setText("Conectar Cliente")
        else:
            self.connect_button.setText("Conectar") # Default text

    def start_server_mode(self):
        """Starts the application in Server mode."""
        ip = self.server_ip_input.text()
        port = self.server_port_input.text()
        porta_serial = self.serial_port_combo.currentText()

        if not ip or not port or not porta_serial:
            self.log_message("Configurações de Servidor incompletas.")
            QMessageBox.warning(self, "Erro de Configuração", "Por favor, preencha todas as configurações do servidor.")
            self.update_status_gui(status_label="Erro de Configuração", server_status="Configuração Incompleta")
            return

        try:
            port_num = int(port)
        except ValueError:
            self.log_message("Porta do servidor inválida. Deve ser um número.")
            QMessageBox.warning(self, "Erro de Configuração", "Porta do servidor inválida. Deve ser um número.")
            self.update_status_gui(status_label="Erro de Configuração", server_status="Porta Inválida")
            return

        self.log_message(f"Iniciando Servidor em: {ip}:{port}")
        self.update_status_gui(status_label="Iniciando Servidor", connection_details=f"Servidor: {ip}:{port}", focused_port=porta_serial, server_status="Iniciando...")

        # Stop any existing server thread
        self.stop_server_mode()

        self.server_thread = ServerThread(ip, port_num, porta_serial, self.serial_port_semaphore, self.log_signal, self.status_signal)
        self.server_thread.client_connected_signal.connect(self.update_connected_clients_count)
        self.server_thread.server_status_signal.connect(self.update_server_status_gui) # Connect server status signals
        self.server_thread.start()
        self.connect_button.setText("Parar Servidor") # Immediately update button text
        self.log_message("Thread Servidor iniciada.")


    def stop_server_mode(self):
        """Stops the server thread if it's running."""
        if self.server_thread and self.server_thread.isRunning():
            self.log_message("Parando thread Servidor...")
            self.update_status_gui(status_label="Parando Servidor", server_status="Parando...")
            self.server_thread.stop_server()
            self.server_thread.wait()
            self.server_thread = None
            self.connected_clients = {}
            self.update_connected_clients_count(0)
        self.update_status_gui(status_label="Desconectado", connection_details="Servidor parado", server_status="Parado")
        self.connect_button.setText("Iniciar Servidor")


    def start_client_mode(self):
        """Starts the application in Client mode."""
        url = self.client_url_input.text()
        porta_serial = self.serial_port_combo.currentText()

        if not url or not porta_serial:
            self.log_message("Configurações de Cliente incompletas.")
            QMessageBox.warning(self, "Erro de Configuração", "Por favor, preencha a URL do cliente e selecione a porta serial.")
            self.update_status_gui(status_label="Erro de Configuração", client_status="Configuração Incompleta")
            return

        self.log_message(f"Conectando ao Cliente em: {url}")
        self.update_status_gui(status_label="Conectando Cliente", connection_details=f"Cliente: {url}", focused_port=porta_serial, client_status="Conectando...")

        # Stop any existing client thread
        self.stop_client_mode()

        self.client_thread = ClientThread(url, porta_serial, self.log_signal, self.serial_port_semaphore, self.status_signal)
        self.client_thread.client_status_signal.connect(self.update_client_status_gui) # Connect client status signal
        self.client_thread.start()
        self.connect_button.setText("Desconectar Cliente") # Immediately update button text
        self.log_message("Thread Cliente iniciada.")


    def stop_client_mode(self):
        """Stops the client thread if it's running."""
        if self.client_thread and self.client_thread.isRunning():
            self.log_message("Parando thread Cliente...")
            self.update_status_gui(status_label="Desconectando Cliente", client_status="Desconectando...")
            self.client_thread.stop_client()
            self.client_thread.wait()
            self.client_thread = None
        self.update_status_gui(status_label="Desconectado", connection_details="Cliente parado", client_status="Desconectado")
        self.connect_button.setText("Conectar Cliente")


    def update_log_content(self):
        """Updates log content in QTextEdit from file."""
        if self.log_file_path:
            try:
                with open(self.log_file_path, 'r') as f:
                    log_content = f.read()
                    self.log_text_edit.setText(log_content)
                    self.log_text_edit.verticalScrollBar().setValue(self.log_text_edit.verticalScrollBar().maximum())
            except FileNotFoundError:
                self.log_text_edit.setText("Arquivo de log não encontrado.")
            except Exception as e:
                self.log_text_edit.setText(f"Erro ao ler o log: {e}")
        else:
             self.log_text_edit.setText("Local do arquivo de log não configurado.")

    def append_log_text(self, message):
        """Appends text to log QTextEdit in GUI thread."""
        self.log_text_edit.append(message)

    def log_message(self, message, level=logging.INFO):
        """Logs a message to system and log window."""
        logging.log(level, message)

    def save_config(self):
        """Saves configuration to JSON file."""
        config = {
            "modo": self.mode_combo.currentText(),
            "server_ip": self.server_ip_input.text(),
            "server_port": self.server_port_input.text(),
            "client_url": self.client_url_input.text(),
            "log_location": self.log_location_input.text(),
            "log_file_name": self.log_file_name_input.text(),
            "usuario": self.user_input.text(),
            "senha": self.password_input.text(),
            "porta_serial": self.serial_port_combo.currentText()
        }
        try:
            with open("config.json", 'w') as f:
                json.dump(config, f, indent=4)
            self.log_message("Configurações salvas em config.json")
        except Exception as e:
            self.log_message(f"Erro ao salvar as configurações: {e}", level=logging.ERROR)

    def load_config(self):
        """Loads configuration from JSON file."""
        try:
            with open("config.json", 'r') as f:
                config = json.load(f)
                self.mode_combo.setCurrentText(config.get("modo", "Cliente"))
                self.server_ip_input.setText(config.get("server_ip", ""))
                self.server_port_input.setText(config.get("server_port", ""))
                self.client_url_input.setText(config.get("client_url", ""))
                self.log_location_input.setText(config.get("log_location", ""))
                self.log_file_name_input.setText(config.get("log_file_name", "app_log.txt"))
                self.log_file_name = self.log_file_name_input.text()
                self.user_input.setText(config.get("usuario", ""))
                self.password_input.setText(config.get("senha", ""))
                serial_port = config.get("porta_serial", "")
                if serial_port:
                    index = self.serial_port_combo.findText(serial_port)
                    if index != -1:
                        self.serial_port_combo.setCurrentIndex(index)

            self.log_message("Configurações carregadas de config.json")
        except FileNotFoundError:
            self.log_message("Arquivo de configuração não encontrado. Usando configurações padrão.")
        except Exception as e:
            self.log_message(f"Erro ao carregar as configurações: {e}", level=logging.ERROR)

    def update_connected_clients_count(self, count):
        """Updates connected clients count in status tab."""
        self.connected_clients_value.setText(str(count))

    def update_status_gui(self, status_label=None, connection_details=None, focused_port=None, server_status=None, client_status=None):
        """Helper to bundle status updates into a signal emission."""
        status_update = {}
        if status_label is not None:
            status_update['status_label'] = status_label
        if connection_details is not None:
            status_update['connection_details'] = connection_details
        if focused_port is not None:
            status_update['focused_port'] = focused_port
        if server_status is not None:
            status_update['server_status'] = server_status
        if client_status is not None:
            status_update['client_status'] = client_status
        self.status_signal.emit(json.dumps(status_update))

    def update_server_status_gui(self, status_message):
        """Updates server specific status in GUI thread."""
        status_data = json.loads(status_message)
        if 'server_status' in status_data:
            self.update_status_gui(server_status=status_data['server_status'])

    def update_client_status_gui(self, status_message):
        """Updates client specific status in GUI thread."""
        status_data = json.loads(status_message)
        if 'client_status' in status_data:
            self.update_status_gui(client_status=status_data['client_status'])


class ServerThread(QThread):
    client_connected_signal = Signal(int)
    server_status_signal = Signal(str) # Signal server status to GUI

    def __init__(self, ip, port, serial_port_name, serial_semaphore, log_signal, status_signal):
        super().__init__()
        self.ip = ip
        self.port = port
        self.serial_port_name = serial_port_name
        self.serial_semaphore = serial_semaphore
        self.log_signal = log_signal
        self.status_signal = status_signal # Status signal for GUI updates
        self._is_running = True
        self.server_socket = None
        self.serial_port = None
        self.connected_clients = {}

    def stop_server(self):
        """Sets stop flag and closes server socket."""
        self._is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                logging.error(f"Erro ao fechar o socket do servidor: {e}")

    def run(self):
        """Server thread execution."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.ip, self.port))
            self.server_socket.listen(5)
            self.log_message(f"Servidor ouvindo em {self.ip}:{self.port}")
            self.update_server_status("Ouvindo") # Update server status to "Ouvindo" in GUI
            self.update_connected_clients_count_signal()
            if not self.open_serial_port(): # Open serial port, check if successful
                return # Exit if serial port opening fails

            while self._is_running:
                try:
                    self.server_socket.settimeout(1) # Set a timeout for accept
                    client_socket, addr = self.server_socket.accept()
                    self.server_socket.settimeout(None) # Reset timeout after accept

                    if not self._is_running:
                        client_socket.close()
                        break

                    client_id = addr[1]
                    self.connected_clients[client_id] = client_socket
                    self.update_connected_clients_count_signal()
                    self.log_message(f"Cliente conectado de {addr}")
                    self.update_server_status("Ouvindo") # Keep status as "Ouvindo", clients are connected

                    client_handler_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
                    client_handler_thread.daemon = True
                    client_handler_thread.start()

                except socket.timeout: # Socket timeout is normal, check running flag
                    if not self._is_running:
                        break
                    continue

                except OSError as e: # Socket closed by stop_server
                    if not self._is_running:
                        break
                    else:
                        self.log_message(f"Erro ao aceitar conexão: {e}", level=logging.ERROR)
                        self.update_server_status("Erro") # Update server status to "Erro"
                        break

                except Exception as e:
                    self.log_message(f"Erro inesperado no loop do servidor: {e}", level=logging.ERROR)
                    self.update_server_status("Erro") # Update server status to "Erro"
                    break

        finally:
            self.close_serial_port()
            if self.server_socket:
                self.server_socket.close()
                self.log_message("Socket do servidor fechado.")
            self.update_server_status("Parado") # Update server status to "Parado" in GUI
            self.log_message("Thread Servidor finalizada.")


    def handle_client(self, client_socket, addr):
        """Handles communication with a single client."""
        client_ip_addr = f"{addr[0]}:{addr[1]}"
        try:
            while self._is_running:
                data = client_socket.recv(1024)
                if not data:
                    self.log_message(f"Cliente {client_ip_addr} desconectado.")
                    break

                decoded_data = data.decode('utf-8')
                self.log_message(f"Recebido do cliente {client_ip_addr}: {decoded_data.strip()}")
                self.write_to_serial_port(decoded_data)

        except Exception as e:
            self.log_message(f"Erro ao lidar com o cliente {client_ip_addr}: {e}", level=logging.ERROR)
        finally:
            client_id = addr[1]
            if client_id in self.connected_clients:
                del self.connected_clients[client_id]
                self.update_connected_clients_count_signal()
            client_socket.close()
            self.log_message(f"Conexão com cliente {client_ip_addr} encerrada.")


    def open_serial_port(self):
        """Opens the serial port and returns success status."""
        try:
            self.serial_port = serial.Serial(self.serial_port_name, baudrate=9600, timeout=1)
            self.log_message(f"Porta serial {self.serial_port_name} aberta.")
            return True # Serial port opened successfully
        except serial.SerialException as e:
            self.log_message(f"Erro ao abrir porta serial {self.serial_port_name}: {e}", level=logging.ERROR)
            self.update_server_status("Erro na Serial") # Update server status to "Erro na Serial"
            self._is_running = False
            return False # Serial port opening failed

    def close_serial_port(self):
        """Closes the serial port."""
        if self.serial_port and self.serial_port.is_open:
            self.serial_port.close()
            self.log_message(f"Porta serial {self.serial_port_name} fechada.")
            self.serial_port = None


    def write_to_serial_port(self, data):
        """Writes data to serial port using semaphore."""
        if not self.serial_port or not self.serial_port.is_open:
            self.log_message("Porta serial não está aberta.", level=logging.WARNING)
            return

        try:
            if self.serial_semaphore.tryAcquire(timeout=5000):
                try:
                    encoded_data = data.encode('utf-8')
                    self.serial_port.write(encoded_data)
                    self.log_message(f"Enviado para serial: {data.strip()}")
                finally:
                    self.serial_semaphore.release()
            else:
                self.log_message("Timeout ao adquirir semáforo para porta serial.", level=logging.WARNING)

        except serial.SerialTimeoutException:
            self.log_message("Timeout ao escrever na porta serial.", level=logging.WARNING)
        except Exception as e:
            self.log_message(f"Erro ao escrever na porta serial: {e}", level=logging.ERROR)


    def log_message(self, message, level=logging.INFO):
        """Logs a message using log signal for GUI."""
        logging.log(level, message)

    def update_connected_clients_count_signal(self):
        """Emits signal to update client count in GUI."""
        self.client_connected_signal.emit(len(self.connected_clients))

    def update_server_status(self, status_text):
        """Updates server status in GUI via signal."""
        status_update = {'server_status': status_text}
        self.status_signal.emit(json.dumps(status_update))


class ClientThread(QThread):
    client_status_signal = Signal(str) # Signal client status to GUI

    def __init__(self, server_url, serial_port_name, log_signal, serial_semaphore, status_signal):
        super().__init__()
        self.server_url = server_url
        self.serial_port_name = serial_port_name
        self.log_signal = log_signal
        self.serial_semaphore = serial_semaphore
        self.status_signal = status_signal # Status signal for GUI updates
        self._is_running = True
        self.serial_port = None
        self.client_socket = None

    def stop_client(self):
        """Sets stop flag and closes resources."""
        self._is_running = False
        self.close_serial_port()
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception as e:
                self.log_message(f"Erro ao fechar socket cliente: {e}")

    def run(self):
        """Client thread execution."""
        try:
            url_parts = self.server_url.split(':')
            host = url_parts[0]
            port = int(url_parts[1]) if len(url_parts) > 1 and url_parts[1] else 80

            self.update_client_status("Conectando...") # Update client status to "Conectando..." in GUI
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
            self.log_message(f"Conectado ao servidor em {self.server_url}")
            self.update_client_status("Conectado") # Update client status to "Conectado" in GUI
            if not self.open_serial_port(): # Open serial port, check if successful
                self.update_client_status("Erro na Serial") # Update client status if serial fails
                return # Exit if serial port fails to open

            while self._is_running:
                data_from_serial = self.read_from_serial_port()
                if data_from_serial:
                    try:
                        self.client_socket.sendall(data_from_serial.encode('utf-8'))
                        self.log_message(f"Enviado para servidor: {data_from_serial.strip()}")
                    except Exception as e:
                        self.log_message(f"Erro ao enviar dados para o servidor: {e}", level=logging.ERROR)
                        self.update_client_status("Erro de Envio") # Update client status to "Erro de Envio"
                        break # Stop client loop on send error

        except ConnectionRefusedError:
            self.log_message(f"Falha ao conectar ao servidor em {self.server_url}. Conexão Recusada.", level=logging.ERROR)
            self.update_client_status("Conexão Recusada") # Update client status to "Conexão Recusada"
        except Exception as e:
            self.log_message(f"Erro na thread Cliente: {e}", level=logging.ERROR)
            self.update_client_status("Erro de Conexão") # Update client status to "Erro de Conexão"
        finally:
            self.close_serial_port()
            if self.client_socket:
                self.client_socket.close()
                self.log_message("Socket cliente fechado.")
            self.update_client_status("Desconectado") # Update client status to "Desconectado" in GUI
            self.log_message("Thread Cliente finalizada.")


    def open_serial_port(self):
        """Opens the serial port and returns success status."""
        try:
            self.serial_port = serial.Serial(self.serial_port_name, baudrate=9600, timeout=1)
            self.log_message(f"Porta serial {self.serial_port_name} aberta.")
            return True # Serial port opened successfully
        except serial.SerialException as e:
            self.log_message(f"Erro ao abrir porta serial {self.serial_port_name}: {e}", level=logging.ERROR)
            return False # Serial port opening failed


    def close_serial_port(self):
        """Closes the serial port."""
        if self.serial_port and self.serial_port.is_open:
            self.serial_port.close()
            self.log_message(f"Porta serial {self.serial_port_name} fechada.")
            self.serial_port = None


    def read_from_serial_port(self):
        """Reads data from serial port using semaphore."""
        if not self.serial_port or not self.serial_port.is_open:
            self.log_message("Porta serial não está aberta para leitura.", level=logging.WARNING)
            return None

        try:
            if self.serial_semaphore.tryAcquire(timeout=5000):
                try:
                    data = self.serial_port.readline().decode('utf-8').strip()
                    if data:
                        self.log_message(f"Recebido da serial: {data}")
                        return data
                finally:
                    self.serial_semaphore.release()
            else:
                self.log_message("Timeout ao adquirir semáforo para leitura da porta serial.", level=logging.WARNING)
        except serial.SerialTimeoutException:
            pass # Timeout during read is normal
        except Exception as e:
            self.log_message(f"Erro ao ler da porta serial: {e}", level=logging.ERROR)

        return None

    def log_message(self, message, level=logging.INFO):
        """Logs a message using log signal for GUI."""
        logging.log(level, message)

    def update_client_status(self, status_text):
        """Updates client status in GUI via signal."""
        status_update = {'client_status': status_text}
        self.status_signal.emit(json.dumps(status_update))


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SerealConWindow()
    window.show()
    sys.exit(app.exec())