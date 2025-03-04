import sys
import json
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QTabWidget, QLabel, QGroupBox, QGridLayout,
                             QLineEdit, QPushButton, QComboBox, QTextEdit,
                             QFileDialog)
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtCore import QTimer, QThread, Signal, QSemaphore  # Import QThread, Signal, QSemaphore
import serial, logging
import serial.tools.list_ports
import socket
import threading

class SerealConWindow(QWidget):
    log_signal = Signal(str) # Signal to update log from threads

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gerenciador de porta sereal")
        self.setWindowIcon(QIcon("./icon.png"))
        self.serial_port = None # To store serial port instance
        self.server_socket = None # To store server socket
        self.client_thread = None # To store client thread
        self.server_thread = None # To store server thread
        self.connected_clients = {} # To store connected clients in server mode
        self.serial_port_semaphore = QSemaphore(1) # Semaphore for serial port access
        self.log_file_path = "" # Initialize log file path
        self.log_file_name = "app_log.txt" # Default log file name, will be configurable

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
        self.setup_logging() # Setup logging after loading config to get log file name
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.update_log_content)
        self.log_timer.start(5000)
        self.log_signal.connect(self.append_log_text) # Connect signal to append log text

        self.log_message("Aplicativo Iniciado.") # Initial log message

    def setup_logging(self):
        """Sets up logging to file and QTextEdit."""
        log_dir = self.log_location_input.text()
        if log_dir:
            self.log_file_path = f"{log_dir}/{self.log_file_name}"
        else:
            self.log_file_path = self.log_file_name # Fallback if no log location is set in config

        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            filename=self.log_file_path,
                            filemode='w') # 'w' to overwrite log on each start, use 'a' to append

        # Redirect stdout and stderr to logging
        class QtHandler(logging.Handler):
            def __init__(self):
                logging.Handler.__init__(self)

            def emit(self, record):
                record = self.format(record)
                self.log_signal.emit(record) # Emit signal with log message

        handler = QtHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)
        logging.info("Logging configurado.")

        # Redirect print to logging.info
        def log_print(*args, **kwargs):
            message = ' '.join(map(str, args))
            logging.info(message)
        sys.stdout.write = log_print
        sys.stderr.write = log_print


    def setup_config_tab(self):
        config_layout = QVBoxLayout(self.config_tab)

        # Modo Cliente/Servidor
        mode_layout = QHBoxLayout()
        mode_label = QLabel("Modo:")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Cliente", "Servidor"])
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)

        # Configurações de Servidor
        self.server_config_group = QGroupBox("Configurações Servidor")
        server_config_layout = QGridLayout()
        self.server_ip_label = QLabel("IP:")
        self.server_ip_input = QLineEdit()
        self.server_port_label = QLabel("Porta:")
        self.server_port_input = QLineEdit()
        server_config_layout.addWidget(self.server_ip_label, 0, 0)
        server_config_layout.addWidget(self.server_ip_input, 0, 1)
        server_config_layout.addWidget(self.server_port_label, 1, 0)
        server_config_layout.addWidget(self.server_port_input, 1, 1)
        self.server_config_group.setLayout(server_config_layout)

        # Configurações de Cliente
        self.client_config_group = QGroupBox("Configurações Cliente")
        client_config_layout = QGridLayout()
        self.client_url_label = QLabel("URL (com porta):")
        self.client_url_input = QLineEdit()
        client_config_layout.addWidget(self.client_url_label, 0, 0)
        client_config_layout.addWidget(self.client_url_input, 0, 1)
        self.client_config_group.setLayout(client_config_layout)

        # Local do Log
        log_location_layout = QHBoxLayout()
        log_location_label = QLabel("Local do Log:")
        self.log_location_input = QLineEdit()
        self.log_location_button = QPushButton("Escolher Pasta")
        self.log_location_button.clicked.connect(self.choose_log_location)
        log_location_layout.addWidget(log_location_label)
        log_location_layout.addWidget(self.log_location_input)
        log_location_layout.addWidget(self.log_location_button)

        # Nome do Arquivo de Log
        log_file_name_layout = QHBoxLayout()
        log_file_name_label = QLabel("Nome Arquivo Log:")
        self.log_file_name_input = QLineEdit()
        self.log_file_name_input.setText(self.log_file_name) # Default value
        log_file_name_layout.addWidget(log_file_name_label)
        log_file_name_layout.addWidget(self.log_file_name_input)


        # Usuário e Senha
        user_pass_layout = QGridLayout()
        user_label = QLabel("Usuário:")
        self.user_input = QLineEdit()
        password_label = QLabel("Senha:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        user_pass_layout.addWidget(user_label, 0, 0)
        user_pass_layout.addWidget(self.user_input, 0, 1)
        user_pass_layout.addWidget(password_label, 1, 0)
        user_pass_layout.addWidget(self.password_input, 1, 1)

        # Porta Serial
        serial_port_layout = QHBoxLayout()
        serial_port_label = QLabel("Porta Serial:")
        self.serial_port_combo = QComboBox()
        ports = serial.tools.list_ports.comports()

        if ports:
            for port, desc, hwid in sorted(ports):
                self.serial_port_combo.addItem(port)

        serial_port_layout.addWidget(serial_port_label)
        serial_port_layout.addWidget(self.serial_port_combo)

        # Botão Conectar
        self.connect_button = QPushButton("Conectar")
        self.connect_button.clicked.connect(self.handle_connect_button)

        config_layout.addLayout(mode_layout)
        config_layout.addWidget(self.server_config_group)
        config_layout.addWidget(self.client_config_group)
        config_layout.addLayout(log_location_layout)
        config_layout.addLayout(log_file_name_layout) # Add log file name input
        config_layout.addLayout(user_pass_layout)
        config_layout.addLayout(serial_port_layout)
        config_layout.addWidget(self.connect_button)
        self.config_tab.setLayout(config_layout)

        self.update_server_client_visibility()
        self.mode_combo.currentIndexChanged.connect(self.update_server_client_visibility)


    def setup_status_tab(self):
        status_layout = QVBoxLayout(self.status_tab)

        # Grupo Status da Conexão
        connection_status_group = QGroupBox("Status da Conexão")
        connection_status_layout = QGridLayout()

        self.status_label_value = QLabel("Desconectado")
        self.connection_details_value = QLabel("N/A")
        self.focused_port_value = QLabel("N/A")
        self.connected_clients_value = QLabel("0") # For server mode client count

        connection_status_layout.addWidget(QLabel("Status:"), 0, 0)
        connection_status_layout.addWidget(self.status_label_value, 0, 1)
        connection_status_layout.addWidget(QLabel("Detalhes da Conexão:"), 1, 0)
        connection_status_layout.addWidget(self.connection_details_value, 1, 1)
        connection_status_layout.addWidget(QLabel("Porta Serial Focada:"), 2, 0)
        connection_status_layout.addWidget(self.focused_port_value, 2, 1)
        connection_status_layout.addWidget(QLabel("Clientes Conectados (Servidor):"), 3, 0) # New for server
        connection_status_layout.addWidget(self.connected_clients_value, 3, 1) # New for server
        connection_status_group.setLayout(connection_status_layout)

        status_layout.addWidget(connection_status_group)
        self.status_tab.setLayout(status_layout)

    def setup_log_tab(self):
        log_layout = QVBoxLayout(self.log_tab)

        self.log_text_edit = QTextEdit()
        self.log_text_edit.setReadOnly(True)

        self.reload_log_button = QPushButton("Recarregar Log")
        self.reload_log_button.clicked.connect(self.update_log_content)

        log_layout.addWidget(self.log_text_edit)
        log_layout.addWidget(self.reload_log_button)
        self.log_tab.setLayout(log_layout)

    def setup_credits_tab(self):
        credits_layout = QVBoxLayout(self.credits_tab)

        self.logo_label = QLabel()
        logo_pixmap = QPixmap("./logo.png")
        if not logo_pixmap.isNull():
            logo_pixmap = logo_pixmap.scaledToWidth(600)
            self.logo_label.setPixmap(logo_pixmap)
        else:
            self.logo_label.setText("Risetec")
            self.logo_label.setStyleSheet("font-size: 20px;")

        credits_text = """
        Desenvolvido por: [Jhonattan/Risetec]
        Versão: 1.0
        Data: 2025-03-20

        Um gerenciador de porta sereal para auxiliar o sistema Microdata a ter suporte a dispositivos que usam esse tipo de porta.
        """
        self.credits_label = QLabel(credits_text)
        self.credits_label.setWordWrap(True)

        credits_layout.addWidget(self.logo_label)
        credits_layout.addWidget(self.credits_label)
        self.credits_tab.setLayout(credits_layout)

    def update_server_client_visibility(self):
        """Atualiza a visibilidade dos grupos Servidor/Cliente baseado no Modo."""
        modo_selecionado = self.mode_combo.currentText()
        if modo_selecionado == "Servidor":
            self.server_config_group.setVisible(True)
            self.client_config_group.setVisible(False)
        elif modo_selecionado == "Cliente":
            self.server_config_group.setVisible(False)
            self.client_config_group.setVisible(True)

    def choose_log_location(self):
        """Abre um diálogo para escolher a pasta de log."""
        log_dir = QFileDialog.getExistingDirectory(self, "Escolher Pasta de Log")
        if log_dir:
            self.log_location_input.setText(log_dir)

    def handle_connect_button(self):
        """Função a ser executada ao clicar no botão Conectar."""
        modo = self.mode_combo.currentText()
        if modo == "Servidor":
            self.start_server_mode()
        elif modo == "Cliente":
            self.start_client_mode()
        else:
            self.log_message("Modo inválido selecionado.")

        self.save_config() # Save config after connect attempt
        self.update_log_content() # Refresh log display


    def start_server_mode(self):
        """Starts the application in Server mode."""
        ip = self.server_ip_input.text()
        port = self.server_port_input.text()
        porta_serial = self.serial_port_combo.currentText()

        if not ip or not port or not porta_serial:
            self.log_message("Configurações de Servidor incompletas.")
            self.status_label_value.setText("Erro de Configuração")
            return

        try:
            port_num = int(port)
        except ValueError:
            self.log_message("Porta do servidor inválida. Deve ser um número.")
            self.status_label_value.setText("Erro de Configuração")
            return

        self.log_message(f"Iniciando Servidor em: {ip}:{port}")
        self.connection_details_value.setText(f"Servidor: {ip}:{port}")
        self.focused_port_value.setText(porta_serial)
        self.status_label_value.setText("Servidor Iniciado")

        # Stop any existing server thread
        self.stop_server_mode()

        self.server_thread = ServerThread(ip, port_num, porta_serial, self.serial_port_semaphore, self.log_signal)
        self.server_thread.client_connected_signal.connect(self.update_connected_clients_count) # Connect signal
        self.server_thread.start()
        self.log_message("Thread Servidor iniciada.")


    def stop_server_mode(self):
        """Stops the server thread if it's running."""
        if self.server_thread and self.server_thread.isRunning():
            self.log_message("Parando thread Servidor...")
            self.server_thread.stop_server() # Signal thread to stop gracefully
            self.server_thread.wait() # Wait for thread to finish
            self.server_thread = None
            self.status_label_value.setText("Desconectado")
            self.connection_details_value.setText("Servidor parado")
            self.connected_clients = {} # Clear connected clients
            self.update_connected_clients_count(0) # Reset client count in GUI


    def start_client_mode(self):
        """Starts the application in Client mode."""
        url = self.client_url_input.text()
        porta_serial = self.serial_port_combo.currentText()

        if not url or not porta_serial:
            self.log_message("Configurações de Cliente incompletas.")
            self.status_label_value.setText("Erro de Configuração")
            return

        self.log_message(f"Conectando ao Cliente em: {url}")
        self.connection_details_value.setText(f"Cliente: {url}")
        self.focused_port_value.setText(porta_serial)
        self.status_label_value.setText("Conectado como Cliente")

        # Stop any existing client thread
        self.stop_client_mode()

        self.client_thread = ClientThread(url, porta_serial, self.log_signal, self.serial_port_semaphore)
        self.client_thread.start()
        self.log_message("Thread Cliente iniciada.")


    def stop_client_mode(self):
        """Stops the client thread if it's running."""
        if self.client_thread and self.client_thread.isRunning():
            self.log_message("Parando thread Cliente...")
            self.client_thread.stop_client() # Signal thread to stop gracefully
            self.client_thread.wait() # Wait for thread to finish
            self.client_thread = None
            self.status_label_value.setText("Desconectado")
            self.connection_details_value.setText("Cliente parado")


    def update_log_content(self):
        """Atualiza o conteúdo do QTextEdit com o log do arquivo."""
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
        """Appends text to the log QTextEdit in GUI thread."""
        self.log_text_edit.append(message)


    def log_message(self, message, level=logging.INFO):
        """Logs a message to the system and displays in log window."""
        logging.log(level, message)


    def save_config(self):
        """Salva as configurações em um arquivo JSON."""
        config = {
            "modo": self.mode_combo.currentText(),
            "server_ip": self.server_ip_input.text(),
            "server_port": self.server_port_input.text(),
            "client_url": self.client_url_input.text(),
            "log_location": self.log_location_input.text(),
            "log_file_name": self.log_file_name_input.text(), # Save log file name
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
        """Carrega as configurações de um arquivo JSON."""
        try:
            with open("config.json", 'r') as f:
                config = json.load(f)
                self.mode_combo.setCurrentText(config.get("modo", "Cliente"))
                self.server_ip_input.setText(config.get("server_ip", ""))
                self.server_port_input.setText(config.get("server_port", ""))
                self.client_url_input.setText(config.get("client_url", ""))
                self.log_location_input.setText(config.get("log_location", ""))
                self.log_file_name_input.setText(config.get("log_file_name", "app_log.txt")) # Load log file name
                self.log_file_name = self.log_file_name_input.text() # Update current log file name
                self.user_input.setText(config.get("usuario", ""))
                self.password_input.setText(config.get("senha", ""))
                serial_port = config.get("porta_serial", "")
                if serial_port: # Check if port exists before setting
                    index = self.serial_port_combo.findText(serial_port)
                    if index != -1:
                        self.serial_port_combo.setCurrentIndex(index)

            self.log_message("Configurações carregadas de config.json")
        except FileNotFoundError:
            self.log_message("Arquivo de configuração não encontrado. Usando configurações padrão.")
        except Exception as e:
            self.log_message(f"Erro ao carregar as configurações: {e}", level=logging.ERROR)

    def update_connected_clients_count(self, count):
        """Updates the connected clients count in the status tab."""
        self.connected_clients_value.setText(str(count))


class ServerThread(QThread):
    client_connected_signal = Signal(int) # Signal to update client count in GUI

    def __init__(self, ip, port, serial_port_name, serial_semaphore, log_signal):
        super().__init__()
        self.ip = ip
        self.port = port
        self.serial_port_name = serial_port_name
        self.serial_semaphore = serial_semaphore
        self.log_signal = log_signal
        self._is_running = True
        self.server_socket = None
        self.connected_clients = {} # Store client connections here

    def stop_server(self):
        """Sets the stop flag and closes the server socket."""
        self._is_running = False
        if self.server_socket:
            try:
                self.server_socket.close() # Close server socket to stop accepting connections
            except Exception as e:
                logging.error(f"Erro ao fechar o socket do servidor: {e}")

    def run(self):
        """Server thread execution."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.ip, self.port))
            self.server_socket.listen(5) # Listen for up to 5 connections
            self.log_message(f"Servidor ouvindo em {self.ip}:{self.port}")
            self.update_connected_clients_count_signal() # Initialize client count in GUI
            self.open_serial_port() # Open serial port in server thread context

            while self._is_running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    if not self._is_running: # Check again inside loop for immediate stop
                        client_socket.close()
                        break

                    client_id = addr[1] # Use port as client ID for simplicity
                    self.connected_clients[client_id] = client_socket # Store client socket
                    self.update_connected_clients_count_signal() # Update client count on connection
                    self.log_message(f"Cliente conectado de {addr}")

                    client_handler_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
                    client_handler_thread.daemon = True # Allow main thread to exit without waiting
                    client_handler_thread.start()

                except socket.timeout: # Non-blocking accept check (if timeout is set)
                    continue # Just continue to loop and check _is_running

                except OSError as e: # Socket might be closed by stop_server
                    if not self._is_running:
                        break # Expected if server is being stopped
                    else:
                        self.log_message(f"Erro ao aceitar conexão: {e}", level=logging.ERROR)
                        break # Unexpected error, stop server loop

                except Exception as e:
                    self.log_message(f"Erro inesperado no loop do servidor: {e}", level=logging.ERROR)
                    break # Stop server loop on unexpected error

        finally:
            self.close_serial_port() # Ensure serial port is closed on server thread exit
            if self.server_socket:
                self.server_socket.close()
                self.log_message("Socket do servidor fechado.")
            self.log_message("Thread Servidor finalizada.")


    def handle_client(self, client_socket, addr):
        """Handles communication with a single client."""
        client_ip_addr = f"{addr[0]}:{addr[1]}"
        try:
            while self._is_running:
                data = client_socket.recv(1024)
                if not data:
                    self.log_message(f"Cliente {client_ip_addr} desconectado.")
                    break # Client disconnected

                decoded_data = data.decode('utf-8')
                self.log_message(f"Recebido do cliente {client_ip_addr}: {decoded_data.strip()}")
                self.write_to_serial_port(decoded_data) # Write received data to serial port

        except Exception as e:
            self.log_message(f"Erro ao lidar com o cliente {client_ip_addr}: {e}", level=logging.ERROR)
        finally:
            client_id = addr[1]
            if client_id in self.connected_clients:
                del self.connected_clients[client_id] # Remove client on disconnect/error
                self.update_connected_clients_count_signal() # Update client count on disconnect
            client_socket.close()
            self.log_message(f"Conexão com cliente {client_ip_addr} encerrada.")


    def open_serial_port(self):
        """Opens the serial port."""
        try:
            self.serial_port = serial.Serial(self.serial_port_name, baudrate=9600, timeout=1) # Example settings
            self.log_message(f"Porta serial {self.serial_port_name} aberta.")
        except serial.SerialException as e:
            self.log_message(f"Erro ao abrir porta serial {self.serial_port_name}: {e}", level=logging.ERROR)
            self._is_running = False # Stop server if serial port fails to open

    def close_serial_port(self):
        """Closes the serial port."""
        if self.serial_port and self.serial_port.is_open:
            self.serial_port.close()
            self.log_message(f"Porta serial {self.serial_port_name} fechada.")
            self.serial_port = None


    def write_to_serial_port(self, data):
        """Writes data to the serial port, using semaphore for control."""
        if not self.serial_port or not self.serial_port.is_open:
            self.log_message("Porta serial não está aberta.", level=logging.WARNING)
            return

        try:
            if self.serial_semaphore.tryAcquire(timeout=5000): # Try acquire with timeout
                try:
                    encoded_data = data.encode('utf-8')
                    self.serial_port.write(encoded_data)
                    self.log_message(f"Enviado para serial: {data.strip()}")
                finally:
                    self.serial_semaphore.release() # Ensure semaphore is released
            else:
                self.log_message("Timeout ao adquirir semáforo para porta serial.", level=logging.WARNING)

        except serial.SerialTimeoutException:
            self.log_message("Timeout ao escrever na porta serial.", level=logging.WARNING)
        except Exception as e:
            self.log_message(f"Erro ao escrever na porta serial: {e}", level=logging.ERROR)


    def log_message(self, message, level=logging.INFO):
        """Logs a message using the provided log signal to update GUI."""
        logging.log(level, message)

    def update_connected_clients_count_signal(self):
        """Emits signal to update client count in GUI thread."""
        self.client_connected_signal.emit(len(self.connected_clients)) # Emit signal with client count



class ClientThread(QThread):
    def __init__(self, server_url, serial_port_name, log_signal, serial_semaphore):
        super().__init__()
        self.server_url = server_url
        self.serial_port_name = serial_port_name
        self.log_signal = log_signal
        self.serial_semaphore = serial_semaphore
        self._is_running = True
        self.serial_port = None
        self.client_socket = None

    def stop_client(self):
        """Sets the stop flag and closes resources."""
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
            port = int(url_parts[1]) if len(url_parts) > 1 and url_parts[1] else 80 # Default HTTP port if no port

            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
            self.log_message(f"Conectado ao servidor em {self.server_url}")
            self.open_serial_port() # Open serial port in client thread context

            while self._is_running:
                data_from_serial = self.read_from_serial_port()
                if data_from_serial:
                    try:
                        self.client_socket.sendall(data_from_serial.encode('utf-8'))
                        self.log_message(f"Enviado para servidor: {data_from_serial.strip()}")
                    except Exception as e:
                        self.log_message(f"Erro ao enviar dados para o servidor: {e}", level=logging.ERROR)
                        break # Stop client loop on send error
        except Exception as e:
            self.log_message(f"Erro na thread Cliente: {e}", level=logging.ERROR)
        finally:
            self.close_serial_port() # Ensure serial port is closed on thread exit
            if self.client_socket:
                self.client_socket.close()
                self.log_message("Socket cliente fechado.")
            self.log_message("Thread Cliente finalizada.")


    def open_serial_port(self):
        """Opens the serial port."""
        try:
            self.serial_port = serial.Serial(self.serial_port_name, baudrate=9600, timeout=1) # Example settings
            self.log_message(f"Porta serial {self.serial_port_name} aberta.")
        except serial.SerialException as e:
            self.log_message(f"Erro ao abrir porta serial {self.serial_port_name}: {e}", level=logging.ERROR)
            self._is_running = False # Stop client if serial port fails to open


    def close_serial_port(self):
        """Closes the serial port."""
        if self.serial_port and self.serial_port.is_open:
            self.serial_port.close()
            self.log_message(f"Porta serial {self.serial_port_name} fechada.")
            self.serial_port = None


    def read_from_serial_port(self):
        """Reads data from the serial port, using semaphore for control."""
        if not self.serial_port or not self.serial_port.is_open:
            self.log_message("Porta serial não está aberta para leitura.", level=logging.WARNING)
            return None

        try:
            if self.serial_semaphore.tryAcquire(timeout=5000): # Try acquire with timeout
                try:
                    data = self.serial_port.readline().decode('utf-8').strip() # Read line and decode
                    if data:
                        self.log_message(f"Recebido da serial: {data}")
                        return data # Return data if read
                finally:
                    self.serial_semaphore.release() # Ensure semaphore is released
            else:
                self.log_message("Timeout ao adquirir semáforo para leitura da porta serial.", level=logging.WARNING)
        except serial.SerialTimeoutException:
            pass # Timeout during read is normal, just return None
        except Exception as e:
            self.log_message(f"Erro ao ler da porta serial: {e}", level=logging.ERROR)

        return None # Return None if no data or error


    def log_message(self, message, level=logging.INFO):
        """Logs a message using the provided log signal to update GUI."""
        logging.log(level, message)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SerealConWindow()
    window.show()
    sys.exit(app.exec())