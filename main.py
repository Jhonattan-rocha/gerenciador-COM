import sys
import json
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QTabWidget, QLabel, QGroupBox, QGridLayout,
                             QLineEdit, QPushButton, QComboBox, QTextEdit,
                             QFileDialog, QMessageBox) # Import QMessageBox for error dialogs
from PySide6.QtGui import QIcon, QPixmap, QDoubleValidator, QIntValidator
from PySide6.QtCore import QTimer, QThread, Signal, QSemaphore
import serial, logging, time
import serial.tools.list_ports
import socket
import threading
from typing import IO

class SerialConWindow(QWidget):
    log_signal = Signal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gerenciador de porta serial")
        self.setWindowIcon(QIcon("./icon.png"))
        self.serial_port = None # To store serial port instance
        self.server_socket = None # To store server socket
        self.client_thread = None # To store client thread
        self.server_thread = None # To store server thread
        self.connected_clients = {} # To store connected clients in server mode
        self.serial_port_semaphore = QSemaphore(1) # Semaphore for serial port access
        self.log_file_path = "" # Initialize log file path
        self.log_file_name = "app_log.txt" # Default log file name, will be configurable
        self.logger: logging = logging.getLogger(__name__)

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

        self.setup_logging()
        self.load_config()
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.update_log_content)
        self.log_timer.start(5000)
        self.log_signal.connect(self.append_log_text) # Connect signal to append log text

        self.log_message("Aplicativo Iniciado.") # Initial log message
        self.update_connect_button_text()

    def setup_logging(self):
        """Configura o sistema de logs e redireciona stdout e stderr para o log."""
        
        log_dir = self.log_location_input.text().strip()
        if not log_dir:
            log_dir = "."  # Diretório atual
        self.log_file_path = f"{log_dir}/{self.log_file_name}"

        # Configuração do logging para arquivo
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(levelname)s - %(message)s",
            filename=self.log_file_path,
            filemode="a"
        )

        # Criando um handler para exibir logs na GUI
        class QtHandler(logging.Handler):
            def __init__(self, log_signal):
                super().__init__()
                self.log_signal = log_signal

            def emit(self, record):
                log_message = self.format(record)
                self.log_signal.emit(log_message)  # Agora emite corretamente

        handler = QtHandler(self.log_signal)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(handler)

        # Redirecionar stdout e stderr para o log
        class LogRedirector(IO):
            def __init__(self, logger):
                self.logger = logger
            
            def write(self, s):
                if s.strip():
                    self.logger.info(s)
                
                super().write(s)
            
        log_redirector = LogRedirector(self.logger)
        sys.stdout = log_redirector
        sys.stderr = log_redirector
        self.logger.info("Logging configurado com sucesso.")

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
        int_validator = QIntValidator()
        self.server_ip_input.setValidator(int_validator)
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
        
        # baud Rate
        baudrate_layout = QHBoxLayout()
        baudrate_label = QLabel("Baud Rate:")
        self.baudrate_combo = QComboBox()
        self.baudrate_combo.addItems(["50", "75", "110", "134", "150", "200", "300", "600", "1200", "1800", "2400", "4800",
                 "9600", "19200", "38400", "57600", "115200", "230400", "460800", "500000", "576000", "921600", "1000000",
                 "1152000", "1500000", "2000000", "2500000", "3000000", "3500000", "4000000"])
        baudrate_layout.addWidget(baudrate_label)
        baudrate_layout.addWidget(self.baudrate_combo)

        timeout_layout = QHBoxLayout()
        timeout_label = QLabel("Timeout:")
        self.timeout_edit = QLineEdit()
        float_validator = QDoubleValidator()
        self.timeout_edit.setValidator(float_validator)
        timeout_layout.addWidget(timeout_label)
        timeout_layout.addWidget(self.timeout_edit)

        # Data Bits
        databits_layout = QHBoxLayout()
        databits_label = QLabel("Data Bits:")
        self.databits_combo = QComboBox()
        self.databits_combo.addItems(["5", "6", "7", "8"])
        self.databits_combo.setCurrentText("8")
        databits_layout.addWidget(databits_label)
        databits_layout.addWidget(self.databits_combo)

        # Stop Bits
        stopbits_layout = QHBoxLayout()
        stopbits_label = QLabel("Stop Bits:")
        self.stopbits_combo = QComboBox()
        self.stopbits_combo.addItems(["1", "1.5", "2"])
        self.stopbits_combo.setCurrentText("2")
        stopbits_layout.addWidget(stopbits_label)
        stopbits_layout.addWidget(self.stopbits_combo)

        # Parity
        parity_layout = QHBoxLayout()
        parity_label = QLabel("Paridade:")
        self.parity_combo = QComboBox()
        self.parity_combo.addItems(["None", "Even", "Odd", "Mark", "Space"])
        self.parity_combo.setCurrentText("Even")
        parity_layout.addWidget(parity_label)
        parity_layout.addWidget(self.parity_combo)

        # Botão Conectar
        self.connect_button = QPushButton("Conectar")
        self.connect_button.clicked.connect(self.handle_connect_button)

        config_layout.addLayout(mode_layout)
        config_layout.addWidget(self.server_config_group)
        config_layout.addWidget(self.client_config_group)
        config_layout.addLayout(log_location_layout)
        config_layout.addLayout(log_file_name_layout)
        config_layout.addLayout(user_pass_layout)
        config_layout.addLayout(serial_port_layout)
        config_layout.addLayout(baudrate_layout)
        config_layout.addLayout(timeout_layout)
        config_layout.addLayout(databits_layout)
        config_layout.addLayout(stopbits_layout)
        config_layout.addLayout(parity_layout)
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

        Um gerenciador de porta serial para auxiliar o sistema Microdata a ter suporte a dispositivos que usam esse tipo de porta.
        """
        self.credits_label = QLabel(credits_text)
        self.credits_label.setWordWrap(True)

        credits_layout.addWidget(self.logo_label)
        credits_layout.addWidget(self.credits_label)
        self.credits_tab.setLayout(credits_layout)

    def update_server_client_visibility(self):
        """Atualiza a visibilidade dos grupos Servidor/Cliente baseado no Modo."""
        self.update_connect_button_text()

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
            if modo == 'Servidor':
                self.connect_button.setText("Iniciar") # Default text
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
            self.update_status_gui({"status_label":"Erro de Configuração", "server_status":"Configuração Incompleta"})
            return

        try:
            port_num = int(port)
        except ValueError:
            self.log_message("Porta do servidor inválida. Deve ser um número.")
            QMessageBox.warning(self, "Erro de Configuração", "Porta do servidor inválida. Deve ser um número.")
            self.update_status_gui({"status_label":"Erro de Configuração", "server_status":"Porta Inválida"})
            return

        self.log_message(f"Iniciando Servidor em: {ip}:{port}")
        self.update_status_gui({"status_label":"Iniciando Servidor", "connection_details":f"Servidor: {ip}:{port}", "focused_port":porta_serial, "server_status":"Iniciando..."})

        self.server_thread = ServerThread(ip, port_num, porta_serial, self.serial_port_semaphore, {"baudrate": self.baudrate_combo.currentText(), "timeout": self.timeout_edit.text(), "databits": self.databits_combo.currentText(), "stopbist": self.stopbits_combo.currentText(), "parity": self.parity_combo.currentText()})
        self.server_thread.client_connected_signal.connect(self.update_connected_clients_count)
        self.server_thread.server_status_signal.connect(self.update_server_status_gui) # Connect server status signals
        self.server_thread.start()
        self.connect_button.setText("Parar Servidor") # Immediately update button text
        self.log_message("Thread Servidor iniciada.")


    def stop_server_mode(self):
        """Stops the server thread if it's running."""
        if self.server_thread and self.server_thread.isRunning():
            self.log_message("Parando thread Servidor...")
            self.update_status_gui({"status_label":"Parando Servidor", "server_status":"Parando..."})
            self.server_thread.stop_server()
            self.server_thread.wait()
            self.server_thread = None
            self.connected_clients = {}
            self.update_connected_clients_count(0)
        self.update_status_gui({"status_label":"Desconectado", "connection_details":"Servidor parado", "server_status":"Parado"})
        self.connect_button.setText("Iniciar Servidor")


    def start_client_mode(self):
        """Starts the application in Client mode."""
        url = self.client_url_input.text()
        porta_serial = self.serial_port_combo.currentText()

        if not url or not porta_serial:
            self.log_message("Configurações de Cliente incompletas.")
            QMessageBox.warning(self, "Erro de Configuração", "Por favor, preencha a URL do cliente e selecione a porta serial.")
            self.update_status_gui({"status_label":"Erro de Configuração", "client_status":"Configuração Incompleta"})
            return

        self.log_message(f"Conectando ao Cliente em: {url}")
        self.update_status_gui({"status_label":"Conectando Cliente", "connection_details":f"Cliente: {url}", "focused_port":porta_serial, "client_status":"Conectando..."})

        # Stop any existing client thread
        self.stop_client_mode()

        self.client_thread = ClientThread(url, porta_serial, self.log_signal, self.serial_port_semaphore, {"baudrate": self.baudrate_combo.currentText(), "timeout": self.timeout_edit.text(), "databits": self.databits_combo.currentText(), "stopbist": self.stopbits_combo.currentText(), "parity": self.parity_combo.currentText()})
        self.client_thread.client_status_signal.connect(self.update_client_status_gui) # Connect client status signal
        self.client_thread.start()
        self.connect_button.setText("Desconectar Cliente") # Immediately update button text
        self.log_message("Thread Cliente iniciada.")


    def stop_client_mode(self):
        """Stops the client thread if it's running."""
        if self.client_thread and self.client_thread.isRunning():
            self.log_message("Parando thread Cliente...")
            self.update_status_gui({"status_label":"Desconectando Cliente", "client_status":"Desconectando..."})
            self.client_thread.stop_client()
            self.client_thread.wait()
            self.client_thread = None
        self.update_status_gui({"status_label":"Desconectado", "connection_details":"Cliente parado", "client_status":"Desconectado"})
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

    def log_message(self, message: str, level=logging.INFO):
        """Logs a message to system and log window."""
        self.logger.info(msg=message, stacklevel=level)

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
            "porta_serial": self.serial_port_combo.currentText(),
            "baudrate": self.baudrate_combo.currentText(),
            "databits": self.databits_combo.currentText(),
            "stopbist": self.stopbits_combo.currentText(),
            "parity": self.parity_combo.currentText()
        }
        try:
            with open("config.json", 'w', encoding='cp850') as f:
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
                self.baudrate_combo.setCurrentText(config.get("baudrate", "9600"))
                self.databits_combo.setCurrentText(config.get("databits", "5"))
                self.stopbits_combo.setCurrentText(config.get("stopbist", "1"))
                self.parity_combo.setCurrentText(config.get("parity", "Even"))
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

    def update_status_gui(self, status_update: dict):
        """Atualiza a GUI com base nos dados do status."""
        if 'status_label' in status_update:
            self.status_label_value.setText(status_update['status_label'])
        if 'connection_details' in status_update:
            self.connection_details_value.setText(status_update['connection_details'])
        if 'focused_port' in status_update:
            self.focused_port_value.setText(status_update['focused_port'])
        if 'server_status' in status_update:
            self.server_status_value.setText(status_update['server_status'])
        if 'client_status' in status_update:
            self.client_status_value.setText(status_update['client_status'])

    def update_server_status_gui(self, status_data: dict):
        """Updates server specific status in GUI thread."""
        if 'server_status' in status_data:
            self.update_status_gui({"server_status": status_data['server_status']})
        
        if 'status_label' in status_data:
            self.update_status_gui({"status_label": status_data['server_status']})

    def update_client_status_gui(self, status_data):
        """Updates client specific status in GUI thread."""

        if 'client_status' in status_data:
            self.update_status_gui({"client_status": status_data['client_status']})
        
        if 'status_label' in status_data:
            self.update_status_gui({"status_label": status_data['server_status']})

class ServerThread(QThread):
    client_connected_signal = Signal(int)
    server_status_signal = Signal(str) # Signal server status to GUI

    def __init__(self, ip, port, serial_port_name, serial_semaphore, params: dict):
        super().__init__()
        self.ip = ip
        self.port = port
        self.serial_port_name = serial_port_name
        self.serial_semaphore: QSemaphore = serial_semaphore
        self._is_running = True
        self.server_socket = None
        self.serial_port = None
        self.connected_clients = {}
        self.params = params

    def stop_server(self):
        """Sets stop flag and closes server socket."""
        self._is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                self.logger.error(f"Erro ao fechar o socket do servidor: {e}")

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
                
                time.sleep(1)

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

                decoded_data = data.decode('cp850')
                self.log_message(f"Recebido do cliente {client_ip_addr}: {decoded_data.strip()}")
                self.write_to_serial_port(decoded_data)

                time.sleep(1)

        except Exception as e:
            self.log_message(f"Erro ao lidar com o cliente {client_ip_addr}: {e}", level=logging.ERROR)
        finally:
            client_id = addr[1]
            if client_id in self.connected_clients:
                self.connected_clients.pop(client_id)
                self.update_connected_clients_count_signal()
            client_socket.close()
            self.log_message(f"Conexão com cliente {client_ip_addr} encerrada.")


    def open_serial_port(self):
        """Opens the serial port and returns success status."""
        try:
            self.serial_port = serial.Serial(self.serial_port_name, baudrate=int(self.params.get("baudrate")), timeout=float(self.params.get("timeout")), bytesize=int(self.params.get("databits")), stopbits=float(self.params.get("stopbist")), parity=str(self.params.get("parity")))
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
        
        max_retries = 3
        retry_delay = 1  # Começa com 1s

        try:
            for attempt in range(max_retries):
                if self.serial_semaphore.tryAcquire():
                    try:
                        encoded_data = data.encode('cp850')
                        self.serial_port.write(encoded_data)
                        self.log_message(f"Enviado para serial: {data.strip()}")
                        break  # Sucesso, sai do loop
                    finally:
                        self.serial_semaphore.release()
                else:
                    self.log_message(f"Tentativa {attempt + 1}/{max_retries}: Falha ao adquirir semáforo. Retentando...", level=logging.WARNING)
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Aumenta o tempo de espera

            if attempt == max_retries - 1:
                self.log_message("Erro crítico: Não foi possível adquirir semáforo para escrita serial.", level=logging.ERROR)

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
        self.server_status_signal.emit(status_update)


class ClientThread(QThread):
    client_status_signal = Signal(str) # Signal client status to GUI

    def __init__(self, server_url, serial_port_name, log_signal, serial_semaphore, params: dict):
        super().__init__()
        self.server_url = server_url
        self.serial_port_name = serial_port_name
        self.log_signal = log_signal
        self.serial_semaphore: QSemaphore = serial_semaphore
        self._is_running = True
        self.serial_port = None
        self.client_socket = None
        self.params = params

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
                        self.client_socket.sendall(data_from_serial.encode('cp850'))
                        self.log_message(f"Enviado para servidor: {data_from_serial.strip()}")
                    except Exception as e:
                        self.log_message(f"Erro ao enviar dados para o servidor: {e}", level=logging.ERROR)
                        self.update_client_status("Erro de Envio") # Update client status to "Erro de Envio"
                        break # Stop client loop on send error
                time.sleep(1)
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
            self.serial_port = serial.Serial(self.serial_port_name, baudrate=int(self.params.get("baudrate")), timeout=float(self.params.get("timeout")), bytesize=int(self.params.get("databits")), stopbits=float(self.params.get("stopbist")), parity=str(self.params.get("parity")))
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
            if self.serial_semaphore.tryAcquire():
                try:
                    data = self.serial_port.readline().decode('cp850').strip()
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
        self.client_status_signal.emit(status_update)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SerialConWindow()
    window.show()
    try:
        sys.exit(app.exec())
    except Exception as e: 
        print(e)