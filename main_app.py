import sys
import json
import platform
import logging
import time # Adicionado para timestamp no log manual
from typing import IO
import os

from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                               QTabWidget, QLabel, QGroupBox, QGridLayout,
                               QLineEdit, QPushButton, QComboBox, QTextEdit,
                               QFileDialog, QMessageBox, QListWidget)
from PySide6.QtGui import QIcon, QPixmap, QDoubleValidator, Qt
from PySide6.QtCore import QTimer, Signal, QSemaphore, QThread # QThread importado para type hinting

import serial.tools.list_ports

# Importar lógica do servidor e cliente
from server_logic import ServerThread
from client_logic import ClientThread

if "linux" in platform.platform().lower():
    import pty

# Constantes
CONFIG_FILE = "config.json"
DEFAULT_LOG_FILENAME = "./app_log.txt"
APP_LOGGER_NAME = "SerialApp"

class QtHandler(logging.Handler):
    """Handler de logging para emitir registros para a GUI."""
    def __init__(self, log_signal: Signal):
        super().__init__()
        self.log_signal = log_signal

    def emit(self, record):
        log_message = self.format(record)
        self.log_signal.emit(log_message)

class LogRedirector(IO):
    """Redireciona stdout/stderr para o logger."""
    def __init__(self, logger, log_level=logging.INFO):
        self.logger = logger
        self.log_level = log_level
        self.buffer = ""

    def write(self, message):
        self.buffer += message
        if '\n' in self.buffer:
            lines = self.buffer.split('\n')
            for line in lines[:-1]: # Processa todas as linhas completas
                if line.strip():
                    self.logger.log(self.log_level, line.strip())
            self.buffer = lines[-1] # Guarda a parte incompleta

    def flush(self):
        if self.buffer.strip(): # Processa o restante do buffer ao final
            self.logger.log(self.log_level, self.buffer.strip())
        self.buffer = ""

class SerialConWindow(QWidget):
    log_signal = Signal(str)  # Sinal para logs na GUI

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gerenciador de Porta Serial v1.1")
        self.setWindowIcon(QIcon("./icon.png"))
        self.setGeometry(100, 100, 700, 600) # Tamanho inicial

        self.serial_port = None # Não usado diretamente aqui, gerenciado por threads
        self.server_thread: ServerThread = None
        self.client_thread: ClientThread = None

        self.serial_port_semaphore = QSemaphore(1)
        self.log_file_path = ""
        self.logger = logging.getLogger(APP_LOGGER_NAME) # Logger nomeado

        self.tab_widget = QTabWidget()
        self.config_tab = QWidget()
        self.status_tab = QWidget()
        self.log_tab = QWidget()
        self.credits_tab = QWidget()

        self.tab_widget.addTab(self.config_tab, "Configuração")
        self.tab_widget.addTab(self.status_tab, "Status da Conexão")
        self.tab_widget.addTab(self.log_tab, "Log")
        self.tab_widget.addTab(self.credits_tab, "Créditos")

        # Inputs precisam ser definidos antes de setup_logging e load_config
        self.log_location_input = QLineEdit() # Definido antes para ser usado em setup_logging
        self.log_file_name_input = QLineEdit()# Definido antes

        self.setup_config_tab() # Configura os widgets da aba de config
        self.setup_logging()    # Configura o logging após os inputs de log estarem disponíveis
        self.setup_status_tab()
        self.setup_log_tab()
        self.setup_credits_tab()

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(self.tab_widget)
        self.setLayout(main_layout)

        self.load_config() # Carrega config após UI estar pronta e logging configurado
        self.log_signal.connect(self.append_log_text)

        self.log_message("Aplicativo Iniciado.")
        self.update_connect_button_state()
        self.update_server_client_visibility() # Chamada inicial

        # Aplicar estilo QSS
        try:
            # CORREÇÃO: Adicionado encoding="utf-8" para ler o arquivo de estilo corretamente.
            with open("style.qss", "r", encoding="utf-8") as f:
                self.setStyleSheet(f.read())
        except FileNotFoundError:
            self.log_message("Arquivo style.qss não encontrado. Usando estilo padrão.", logging.WARNING)
        except Exception as e:
            self.log_message(f"Erro ao carregar style.qss: {e}", logging.ERROR)


    def setup_logging(self):
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers = [] # Limpa handlers anteriores para evitar duplicação

        # Handler para arquivo
        log_dir = self.log_location_input.text().strip() or "."
        log_filename = self.log_file_name_input.text().strip() or DEFAULT_LOG_FILENAME
        self.log_file_path = os.path.join(log_dir, log_filename)

        try:
            os.makedirs(log_dir, exist_ok=True) # Garante que o diretório de log exista
            file_handler = logging.FileHandler(self.log_file_path, mode="a", encoding="utf-8")
            file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(module)s - %(message)s")
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
        except Exception as e:
            QMessageBox.warning(self, "Erro de Logging", f"Não foi possível configurar o log em arquivo: {e}")


        # Handler para GUI
        gui_handler = QtHandler(self.log_signal)
        gui_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        gui_handler.setFormatter(gui_formatter)
        self.logger.addHandler(gui_handler)

        # Redirecionar stdout e stderr
        sys.stdout = LogRedirector(self.logger, logging.INFO)
        sys.stderr = LogRedirector(self.logger, logging.ERROR)

        self.logger.info("Sistema de logging configurado.")

    def setup_config_tab(self):
        config_layout = QVBoxLayout()

        # Modo Cliente/Servidor
        mode_layout = QHBoxLayout()
        mode_label = QLabel("Modo:")
        mode_label.setObjectName('mode_label')
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Cliente", "Servidor"])
        self.mode_combo.setObjectName("mode_combo")
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)
        config_layout.addLayout(mode_layout)

        # Configurações de Servidor
        self.server_config_group = QGroupBox("Configurações Servidor")
        server_config_layout = QGridLayout()
        self.server_ip_label = QLabel("IP do Servidor:")
        self.server_ip_input = QLineEdit("0.0.0.0") # Default para ouvir em todas as interfaces
        self.server_port_label = QLabel("Porta do Servidor:")
        self.server_port_input = QLineEdit("8888")
        server_config_layout.addWidget(self.server_ip_label, 0, 0)
        server_config_layout.addWidget(self.server_ip_input, 0, 1)
        server_config_layout.addWidget(self.server_port_label, 1, 0)
        server_config_layout.addWidget(self.server_port_input, 1, 1)
        self.server_config_group.setLayout(server_config_layout)
        config_layout.addWidget(self.server_config_group)

        # Configurações de Cliente
        self.client_config_group = QGroupBox("Configurações Cliente")
        client_config_layout = QGridLayout()
        self.client_url_label = QLabel("URL do Servidor (IP:Porta):")
        self.client_url_input = QLineEdit("127.0.0.1:8888")
        client_config_layout.addWidget(self.client_url_label, 0, 0)
        client_config_layout.addWidget(self.client_url_input, 0, 1)
        self.client_config_group.setLayout(client_config_layout)
        config_layout.addWidget(self.client_config_group)

        # Local do Log
        log_location_group = QGroupBox("Configurações de Log")
        log_config_layout = QGridLayout(log_location_group)

        log_location_label = QLabel("Pasta do Log:")
        # self.log_location_input já foi inicializado
        self.log_location_button = QPushButton("Escolher Pasta")
        self.log_location_button.clicked.connect(self.choose_log_location)
        log_config_layout.addWidget(log_location_label, 0, 0)
        log_config_layout.addWidget(self.log_location_input, 0, 1)
        log_config_layout.addWidget(self.log_location_button, 0, 2)

        log_file_name_label = QLabel("Nome Arquivo Log:")
        # self.log_file_name_input já foi inicializado
        self.log_file_name_input.setText(DEFAULT_LOG_FILENAME) # Default value
        log_config_layout.addWidget(log_file_name_label, 1, 0)
        log_config_layout.addWidget(self.log_file_name_input, 1, 1)
        config_layout.addWidget(log_location_group)


        # Usuário e Senha (se necessário para autenticação futura)
        auth_group = QGroupBox("Autenticação (Opcional)")
        auth_layout = QGridLayout(auth_group)
        user_label = QLabel("Usuário:")
        self.user_input = QLineEdit()
        password_label = QLabel("Senha:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        auth_layout.addWidget(user_label, 0, 0)
        auth_layout.addWidget(self.user_input, 0, 1)
        auth_layout.addWidget(password_label, 1, 0)
        auth_layout.addWidget(self.password_input, 1, 1)
        config_layout.addWidget(auth_group)

        # Configurações da Porta Serial
        serial_config_group = QGroupBox("Configurações da Porta Serial")
        serial_config_layout = QGridLayout(serial_config_group)

        serial_port_label = QLabel("Porta Serial:")
        self.serial_port_combo = QComboBox()
        self.refresh_serial_ports() # Popula as portas seriais
        serial_config_layout.addWidget(serial_port_label, 0, 0)
        serial_config_layout.addWidget(self.serial_port_combo, 0, 1)

        refresh_ports_button = QPushButton("Atualizar Portas")
        refresh_ports_button.clicked.connect(self.refresh_serial_ports)
        serial_config_layout.addWidget(refresh_ports_button, 0, 2)


        baudrate_label = QLabel("Baud Rate:")
        self.baudrate_combo = QComboBox()
        self.baudrate_combo.addItems(["9600", "19200", "38400", "57600", "115200", "50", "75", "110", "134", "150", "200", "300", "600", "1200", "1800", "2400", "4800", "230400", "460800", "500000", "576000", "921600", "1000000", "1152000", "1500000", "2000000", "2500000", "3000000", "3500000", "4000000"])
        self.baudrate_combo.setCurrentText("9600")
        serial_config_layout.addWidget(baudrate_label, 1, 0)
        serial_config_layout.addWidget(self.baudrate_combo, 1, 1)

        timeout_label = QLabel("Timeout (s):")
        self.timeout_edit = QLineEdit("1")
        float_validator = QDoubleValidator(0.1, 60.0, 2) # Min 0.1s, Max 60s, 2 decimais
        self.timeout_edit.setValidator(float_validator)
        serial_config_layout.addWidget(timeout_label, 1, 2)
        serial_config_layout.addWidget(self.timeout_edit, 1, 3)


        databits_label = QLabel("Data Bits:")
        self.databits_combo = QComboBox()
        self.databits_combo.addItems(["8", "7", "6", "5"])
        self.databits_combo.setCurrentText("8")
        serial_config_layout.addWidget(databits_label, 2, 0)
        serial_config_layout.addWidget(self.databits_combo, 2, 1)

        stopbits_label = QLabel("Stop Bits:")
        self.stopbits_combo = QComboBox()
        self.stopbits_combo.addItems(["1", "1.5", "2"])
        self.stopbits_combo.setCurrentText("1")
        serial_config_layout.addWidget(stopbits_label, 2, 2)
        serial_config_layout.addWidget(self.stopbits_combo, 2, 3)

        parity_label = QLabel("Paridade:")
        self.parity_combo = QComboBox()
        self.parity_combo.addItems(["None", "Even", "Odd", "Mark", "Space"])
        self.parity_combo.setCurrentText("None")
        serial_config_layout.addWidget(parity_label, 3, 0)
        serial_config_layout.addWidget(self.parity_combo, 3, 1)

        flow_control_label = QLabel("Controle de Fluxo:")
        serial_config_layout.addWidget(flow_control_label, 4,0)
        self.rtscts_combo = QComboBox()
        self.rtscts_combo.addItems(["Desativado", "Ativado"])
        serial_config_layout.addWidget(QLabel("RTS/CTS:"), 4, 1)
        serial_config_layout.addWidget(self.rtscts_combo, 4, 2)

        self.dsrdtr_combo = QComboBox()
        self.dsrdtr_combo.addItems(["Desativado", "Ativado"])
        serial_config_layout.addWidget(QLabel("DSR/DTR:"), 5, 1)
        serial_config_layout.addWidget(self.dsrdtr_combo, 5, 2)

        config_layout.addWidget(serial_config_group)

        # Botão Conectar/Iniciar
        self.connect_button = QPushButton("Conectar")
        self.connect_button.clicked.connect(self.handle_connect_button)
        config_layout.addWidget(self.connect_button)
        config_layout.addStretch(1) # Adiciona espaço flexível no final

        self.config_tab.setLayout(config_layout)
        self.mode_combo.currentIndexChanged.connect(self.update_server_client_visibility)


    def refresh_serial_ports(self):
        self.serial_port_combo.clear()
        ports = serial.tools.list_ports.comports()
        if ports:
            for port, desc, hwid in sorted(ports):
                self.serial_port_combo.addItem(f"{port} ({desc})", userData=port) # Guarda o nome da porta
        else:
            self.serial_port_combo.addItem("Nenhuma porta serial encontrada")

        if "windows" in platform.platform().lower():
            for i in range(1, 5): # Menos portas loopback para não poluir tanto
                self.serial_port_combo.addItem(f"loop://{i}", userData=f"loop://{i}")
        elif "linux" in platform.platform().lower():
            self.serial_port_combo.addItem("Gerar Porta Virtual", userData="<GENERATE_VIRTUAL>")

    def get_selected_serial_port(self) -> str:
        """Retorna o nome da porta serial selecionada (userData)."""
        return self.serial_port_combo.currentData()

    def setup_status_tab(self):
        status_layout = QVBoxLayout(self.status_tab)

        # Grupo de Status Geral
        connection_status_group = QGroupBox("Status Geral")
        connection_status_layout = QGridLayout(connection_status_group)
        self.status_label_value = QLabel("Desconectado")
        self.status_label_value.setObjectName("status_label_value")
        self.uptime_value = QLabel("00:00:00")
        connection_status_layout.addWidget(QLabel("Status:"), 0, 0)
        connection_status_layout.addWidget(self.status_label_value, 0, 1)
        connection_status_layout.addWidget(QLabel("Tempo de Atividade:"), 1, 0)
        connection_status_layout.addWidget(self.uptime_value, 1, 1)
        status_layout.addWidget(connection_status_group)

        # Grupo de Detalhes da Conexão
        details_group = QGroupBox("Detalhes da Conexão")
        details_layout = QGridLayout(details_group)
        self.connection_details_value = QLabel("N/A")
        self.focused_port_value = QLabel("N/A")
        details_layout.addWidget(QLabel("Endereço:"), 0, 0)
        details_layout.addWidget(self.connection_details_value, 0, 1)
        details_layout.addWidget(QLabel("Porta Serial:"), 1, 0)
        details_layout.addWidget(self.focused_port_value, 1, 1)
        status_layout.addWidget(details_group)

        # Grupo de Estatísticas de Dados
        data_stats_group = QGroupBox("Estatísticas de Dados")
        data_stats_layout = QGridLayout(data_stats_group)
        self.bytes_sent_value = QLabel("0")
        self.bytes_received_value = QLabel("0")
        data_stats_layout.addWidget(QLabel("Bytes Enviados:"), 0, 0)
        data_stats_layout.addWidget(self.bytes_sent_value, 0, 1)
        data_stats_layout.addWidget(QLabel("Bytes Recebidos:"), 1, 0)
        data_stats_layout.addWidget(self.bytes_received_value, 1, 1)
        status_layout.addWidget(data_stats_group)

        # --- Widgets Específicos do Servidor ---
        self.server_status_group = QGroupBox("Status do Servidor")
        server_status_layout = QVBoxLayout(self.server_status_group)
        self.connected_clients_list = QListWidget()
        self.connected_clients_list.setMaximumHeight(120)
        self.connected_clients_list.setObjectName("connected_clients_list")
        server_status_layout.addWidget(QLabel("Clientes Conectados:"))
        server_status_layout.addWidget(self.connected_clients_list)
        status_layout.addWidget(self.server_status_group)

        # --- Widgets Específicos do Cliente ---
        self.client_status_group = QGroupBox("Status do Cliente")
        client_status_layout = QGridLayout(self.client_status_group)
        self.client_status_value = QLabel("Desconectado")
        self.client_status_value.setObjectName("client_status_value")
        client_status_layout.addWidget(QLabel("Status da Conexão:"), 0, 0)
        client_status_layout.addWidget(self.client_status_value, 0, 1)
        status_layout.addWidget(self.client_status_group)

        status_layout.addStretch(1)
        self.status_tab.setLayout(status_layout)

    def setup_log_tab(self):
        log_layout = QVBoxLayout(self.log_tab)
        self.log_text_edit = QTextEdit()
        self.log_text_edit.setReadOnly(True)
        self.log_text_edit.setStyleSheet("font-family: 'Courier New', monospace; font-size: 9pt;")


        button_layout = QHBoxLayout()
        self.reload_log_button = QPushButton("Recarregar Log do Arquivo")
        self.reload_log_button.clicked.connect(self.load_log_from_file)
        self.clear_log_button = QPushButton("Limpar Log da Tela")
        self.clear_log_button.clicked.connect(self.log_text_edit.clear)

        button_layout.addWidget(self.clear_log_button)
        button_layout.addWidget(self.reload_log_button)
        button_layout.addStretch()

        log_layout.addWidget(self.log_text_edit)
        log_layout.addLayout(button_layout)
        self.log_tab.setLayout(log_layout)

    def setup_credits_tab(self):
        credits_layout = QVBoxLayout(self.credits_tab)
        credits_layout.setContentsMargins(20, 20, 20, 20)

        self.logo_label = QLabel()
        try:
            logo_pixmap = QPixmap("./logo.png")
            if not logo_pixmap.isNull():
                logo_pixmap = logo_pixmap.scaledToWidth(300, Qt.SmoothTransformation)
                self.logo_label.setPixmap(logo_pixmap)
                self.logo_label.setAlignment(Qt.AlignCenter)
            else:
                self.logo_label.setText("Risetec") # Fallback
        except Exception as e:
            self.log_message(f"Erro ao carregar logo: {e}", logging.WARNING)
            self.logo_label.setText("Risetec")

        credits_text = """
        <h2 align="center">Gerenciador de Porta Serial</h2>
        <p align="center">Desenvolvido por: <b>Jhonattan / Risetec</b></p>
        <p align="center">Versão: 1.1</p>
        <p align="center">Data: 2025-05-25</p>
        <hr>
        <p>Este aplicativo facilita a comunicação com dispositivos seriais,
        atuando como um proxy TCP/IP para integrar com sistemas como o Microdata.</p>
        <p><b>Funcionalidades:</b></p>
        <ul>
            <li>Modo Servidor: Compartilha uma porta serial na rede.</li>
            <li>Modo Cliente: Conecta a uma porta serial remota via TCP.</li>
            <li>Configuração flexível de parâmetros seriais.</li>
            <li>Logging de eventos e comunicação.</li>
        </ul>
        """
        self.credits_label = QLabel(credits_text)
        self.credits_label.setWordWrap(True)
        self.credits_label.setTextFormat(Qt.RichText) # Permite HTML básico
        self.credits_label.setAlignment(Qt.AlignTop)
        self.credits_label.setObjectName("credits_label")


        credits_layout.addWidget(self.logo_label)
        credits_layout.addWidget(self.credits_label)
        credits_layout.addStretch(1)
        self.credits_tab.setLayout(credits_layout)

    def update_server_client_visibility(self):
        modo_selecionado = self.mode_combo.currentText()
        is_server_mode = (modo_selecionado == "Servidor")

        self.server_config_group.setVisible(is_server_mode)
        self.client_config_group.setVisible(not is_server_mode)

        # Atualiza visibilidade dos grupos de status
        self.server_status_group.setVisible(is_server_mode)
        self.client_status_group.setVisible(not is_server_mode)

        self.update_connect_button_state()


    def choose_log_location(self):
        log_dir = QFileDialog.getExistingDirectory(self, "Escolher Pasta de Log", self.log_location_input.text() or ".")
        if log_dir:
            self.log_location_input.setText(log_dir)
            # Reconfigurar o logging se o caminho mudar e o logger já estiver ativo
            self.setup_logging()
            self.log_message(f"Pasta de log alterada para: {log_dir}")


    def handle_connect_button(self):
        modo = self.mode_combo.currentText()
        selected_serial_port_name_display = self.serial_port_combo.currentText() # Para log
        selected_serial_port_actual = self.get_selected_serial_port()

        if not selected_serial_port_actual or selected_serial_port_actual == "Nenhuma porta serial encontrada":
            QMessageBox.warning(self, "Erro", "Nenhuma porta serial selecionada ou disponível.")
            self.log_message("Tentativa de conexão sem porta serial selecionada.", logging.ERROR)
            return

        if modo == "Servidor":
            if not self.server_ip_input.text() or not self.server_port_input.text():
                QMessageBox.warning(self, "Erro de Configuração", "IP e Porta do Servidor são obrigatórios.")
                self.update_status_labels(server_status="Erro de Configuração")
                return
            if not self.server_thread or not self.server_thread.isRunning():
                self.start_server_mode(selected_serial_port_actual)
            else:
                self.stop_server_mode()
        elif modo == "Cliente":
            if not self.client_url_input.text():
                QMessageBox.warning(self, "Erro de Configuração", "URL do Cliente é obrigatória.")
                self.update_status_labels(client_status="Erro de Configuração")
                return
            if not self.client_thread or not self.client_thread.isRunning():
                self.start_client_mode(selected_serial_port_actual)
            else:
                self.stop_client_mode()

        self.save_config()
        self.update_connect_button_state()


    def update_connect_button_state(self):
        modo = self.mode_combo.currentText()
        if modo == "Servidor":
            if self.server_thread and self.server_thread.isRunning():
                self.connect_button.setText("Parar Servidor")
                self.connect_button.setProperty("active", True)
            else:
                self.connect_button.setText("Iniciar Servidor")
                self.connect_button.setProperty("active", False)
        elif modo == "Cliente":
            if self.client_thread and self.client_thread.isRunning():
                self.connect_button.setText("Desconectar Cliente")
                self.connect_button.setProperty("active", True)
            else:
                self.connect_button.setText("Conectar Cliente")
                self.connect_button.setProperty("active", False)
        
        # Forçar reavaliação do estilo para o botão (se QSS usar a propriedade 'active')
        self.style().unpolish(self.connect_button)
        self.style().polish(self.connect_button)

    def get_serial_params(self) -> dict:
        parity_map = {
            "None": serial.PARITY_NONE,
            "Even": serial.PARITY_EVEN,
            "Odd": serial.PARITY_ODD,
            "Mark": serial.PARITY_MARK,
            "Space": serial.PARITY_SPACE,
        }
        return {
            "baudrate": int(self.baudrate_combo.currentText()),
            "timeout": float(self.timeout_edit.text() or 1), # Default 1s se vazio
            "bytesize": int(self.databits_combo.currentText()),
            "stopbits": float(self.stopbits_combo.currentText()),
            "parity": parity_map.get(self.parity_combo.currentText(), serial.PARITY_NONE),
            "rtscts": self.rtscts_combo.currentText() == "Ativado",
            "dsrdtr": self.dsrdtr_combo.currentText() == "Ativado",
        }

    def start_server_mode(self, porta_serial_raw: str):
        ip = self.server_ip_input.text()
        try:
            port_num = int(self.server_port_input.text())
        except ValueError:
            self.log_message("Porta do servidor inválida. Deve ser um número.", logging.ERROR)
            QMessageBox.warning(self, "Erro de Configuração", "Porta do servidor inválida.")
            self.update_status_labels(general_status="Erro de Configuração", server_status="Porta Inválida")
            return

        porta_serial_para_uso = porta_serial_raw
        if porta_serial_raw == "<GENERATE_VIRTUAL>" and "linux" in platform.platform().lower():
            try:
                master, slave = pty.openpty()
                porta_serial_para_uso = os.ttyname(slave)
                # O master fd (master) precisaria ser mantido aberto e talvez passado ou gerenciado
                # Esta é uma simplificação; a gestão completa de PTY pode ser complexa.
                self.log_message(f"Porta virtual mestre: {os.ttyname(master)}, escravo: {porta_serial_para_uso} (usado pela app)")
            except Exception as e:
                self.log_message(f"Falha ao criar porta virtual: {e}", logging.ERROR)
                QMessageBox.critical(self, "Erro PTY", f"Não foi possível criar porta virtual: {e}")
                return

        self.log_message(f"Iniciando Servidor em: {ip}:{port_num} usando porta serial {porta_serial_para_uso}")
        self.update_status_labels(general_status="Iniciando Servidor",
                                  connection_details=f"Servidor: {ip}:{port_num}",
                                  focused_port=porta_serial_para_uso,
                                  server_status="Iniciando...")
        self.reset_stats()

        serial_params = self.get_serial_params()
        self.server_thread = ServerThread(ip, port_num, porta_serial_para_uso,
                                          self.serial_port_semaphore, serial_params,
                                          self.log_signal) # Passa o log_signal
        
        # Conectar sinais do ServerThread
        self.server_thread.status_update_signal.connect(self.handle_server_status_update)
        self.server_thread.client_list_signal.connect(self.update_client_list)
        self.server_thread.data_transmitted_signal.connect(self.update_bytes_sent)
        self.server_thread.data_received_signal.connect(self.update_bytes_received)
        self.server_thread.uptime_signal.connect(self.update_uptime)
        
        self.server_thread.start()
        self.update_connect_button_state() # Atualiza texto do botão

    def stop_server_mode(self):
        if self.server_thread and self.server_thread.isRunning():
            self.log_message("Parando Servidor...")
            self.update_status_labels(general_status="Parando Servidor", server_status="Parando...")
            self.server_thread.stop_server()
            # Espera a thread terminar de forma limpa.
            if not self.server_thread.wait(5000): # Espera 5 segundos
                self.log_message("Thread do servidor não parou a tempo. Isso pode indicar um problema.", logging.WARNING)
                # CORREÇÃO: A chamada a terminate() foi removida por ser perigosa.
                # self.server_thread.terminate()
                # self.server_thread.wait()

            self.server_thread = None
            self.update_status_labels(general_status="Desconectado",
                                      connection_details="Servidor parado",
                                      server_status="Parado")
            self.reset_stats()
        self.update_connect_button_state()


    def start_client_mode(self, porta_serial_raw: str):
        url = self.client_url_input.text()
        
        porta_serial_para_uso = porta_serial_raw
        if porta_serial_raw == "<GENERATE_VIRTUAL>" and "linux" in platform.platform().lower():
            # Mesma lógica de criação de porta virtual do servidor
            try:
                master, slave = pty.openpty()
                porta_serial_para_uso = os.ttyname(slave)
                self.log_message(f"Porta virtual mestre: {os.ttyname(master)}, escravo: {porta_serial_para_uso} (usado pela app)")
            except Exception as e:
                self.log_message(f"Falha ao criar porta virtual: {e}", logging.ERROR)
                QMessageBox.critical(self, "Erro PTY", f"Não foi possível criar porta virtual: {e}")
                return

        self.log_message(f"Conectando ao Servidor em: {url} usando porta serial {porta_serial_para_uso}")
        self.update_status_labels(general_status="Conectando ao Servidor",
                                  connection_details=f"Cliente para: {url}",
                                  focused_port=porta_serial_para_uso,
                                  client_status="Conectando...")
        self.reset_stats()

        serial_params = self.get_serial_params()
        self.client_thread = ClientThread(url, porta_serial_para_uso,
                                          self.serial_port_semaphore, serial_params,
                                          self.log_signal) # Passa o log_signal

        self.client_thread.status_update_signal.connect(self.handle_client_status_update)
        self.client_thread.data_transmitted_signal.connect(self.update_bytes_sent)
        self.client_thread.data_received_signal.connect(self.update_bytes_received)
        self.client_thread.uptime_signal.connect(self.update_uptime)

        self.client_thread.start()
        self.update_connect_button_state()

    def stop_client_mode(self):
        if self.client_thread and self.client_thread.isRunning():
            self.log_message("Desconectando Cliente...")
            self.update_status_labels(general_status="Desconectando Cliente", client_status="Desconectando...")
            self.client_thread.stop_client()
            if not self.client_thread.wait(5000):
                self.log_message("Thread do cliente não parou a tempo. Isso pode indicar um problema.", logging.WARNING)
                # CORREÇÃO: A chamada a terminate() foi removida por ser perigosa.
                # self.client_thread.terminate()
                # self.client_thread.wait()

            self.client_thread = None
            self.update_status_labels(general_status="Desconectado",
                                      connection_details="Cliente parado",
                                      client_status="Desconectado")
            self.reset_stats()
        self.update_connect_button_state()


    def handle_server_status_update(self, status_type: str, message: str):
        """Recebe atualizações de status do ServerThread."""
        if status_type == "server_status":
            self.update_status_labels(server_status=message)
            if message == "Ouvindo" or message == "Online":
                 self.update_status_labels(general_status="Conectado")
            elif "Erro" in message:
                self.update_status_labels(general_status="Erro")
        elif status_type == "connection_detail":
            self.update_status_labels(connection_details=message)
        # Adicionar mais tipos conforme necessário (ex: "error", "info")

    def handle_client_status_update(self, status_type: str, message: str):
        """Recebe atualizações de status do ClientThread."""
        if status_type == "client_status":
            self.update_status_labels(client_status=message)
            if message == "Conectado":
                self.update_status_labels(general_status="Conectado")
            elif "Erro" in message or "Recusada" in message or "Falha" in message:
                 self.update_status_labels(general_status="Erro")
        elif status_type == "connection_detail":
            self.update_status_labels(connection_details=message)


    def load_log_from_file(self):
        if self.log_file_path and os.path.exists(self.log_file_path):
            try:
                with open(self.log_file_path, 'r', encoding='utf-8') as f:
                    log_content = f.read()
                    self.log_text_edit.setText(log_content)
                    self.log_text_edit.verticalScrollBar().setValue(self.log_text_edit.verticalScrollBar().maximum())
            except Exception as e:
                self.log_text_edit.setText(f"Erro ao ler o log: {e}")
                self.log_message(f"Erro ao ler o log do arquivo: {e}", logging.ERROR)
        else:
            self.log_text_edit.setText("Arquivo de log não encontrado ou caminho não configurado.")

    def append_log_text(self, message: str):
        self.log_text_edit.append(message)
        self.log_text_edit.verticalScrollBar().setValue(self.log_text_edit.verticalScrollBar().maximum())


    def log_message(self, message: str, level=logging.INFO):
        # self.logger já está configurado para enviar para GUI e arquivo
        self.logger.log(level, message)

    def save_config(self):
        # Garante que os inputs de log reflitam os valores atuais antes de salvar
        current_log_dir = self.log_location_input.text().strip()
        current_log_filename = self.log_file_name_input.text().strip() or DEFAULT_LOG_FILENAME

        config = {
            "modo": self.mode_combo.currentText(),
            "server_ip": self.server_ip_input.text(),
            "server_port": self.server_port_input.text(),
            "client_url": self.client_url_input.text(),
            "log_location": current_log_dir,
            "log_file_name": current_log_filename,
            "usuario": self.user_input.text(),
            # "senha": self.password_input.text(), # Evitar salvar senhas em plain text
            "porta_serial_display": self.serial_port_combo.currentText(), # Salva o texto exibido
            "porta_serial_actual": self.get_selected_serial_port(),      # Salva o valor real da porta
            "baudrate": self.baudrate_combo.currentText(),
            "databits": self.databits_combo.currentText(),
            "stopbits": self.stopbits_combo.currentText(),
            "parity": self.parity_combo.currentText(),
            "timeout": self.timeout_edit.text(),
            "rtscts": self.rtscts_combo.currentText() == "Ativado",
            "dsrdtr": self.dsrdtr_combo.currentText() == "Ativado"
        }
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f: # Usar UTF-8
                json.dump(config, f, indent=4)
            self.log_message(f"Configurações salvas em {CONFIG_FILE}")
        except Exception as e:
            self.log_message(f"Erro ao salvar as configurações: {e}", logging.ERROR)

    def load_config(self):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f: # Usar UTF-8
                config = json.load(f)

            self.mode_combo.setCurrentText(config.get("modo", "Cliente"))
            self.server_ip_input.setText(config.get("server_ip", "0.0.0.0"))
            self.server_port_input.setText(config.get("server_port", "8888"))
            self.client_url_input.setText(config.get("client_url", "127.0.0.1:8888"))
            self.log_location_input.setText(config.get("log_location", "."))
            self.log_file_name_input.setText(config.get("log_file_name", DEFAULT_LOG_FILENAME))
            self.user_input.setText(config.get("usuario", ""))
            # self.password_input.setText(config.get("senha", ""))

            saved_serial_port = config.get("porta_serial_actual") # Usar o valor real
            if saved_serial_port:
                # Tenta encontrar pelo valor userData
                for i in range(self.serial_port_combo.count()):
                    if self.serial_port_combo.itemData(i) == saved_serial_port:
                        self.serial_port_combo.setCurrentIndex(i)
                        break
                else: # Se não encontrar por userData, tenta pelo texto (menos ideal)
                    idx = self.serial_port_combo.findText(config.get("porta_serial_display", ""))
                    if idx != -1: self.serial_port_combo.setCurrentIndex(idx)


            self.baudrate_combo.setCurrentText(config.get("baudrate", "9600"))
            self.databits_combo.setCurrentText(config.get("databits", "8"))
            self.stopbits_combo.setCurrentText(config.get("stopbits", "1"))
            self.parity_combo.setCurrentText(config.get("parity", "None"))
            self.timeout_edit.setText(config.get("timeout", "1"))
            self.rtscts_combo.setCurrentText("Ativado" if config.get("rtscts", False) else "Desativado")
            self.dsrdtr_combo.setCurrentText("Ativado" if config.get("dsrdtr", False) else "Desativado")
            
            # Após carregar configs de log, reconfigure o logging
            self.setup_logging()
            self.log_message(f"Configurações carregadas de {CONFIG_FILE}")

        except FileNotFoundError:
            self.log_message(f"{CONFIG_FILE} não encontrado. Usando padrões e salvando nova config.")
            self.save_config() # Salva um config padrão se não existir
        except json.JSONDecodeError:
            self.log_message(f"Erro ao decodificar {CONFIG_FILE}. Arquivo pode estar corrompido. Usando padrões.", logging.ERROR)
            self.save_config()
        except Exception as e:
            self.log_message(f"Erro ao carregar as configurações: {e}", logging.ERROR)


    def update_client_list(self, clients: list):
        self.connected_clients_list.clear()
        self.connected_clients_list.addItems(clients)

    def update_bytes_sent(self, bytes_count: int):
        self.bytes_sent_value.setText(f"{bytes_count:,}".replace(",", "."))

    def update_bytes_received(self, bytes_count: int):
        self.bytes_received_value.setText(f"{bytes_count:,}".replace(",", "."))

    def update_uptime(self, uptime_str: str):
        self.uptime_value.setText(uptime_str)

    def reset_stats(self):
        """Reseta as estatísticas da UI para o estado inicial."""
        self.update_uptime("00:00:00")
        self.update_bytes_sent(0)
        self.update_bytes_received(0)
        if hasattr(self, 'connected_clients_list'):
            self.connected_clients_list.clear()


    def update_status_labels(self, general_status=None, connection_details=None,
                             focused_port=None, server_status=None,
                             client_status=None, connected_clients=None):
        """Atualiza os QLabels de status de forma centralizada."""
        if general_status is not None:
            self.status_label_value.setText(general_status)
            self.status_label_value.setProperty("status", general_status) # Para QSS
            self.style().unpolish(self.status_label_value)
            self.style().polish(self.status_label_value)
        if connection_details is not None:
            self.connection_details_value.setText(connection_details)
        if focused_port is not None:
            self.focused_port_value.setText(focused_port)
        if server_status is not None:
             # Este label não existe mais, mas mantemos a lógica para o status geral
            pass
        if client_status is not None:
            self.client_status_value.setText(client_status)
            self.client_status_value.setProperty("status", client_status) # Para QSS
            self.style().unpolish(self.client_status_value)
            self.style().polish(self.client_status_value)


    def closeEvent(self, event):
        self.log_message("Fechando aplicativo...")
        self.save_config() # Salva configuração ao sair

        if self.server_thread and self.server_thread.isRunning():
            self.log_message("Parando servidor antes de sair...")
            self.stop_server_mode()

        if self.client_thread and self.client_thread.isRunning():
            self.log_message("Parando cliente antes de sair...")
            self.stop_client_mode()
        
        # Garante que o buffer do LogRedirector seja escrito
        if hasattr(sys.stdout, 'flush'):
            sys.stdout.flush()
        if hasattr(sys.stderr, 'flush'):
            sys.stderr.flush()

        super().closeEvent(event)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SerialConWindow()
    window.show()
    try:
        sys.exit(app.exec())
    except Exception as e:
        # Este print pode não ser capturado se o redirector já foi resetado
        # ou se o erro for na finalização do Qt.
        logging.getLogger(APP_LOGGER_NAME).critical(f"Erro fatal na aplicação: {e}", exc_info=True)
        print(f"Erro fatal na aplicação: {e}")