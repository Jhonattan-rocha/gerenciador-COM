import sys
import json
import platform
import logging
import time
from typing import Dict, Any, Optional
import os
from pathlib import Path

from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                               QTabWidget, QLabel, QGroupBox, QGridLayout,
                               QLineEdit, QPushButton, QComboBox, QTextEdit,
                               QFileDialog, QMessageBox, QProgressBar)
from PySide6.QtGui import QIcon, QPixmap, QDoubleValidator, Qt
from PySide6.QtCore import QTimer, Signal

import serial.tools.list_ports

# Importar nova arquitetura
from core import SerialManager, ConnectionManager, AgentStateMachine, DataProcessor
from utils import ConfigManager, setup_logger, get_logger, validate_agent_config
from api_client import APIClient

if "linux" in platform.platform().lower():
    import pty

# Constantes
CONFIG_FILE = "config.json"
DEFAULT_LOG_FILENAME = "./app_log.txt"
APP_LOGGER_NAME = "SerialApp"

class QtLogHandler(logging.Handler):
    """Handler de logging para emitir registros para a GUI."""
    def __init__(self, log_signal: Signal):
        super().__init__()
        self.log_signal = log_signal

    def emit(self, record):
        log_message = self.format(record)
        self.log_signal.emit(log_message)

class SerialConWindow(QWidget):
    log_signal = Signal(str)  # Sinal para logs na GUI
    status_update_signal = Signal(str, str)  # Sinal para atualizações de status
    data_received_signal = Signal(bytes)  # Sinal para dados recebidos

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gerenciador de Porta Serial v2.0 - Arquitetura Refatorada")
        self.setWindowIcon(QIcon("./icon.png"))
        self.setGeometry(100, 100, 800, 700)

        # Componentes da nova arquitetura
        self.config_manager: Optional[ConfigManager] = None
        self.serial_manager: Optional[SerialManager] = None
        self.connection_manager: Optional[ConnectionManager] = None
        self.state_machine: Optional[AgentStateMachine] = None
        self.data_processor: Optional[DataProcessor] = None
        self.api_client: Optional[APIClient] = None
        
        # Logger
        self.logger = get_logger(APP_LOGGER_NAME)
        self.log_file_path = ""

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
            with open("style.qss", "r") as f:
                self.setStyleSheet(f.read())
        except FileNotFoundError:
            self.log_message("Arquivo style.qss não encontrado. Usando estilo padrão.", logging.WARNING)
        except Exception as e:
            self.log_message(f"Erro ao carregar style.qss: {e}", logging.ERROR)


    def setup_logging(self):
        """Configura o sistema de logging usando a nova arquitetura."""
        log_dir = self.log_location_input.text().strip() or "."
        log_filename = self.log_file_name_input.text().strip() or DEFAULT_LOG_FILENAME
        self.log_file_path = os.path.join(log_dir, log_filename)

        try:
            # Usar o setup_logger da nova arquitetura
            setup_logger(
                name=APP_LOGGER_NAME,
                level=logging.DEBUG,
                log_file=self.log_file_path,
                console_output=False  # Não usar console, apenas GUI
            )
            
            # Obter o logger configurado
            self.logger = get_logger(APP_LOGGER_NAME)
            
            # Adicionar handler para GUI
            gui_handler = QtLogHandler(self.log_signal)
            gui_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            gui_handler.setFormatter(gui_formatter)
            self.logger.addHandler(gui_handler)
            
            self.logger.info("Sistema de logging configurado com nova arquitetura.")
            
        except Exception as e:
            QMessageBox.warning(self, "Erro de Logging", f"Não foi possível configurar o log: {e}")

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

        backend_group = QGroupBox("Configurações do Backend")
        backend_layout = QGridLayout(backend_group)
        self.backend_url_input = QLineEdit("localhost:8000")
        backend_layout.addWidget(QLabel("URL do Backend:"), 0, 0)
        backend_layout.addWidget(self.backend_url_input, 0, 1)
        config_layout.addWidget(backend_group)

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


        # API Key para autenticação
        auth_group = QGroupBox("Autenticação do Agente")
        auth_layout = QGridLayout(auth_group)
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.Password)
        self.api_key_input.setPlaceholderText("Cole aqui a API Key do agente")
        auth_layout.addWidget(QLabel("API Key:"), 0, 0)
        auth_layout.addWidget(self.api_key_input, 0, 1)
        
        # Status da conexão WebSocket
        self.ws_status_label = QLabel("Status: Desconectado")
        self.ws_status_label.setStyleSheet("color: red; font-weight: bold;")
        auth_layout.addWidget(QLabel("WebSocket:"), 1, 0)
        auth_layout.addWidget(self.ws_status_label, 1, 1)
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

        connection_status_group = QGroupBox("Status da Conexão")
        connection_status_layout = QGridLayout(connection_status_group)

        self.status_label_value = QLabel("Desconectado")
        self.status_label_value.setObjectName("status_label_value") # Para QSS
        self.connection_details_value = QLabel("N/A")
        self.focused_port_value = QLabel("N/A")

        self.server_status_label = QLabel("Status Servidor:")
        self.server_status_value = QLabel("Parado")
        self.server_status_value.setObjectName("server_status_value") # Para QSS
        self.connected_clients_label = QLabel("Clientes Conectados (Servidor):")
        self.connected_clients_value = QLabel("0")

        self.client_status_label = QLabel("Status Cliente:")
        self.client_status_value = QLabel("Desconectado")
        self.client_status_value.setObjectName("client_status_value") # Para QSS

        row = 0
        connection_status_layout.addWidget(QLabel("Status Geral:"), row, 0)
        connection_status_layout.addWidget(self.status_label_value, row, 1)
        row += 1
        connection_status_layout.addWidget(QLabel("Detalhes da Conexão:"), row, 0)
        connection_status_layout.addWidget(self.connection_details_value, row, 1, 1, 2) # Span 2 colunas
        row += 1
        connection_status_layout.addWidget(QLabel("Porta Serial Focada:"), row, 0)
        connection_status_layout.addWidget(self.focused_port_value, row, 1, 1, 2) # Span
        row += 1
        connection_status_layout.addWidget(self.server_status_label, row, 0)
        connection_status_layout.addWidget(self.server_status_value, row, 1)
        row += 1
        connection_status_layout.addWidget(self.connected_clients_label, row, 0)
        connection_status_layout.addWidget(self.connected_clients_value, row, 1)
        row += 1
        connection_status_layout.addWidget(self.client_status_label, row, 0)
        connection_status_layout.addWidget(self.client_status_value, row, 1)

        status_layout.addWidget(connection_status_group)
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

        # Atualiza visibilidade dos status específicos
        self.server_status_label.setVisible(is_server_mode)
        self.server_status_value.setVisible(is_server_mode)
        self.connected_clients_label.setVisible(is_server_mode)
        self.connected_clients_value.setVisible(is_server_mode)

        self.client_status_label.setVisible(not is_server_mode)
        self.client_status_value.setVisible(not is_server_mode)

        self.update_connect_button_state()


    def choose_log_location(self):
        log_dir = QFileDialog.getExistingDirectory(self, "Escolher Pasta de Log", self.log_location_input.text() or ".")
        if log_dir:
            self.log_location_input.setText(log_dir)
            # Reconfigurar o logging se o caminho mudar e o logger já estiver ativo
            self.setup_logging()
            self.log_message(f"Pasta de log alterada para: {log_dir}")


    def handle_connect_button(self):
        """
        Lógica de conexão refatorada para usar a nova arquitetura.
        """
        # Se já estiver conectado, o botão irá parar/desconectar
        is_running = (self.state_machine and self.state_machine.is_running()) or \
                     (self.api_client and self.api_client.is_connected)
        if is_running:
            self.stop_agent()
            return

        # 1. Validação dos campos da interface
        api_key = self.api_key_input.text().strip()
        backend_url = self.backend_url_input.text().strip()
        selected_serial_port = self.get_selected_serial_port()

        if not all([api_key, backend_url]):
            QMessageBox.warning(self, "Validação Falhou", "Os campos 'URL do Backend' e 'API Key' são obrigatórios.")
            return

        if not selected_serial_port or "Nenhuma" in selected_serial_port:
            QMessageBox.warning(self, "Erro", "Nenhuma porta serial selecionada.")
            return

        # 2. Inicializar ConfigManager e criar configuração
        try:
            self.config_manager = ConfigManager()
            
            # Criar configuração baseada na interface
            config_data = self._create_agent_config()
            
            # Validar configuração
            validation_result = validate_agent_config(config_data)
            if not validation_result.is_valid:
                error_msg = "\n".join(validation_result.errors)
                QMessageBox.critical(self, "Configuração Inválida", f"Erros na configuração:\n{error_msg}")
                return
                
            # Carregar configuração no ConfigManager
            self.config_manager.update_config(config_data)
            
        except Exception as e:
            self.log_message(f"Erro ao inicializar configuração: {e}", logging.ERROR)
            QMessageBox.critical(self, "Erro de Configuração", f"Falha ao configurar o sistema: {e}")
            return

        # 3. Autenticação com API Key
        self.api_client = APIClient(backend_url)
        self.log_message(f"Iniciando processo de autenticação com API Key...")
        QApplication.setOverrideCursor(Qt.WaitCursor)

        auth_ok, auth_message = self.api_client.autenticar_api_key(api_key)
        QApplication.restoreOverrideCursor()

        if not auth_ok:
            self.log_message(f"Falha na autenticação: {auth_message}", logging.ERROR)
            QMessageBox.critical(self, "Falha na Autenticação", auth_message)
            return

        self.log_message(f"Autenticação bem-sucedida: {auth_message}")

        # 4. Conectar WebSocket
        self.log_message("Estabelecendo conexão WebSocket...")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        
        ws_ok, ws_message = self.api_client.conectar_websocket(
            on_message_callback=self.handle_ws_message,
            on_status_callback=self.update_ws_status
        )
        QApplication.restoreOverrideCursor()

        if not ws_ok:
            self.log_message(f"Falha na conexão WebSocket: {ws_message}", logging.ERROR)
            QMessageBox.critical(self, "Falha na Conexão", ws_message)
            return

        # 5. Inicializar componentes da nova arquitetura
        try:
            self.start_agent()
            self.log_message(f"WebSocket conectado: {ws_message}", logging.INFO)
            QMessageBox.information(self, "Conexão Estabelecida", "Agente conectado com sucesso ao backend!")
            
        except Exception as e:
            self.log_message(f"Erro ao iniciar agente: {e}", logging.ERROR)
            QMessageBox.critical(self, "Erro de Inicialização", f"Falha ao iniciar o agente: {e}")
            return

        self.save_config()
        self.update_connect_button_state()


    def update_connect_button_state(self):
        """Atualiza o estado do botão de conexão baseado na nova arquitetura."""
        is_running = (self.state_machine and self.state_machine.is_running()) or \
                     (self.api_client and self.api_client.is_connected)
        
        if is_running:
            self.connect_button.setText("Desconectar Agente")
            self.connect_button.setProperty("active", True)
        else:
            self.connect_button.setText("Conectar Agente")
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

    def _create_agent_config(self) -> Dict[str, Any]:
        """Cria a configuração do agente baseada nos valores da interface."""
        from utils.config_manager import SerialConfig, NetworkConfig, ProcessingConfig, LoggingConfig, AgentConfig
        
        # Configuração da porta serial
        serial_params = self.get_serial_params()
        serial_config = SerialConfig(
            port=self.get_selected_serial_port(),
            **serial_params
        )
        
        # Configuração de rede
        modo = self.mode_combo.currentText()
        if modo == "Servidor":
            network_config = NetworkConfig(
                mode="server",
                host=self.server_ip_input.text().strip() or "0.0.0.0",
                port=int(self.server_port_input.text().strip() or "8888")
            )
        else:
            client_url = self.client_url_input.text().strip() or "127.0.0.1:8888"
            if ":" in client_url:
                host, port_str = client_url.split(":", 1)
                port = int(port_str)
            else:
                host = client_url
                port = 8888
            network_config = NetworkConfig(
                mode="client",
                host=host,
                port=port
            )
        
        # Configuração de processamento
        processing_config = ProcessingConfig(
            enable_filtering=True,
            enable_validation=True,
            max_queue_size=1000
        )
        
        # Configuração de logging
        logging_config = LoggingConfig(
            level="DEBUG",
            file_path=self.log_file_path,
            max_file_size=10*1024*1024,  # 10MB
            backup_count=5
        )
        
        # Configuração principal do agente
        agent_config = AgentConfig(
            agent_id=f"agent_{int(time.time())}",
            serial=serial_config,
            network=network_config,
            processing=processing_config,
            logging=logging_config
        )
        
        return agent_config.__dict__

    def start_agent(self):
        """Inicia todos os componentes da nova arquitetura."""
        try:
            # 1. Inicializar SerialManager
            serial_config = self.config_manager.get_config().serial
            self.serial_manager = SerialManager(
                port=serial_config.port,
                baudrate=serial_config.baudrate,
                timeout=serial_config.timeout,
                bytesize=serial_config.bytesize,
                stopbits=serial_config.stopbits,
                parity=serial_config.parity,
                rtscts=serial_config.rtscts,
                dsrdtr=serial_config.dsrdtr
            )
            
            # 2. Inicializar ConnectionManager
            network_config = self.config_manager.get_config().network
            self.connection_manager = ConnectionManager(
                mode=network_config.mode,
                host=network_config.host,
                port=network_config.port
            )
            
            # 3. Inicializar DataProcessor
            processing_config = self.config_manager.get_config().processing
            self.data_processor = DataProcessor(
                enable_filtering=processing_config.enable_filtering,
                enable_validation=processing_config.enable_validation,
                max_queue_size=processing_config.max_queue_size
            )
            
            # 4. Inicializar AgentStateMachine
            self.state_machine = AgentStateMachine()
            
            # 5. Configurar callbacks
            self.serial_manager.set_data_callback(self._on_serial_data_received)
            self.serial_manager.set_status_callback(self._on_serial_status_changed)
            self.connection_manager.set_message_callback(self._on_network_message_received)
            self.connection_manager.set_status_callback(self._on_network_status_changed)
            self.state_machine.set_state_callback(self._on_state_changed)
            
            # 6. Conectar sinais
            self.status_update_signal.connect(self._handle_status_update)
            self.data_received_signal.connect(self._handle_data_received)
            
            # 7. Iniciar componentes
            self.serial_manager.connect()
            self.connection_manager.start()
            self.state_machine.start()
            
            self.log_message("Agente iniciado com sucesso usando nova arquitetura.")
            
        except Exception as e:
            self.log_message(f"Erro ao iniciar agente: {e}", logging.ERROR)
            self.stop_agent()  # Limpar recursos em caso de erro
            raise

    def stop_agent(self):
        """Para todos os componentes da nova arquitetura."""
        try:
            # Parar componentes na ordem inversa
            if self.state_machine:
                self.state_machine.stop()
                self.state_machine = None
                
            if self.connection_manager:
                self.connection_manager.stop()
                self.connection_manager = None
                
            if self.serial_manager:
                self.serial_manager.disconnect()
                self.serial_manager = None
                
            if self.data_processor:
                self.data_processor = None
                
            if self.api_client:
                self.api_client.desconectar()
                self.api_client = None
                
            self.log_message("Agente parado com sucesso.")
            self.update_connect_button_state()
            self.update_ws_status("disconnected", "Desconectado")
            
        except Exception as e:
            self.log_message(f"Erro ao parar agente: {e}", logging.ERROR)

    def _on_serial_data_received(self, data: bytes):
        """Callback para dados recebidos da porta serial."""
        self.data_received_signal.emit(data)
        
    def _on_serial_status_changed(self, status: str, message: str):
        """Callback para mudanças de status da porta serial."""
        self.status_update_signal.emit(f"serial_{status}", message)
        
    def _on_network_message_received(self, message: bytes, client_info: Optional[Dict] = None):
        """Callback para mensagens recebidas da rede."""
        # Processar mensagem através do DataProcessor
        if self.data_processor:
            self.data_processor.process_data(message)
            
    def _on_network_status_changed(self, status: str, message: str):
        """Callback para mudanças de status da rede."""
        self.status_update_signal.emit(f"network_{status}", message)
        
    def _on_state_changed(self, old_state: str, new_state: str):
        """Callback para mudanças de estado do agente."""
        self.status_update_signal.emit("state_change", f"Estado: {old_state} -> {new_state}")
        
    def _handle_status_update(self, status_type: str, message: str):
        """Manipula atualizações de status dos componentes."""
        self.log_message(f"[{status_type}] {message}")
        # Atualizar labels de status na interface se necessário
        
    def _handle_data_received(self, data: bytes):
        """Manipula dados recebidos."""
        # Processar dados através do DataProcessor
        if self.data_processor:
            processed_data = self.data_processor.process_data(data)
            # Enviar dados processados através da rede se necessário
            if self.connection_manager and processed_data:
                self.connection_manager.send_message(processed_data)

    # Métodos antigos removidos - agora usando a nova arquitetura com start_agent/stop_agent


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
            "api_key": self.api_key_input.text(),
            "backend_url": self.backend_url_input.text(),
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
            self.backend_url_input.setText(config.get("backend_url", "localhost:8000"))
            self.log_location_input.setText(config.get("log_location", "."))
            self.log_file_name_input.setText(config.get("log_file_name", DEFAULT_LOG_FILENAME))
            self.api_key_input.setText(config.get("api_key", ""))

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


    def update_connected_clients_count(self, count: int):
        self.connected_clients_value.setText(str(count))
        self.update_status_labels(connected_clients=count)
    
    def handle_ws_message(self, data):
        """Processa mensagens recebidas via WebSocket."""
        try:
            message_type = data.get('type', 'unknown')
            
            if message_type == 'heartbeat_ack':
                # Apenas log de debug para heartbeat
                self.logger.debug("Heartbeat ACK recebido")
                return
                
            self.log_message(f"Mensagem WebSocket recebida: {message_type}")
            
            if message_type == 'command':
                # Processa comandos do backend
                command = data.get('command')
                if command == 'restart':
                    self.log_message("Comando de reinicialização recebido do servidor")
                    QMessageBox.information(self, "Comando do Servidor", "O servidor solicitou reinicialização do agente.")
                    # Implementar lógica de reinicialização se necessário
                elif command == 'disconnect':
                    self.log_message("Comando de desconexão recebido do servidor")
                    if self.api_client and self.api_client.is_connected:
                        self.api_client.desconectar()
                        self.update_ws_status("disconnected", "Desconectado pelo servidor")
                        self.update_connect_button_state()
            
            elif message_type == 'message':
                # Exibe mensagens do backend
                message = data.get('content', 'Sem conteúdo')
                self.log_message(f"Mensagem do servidor: {message}")
                QMessageBox.information(self, "Mensagem do Servidor", message)
                
        except Exception as e:
            self.log_message(f"Erro ao processar mensagem WebSocket: {e}", logging.ERROR)
    
    def update_ws_status(self, status_type: str, message: str):
        """Atualiza o status da conexão WebSocket na interface."""
        if status_type == "connected":
            self.ws_status_label.setText(f"Status: Conectado")
            self.ws_status_label.setStyleSheet("color: green; font-weight: bold;")
        elif status_type == "connecting":
            self.ws_status_label.setText(f"Status: Conectando...")
            self.ws_status_label.setStyleSheet("color: orange; font-weight: bold;")
        elif status_type == "error":
            self.ws_status_label.setText(f"Status: Erro")
            self.ws_status_label.setStyleSheet("color: red; font-weight: bold;")
        else:  # disconnected
            self.ws_status_label.setText(f"Status: Desconectado")
            self.ws_status_label.setStyleSheet("color: red; font-weight: bold;")
            
        self.log_message(f"Status WebSocket: {message}")


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
            self.server_status_value.setText(server_status)
            self.server_status_value.setProperty("status", server_status) # Para QSS
            self.style().unpolish(self.server_status_value)
            self.style().polish(self.server_status_value)
        if client_status is not None:
            self.client_status_value.setText(client_status)
            self.client_status_value.setProperty("status", client_status) # Para QSS
            self.style().unpolish(self.client_status_value)
            self.style().polish(self.client_status_value)
        if connected_clients is not None:
            self.connected_clients_value.setText(str(connected_clients))


    def closeEvent(self, event):
        self.log_message("Fechando aplicativo...")
        self.save_config() # Salva configuração ao sair

        # Para os componentes da nova arquitetura
        if (self.state_machine and self.state_machine.is_running()) or \
           (self.api_client and self.api_client.is_connected()):
            self.log_message("Parando agente antes de sair...")
            self.stop_agent()
        
        # Garante que o buffer seja escrito
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