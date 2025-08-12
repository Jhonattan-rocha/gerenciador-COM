import json
import os
import threading
import time
import logging
from typing import Dict, Any, Optional, Callable, List
from dataclasses import dataclass, asdict
from pathlib import Path
import serial


@dataclass
class SerialConfig:
    """Serial port configuration."""
    port: str
    baudrate: int = 9600
    bytesize: int = serial.EIGHTBITS
    parity: str = serial.PARITY_NONE
    stopbits: float = serial.STOPBITS_ONE
    timeout: float = 1.0
    write_timeout: float = 1.0
    xonxoff: bool = False
    rtscts: bool = False
    dsrdtr: bool = False
    encoding: str = 'cp850'
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SerialConfig':
        return cls(**data)


@dataclass
class NetworkConfig:
    """Network configuration."""
    mode: str  # 'server' or 'client'
    host: str = 'localhost'
    port: int = 8080
    timeout: float = 10.0
    max_connections: int = 5
    reconnect_attempts: int = 10
    reconnect_delay: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NetworkConfig':
        return cls(**data)


@dataclass
class WebSocketConfig:
    """WebSocket configuration."""
    url: str
    api_key: str
    reconnect_attempts: int = 10
    reconnect_delay: float = 1.0
    heartbeat_interval: float = 30.0
    timeout: float = 10.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WebSocketConfig':
        return cls(**data)


@dataclass
class ProcessingConfig:
    """Data processing configuration."""
    max_packet_size: int = 1024 * 1024  # 1MB
    processing_timeout: float = 5.0
    enable_integrity_check: bool = True
    auto_retry_failed: bool = True
    batch_processing: bool = False
    batch_size: int = 10
    max_queue_size: int = 1000
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProcessingConfig':
        return cls(**data)


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = 'INFO'
    format: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    file_path: Optional[str] = None
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    console_output: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LoggingConfig':
        return cls(**data)


@dataclass
class AgentConfig:
    """Complete agent configuration."""
    agent_id: str
    agent_name: str
    company_id: Optional[str] = None
    serial: Optional[SerialConfig] = None
    network: Optional[NetworkConfig] = None
    websocket: Optional[WebSocketConfig] = None
    processing: Optional[ProcessingConfig] = None
    logging: Optional[LoggingConfig] = None
    custom_settings: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.custom_settings is None:
            self.custom_settings = {}
        if self.processing is None:
            self.processing = ProcessingConfig()
        if self.logging is None:
            self.logging = LoggingConfig()
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentConfig':
        # Convert nested configs
        if 'serial' in data and data['serial']:
            data['serial'] = SerialConfig.from_dict(data['serial'])
        if 'network' in data and data['network']:
            data['network'] = NetworkConfig.from_dict(data['network'])
        if 'websocket' in data and data['websocket']:
            data['websocket'] = WebSocketConfig.from_dict(data['websocket'])
        if 'processing' in data and data['processing']:
            data['processing'] = ProcessingConfig.from_dict(data['processing'])
        if 'logging' in data and data['logging']:
            data['logging'] = LoggingConfig.from_dict(data['logging'])
        
        return cls(**data)


class ConfigManager:
    """Thread-safe configuration manager with file watching and validation."""
    
    def __init__(self, config_file: str = "agent_config.json"):
        self.config_file = Path(config_file)
        self.config: Optional[AgentConfig] = None
        
        # Threading
        self._lock = threading.RLock()
        self._file_watcher_thread: Optional[threading.Thread] = None
        self._watching = False
        
        # Callbacks
        self._change_callbacks: List[Callable[[AgentConfig], None]] = []
        
        # File watching
        self._last_modified = 0.0
        self._check_interval = 1.0  # seconds
        
        # Validation
        self._validation_errors: List[str] = []
        
        self.logger = logging.getLogger("ConfigManager")
    
    def load_config(self) -> bool:
        """Load configuration from file."""
        with self._lock:
            try:
                if not self.config_file.exists():
                    self.logger.warning(f"Config file {self.config_file} not found, creating default")
                    self._create_default_config()
                    return True
                
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                
                self.config = AgentConfig.from_dict(config_data)
                self._last_modified = self.config_file.stat().st_mtime
                
                # Validate configuration
                if not self._validate_config():
                    self.logger.error(f"Configuration validation failed: {self._validation_errors}")
                    return False
                
                self.logger.info(f"Configuration loaded from {self.config_file}")
                return True
                
            except json.JSONDecodeError as e:
                self.logger.error(f"Invalid JSON in config file: {e}")
                return False
            except Exception as e:
                self.logger.error(f"Error loading config: {e}")
                return False
    
    def save_config(self) -> bool:
        """Save current configuration to file."""
        with self._lock:
            if not self.config:
                self.logger.error("No configuration to save")
                return False
            
            try:
                # Validate before saving
                if not self._validate_config():
                    self.logger.error(f"Cannot save invalid configuration: {self._validation_errors}")
                    return False
                
                # Create backup
                if self.config_file.exists():
                    backup_file = self.config_file.with_suffix('.json.bak')
                    self.config_file.rename(backup_file)
                
                # Save new config
                with open(self.config_file, 'w', encoding='utf-8') as f:
                    json.dump(self.config.to_dict(), f, indent=2, ensure_ascii=False)
                
                self._last_modified = self.config_file.stat().st_mtime
                self.logger.info(f"Configuration saved to {self.config_file}")
                return True
                
            except Exception as e:
                self.logger.error(f"Error saving config: {e}")
                return False
    
    def get_config(self) -> Optional[AgentConfig]:
        """Get current configuration."""
        with self._lock:
            return self.config
    
    def update_config(self, updates: Dict[str, Any]) -> bool:
        """Update configuration with new values."""
        with self._lock:
            if not self.config:
                self.logger.error("No configuration loaded")
                return False
            
            try:
                # Create updated config
                config_dict = self.config.to_dict()
                self._deep_update(config_dict, updates)
                
                new_config = AgentConfig.from_dict(config_dict)
                
                # Validate new config
                old_config = self.config
                self.config = new_config
                
                if not self._validate_config():
                    self.config = old_config  # Restore old config
                    self.logger.error(f"Configuration update failed validation: {self._validation_errors}")
                    return False
                
                # Notify callbacks
                self._notify_change_callbacks()
                
                self.logger.info("Configuration updated")
                return True
                
            except Exception as e:
                self.logger.error(f"Error updating config: {e}")
                return False
    
    def add_change_callback(self, callback: Callable[[AgentConfig], None]):
        """Add callback for configuration changes."""
        with self._lock:
            self._change_callbacks.append(callback)
    
    def remove_change_callback(self, callback: Callable[[AgentConfig], None]):
        """Remove configuration change callback."""
        with self._lock:
            if callback in self._change_callbacks:
                self._change_callbacks.remove(callback)
    
    def start_file_watching(self):
        """Start watching config file for changes."""
        with self._lock:
            if self._watching:
                return
            
            self._watching = True
            self._file_watcher_thread = threading.Thread(target=self._file_watcher_loop, daemon=True)
            self._file_watcher_thread.start()
            
            self.logger.info("Started file watching")
    
    def stop_file_watching(self):
        """Stop watching config file for changes."""
        with self._lock:
            if not self._watching:
                return
            
            self._watching = False
            
            if self._file_watcher_thread and self._file_watcher_thread.is_alive():
                self._file_watcher_thread.join(timeout=2.0)
            
            self.logger.info("Stopped file watching")
    
    def get_validation_errors(self) -> List[str]:
        """Get current validation errors."""
        with self._lock:
            return self._validation_errors.copy()
    
    def _create_default_config(self):
        """Create default configuration file."""
        default_config = AgentConfig(
            agent_id="agent_001",
            agent_name="Default Agent",
            serial=SerialConfig(port="COM1"),
            network=NetworkConfig(mode="client"),
            websocket=WebSocketConfig(
                url="ws://localhost:8000/ws/agent",
                api_key="your_api_key_here"
            )
        )
        
        self.config = default_config
        self.save_config()
    
    def _validate_config(self) -> bool:
        """Validate current configuration."""
        self._validation_errors.clear()
        
        if not self.config:
            self._validation_errors.append("No configuration loaded")
            return False
        
        # Validate agent info
        if not self.config.agent_id:
            self._validation_errors.append("Agent ID is required")
        
        if not self.config.agent_name:
            self._validation_errors.append("Agent name is required")
        
        # Validate serial config
        if self.config.serial:
            if not self.config.serial.port:
                self._validation_errors.append("Serial port is required")
            
            if self.config.serial.baudrate <= 0:
                self._validation_errors.append("Serial baudrate must be positive")
        
        # Validate network config
        if self.config.network:
            if self.config.network.mode not in ['server', 'client']:
                self._validation_errors.append("Network mode must be 'server' or 'client'")
            
            if not self.config.network.host:
                self._validation_errors.append("Network host is required")
            
            if not (1 <= self.config.network.port <= 65535):
                self._validation_errors.append("Network port must be between 1 and 65535")
        
        # Validate websocket config
        if self.config.websocket:
            if not self.config.websocket.url:
                self._validation_errors.append("WebSocket URL is required")
            
            if not self.config.websocket.api_key:
                self._validation_errors.append("WebSocket API key is required")
        
        # Validate processing config
        if self.config.processing:
            if self.config.processing.max_packet_size <= 0:
                self._validation_errors.append("Max packet size must be positive")
            
            if self.config.processing.processing_timeout <= 0:
                self._validation_errors.append("Processing timeout must be positive")
        
        return len(self._validation_errors) == 0
    
    def _file_watcher_loop(self):
        """File watcher loop running in separate thread."""
        self.logger.debug("File watcher started")
        
        while self._watching:
            try:
                if self.config_file.exists():
                    current_modified = self.config_file.stat().st_mtime
                    
                    if current_modified > self._last_modified:
                        self.logger.info("Config file changed, reloading...")
                        
                        if self.load_config():
                            self._notify_change_callbacks()
                        else:
                            self.logger.error("Failed to reload config file")
                
                time.sleep(self._check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in file watcher: {e}")
                time.sleep(self._check_interval)
        
        self.logger.debug("File watcher stopped")
    
    def _notify_change_callbacks(self):
        """Notify all change callbacks."""
        for callback in self._change_callbacks:
            try:
                callback(self.config)
            except Exception as e:
                self.logger.error(f"Error in change callback: {e}")
    
    def _deep_update(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]):
        """Deep update dictionary."""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value


# Validation functions
def validate_serial_config(config: SerialConfig) -> List[str]:
    """Validate serial configuration."""
    errors = []
    
    if not config.port:
        errors.append("Serial port is required")
    
    if config.baudrate <= 0:
        errors.append("Baudrate must be positive")
    
    if config.timeout < 0:
        errors.append("Timeout cannot be negative")
    
    if config.write_timeout < 0:
        errors.append("Write timeout cannot be negative")
    
    return errors


def validate_network_config(config: NetworkConfig) -> List[str]:
    """Validate network configuration."""
    errors = []
    
    if config.mode not in ['server', 'client']:
        errors.append("Mode must be 'server' or 'client'")
    
    if not config.host:
        errors.append("Host is required")
    
    if not (1 <= config.port <= 65535):
        errors.append("Port must be between 1 and 65535")
    
    if config.timeout <= 0:
        errors.append("Timeout must be positive")
    
    if config.max_connections <= 0:
        errors.append("Max connections must be positive")
    
    return errors