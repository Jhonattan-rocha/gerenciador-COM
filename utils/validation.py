import re
import ipaddress
import socket
from typing import Dict, Any, List, Optional, Union, Tuple
from pathlib import Path
import serial
import json
from dataclasses import dataclass
from enum import Enum


class ValidationError(Exception):
    """Custom validation error."""
    pass


class ValidationResult:
    """Result of validation operation."""
    
    def __init__(self, is_valid: bool, errors: Optional[List[str]] = None, warnings: Optional[List[str]] = None):
        self.is_valid = is_valid
        self.errors = errors or []
        self.warnings = warnings or []
    
    def add_error(self, error: str):
        """Add validation error."""
        self.errors.append(error)
        self.is_valid = False
    
    def add_warning(self, warning: str):
        """Add validation warning."""
        self.warnings.append(warning)
    
    def merge(self, other: 'ValidationResult'):
        """Merge with another validation result."""
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        if not other.is_valid:
            self.is_valid = False
    
    def __bool__(self) -> bool:
        return self.is_valid
    
    def __str__(self) -> str:
        parts = []
        if self.errors:
            parts.append(f"Errors: {', '.join(self.errors)}")
        if self.warnings:
            parts.append(f"Warnings: {', '.join(self.warnings)}")
        return '; '.join(parts) if parts else "Valid"


def validate_serial_config(config: Dict[str, Any]) -> ValidationResult:
    """Validate serial port configuration."""
    result = ValidationResult(True)
    
    # Required fields
    required_fields = ['port', 'baudrate', 'bytesize', 'parity', 'stopbits']
    for field in required_fields:
        if field not in config:
            result.add_error(f"Missing required field: {field}")
    
    if not result.is_valid:
        return result
    
    # Validate port
    port = config.get('port')
    if not isinstance(port, str) or not port.strip():
        result.add_error("Port must be a non-empty string")
    elif not _is_valid_serial_port(port):
        result.add_warning(f"Port '{port}' may not exist or be accessible")
    
    # Validate baudrate
    baudrate = config.get('baudrate')
    valid_baudrates = [110, 300, 600, 1200, 2400, 4800, 9600, 14400, 19200, 38400, 57600, 115200, 128000, 256000]
    if not isinstance(baudrate, int) or baudrate not in valid_baudrates:
        result.add_error(f"Invalid baudrate. Must be one of: {valid_baudrates}")
    
    # Validate bytesize
    bytesize = config.get('bytesize')
    if bytesize not in [5, 6, 7, 8]:
        result.add_error("Bytesize must be 5, 6, 7, or 8")
    
    # Validate parity
    parity = config.get('parity')
    valid_parities = ['N', 'E', 'O', 'M', 'S']  # None, Even, Odd, Mark, Space
    if parity not in valid_parities:
        result.add_error(f"Invalid parity. Must be one of: {valid_parities}")
    
    # Validate stopbits
    stopbits = config.get('stopbits')
    if stopbits not in [1, 1.5, 2]:
        result.add_error("Stopbits must be 1, 1.5, or 2")
    
    # Validate timeout (optional)
    timeout = config.get('timeout')
    if timeout is not None:
        if not isinstance(timeout, (int, float)) or timeout < 0:
            result.add_error("Timeout must be a non-negative number")
    
    # Validate write_timeout (optional)
    write_timeout = config.get('write_timeout')
    if write_timeout is not None:
        if not isinstance(write_timeout, (int, float)) or write_timeout < 0:
            result.add_error("Write timeout must be a non-negative number")
    
    # Validate inter_byte_timeout (optional)
    inter_byte_timeout = config.get('inter_byte_timeout')
    if inter_byte_timeout is not None:
        if not isinstance(inter_byte_timeout, (int, float)) or inter_byte_timeout < 0:
            result.add_error("Inter-byte timeout must be a non-negative number")
    
    return result


def validate_network_config(config: Dict[str, Any]) -> ValidationResult:
    """Validate network configuration."""
    result = ValidationResult(True)
    
    # Required fields
    required_fields = ['host', 'port']
    for field in required_fields:
        if field not in config:
            result.add_error(f"Missing required field: {field}")
    
    if not result.is_valid:
        return result
    
    # Validate host
    host = config.get('host')
    if not isinstance(host, str) or not host.strip():
        result.add_error("Host must be a non-empty string")
    elif not _is_valid_host(host):
        result.add_error(f"Invalid host format: {host}")
    
    # Validate port
    port = config.get('port')
    if not isinstance(port, int) or not (1 <= port <= 65535):
        result.add_error("Port must be an integer between 1 and 65535")
    elif port < 1024:
        result.add_warning(f"Port {port} is in the reserved range (< 1024)")
    
    # Validate timeout (optional)
    timeout = config.get('timeout')
    if timeout is not None:
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            result.add_error("Timeout must be a positive number")
    
    # Validate max_connections (optional, for server)
    max_connections = config.get('max_connections')
    if max_connections is not None:
        if not isinstance(max_connections, int) or max_connections <= 0:
            result.add_error("Max connections must be a positive integer")
    
    return result


def validate_websocket_config(config: Dict[str, Any]) -> ValidationResult:
    """Validate WebSocket configuration."""
    result = ValidationResult(True)
    
    # Required fields
    required_fields = ['url']
    for field in required_fields:
        if field not in config:
            result.add_error(f"Missing required field: {field}")
    
    if not result.is_valid:
        return result
    
    # Validate URL
    url = config.get('url')
    if not isinstance(url, str) or not url.strip():
        result.add_error("URL must be a non-empty string")
    elif not _is_valid_websocket_url(url):
        result.add_error(f"Invalid WebSocket URL format: {url}")
    
    # Validate reconnect_interval (optional)
    reconnect_interval = config.get('reconnect_interval')
    if reconnect_interval is not None:
        if not isinstance(reconnect_interval, (int, float)) or reconnect_interval <= 0:
            result.add_error("Reconnect interval must be a positive number")
    
    # Validate max_reconnect_attempts (optional)
    max_attempts = config.get('max_reconnect_attempts')
    if max_attempts is not None:
        if not isinstance(max_attempts, int) or max_attempts < 0:
            result.add_error("Max reconnect attempts must be a non-negative integer")
    
    # Validate heartbeat_interval (optional)
    heartbeat_interval = config.get('heartbeat_interval')
    if heartbeat_interval is not None:
        if not isinstance(heartbeat_interval, (int, float)) or heartbeat_interval <= 0:
            result.add_error("Heartbeat interval must be a positive number")
    
    return result


def validate_processing_config(config: Dict[str, Any]) -> ValidationResult:
    """Validate data processing configuration."""
    result = ValidationResult(True)
    
    # Validate buffer_size (optional)
    buffer_size = config.get('buffer_size')
    if buffer_size is not None:
        if not isinstance(buffer_size, int) or buffer_size <= 0:
            result.add_error("Buffer size must be a positive integer")
    
    # Validate max_packet_size (optional)
    max_packet_size = config.get('max_packet_size')
    if max_packet_size is not None:
        if not isinstance(max_packet_size, int) or max_packet_size <= 0:
            result.add_error("Max packet size must be a positive integer")
    
    # Validate encoding (optional)
    encoding = config.get('encoding')
    if encoding is not None:
        if not isinstance(encoding, str):
            result.add_error("Encoding must be a string")
        else:
            try:
                'test'.encode(encoding)
            except LookupError:
                result.add_error(f"Invalid encoding: {encoding}")
    
    # Validate filters (optional)
    filters = config.get('filters')
    if filters is not None:
        if not isinstance(filters, list):
            result.add_error("Filters must be a list")
        else:
            for i, filter_config in enumerate(filters):
                filter_result = validate_filter_config(filter_config)
                if not filter_result.is_valid:
                    result.add_error(f"Invalid filter at index {i}: {filter_result}")
    
    return result


def validate_filter_config(config: Dict[str, Any]) -> ValidationResult:
    """Validate filter configuration."""
    result = ValidationResult(True)
    
    # Required fields
    if 'type' not in config:
        result.add_error("Missing required field: type")
        return result
    
    filter_type = config.get('type')
    valid_types = ['regex', 'size', 'rate_limit']
    
    if filter_type not in valid_types:
        result.add_error(f"Invalid filter type. Must be one of: {valid_types}")
        return result
    
    # Validate based on filter type
    if filter_type == 'regex':
        pattern = config.get('pattern')
        if not isinstance(pattern, str):
            result.add_error("Regex filter requires 'pattern' field as string")
        else:
            try:
                re.compile(pattern)
            except re.error as e:
                result.add_error(f"Invalid regex pattern: {e}")
    
    elif filter_type == 'size':
        min_size = config.get('min_size')
        max_size = config.get('max_size')
        
        if min_size is not None and (not isinstance(min_size, int) or min_size < 0):
            result.add_error("min_size must be a non-negative integer")
        
        if max_size is not None and (not isinstance(max_size, int) or max_size < 0):
            result.add_error("max_size must be a non-negative integer")
        
        if min_size is not None and max_size is not None and min_size > max_size:
            result.add_error("min_size cannot be greater than max_size")
    
    elif filter_type == 'rate_limit':
        max_rate = config.get('max_rate')
        window_size = config.get('window_size')
        
        if not isinstance(max_rate, (int, float)) or max_rate <= 0:
            result.add_error("max_rate must be a positive number")
        
        if not isinstance(window_size, (int, float)) or window_size <= 0:
            result.add_error("window_size must be a positive number")
    
    return result


def validate_logging_config(config: Dict[str, Any]) -> ValidationResult:
    """Validate logging configuration."""
    result = ValidationResult(True)
    
    # Validate level (optional)
    level = config.get('level')
    if level is not None:
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if level not in valid_levels:
            result.add_error(f"Invalid log level. Must be one of: {valid_levels}")
    
    # Validate log_file (optional)
    log_file = config.get('log_file')
    if log_file is not None:
        if not isinstance(log_file, str):
            result.add_error("log_file must be a string")
        else:
            log_path = Path(log_file)
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                result.add_error(f"Cannot create log directory: {e}")
    
    # Validate max_file_size (optional)
    max_file_size = config.get('max_file_size')
    if max_file_size is not None:
        if not isinstance(max_file_size, int) or max_file_size <= 0:
            result.add_error("max_file_size must be a positive integer")
    
    # Validate backup_count (optional)
    backup_count = config.get('backup_count')
    if backup_count is not None:
        if not isinstance(backup_count, int) or backup_count < 0:
            result.add_error("backup_count must be a non-negative integer")
    
    return result


def validate_data_packet(data: bytes, expected_size: Optional[int] = None, 
                        max_size: Optional[int] = None) -> ValidationResult:
    """Validate data packet."""
    result = ValidationResult(True)
    
    if not isinstance(data, bytes):
        result.add_error("Data must be bytes")
        return result
    
    if len(data) == 0:
        result.add_error("Data cannot be empty")
    
    if expected_size is not None and len(data) != expected_size:
        result.add_error(f"Expected data size {expected_size}, got {len(data)}")
    
    if max_size is not None and len(data) > max_size:
        result.add_error(f"Data size {len(data)} exceeds maximum {max_size}")
    
    return result


def validate_json_data(data: str) -> ValidationResult:
    """Validate JSON data."""
    result = ValidationResult(True)
    
    if not isinstance(data, str):
        result.add_error("JSON data must be a string")
        return result
    
    try:
        json.loads(data)
    except json.JSONDecodeError as e:
        result.add_error(f"Invalid JSON: {e}")
    
    return result


def validate_file_path(path: str, must_exist: bool = False, 
                      must_be_writable: bool = False) -> ValidationResult:
    """Validate file path."""
    result = ValidationResult(True)
    
    if not isinstance(path, str) or not path.strip():
        result.add_error("Path must be a non-empty string")
        return result
    
    file_path = Path(path)
    
    if must_exist and not file_path.exists():
        result.add_error(f"Path does not exist: {path}")
    
    if must_be_writable:
        try:
            if file_path.exists():
                # Check if file is writable
                if not file_path.is_file():
                    result.add_error(f"Path is not a file: {path}")
                elif not os.access(file_path, os.W_OK):
                    result.add_error(f"File is not writable: {path}")
            else:
                # Check if parent directory is writable
                parent = file_path.parent
                if not parent.exists():
                    try:
                        parent.mkdir(parents=True, exist_ok=True)
                    except Exception as e:
                        result.add_error(f"Cannot create parent directory: {e}")
                elif not os.access(parent, os.W_OK):
                    result.add_error(f"Parent directory is not writable: {parent}")
        except Exception as e:
            result.add_error(f"Error checking file permissions: {e}")
    
    return result


def _is_valid_serial_port(port: str) -> bool:
    """Check if serial port is valid (basic check)."""
    try:
        # Try to list available ports
        available_ports = [p.device for p in serial.tools.list_ports.comports()]
        return port in available_ports
    except Exception:
        # If we can't list ports, assume it might be valid
        return True


def _is_valid_host(host: str) -> bool:
    """Check if host is a valid IP address or hostname."""
    try:
        # Try to parse as IP address
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # Try as hostname
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?))*$', host):
            return True
        # Special cases
        return host.lower() in ['localhost', '0.0.0.0']


def _is_valid_websocket_url(url: str) -> bool:
    """Check if URL is a valid WebSocket URL."""
    return url.startswith(('ws://', 'wss://')) and len(url) > 5


def validate_agent_config(config: Dict[str, Any]) -> ValidationResult:
    """Validate complete agent configuration."""
    result = ValidationResult(True)
    
    # Validate serial config
    if 'serial' in config:
        serial_result = validate_serial_config(config['serial'])
        if not serial_result.is_valid:
            result.add_error(f"Serial config: {serial_result}")
        result.merge(serial_result)
    
    # Validate network config
    if 'network' in config:
        network_result = validate_network_config(config['network'])
        if not network_result.is_valid:
            result.add_error(f"Network config: {network_result}")
        result.merge(network_result)
    
    # Validate websocket config
    if 'websocket' in config:
        websocket_result = validate_websocket_config(config['websocket'])
        if not websocket_result.is_valid:
            result.add_error(f"WebSocket config: {websocket_result}")
        result.merge(websocket_result)
    
    # Validate processing config
    if 'processing' in config:
        processing_result = validate_processing_config(config['processing'])
        if not processing_result.is_valid:
            result.add_error(f"Processing config: {processing_result}")
        result.merge(processing_result)
    
    # Validate logging config
    if 'logging' in config:
        logging_result = validate_logging_config(config['logging'])
        if not logging_result.is_valid:
            result.add_error(f"Logging config: {logging_result}")
        result.merge(logging_result)
    
    return result


def sanitize_string(value: str, max_length: Optional[int] = None, 
                   allowed_chars: Optional[str] = None) -> str:
    """Sanitize string input."""
    if not isinstance(value, str):
        value = str(value)
    
    # Remove control characters
    value = ''.join(char for char in value if ord(char) >= 32 or char in '\t\n\r')
    
    # Filter allowed characters
    if allowed_chars:
        value = ''.join(char for char in value if char in allowed_chars)
    
    # Truncate if necessary
    if max_length and len(value) > max_length:
        value = value[:max_length]
    
    return value


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to be safe for filesystem."""
    # Remove/replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    
    # Ensure it's not empty
    if not filename:
        filename = 'unnamed'
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename


def validate_and_sanitize_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], ValidationResult]:
    """Validate and sanitize configuration."""
    result = validate_agent_config(config)
    
    # Create sanitized copy
    sanitized_config = {}
    
    for key, value in config.items():
        if isinstance(value, dict):
            sanitized_config[key] = {}
            for sub_key, sub_value in value.items():
                if isinstance(sub_value, str):
                    sanitized_config[key][sub_key] = sanitize_string(sub_value, max_length=1000)
                else:
                    sanitized_config[key][sub_key] = sub_value
        elif isinstance(value, str):
            sanitized_config[key] = sanitize_string(value, max_length=1000)
        else:
            sanitized_config[key] = value
    
    return sanitized_config, result