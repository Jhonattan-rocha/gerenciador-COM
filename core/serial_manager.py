import serial
import threading
import time
import logging
from typing import Optional, Dict, Any, Callable
from collections import deque
from dataclasses import dataclass
from enum import Enum


class SerialStatus(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"
    RECONNECTING = "reconnecting"


@dataclass
class SerialData:
    """Container for serial data with metadata."""
    data: bytes
    timestamp: float
    decoded_str: Optional[str] = None
    encoding: str = 'cp850'


class SerialManager:
    """Thread-safe serial port manager with automatic reconnection."""
    
    def __init__(self, port_name: str, config: Dict[str, Any], 
                 data_callback: Optional[Callable[[SerialData], None]] = None,
                 status_callback: Optional[Callable[[SerialStatus, str], None]] = None):
        self.port_name = port_name
        self.config = config
        self.data_callback = data_callback
        self.status_callback = status_callback
        
        # Serial connection
        self.serial_port: Optional[serial.Serial] = None
        self.status = SerialStatus.DISCONNECTED
        
        # Threading
        self._lock = threading.RLock()
        self._read_thread: Optional[threading.Thread] = None
        self._write_thread: Optional[threading.Thread] = None
        self._running = False
        
        # Data buffers (thread-safe)
        self._write_queue = deque(maxlen=1000)
        self._write_queue_lock = threading.Lock()
        self._read_buffer = deque(maxlen=100)
        self._read_buffer_lock = threading.Lock()
        
        # Reconnection
        self._reconnect_attempts = 0
        self._max_reconnect_attempts = 5
        self._reconnect_delay = 1.0  # seconds
        self._last_error: Optional[str] = None
        
        # Statistics
        self._bytes_sent = 0
        self._bytes_received = 0
        self._errors_count = 0
        
        self.logger = logging.getLogger(f"SerialManager.{port_name}")
    
    def start(self) -> bool:
        """Start the serial manager."""
        with self._lock:
            if self._running:
                return True
                
            self._running = True
            self._update_status(SerialStatus.CONNECTING, "Iniciando gerenciador serial")
            
            if self._connect():
                self._start_threads()
                return True
            else:
                self._running = False
                return False
    
    def stop(self):
        """Stop the serial manager gracefully."""
        with self._lock:
            if not self._running:
                return
                
            self._running = False
            self._update_status(SerialStatus.DISCONNECTED, "Parando gerenciador serial")
            
            # Stop threads
            if self._read_thread and self._read_thread.is_alive():
                self._read_thread.join(timeout=2.0)
            if self._write_thread and self._write_thread.is_alive():
                self._write_thread.join(timeout=2.0)
                
            # Close serial port
            self._disconnect()
    
    def write_data(self, data: bytes) -> bool:
        """Queue data for writing to serial port."""
        if not self._running or self.status != SerialStatus.CONNECTED:
            return False
            
        try:
            with self._write_queue_lock:
                self._write_queue.append(SerialData(
                    data=data,
                    timestamp=time.time()
                ))
            return True
        except Exception as e:
            self.logger.error(f"Error queuing data for write: {e}")
            return False
    
    def get_recent_data(self, max_items: int = 10) -> list[SerialData]:
        """Get recent received data."""
        with self._read_buffer_lock:
            return list(self._read_buffer)[-max_items:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get connection statistics."""
        return {
            'status': self.status.value,
            'port_name': self.port_name,
            'bytes_sent': self._bytes_sent,
            'bytes_received': self._bytes_received,
            'errors_count': self._errors_count,
            'reconnect_attempts': self._reconnect_attempts,
            'last_error': self._last_error,
            'write_queue_size': len(self._write_queue),
            'read_buffer_size': len(self._read_buffer)
        }
    
    def _connect(self) -> bool:
        """Connect to serial port."""
        try:
            self.serial_port = serial.Serial(
                port=self.port_name,
                baudrate=self.config.get('baudrate', 9600),
                bytesize=self.config.get('bytesize', serial.EIGHTBITS),
                parity=self.config.get('parity', serial.PARITY_NONE),
                stopbits=self.config.get('stopbits', serial.STOPBITS_ONE),
                timeout=self.config.get('timeout', 1.0),
                write_timeout=self.config.get('write_timeout', 1.0),
                xonxoff=self.config.get('xonxoff', False),
                rtscts=self.config.get('rtscts', False),
                dsrdtr=self.config.get('dsrdtr', False)
            )
            
            self._update_status(SerialStatus.CONNECTED, f"Conectado à porta {self.port_name}")
            self._reconnect_attempts = 0
            self._last_error = None
            self.logger.info(f"Connected to serial port {self.port_name}")
            return True
            
        except serial.SerialException as e:
            error_msg = f"Erro ao conectar à porta {self.port_name}: {e}"
            self._last_error = str(e)
            self._update_status(SerialStatus.ERROR, error_msg)
            self.logger.error(error_msg)
            return False
        except Exception as e:
            error_msg = f"Erro inesperado ao conectar: {e}"
            self._last_error = str(e)
            self._update_status(SerialStatus.ERROR, error_msg)
            self.logger.error(error_msg)
            return False
    
    def _disconnect(self):
        """Disconnect from serial port."""
        if self.serial_port and self.serial_port.is_open:
            try:
                self.serial_port.close()
                self.logger.info(f"Disconnected from serial port {self.port_name}")
            except Exception as e:
                self.logger.error(f"Error closing serial port: {e}")
        self.serial_port = None
    
    def _start_threads(self):
        """Start read and write threads."""
        self._read_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._write_thread = threading.Thread(target=self._write_loop, daemon=True)
        
        self._read_thread.start()
        self._write_thread.start()
    
    def _read_loop(self):
        """Main read loop running in separate thread."""
        self.logger.debug("Read thread started")
        
        while self._running:
            try:
                if not self.serial_port or not self.serial_port.is_open:
                    if not self._attempt_reconnect():
                        time.sleep(1.0)
                        continue
                
                if self.serial_port.in_waiting > 0:
                    data = self.serial_port.read(self.serial_port.in_waiting)
                    if data:
                        self._process_received_data(data)
                else:
                    time.sleep(0.01)  # Small delay to prevent busy waiting
                    
            except serial.SerialException as e:
                self.logger.error(f"Serial read error: {e}")
                self._errors_count += 1
                self._last_error = str(e)
                self._update_status(SerialStatus.ERROR, f"Erro de leitura: {e}")
                self._disconnect()
                time.sleep(1.0)
            except Exception as e:
                self.logger.error(f"Unexpected error in read loop: {e}")
                self._errors_count += 1
                time.sleep(1.0)
        
        self.logger.debug("Read thread stopped")
    
    def _write_loop(self):
        """Main write loop running in separate thread."""
        self.logger.debug("Write thread started")
        
        while self._running:
            try:
                if not self.serial_port or not self.serial_port.is_open:
                    time.sleep(0.1)
                    continue
                
                # Get data from queue
                serial_data = None
                with self._write_queue_lock:
                    if self._write_queue:
                        serial_data = self._write_queue.popleft()
                
                if serial_data:
                    bytes_written = self.serial_port.write(serial_data.data)
                    self.serial_port.flush()
                    self._bytes_sent += bytes_written
                    
                    self.logger.debug(f"Wrote {bytes_written} bytes to serial")
                else:
                    time.sleep(0.01)  # Small delay when no data to write
                    
            except serial.SerialTimeoutException:
                self.logger.warning("Serial write timeout")
            except serial.SerialException as e:
                self.logger.error(f"Serial write error: {e}")
                self._errors_count += 1
                self._last_error = str(e)
                self._disconnect()
                time.sleep(1.0)
            except Exception as e:
                self.logger.error(f"Unexpected error in write loop: {e}")
                self._errors_count += 1
                time.sleep(1.0)
        
        self.logger.debug("Write thread stopped")
    
    def _process_received_data(self, data: bytes):
        """Process received data and notify callback."""
        self._bytes_received += len(data)
        
        # Try to decode data
        decoded_str = None
        encoding = self.config.get('encoding', 'cp850')
        
        try:
            decoded_str = data.decode(encoding).strip()
        except UnicodeDecodeError:
            try:
                decoded_str = data.decode('ascii', errors='replace').strip()
                encoding = 'ascii'
            except Exception:
                self.logger.warning(f"Failed to decode received data: {data}")
        
        serial_data = SerialData(
            data=data,
            timestamp=time.time(),
            decoded_str=decoded_str,
            encoding=encoding
        )
        
        # Add to buffer
        with self._read_buffer_lock:
            self._read_buffer.append(serial_data)
        
        # Notify callback
        if self.data_callback:
            try:
                self.data_callback(serial_data)
            except Exception as e:
                self.logger.error(f"Error in data callback: {e}")
    
    def _attempt_reconnect(self) -> bool:
        """Attempt to reconnect to serial port."""
        if self._reconnect_attempts >= self._max_reconnect_attempts:
            return False
        
        self._reconnect_attempts += 1
        self._update_status(SerialStatus.RECONNECTING, 
                          f"Tentativa de reconexão {self._reconnect_attempts}/{self._max_reconnect_attempts}")
        
        time.sleep(self._reconnect_delay * self._reconnect_attempts)  # Exponential backoff
        
        return self._connect()
    
    def _update_status(self, status: SerialStatus, message: str):
        """Update status and notify callback."""
        self.status = status
        self.logger.info(f"Status: {status.value} - {message}")
        
        if self.status_callback:
            try:
                self.status_callback(status, message)
            except Exception as e:
                self.logger.error(f"Error in status callback: {e}")