import socket
import threading
import time
import json
import logging
from typing import Optional, Dict, Any, Callable, Union
from collections import deque
from dataclasses import dataclass
from enum import Enum
import struct


class ConnectionType(Enum):
    TCP_SERVER = "tcp_server"
    TCP_CLIENT = "tcp_client"
    WEBSOCKET = "websocket"


class ConnectionStatus(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    LISTENING = "listening"
    ERROR = "error"
    RECONNECTING = "reconnecting"


@dataclass
class NetworkMessage:
    """Container for network messages with metadata."""
    data: Union[bytes, str, dict]
    timestamp: float
    source: str
    message_type: str = "data"
    client_id: Optional[str] = None


class ConnectionManager:
    """Thread-safe connection manager for TCP and WebSocket connections."""
    
    def __init__(self, connection_type: ConnectionType, config: Dict[str, Any],
                 message_callback: Optional[Callable[[NetworkMessage], None]] = None,
                 status_callback: Optional[Callable[[ConnectionStatus, str], None]] = None):
        self.connection_type = connection_type
        self.config = config
        self.message_callback = message_callback
        self.status_callback = status_callback
        
        # Connection objects
        self.server_socket: Optional[socket.socket] = None
        self.client_socket: Optional[socket.socket] = None
        self.client_sockets: Dict[str, socket.socket] = {}  # For server mode
        self.status = ConnectionStatus.DISCONNECTED
        
        # Threading
        self._lock = threading.RLock()
        self._server_thread: Optional[threading.Thread] = None
        self._client_threads: Dict[str, threading.Thread] = {}
        self._running = False
        
        # Message queues (thread-safe)
        self._send_queue = deque(maxlen=1000)
        self._send_queue_lock = threading.Lock()
        self._received_messages = deque(maxlen=100)
        self._received_messages_lock = threading.Lock()
        
        # Reconnection (for client mode)
        self._reconnect_attempts = 0
        self._max_reconnect_attempts = 10
        self._reconnect_delay = 1.0  # seconds
        self._last_error: Optional[str] = None
        
        # Statistics
        self._bytes_sent = 0
        self._bytes_received = 0
        self._messages_sent = 0
        self._messages_received = 0
        self._errors_count = 0
        
        self.logger = logging.getLogger(f"ConnectionManager.{connection_type.value}")
    
    def start(self) -> bool:
        """Start the connection manager."""
        with self._lock:
            if self._running:
                return True
                
            self._running = True
            
            if self.connection_type == ConnectionType.TCP_SERVER:
                return self._start_server()
            elif self.connection_type == ConnectionType.TCP_CLIENT:
                return self._start_client()
            else:
                self.logger.error(f"Unsupported connection type: {self.connection_type}")
                return False
    
    def stop(self):
        """Stop the connection manager gracefully."""
        with self._lock:
            if not self._running:
                return
                
            self._running = False
            self._update_status(ConnectionStatus.DISCONNECTED, "Parando gerenciador de conexão")
            
            # Stop all threads
            if self._server_thread and self._server_thread.is_alive():
                self._server_thread.join(timeout=2.0)
                
            for thread in self._client_threads.values():
                if thread.is_alive():
                    thread.join(timeout=2.0)
            
            # Close all sockets
            self._close_all_connections()
    
    def send_message(self, message: Union[bytes, str, dict], client_id: Optional[str] = None) -> bool:
        """Queue message for sending."""
        if not self._running:
            return False
        
        try:
            network_message = NetworkMessage(
                data=message,
                timestamp=time.time(),
                source="local",
                client_id=client_id
            )
            
            with self._send_queue_lock:
                self._send_queue.append(network_message)
            return True
        except Exception as e:
            self.logger.error(f"Error queuing message: {e}")
            return False
    
    def get_recent_messages(self, max_items: int = 10) -> list[NetworkMessage]:
        """Get recent received messages."""
        with self._received_messages_lock:
            return list(self._received_messages)[-max_items:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get connection statistics."""
        return {
            'status': self.status.value,
            'connection_type': self.connection_type.value,
            'bytes_sent': self._bytes_sent,
            'bytes_received': self._bytes_received,
            'messages_sent': self._messages_sent,
            'messages_received': self._messages_received,
            'errors_count': self._errors_count,
            'reconnect_attempts': self._reconnect_attempts,
            'last_error': self._last_error,
            'send_queue_size': len(self._send_queue),
            'received_messages_size': len(self._received_messages),
            'connected_clients': len(self.client_sockets)
        }
    
    def _start_server(self) -> bool:
        """Start TCP server."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            host = self.config.get('host', 'localhost')
            port = self.config.get('port', 8080)
            
            self.server_socket.bind((host, port))
            self.server_socket.listen(self.config.get('max_connections', 5))
            
            self._update_status(ConnectionStatus.LISTENING, f"Servidor ouvindo em {host}:{port}")
            
            # Start server thread
            self._server_thread = threading.Thread(target=self._server_loop, daemon=True)
            self._server_thread.start()
            
            self.logger.info(f"TCP server started on {host}:{port}")
            return True
            
        except Exception as e:
            error_msg = f"Erro ao iniciar servidor: {e}"
            self._last_error = str(e)
            self._update_status(ConnectionStatus.ERROR, error_msg)
            self.logger.error(error_msg)
            return False
    
    def _start_client(self) -> bool:
        """Start TCP client."""
        self._update_status(ConnectionStatus.CONNECTING, "Conectando ao servidor")
        
        if self._connect_client():
            # Start client thread
            client_thread = threading.Thread(target=self._client_loop, daemon=True)
            client_thread.start()
            self._client_threads['main'] = client_thread
            return True
        else:
            return False
    
    def _connect_client(self) -> bool:
        """Connect to TCP server."""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(self.config.get('timeout', 10.0))
            
            host = self.config.get('host', 'localhost')
            port = self.config.get('port', 8080)
            
            self.client_socket.connect((host, port))
            
            self._update_status(ConnectionStatus.CONNECTED, f"Conectado ao servidor {host}:{port}")
            self._reconnect_attempts = 0
            self._last_error = None
            
            self.logger.info(f"Connected to server {host}:{port}")
            return True
            
        except Exception as e:
            error_msg = f"Erro ao conectar: {e}"
            self._last_error = str(e)
            self._update_status(ConnectionStatus.ERROR, error_msg)
            self.logger.error(error_msg)
            
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
            
            return False
    
    def _server_loop(self):
        """Main server loop for accepting connections."""
        self.logger.debug("Server thread started")
        
        while self._running and self.server_socket:
            try:
                client_socket, address = self.server_socket.accept()
                client_id = f"{address[0]}:{address[1]}"
                
                self.logger.info(f"New client connected: {client_id}")
                
                # Store client socket
                self.client_sockets[client_id] = client_socket
                
                # Start client handler thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_id),
                    daemon=True
                )
                client_thread.start()
                self._client_threads[client_id] = client_thread
                
            except socket.error as e:
                if self._running:
                    self.logger.error(f"Server socket error: {e}")
                    self._errors_count += 1
                break
            except Exception as e:
                self.logger.error(f"Unexpected error in server loop: {e}")
                self._errors_count += 1
                time.sleep(1.0)
        
        self.logger.debug("Server thread stopped")
    
    def _handle_client(self, client_socket: socket.socket, client_id: str):
        """Handle individual client connection."""
        self.logger.debug(f"Client handler started for {client_id}")
        
        try:
            while self._running:
                # Receive data
                try:
                    # First, receive the size of the message (4 bytes)
                    size_data = self._receive_exact(client_socket, 4)
                    if not size_data:
                        break
                    
                    message_size = struct.unpack('!I', size_data)[0]
                    
                    # Then receive the actual message
                    message_data = self._receive_exact(client_socket, message_size)
                    if not message_data:
                        break
                    
                    self._process_received_message(message_data, client_id)
                    
                except socket.timeout:
                    continue
                except socket.error as e:
                    self.logger.error(f"Socket error with client {client_id}: {e}")
                    break
                
                # Send queued messages to this client
                self._send_queued_messages(client_socket, client_id)
                
        except Exception as e:
            self.logger.error(f"Error handling client {client_id}: {e}")
        finally:
            # Clean up client
            self._cleanup_client(client_socket, client_id)
    
    def _client_loop(self):
        """Main client loop for communication."""
        self.logger.debug("Client thread started")
        
        while self._running:
            try:
                if not self.client_socket:
                    if not self._attempt_reconnect():
                        time.sleep(1.0)
                        continue
                
                # Receive data
                try:
                    # First, receive the size of the message (4 bytes)
                    size_data = self._receive_exact(self.client_socket, 4)
                    if not size_data:
                        self._disconnect_client()
                        continue
                    
                    message_size = struct.unpack('!I', size_data)[0]
                    
                    # Then receive the actual message
                    message_data = self._receive_exact(self.client_socket, message_size)
                    if not message_data:
                        self._disconnect_client()
                        continue
                    
                    self._process_received_message(message_data, "server")
                    
                except socket.timeout:
                    pass  # Continue to send queued messages
                except socket.error as e:
                    self.logger.error(f"Client socket error: {e}")
                    self._disconnect_client()
                    continue
                
                # Send queued messages
                self._send_queued_messages(self.client_socket, None)
                
            except Exception as e:
                self.logger.error(f"Unexpected error in client loop: {e}")
                self._errors_count += 1
                time.sleep(1.0)
        
        self.logger.debug("Client thread stopped")
    
    def _receive_exact(self, sock: socket.socket, size: int) -> Optional[bytes]:
        """Receive exactly 'size' bytes from socket."""
        data = b''
        while len(data) < size:
            try:
                chunk = sock.recv(size - len(data))
                if not chunk:
                    return None
                data += chunk
            except socket.timeout:
                if not self._running:
                    return None
                continue
        return data
    
    def _send_queued_messages(self, sock: socket.socket, client_id: Optional[str]):
        """Send queued messages through socket."""
        messages_to_send = []
        
        with self._send_queue_lock:
            # Get messages for this client (or all if client_id is None)
            while self._send_queue:
                message = self._send_queue[0]
                if client_id is None or message.client_id is None or message.client_id == client_id:
                    messages_to_send.append(self._send_queue.popleft())
                else:
                    break
        
        for message in messages_to_send:
            try:
                # Prepare data
                if isinstance(message.data, dict):
                    data = json.dumps(message.data).encode('utf-8')
                elif isinstance(message.data, str):
                    data = message.data.encode('utf-8')
                else:
                    data = message.data
                
                # Send size first, then data
                size_data = struct.pack('!I', len(data))
                sock.send(size_data + data)
                
                self._bytes_sent += len(data) + 4
                self._messages_sent += 1
                
                self.logger.debug(f"Sent {len(data)} bytes")
                
            except socket.error as e:
                self.logger.error(f"Error sending message: {e}")
                self._errors_count += 1
                # Put message back in queue
                with self._send_queue_lock:
                    self._send_queue.appendleft(message)
                break
    
    def _process_received_message(self, data: bytes, source: str):
        """Process received message and notify callback."""
        self._bytes_received += len(data)
        self._messages_received += 1
        
        # Try to decode as JSON first, then as string
        try:
            decoded_data = json.loads(data.decode('utf-8'))
            message_type = "json"
        except (json.JSONDecodeError, UnicodeDecodeError):
            try:
                decoded_data = data.decode('utf-8')
                message_type = "text"
            except UnicodeDecodeError:
                decoded_data = data
                message_type = "binary"
        
        network_message = NetworkMessage(
            data=decoded_data,
            timestamp=time.time(),
            source=source,
            message_type=message_type
        )
        
        # Add to received messages buffer
        with self._received_messages_lock:
            self._received_messages.append(network_message)
        
        # Notify callback
        if self.message_callback:
            try:
                self.message_callback(network_message)
            except Exception as e:
                self.logger.error(f"Error in message callback: {e}")
    
    def _attempt_reconnect(self) -> bool:
        """Attempt to reconnect (client mode only)."""
        if self.connection_type != ConnectionType.TCP_CLIENT:
            return False
            
        if self._reconnect_attempts >= self._max_reconnect_attempts:
            return False
        
        self._reconnect_attempts += 1
        self._update_status(ConnectionStatus.RECONNECTING, 
                          f"Tentativa de reconexão {self._reconnect_attempts}/{self._max_reconnect_attempts}")
        
        time.sleep(self._reconnect_delay * self._reconnect_attempts)  # Exponential backoff
        
        return self._connect_client()
    
    def _disconnect_client(self):
        """Disconnect client socket."""
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception as e:
                self.logger.error(f"Error closing client socket: {e}")
            self.client_socket = None
            self._update_status(ConnectionStatus.DISCONNECTED, "Desconectado do servidor")
    
    def _cleanup_client(self, client_socket: socket.socket, client_id: str):
        """Clean up client connection."""
        try:
            client_socket.close()
        except Exception as e:
            self.logger.error(f"Error closing client socket {client_id}: {e}")
        
        # Remove from tracking
        if client_id in self.client_sockets:
            del self.client_sockets[client_id]
        if client_id in self._client_threads:
            del self._client_threads[client_id]
        
        self.logger.info(f"Client {client_id} disconnected")
    
    def _close_all_connections(self):
        """Close all connections."""
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                self.logger.error(f"Error closing server socket: {e}")
            self.server_socket = None
        
        # Close client socket
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception as e:
                self.logger.error(f"Error closing client socket: {e}")
            self.client_socket = None
        
        # Close all client sockets
        for client_id, client_socket in self.client_sockets.items():
            try:
                client_socket.close()
            except Exception as e:
                self.logger.error(f"Error closing client socket {client_id}: {e}")
        
        self.client_sockets.clear()
    
    def _update_status(self, status: ConnectionStatus, message: str):
        """Update status and notify callback."""
        self.status = status
        self.logger.info(f"Status: {status.value} - {message}")
        
        if self.status_callback:
            try:
                self.status_callback(status, message)
            except Exception as e:
                self.logger.error(f"Error in status callback: {e}")