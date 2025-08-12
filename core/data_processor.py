import threading
import time
import json
import hashlib
import logging
from typing import Optional, Dict, Any, Callable, List, Union
from collections import deque
from dataclasses import dataclass, asdict
from enum import Enum
import re


class DataType(Enum):
    RAW_BYTES = "raw_bytes"
    TEXT = "text"
    JSON = "json"
    COMMAND = "command"
    HEARTBEAT = "heartbeat"
    ERROR = "error"


class ProcessingStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    FILTERED = "filtered"


@dataclass
class DataPacket:
    """Container for processed data with metadata."""
    id: str
    data: Union[bytes, str, dict]
    data_type: DataType
    timestamp: float
    source: str
    destination: Optional[str] = None
    status: ProcessingStatus = ProcessingStatus.PENDING
    metadata: Dict[str, Any] = None
    checksum: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.checksum is None:
            self.checksum = self._calculate_checksum()
    
    def _calculate_checksum(self) -> str:
        """Calculate checksum for data integrity."""
        if isinstance(self.data, bytes):
            return hashlib.md5(self.data).hexdigest()
        elif isinstance(self.data, str):
            return hashlib.md5(self.data.encode('utf-8')).hexdigest()
        elif isinstance(self.data, dict):
            json_str = json.dumps(self.data, sort_keys=True)
            return hashlib.md5(json_str.encode('utf-8')).hexdigest()
        return ""
    
    def verify_integrity(self) -> bool:
        """Verify data integrity using checksum."""
        return self.checksum == self._calculate_checksum()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)


class DataFilter:
    """Base class for data filters."""
    
    def __init__(self, name: str):
        self.name = name
        self.enabled = True
    
    def should_process(self, packet: DataPacket) -> bool:
        """Return True if packet should be processed."""
        raise NotImplementedError
    
    def transform(self, packet: DataPacket) -> Optional[DataPacket]:
        """Transform packet data. Return None to filter out."""
        return packet


class RegexFilter(DataFilter):
    """Filter based on regex pattern."""
    
    def __init__(self, name: str, pattern: str, include: bool = True):
        super().__init__(name)
        self.pattern = re.compile(pattern)
        self.include = include  # True to include matches, False to exclude
    
    def should_process(self, packet: DataPacket) -> bool:
        if not self.enabled:
            return True
            
        if packet.data_type != DataType.TEXT:
            return True
        
        text_data = str(packet.data)
        matches = bool(self.pattern.search(text_data))
        
        return matches if self.include else not matches


class SizeFilter(DataFilter):
    """Filter based on data size."""
    
    def __init__(self, name: str, min_size: int = 0, max_size: int = float('inf')):
        super().__init__(name)
        self.min_size = min_size
        self.max_size = max_size
    
    def should_process(self, packet: DataPacket) -> bool:
        if not self.enabled:
            return True
        
        if isinstance(packet.data, bytes):
            size = len(packet.data)
        elif isinstance(packet.data, str):
            size = len(packet.data.encode('utf-8'))
        elif isinstance(packet.data, dict):
            size = len(json.dumps(packet.data).encode('utf-8'))
        else:
            return True
        
        return self.min_size <= size <= self.max_size


class RateLimitFilter(DataFilter):
    """Filter based on rate limiting."""
    
    def __init__(self, name: str, max_packets_per_second: float):
        super().__init__(name)
        self.max_packets_per_second = max_packets_per_second
        self.packet_times = deque(maxlen=1000)
        self._lock = threading.Lock()
    
    def should_process(self, packet: DataPacket) -> bool:
        if not self.enabled:
            return True
        
        current_time = time.time()
        
        with self._lock:
            # Remove old timestamps
            cutoff_time = current_time - 1.0  # 1 second window
            while self.packet_times and self.packet_times[0] < cutoff_time:
                self.packet_times.popleft()
            
            # Check rate limit
            if len(self.packet_times) >= self.max_packets_per_second:
                return False
            
            # Add current timestamp
            self.packet_times.append(current_time)
            return True


class DataProcessor:
    """Thread-safe data processor with filtering, validation, and transformation."""
    
    def __init__(self,
                 input_callback: Optional[Callable[[DataPacket], None]] = None,
                 output_callback: Optional[Callable[[DataPacket], None]] = None,
                 error_callback: Optional[Callable[[DataPacket, Exception], None]] = None):
        self.input_callback = input_callback
        self.output_callback = output_callback
        self.error_callback = error_callback
        
        # Processing queues
        self._input_queue = deque(maxlen=1000)
        self._output_queue = deque(maxlen=1000)
        self._error_queue = deque(maxlen=100)
        
        # Threading
        self._lock = threading.RLock()
        self._input_queue_lock = threading.Lock()
        self._output_queue_lock = threading.Lock()
        self._error_queue_lock = threading.Lock()
        
        self._processor_thread: Optional[threading.Thread] = None
        self._running = False
        
        # Filters and transformers
        self._filters: List[DataFilter] = []
        self._transformers: List[Callable[[DataPacket], DataPacket]] = []
        
        # Statistics
        self._packets_processed = 0
        self._packets_filtered = 0
        self._packets_failed = 0
        self._processing_times = deque(maxlen=1000)
        
        # Configuration
        self.config = {
            'max_packet_size': 1024 * 1024,  # 1MB
            'processing_timeout': 5.0,  # seconds
            'enable_integrity_check': True,
            'auto_retry_failed': True,
            'batch_processing': False,
            'batch_size': 10
        }
        
        self.logger = logging.getLogger("DataProcessor")
    
    def start(self) -> bool:
        """Start the data processor."""
        with self._lock:
            if self._running:
                return True
            
            self._running = True
            self._processor_thread = threading.Thread(target=self._processing_loop, daemon=True)
            self._processor_thread.start()
            
            self.logger.info("Data processor started")
            return True
    
    def stop(self):
        """Stop the data processor gracefully."""
        with self._lock:
            if not self._running:
                return
            
            self._running = False
            
            if self._processor_thread and self._processor_thread.is_alive():
                self._processor_thread.join(timeout=2.0)
            
            self.logger.info("Data processor stopped")
    
    def add_filter(self, filter_obj: DataFilter):
        """Add a data filter."""
        with self._lock:
            self._filters.append(filter_obj)
            self.logger.debug(f"Added filter: {filter_obj.name}")
    
    def remove_filter(self, filter_name: str) -> bool:
        """Remove a data filter by name."""
        with self._lock:
            for i, filter_obj in enumerate(self._filters):
                if filter_obj.name == filter_name:
                    del self._filters[i]
                    self.logger.debug(f"Removed filter: {filter_name}")
                    return True
            return False
    
    def add_transformer(self, transformer: Callable[[DataPacket], DataPacket]):
        """Add a data transformer function."""
        with self._lock:
            self._transformers.append(transformer)
            self.logger.debug("Added transformer")
    
    def process_data(self, data: Union[bytes, str, dict], source: str, 
                    destination: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Queue data for processing. Returns packet ID."""
        # Create data packet
        packet_id = self._generate_packet_id()
        data_type = self._detect_data_type(data)
        
        packet = DataPacket(
            id=packet_id,
            data=data,
            data_type=data_type,
            timestamp=time.time(),
            source=source,
            destination=destination,
            metadata=metadata or {}
        )
        
        # Add to input queue
        with self._input_queue_lock:
            self._input_queue.append(packet)
        
        self.logger.debug(f"Queued packet {packet_id} for processing")
        return packet_id
    
    def get_processed_data(self, max_items: int = 10) -> List[DataPacket]:
        """Get recently processed data."""
        with self._output_queue_lock:
            return list(self._output_queue)[-max_items:]
    
    def get_failed_data(self, max_items: int = 10) -> List[DataPacket]:
        """Get recently failed data."""
        with self._error_queue_lock:
            return list(self._error_queue)[-max_items:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics."""
        with self._lock:
            avg_processing_time = (
                sum(self._processing_times) / len(self._processing_times)
                if self._processing_times else 0
            )
            
            return {
                'packets_processed': self._packets_processed,
                'packets_filtered': self._packets_filtered,
                'packets_failed': self._packets_failed,
                'input_queue_size': len(self._input_queue),
                'output_queue_size': len(self._output_queue),
                'error_queue_size': len(self._error_queue),
                'average_processing_time': avg_processing_time,
                'active_filters': len([f for f in self._filters if f.enabled]),
                'total_filters': len(self._filters),
                'transformers_count': len(self._transformers)
            }
    
    def _processing_loop(self):
        """Main processing loop."""
        self.logger.debug("Processing loop started")
        
        while self._running:
            try:
                # Get packet from input queue
                packet = None
                with self._input_queue_lock:
                    if self._input_queue:
                        packet = self._input_queue.popleft()
                
                if packet:
                    self._process_packet(packet)
                else:
                    time.sleep(0.01)  # Small delay when no data
                    
            except Exception as e:
                self.logger.error(f"Error in processing loop: {e}")
                time.sleep(1.0)
        
        self.logger.debug("Processing loop stopped")
    
    def _process_packet(self, packet: DataPacket):
        """Process a single data packet."""
        start_time = time.time()
        
        try:
            packet.status = ProcessingStatus.PROCESSING
            
            # Validate packet
            if not self._validate_packet(packet):
                packet.status = ProcessingStatus.FAILED
                self._handle_failed_packet(packet, Exception("Packet validation failed"))
                return
            
            # Apply filters
            if not self._apply_filters(packet):
                packet.status = ProcessingStatus.FILTERED
                self._packets_filtered += 1
                self.logger.debug(f"Packet {packet.id} filtered out")
                return
            
            # Apply transformers
            transformed_packet = self._apply_transformers(packet)
            if not transformed_packet:
                packet.status = ProcessingStatus.FAILED
                self._handle_failed_packet(packet, Exception("Transformation failed"))
                return
            
            # Mark as completed
            transformed_packet.status = ProcessingStatus.COMPLETED
            self._packets_processed += 1
            
            # Record processing time
            processing_time = time.time() - start_time
            self._processing_times.append(processing_time)
            
            # Add to output queue
            with self._output_queue_lock:
                self._output_queue.append(transformed_packet)
            
            # Notify callback
            if self.output_callback:
                try:
                    self.output_callback(transformed_packet)
                except Exception as e:
                    self.logger.error(f"Error in output callback: {e}")
            
            self.logger.debug(f"Processed packet {packet.id} in {processing_time:.3f}s")
            
        except Exception as e:
            self.logger.error(f"Error processing packet {packet.id}: {e}")
            self._handle_failed_packet(packet, e)
    
    def _validate_packet(self, packet: DataPacket) -> bool:
        """Validate data packet."""
        # Check packet size
        if isinstance(packet.data, bytes):
            size = len(packet.data)
        elif isinstance(packet.data, str):
            size = len(packet.data.encode('utf-8'))
        elif isinstance(packet.data, dict):
            size = len(json.dumps(packet.data).encode('utf-8'))
        else:
            size = 0
        
        if size > self.config['max_packet_size']:
            self.logger.warning(f"Packet {packet.id} exceeds maximum size: {size} bytes")
            return False
        
        # Check data integrity
        if self.config['enable_integrity_check'] and not packet.verify_integrity():
            self.logger.warning(f"Packet {packet.id} failed integrity check")
            return False
        
        return True
    
    def _apply_filters(self, packet: DataPacket) -> bool:
        """Apply all filters to packet."""
        for filter_obj in self._filters:
            if not filter_obj.enabled:
                continue
            
            try:
                if not filter_obj.should_process(packet):
                    self.logger.debug(f"Packet {packet.id} filtered by {filter_obj.name}")
                    return False
                
                # Apply transformation if filter has one
                transformed = filter_obj.transform(packet)
                if transformed is None:
                    self.logger.debug(f"Packet {packet.id} filtered out by {filter_obj.name} transform")
                    return False
                
                packet = transformed
                
            except Exception as e:
                self.logger.error(f"Error in filter {filter_obj.name}: {e}")
                return False
        
        return True
    
    def _apply_transformers(self, packet: DataPacket) -> Optional[DataPacket]:
        """Apply all transformers to packet."""
        try:
            for transformer in self._transformers:
                packet = transformer(packet)
                if packet is None:
                    return None
            return packet
        except Exception as e:
            self.logger.error(f"Error in transformer: {e}")
            return None
    
    def _handle_failed_packet(self, packet: DataPacket, error: Exception):
        """Handle failed packet processing."""
        packet.status = ProcessingStatus.FAILED
        self._packets_failed += 1
        
        # Add to error queue
        with self._error_queue_lock:
            self._error_queue.append(packet)
        
        # Retry if configured
        if (self.config['auto_retry_failed'] and 
            packet.retry_count < packet.max_retries):
            packet.retry_count += 1
            packet.status = ProcessingStatus.PENDING
            
            # Add back to input queue
            with self._input_queue_lock:
                self._input_queue.append(packet)
            
            self.logger.debug(f"Retrying packet {packet.id} (attempt {packet.retry_count})")
        else:
            # Notify error callback
            if self.error_callback:
                try:
                    self.error_callback(packet, error)
                except Exception as e:
                    self.logger.error(f"Error in error callback: {e}")
    
    def _detect_data_type(self, data: Union[bytes, str, dict]) -> DataType:
        """Detect the type of data."""
        if isinstance(data, dict):
            # Check for specific command or heartbeat patterns
            if 'command' in data:
                return DataType.COMMAND
            elif 'heartbeat' in data or 'ping' in data:
                return DataType.HEARTBEAT
            else:
                return DataType.JSON
        elif isinstance(data, str):
            # Try to parse as JSON
            try:
                json.loads(data)
                return DataType.JSON
            except json.JSONDecodeError:
                return DataType.TEXT
        elif isinstance(data, bytes):
            # Try to decode as text
            try:
                data.decode('utf-8')
                return DataType.TEXT
            except UnicodeDecodeError:
                return DataType.RAW_BYTES
        else:
            return DataType.RAW_BYTES
    
    def _generate_packet_id(self) -> str:
        """Generate unique packet ID."""
        timestamp = str(time.time())
        return hashlib.md5(timestamp.encode()).hexdigest()[:8]