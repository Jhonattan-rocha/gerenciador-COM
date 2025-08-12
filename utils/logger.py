import logging
import logging.handlers
import sys
import os
import json
import threading
import time
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum


class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class LogEntry:
    """Structured log entry."""
    timestamp: str
    level: str
    logger_name: str
    message: str
    module: Optional[str] = None
    function: Optional[str] = None
    line_number: Optional[int] = None
    thread_id: Optional[int] = None
    process_id: Optional[int] = None
    extra_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured logging."""
    
    def __init__(self, include_extra: bool = True):
        super().__init__()
        self.include_extra = include_extra
    
    def format(self, record: logging.LogRecord) -> str:
        # Create structured log entry
        log_entry = LogEntry(
            timestamp=datetime.fromtimestamp(record.created).isoformat(),
            level=record.levelname,
            logger_name=record.name,
            message=record.getMessage(),
            module=record.module,
            function=record.funcName,
            line_number=record.lineno,
            thread_id=record.thread,
            process_id=record.process
        )
        
        # Add extra data if present
        if self.include_extra and hasattr(record, 'extra_data'):
            log_entry.extra_data = record.extra_data
        
        return log_entry.to_json()


class ColoredConsoleFormatter(logging.Formatter):
    """Colored console formatter."""
    
    # Color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }
    
    def __init__(self, use_colors: bool = True):
        super().__init__()
        self.use_colors = use_colors and sys.stdout.isatty()
    
    def format(self, record: logging.LogRecord) -> str:
        if self.use_colors:
            color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
            reset = self.COLORS['RESET']
            
            # Format: [TIMESTAMP] LEVEL LOGGER_NAME - MESSAGE
            formatted = (
                f"[{datetime.fromtimestamp(record.created).strftime('%H:%M:%S')}] "
                f"{color}{record.levelname:<8}{reset} "
                f"{record.name:<20} - {record.getMessage()}"
            )
        else:
            formatted = (
                f"[{datetime.fromtimestamp(record.created).strftime('%H:%M:%S')}] "
                f"{record.levelname:<8} "
                f"{record.name:<20} - {record.getMessage()}"
            )
        
        # Add exception info if present
        if record.exc_info:
            formatted += "\n" + self.formatException(record.exc_info)
        
        return formatted


class LogBuffer:
    """Thread-safe log buffer for recent log entries."""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._buffer: List[LogEntry] = []
        self._lock = threading.Lock()
    
    def add(self, log_entry: LogEntry):
        """Add log entry to buffer."""
        with self._lock:
            self._buffer.append(log_entry)
            if len(self._buffer) > self.max_size:
                self._buffer.pop(0)
    
    def get_recent(self, count: int = 100, level: Optional[str] = None) -> List[LogEntry]:
        """Get recent log entries."""
        with self._lock:
            entries = self._buffer[-count:] if count > 0 else self._buffer[:]
            
            if level:
                entries = [entry for entry in entries if entry.level == level]
            
            return entries
    
    def clear(self):
        """Clear the buffer."""
        with self._lock:
            self._buffer.clear()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get buffer statistics."""
        with self._lock:
            level_counts = {}
            for entry in self._buffer:
                level_counts[entry.level] = level_counts.get(entry.level, 0) + 1
            
            return {
                'total_entries': len(self._buffer),
                'level_counts': level_counts,
                'buffer_size': self.max_size
            }


class BufferHandler(logging.Handler):
    """Custom handler that stores logs in buffer."""
    
    def __init__(self, log_buffer: LogBuffer):
        super().__init__()
        self.log_buffer = log_buffer
    
    def emit(self, record: logging.LogRecord):
        try:
            log_entry = LogEntry(
                timestamp=datetime.fromtimestamp(record.created).isoformat(),
                level=record.levelname,
                logger_name=record.name,
                message=record.getMessage(),
                module=record.module,
                function=record.funcName,
                line_number=record.lineno,
                thread_id=record.thread,
                process_id=record.process,
                extra_data=getattr(record, 'extra_data', None)
            )
            
            self.log_buffer.add(log_entry)
        except Exception:
            self.handleError(record)


class LoggerManager:
    """Centralized logger management."""
    
    def __init__(self):
        self._loggers: Dict[str, logging.Logger] = {}
        self._handlers: Dict[str, logging.Handler] = {}
        self._log_buffer = LogBuffer()
        self._configured = False
        self._lock = threading.Lock()
    
    def setup_logging(self, 
                     level: str = "INFO",
                     log_file: Optional[str] = None,
                     max_file_size: int = 10 * 1024 * 1024,  # 10MB
                     backup_count: int = 5,
                     console_output: bool = True,
                     structured_format: bool = False,
                     use_colors: bool = True) -> bool:
        """Setup logging configuration."""
        with self._lock:
            try:
                # Clear existing handlers
                self._clear_handlers()
                
                # Set root logger level
                root_logger = logging.getLogger()
                root_logger.setLevel(getattr(logging, level.upper()))
                
                # Console handler
                if console_output:
                    console_handler = logging.StreamHandler(sys.stdout)
                    
                    if structured_format:
                        console_formatter = StructuredFormatter()
                    else:
                        console_formatter = ColoredConsoleFormatter(use_colors)
                    
                    console_handler.setFormatter(console_formatter)
                    console_handler.setLevel(getattr(logging, level.upper()))
                    
                    root_logger.addHandler(console_handler)
                    self._handlers['console'] = console_handler
                
                # File handler
                if log_file:
                    log_path = Path(log_file)
                    log_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    file_handler = logging.handlers.RotatingFileHandler(
                        log_file,
                        maxBytes=max_file_size,
                        backupCount=backup_count,
                        encoding='utf-8'
                    )
                    
                    if structured_format:
                        file_formatter = StructuredFormatter()
                    else:
                        file_formatter = logging.Formatter(
                            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                        )
                    
                    file_handler.setFormatter(file_formatter)
                    file_handler.setLevel(getattr(logging, level.upper()))
                    
                    root_logger.addHandler(file_handler)
                    self._handlers['file'] = file_handler
                
                # Buffer handler
                buffer_handler = BufferHandler(self._log_buffer)
                buffer_handler.setLevel(logging.DEBUG)  # Capture all levels
                root_logger.addHandler(buffer_handler)
                self._handlers['buffer'] = buffer_handler
                
                self._configured = True
                logging.info("Logging system configured successfully")
                return True
                
            except Exception as e:
                print(f"Error setting up logging: {e}", file=sys.stderr)
                return False
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get or create a logger with the given name."""
        with self._lock:
            if name not in self._loggers:
                logger = logging.getLogger(name)
                self._loggers[name] = logger
            
            return self._loggers[name]
    
    def log_with_extra(self, logger_name: str, level: str, message: str, extra_data: Dict[str, Any]):
        """Log message with extra structured data."""
        logger = self.get_logger(logger_name)
        log_level = getattr(logging, level.upper())
        
        # Create log record with extra data
        record = logger.makeRecord(
            logger.name, log_level, "", 0, message, (), None
        )
        record.extra_data = extra_data
        
        logger.handle(record)
    
    def get_recent_logs(self, count: int = 100, level: Optional[str] = None) -> List[LogEntry]:
        """Get recent log entries from buffer."""
        return self._log_buffer.get_recent(count, level)
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get logging statistics."""
        return self._log_buffer.get_statistics()
    
    def clear_log_buffer(self):
        """Clear the log buffer."""
        self._log_buffer.clear()
    
    def set_logger_level(self, logger_name: str, level: str):
        """Set level for specific logger."""
        logger = self.get_logger(logger_name)
        logger.setLevel(getattr(logging, level.upper()))
    
    def add_file_handler(self, logger_name: str, file_path: str, 
                        level: str = "INFO", structured: bool = False) -> bool:
        """Add file handler to specific logger."""
        try:
            logger = self.get_logger(logger_name)
            
            # Create file handler
            handler = logging.FileHandler(file_path, encoding='utf-8')
            handler.setLevel(getattr(logging, level.upper()))
            
            # Set formatter
            if structured:
                formatter = StructuredFormatter()
            else:
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
            handler_key = f"{logger_name}_file"
            self._handlers[handler_key] = handler
            
            return True
        except Exception as e:
            logging.error(f"Error adding file handler: {e}")
            return False
    
    def remove_handler(self, logger_name: str, handler_type: str) -> bool:
        """Remove handler from logger."""
        try:
            logger = self.get_logger(logger_name)
            handler_key = f"{logger_name}_{handler_type}"
            
            if handler_key in self._handlers:
                handler = self._handlers[handler_key]
                logger.removeHandler(handler)
                handler.close()
                del self._handlers[handler_key]
                return True
            
            return False
        except Exception as e:
            logging.error(f"Error removing handler: {e}")
            return False
    
    def _clear_handlers(self):
        """Clear all existing handlers."""
        root_logger = logging.getLogger()
        
        # Remove all handlers from root logger
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
            handler.close()
        
        # Clear handler registry
        for handler in self._handlers.values():
            handler.close()
        
        self._handlers.clear()
    
    def shutdown(self):
        """Shutdown logging system."""
        with self._lock:
            self._clear_handlers()
            logging.shutdown()
            self._configured = False


# Global logger manager instance
_logger_manager = LoggerManager()


def setup_logger(level: str = "INFO",
                log_file: Optional[str] = None,
                max_file_size: int = 10 * 1024 * 1024,
                backup_count: int = 5,
                console_output: bool = True,
                structured_format: bool = False,
                use_colors: bool = True) -> bool:
    """Setup global logging configuration."""
    return _logger_manager.setup_logging(
        level=level,
        log_file=log_file,
        max_file_size=max_file_size,
        backup_count=backup_count,
        console_output=console_output,
        structured_format=structured_format,
        use_colors=use_colors
    )


def get_logger(name: str) -> logging.Logger:
    """Get logger instance."""
    return _logger_manager.get_logger(name)


def log_with_extra(logger_name: str, level: str, message: str, extra_data: Dict[str, Any]):
    """Log message with extra structured data."""
    _logger_manager.log_with_extra(logger_name, level, message, extra_data)


def get_recent_logs(count: int = 100, level: Optional[str] = None) -> List[LogEntry]:
    """Get recent log entries."""
    return _logger_manager.get_recent_logs(count, level)


def get_log_statistics() -> Dict[str, Any]:
    """Get logging statistics."""
    return _logger_manager.get_log_statistics()


def clear_log_buffer():
    """Clear log buffer."""
    _logger_manager.clear_log_buffer()


def shutdown_logging():
    """Shutdown logging system."""
    _logger_manager.shutdown()


# Context manager for temporary log level
class temporary_log_level:
    """Context manager for temporarily changing log level."""
    
    def __init__(self, logger_name: str, level: str):
        self.logger_name = logger_name
        self.new_level = level
        self.old_level = None
    
    def __enter__(self):
        logger = get_logger(self.logger_name)
        self.old_level = logger.level
        logger.setLevel(getattr(logging, self.new_level.upper()))
        return logger
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.old_level is not None:
            logger = get_logger(self.logger_name)
            logger.setLevel(self.old_level)


# Decorator for logging function calls
def log_function_call(logger_name: str, level: str = "DEBUG"):
    """Decorator to log function calls."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            logger = get_logger(logger_name)
            start_time = time.time()
            
            logger.log(
                getattr(logging, level.upper()),
                f"Calling {func.__name__} with args={args}, kwargs={kwargs}"
            )
            
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                
                logger.log(
                    getattr(logging, level.upper()),
                    f"Completed {func.__name__} in {execution_time:.3f}s"
                )
                
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                
                logger.error(
                    f"Error in {func.__name__} after {execution_time:.3f}s: {e}"
                )
                raise
        
        return wrapper
    return decorator