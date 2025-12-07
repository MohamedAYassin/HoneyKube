"""
Shared utilities for HoneyKube services.
"""

import hashlib
import json
import logging
import os
import sys
from datetime import datetime
from typing import Any, Dict

# Structured JSON logging setup
class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add extra fields if present
        if hasattr(record, "extra"):
            log_entry["extra"] = record.extra
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry)


def setup_logging(name: str, level: str = None) -> logging.Logger:
    """Configure structured JSON logging."""
    level = level or os.getenv("LOG_LEVEL", "INFO")
    
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    logger.handlers = []
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)
    
    return logger


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of data."""
    return hashlib.sha256(data).hexdigest()


def sanitize_path(path: str) -> str:
    """Sanitize file path to prevent directory traversal."""
    # Remove null bytes and normalize
    path = path.replace("\x00", "")
    # Remove leading slashes and dots
    while path.startswith(("/", "\\", ".")):
        path = path[1:]
    # Replace path separators
    path = path.replace("\\", "/")
    # Remove any remaining traversal attempts
    parts = [p for p in path.split("/") if p and p != ".."]
    return "/".join(parts) if parts else "unnamed"





def truncate_string(s: str, max_length: int = 1000) -> str:
    """Truncate string to max length."""
    if len(s) > max_length:
        return s[:max_length] + "...[truncated]"
    return s


def get_timestamp() -> str:
    """Get current UTC timestamp in ISO format."""
    return datetime.utcnow().isoformat()






