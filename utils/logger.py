# utils/logger.py - Enhanced Logging Utility (Fixed)
import os
import logging
import logging.handlers
from datetime import datetime
from typing import Optional, Dict, Any

def setup_logging(config):
    """Setup enhanced logging with rotation and multiple handlers"""
    
    # Create logs directory
    log_dir = os.path.dirname(config.logging.file_path)
    os.makedirs(log_dir, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, config.logging.level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        config.logging.file_path,
        maxBytes=config.logging.max_file_size,
        backupCount=config.logging.backup_count
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(getattr(logging, config.logging.level.upper()))
    root_logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)  # Always show INFO+ on console
    root_logger.addHandler(console_handler)
    
    # Syslog handler (Unix systems only)
    if config.logging.enable_syslog and os.name == 'posix':
        try:
            syslog_handler = logging.handlers.SysLogHandler(
                address=config.logging.syslog_address
            )
            syslog_handler.setFormatter(formatter)
            syslog_handler.setLevel(logging.WARNING)  # Only warnings+ to syslog
            root_logger.addHandler(syslog_handler)
        except Exception as e:
            logging.warning(f"Failed to setup syslog handler: {e}")
    
    logging.info("Logging configured successfully")

class SecurityLogger:
    """Specialized logger for security events"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('ccaf.security')
        
        # Create separate security log file
        security_log_path = os.path.join(
            os.path.dirname(config.logging.file_path),
            'security.log'
        )
        
        # Only add handler if not already present
        if not any(isinstance(h, logging.handlers.RotatingFileHandler) 
                  for h in self.logger.handlers):
            security_handler = logging.handlers.RotatingFileHandler(
                security_log_path,
                maxBytes=config.logging.max_file_size,
                backupCount=config.logging.backup_count
            )
            
            security_formatter = logging.Formatter(
                '%(asctime)s - SECURITY - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            security_handler.setFormatter(security_formatter)
            self.logger.addHandler(security_handler)
            self.logger.setLevel(logging.INFO)
    
    def log_event(self, event_type: str, severity: str, message: str, details: Optional[Dict[str, Any]] = None):
        """Log a security event"""
        log_message = f"[{event_type.upper()}] {message}"
        if details:
            log_message += f" - Details: {details}"
        
        if severity.lower() == 'critical':
            self.logger.critical(log_message)
        elif severity.lower() == 'high':
            self.logger.error(log_message)
        elif severity.lower() == 'medium':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)

class CCCFLogger:
    """Main CCAF logger class"""
    
    def __init__(self, config):
        self.config = config
        self.security_logger = SecurityLogger(config)
        self.logger = logging.getLogger('ccaf.main')
    
    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message: str):
        """Log critical message"""
        self.logger.critical(message)
    
    def log_firewall_action(self, action: str, target: str, rule_type: str, success: bool):
        """Log firewall action"""
        status = "SUCCESS" if success else "FAILED"
        message = f"Firewall action {action} on {target} ({rule_type}) - {status}"
        
        if success:
            self.logger.info(message)
        else:
            self.logger.error(message)
    
    def log_security_event(self, event_type: str, severity: str, message: str, details: Optional[Dict[str, Any]] = None):
        """Log security event using SecurityLogger"""
        self.security_logger.log_event(event_type, severity, message, details)
    
    def log_user_action(self, username: str, action: str, ip_address: str = None):
        """Log user action"""
        log_message = f"User '{username}' performed action: {action}"
        if ip_address:
            log_message += f" from IP: {ip_address}"
        
        self.logger.info(log_message)
    
    def log_system_event(self, event: str, details: Optional[str] = None):
        """Log system event"""
        message = f"System event: {event}"
        if details:
            message += f" - {details}"
        
        self.logger.info(message)