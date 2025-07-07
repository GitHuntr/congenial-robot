# utils/security.py - Security Utilities (Fixed)
import bcrypt
import jwt
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_session_token() -> str:
    """Generate a secure session token"""
    return secrets.token_urlsafe(32)

def generate_secret_key() -> str:
    """Generate a secure secret key"""
    return secrets.token_hex(32)

class SecurityManager:
    """Manages authentication and security"""
    
    def __init__(self, config):
        self.config = config
        self.failed_attempts = {}  # IP -> (count, last_attempt)
        self.logger = logging.getLogger('ccaf.security')
    
    def create_jwt_token(self, user_id: int, username: str) -> str:
        """Create a JWT token for user authentication"""
        payload = {
            'user_id': user_id,
            'username': username,
            'exp': datetime.utcnow() + timedelta(seconds=self.config.security.jwt_expiration),
            'iat': datetime.utcnow()
        }
        
        return jwt.encode(payload, self.config.security.secret_key, algorithm='HS256')
    
    def verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode a JWT token"""
        try:
            payload = jwt.decode(token, self.config.security.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            self.logger.warning("JWT token expired")
            return None
        except jwt.InvalidTokenError:
            self.logger.warning("Invalid JWT token")
            return None
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if an IP address is temporarily blocked"""
        if ip_address in self.failed_attempts:
            count, last_attempt = self.failed_attempts[ip_address]
            
            # Check if lockout period has expired
            if datetime.utcnow() - last_attempt > timedelta(seconds=self.config.security.lockout_duration):
                del self.failed_attempts[ip_address]
                return False
            
            return count >= self.config.security.max_login_attempts
        
        return False
    
    def record_failed_attempt(self, ip_address: str):
        """Record a failed login attempt"""
        now = datetime.utcnow()
        
        if ip_address in self.failed_attempts:
            count, _ = self.failed_attempts[ip_address]
            self.failed_attempts[ip_address] = (count + 1, now)
        else:
            self.failed_attempts[ip_address] = (1, now)
        
        self.logger.warning(f"Failed login attempt from {ip_address}")
    
    def clear_failed_attempts(self, ip_address: str):
        """Clear failed attempts for an IP address"""
        if ip_address in self.failed_attempts:
            del self.failed_attempts[ip_address]
            self.logger.info(f"Cleared failed attempts for {ip_address}")
    
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

class SecurityLogger:
    """Specialized logger for security events"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('ccaf.security')
        
        # Create separate security log file
        import os
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