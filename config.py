import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class EnvironmentType(Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    TESTING = "testing"

@dataclass
class DatabaseConfig:
    """Database configuration settings"""
    path: str = "data/database/ccaf.db"
    backup_interval: int = 3600  # seconds
    max_backups: int = 10
    enable_wal: bool = True
    
@dataclass
class SecurityConfig:
    """Security configuration settings"""
    secret_key: str = "CHANGE_THIS_SECRET_KEY"
    session_timeout: int = 3600  # seconds
    max_login_attempts: int = 5
    lockout_duration: int = 900  # seconds
    enable_2fa: bool = False
    jwt_expiration: int = 86400  # seconds
    
@dataclass
class NetworkConfig:
    """Network monitoring configuration"""
    scan_interval: int = 30  # seconds
    interface: Optional[str] = None
    enable_deep_inspection: bool = False
    max_connections_per_ip: int = 100
    enable_geolocation: bool = True
    
@dataclass
class FirewallConfig:
    """Firewall configuration"""
    enable_logging: bool = True
    log_blocked_attempts: bool = True
    auto_block_suspicious: bool = False
    max_rules: int = 1000
    rule_timeout: int = 0  # 0 = permanent
    backup_rules: bool = True
    
@dataclass
class WebConfig:
    """Web interface configuration"""
    host: str = "0.0.0.0"
    port: int = 5000
    debug: bool = False
    enable_ssl: bool = False
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    
@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    file_path: str = "data/logs/ccaf.log"
    max_file_size: int = 10485760  # 10MB
    backup_count: int = 5
    enable_syslog: bool = False
    syslog_address: str = "localhost"
    
@dataclass
class ModuleConfig:
    """Module enablement configuration"""
    intrusion_detection: bool = True
    bandwidth_control: bool = True
    content_filter: bool = True
    vpn_integration: bool = False
    threat_intelligence: bool = True
    
class CCCFConfig:
    """Main configuration class for CCAF system"""
    
    def __init__(self, config_file: Optional[str] = None, environment: str = "production"):
        self.environment = EnvironmentType(environment)
        self.config_file = config_file or self._get_default_config_path()
        
        # Initialize configuration objects
        self.database = DatabaseConfig()
        self.security = SecurityConfig()
        self.network = NetworkConfig()
        self.firewall = FirewallConfig()
        self.web = WebConfig()
        self.logging = LoggingConfig()
        self.modules = ModuleConfig()
        
        # Load configuration
        self._load_config()
        self._setup_environment()
        self._validate_config()
        
    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        return f"configs/{self.environment.value}.json"
        
    def _load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                    
                # Update configuration objects
                for section, values in config_data.items():
                    if hasattr(self, section):
                        config_obj = getattr(self, section)
                        for key, value in values.items():
                            if hasattr(config_obj, key):
                                setattr(config_obj, key, value)
                                
            except Exception as e:
                logging.warning(f"Failed to load config file {self.config_file}: {e}")
                
    def _setup_environment(self):
        """Setup environment-specific configurations"""
        if self.environment == EnvironmentType.DEVELOPMENT:
            self.web.debug = True
            self.web.host = "127.0.0.1"
            self.logging.level = "DEBUG"
            self.security.enable_2fa = False
            
        elif self.environment == EnvironmentType.TESTING:
            self.database.path = ":memory:"
            self.web.port = 5001
            self.logging.level = "ERROR"
            
        elif self.environment == EnvironmentType.PRODUCTION:
            self.web.debug = False
            self.security.enable_2fa = True
            self.firewall.auto_block_suspicious = True
            
    def _validate_config(self):
        """Validate configuration settings"""
        errors = []
        
        # Validate paths
        config_dir = Path(self.config_file).parent
        if not config_dir.exists():
            config_dir.mkdir(parents=True, exist_ok=True)
            
        # Validate database path
        db_dir = Path(self.database.path).parent
        if not db_dir.exists():
            db_dir.mkdir(parents=True, exist_ok=True)
            
        # Validate log path
        log_dir = Path(self.logging.file_path).parent
        if not log_dir.exists():
            log_dir.mkdir(parents=True, exist_ok=True)
            
        # Validate security settings
        if self.security.secret_key == "CHANGE_THIS_SECRET_KEY":
            errors.append("Security: Please change the default secret key")
            
        # Validate SSL settings
        if self.web.enable_ssl:
            if not self.web.ssl_cert_path or not os.path.exists(self.web.ssl_cert_path):
                errors.append("Web: SSL certificate file not found")
            if not self.web.ssl_key_path or not os.path.exists(self.web.ssl_key_path):
                errors.append("Web: SSL key file not found")
                
        if errors:
            for error in errors:
                logging.warning(f"Configuration validation error: {error}")
                
    def save_config(self):
        """Save current configuration to file"""
        config_data = {
            'database': asdict(self.database),
            'security': asdict(self.security),
            'network': asdict(self.network),
            'firewall': asdict(self.firewall),
            'web': asdict(self.web),
            'logging': asdict(self.logging),
            'modules': asdict(self.modules)
        }
        
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            logging.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logging.error(f"Failed to save configuration: {e}")
            
    def get_database_url(self) -> str:
        """Get database connection URL"""
        return f"sqlite:///{self.database.path}"
        
    def is_module_enabled(self, module_name: str) -> bool:
        """Check if a module is enabled"""
        return getattr(self.modules, module_name, False)
        
    def get_ssl_context(self):
        """Get SSL context for Flask"""
        if self.web.enable_ssl:
            return (self.web.ssl_cert_path, self.web.ssl_key_path)
        return None
        
    def update_config(self, section: str, key: str, value: Any):
        """Update a configuration value"""
        if hasattr(self, section):
            config_obj = getattr(self, section)
            if hasattr(config_obj, key):
                setattr(config_obj, key, value)
                self.save_config()
                return True
        return False
        
    def get_config_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary"""
        return {
            'database': asdict(self.database),
            'security': asdict(self.security),
            'network': asdict(self.network),
            'firewall': asdict(self.firewall),
            'web': asdict(self.web),
            'logging': asdict(self.logging),
            'modules': asdict(self.modules),
            'environment': self.environment.value
        }

# Global configuration instance
config = None

def init_config(config_file: Optional[str] = None, environment: str = None) -> CCCFConfig:
    """Initialize global configuration"""
    global config
    
    # Get environment from environment variable if not provided
    if environment is None:
        environment = os.getenv('CCAF_ENV', 'production')
        
    config = CCCFConfig(config_file, environment)
    return config

def get_config() -> CCCFConfig:
    """Get global configuration instance"""
    global config
    if config is None:
        config = init_config()
    return config

# Environment variable loader
def load_env_vars():
    """Load configuration from environment variables"""
    env_mapping = {
        'CCAF_SECRET_KEY': ('security', 'secret_key'),
        'CCAF_DB_PATH': ('database', 'path'),
        'CCAF_WEB_HOST': ('web', 'host'),
        'CCAF_WEB_PORT': ('web', 'port'),
        'CCAF_LOG_LEVEL': ('logging', 'level'),
        'CCAF_ENABLE_SSL': ('web', 'enable_ssl'),
        'CCAF_SSL_CERT': ('web', 'ssl_cert_path'),
        'CCAF_SSL_KEY': ('web', 'ssl_key_path'),
    }
    
    cfg = get_config()
    
    for env_var, (section, key) in env_mapping.items():
        value = os.getenv(env_var)
        if value is not None:
            # Type conversion
            if key in ['port', 'session_timeout', 'max_login_attempts']:
                value = int(value)
            elif key in ['enable_ssl', 'debug', 'enable_2fa']:
                value = value.lower() in ('true', '1', 'yes', 'on')
                
            cfg.update_config(section, key, value)

if __name__ == "__main__":
    # Example usage
    config = init_config(environment="development")
    print("Configuration loaded:")
    print(json.dumps(config.get_config_dict(), indent=2))

# config.py - Centralized Configuration Management
