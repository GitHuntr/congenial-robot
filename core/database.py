# core/database.py - Database models and management
import json
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.dialects.sqlite import JSON
from contextlib import contextmanager

from config import get_config

Base = declarative_base()

class User(Base):
    """User accounts for system access"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default='user')  # admin, user, viewer
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    rules = relationship("FirewallRule", back_populates="created_by_user")
    sessions = relationship("UserSession", back_populates="user")

class UserSession(Base):
    """User session tracking"""
    __tablename__ = 'user_sessions'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    session_token = Column(String(255), unique=True, nullable=False)
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(Text)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="sessions")

class NetworkDevice(Base):
    """Discovered network devices"""
    __tablename__ = 'network_devices'
    
    id = Column(Integer, primary_key=True)
    mac_address = Column(String(17), unique=True, nullable=False)
    ip_address = Column(String(45))
    hostname = Column(String(255))
    vendor = Column(String(100))
    device_type = Column(String(50))  # computer, smartphone, iot, etc.
    os_type = Column(String(50))
    is_trusted = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_online = Column(Boolean, default=True)
    
    # Relationships
    traffic_logs = relationship("TrafficLog", back_populates="device")
    bandwidth_rules = relationship("BandwidthRule", back_populates="device")

class FirewallRule(Base):
    """Firewall rules"""
    __tablename__ = 'firewall_rules'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    target = Column(String(255), nullable=False)
    rule_type = Column(String(20), nullable=False)  # domain, ip, application, port
    action = Column(String(20), default='block')  # block, allow, redirect
    protocol = Column(String(10))  # tcp, udp, icmp, all
    port_range = Column(String(20))  # e.g., "80", "8000-8080", "80,443"
    direction = Column(String(10), default='both')  # inbound, outbound, both
    priority = Column(Integer, default=100)
    status = Column(String(20), default='active')  # active, inactive, scheduled
    reason = Column(Text)
    
    # Scheduling
    schedule_enabled = Column(Boolean, default=False)
    schedule_start = Column(DateTime)
    schedule_end = Column(DateTime)
    schedule_days = Column(String(20))  # JSON: ["mon", "tue", ...]
    
    # User and group targeting
    applies_to_users = Column(Text)  # JSON list of user IDs
    applies_to_devices = Column(Text)  # JSON list of device IDs
    
    # Metadata
    created_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_triggered = Column(DateTime)
    trigger_count = Column(Integer, default=0)
    
    # Relationships
    created_by_user = relationship("User", back_populates="rules")
    logs = relationship("FirewallLog", back_populates="rule")

class FirewallLog(Base):
    """Firewall action logs"""
    __tablename__ = 'firewall_logs'
    
    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey('firewall_rules.id'))
    action = Column(String(20), nullable=False)  # blocked, allowed, redirected
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(10))
    packet_size = Column(Integer)
    target = Column(String(255))
    reason = Column(String(100))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    rule = relationship("FirewallRule", back_populates="logs")

class TrafficLog(Base):
    """Network traffic monitoring"""
    __tablename__ = 'traffic_logs'
    
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey('network_devices.id'))
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(10))
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)
    packets_sent = Column(Integer, default=0)
    packets_received = Column(Integer, default=0)
    connection_duration = Column(Float)  # seconds
    application = Column(String(100))
    category = Column(String(50))  # web, social, gaming, etc.
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    device = relationship("NetworkDevice", back_populates="traffic_logs")

class SecurityEvent(Base):
    """Security incidents and alerts"""
    __tablename__ = 'security_events'
    
    id = Column(Integer, primary_key=True)
    event_type = Column(String(50), nullable=False)  # port_scan, brute_force, malware, etc.
    severity = Column(String(20), default='medium')  # low, medium, high, critical
    source_ip = Column(String(45))
    target_ip = Column(String(45))
    description = Column(Text)
    details = Column(Text)  # JSON with additional details
    is_resolved = Column(Boolean, default=False)
    auto_blocked = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_at = Column(DateTime)
    resolved_by = Column(Integer, ForeignKey('users.id'))

class BandwidthRule(Base):
    """Bandwidth management rules"""
    __tablename__ = 'bandwidth_rules'
    
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey('network_devices.id'))
    name = Column(String(100), nullable=False)
    upload_limit = Column(Integer)  # Kbps
    download_limit = Column(Integer)  # Kbps
    priority = Column(Integer, default=5)  # 1-10 scale
    is_active = Column(Boolean, default=True)
    quota_daily = Column(Integer)  # MB per day
    quota_monthly = Column(Integer)  # MB per month
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    device = relationship("NetworkDevice", back_populates="bandwidth_rules")

class SystemConfiguration(Base):
    """System configuration storage"""
    __tablename__ = 'system_configurations'
    
    id = Column(Integer, primary_key=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(Text)
    description = Column(Text)
    is_encrypted = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(Integer, ForeignKey('users.id'))

class DatabaseManager:
    """Database connection and session management"""
    
    def __init__(self):
        self.config = get_config()
        self.engine = None
        self.SessionLocal = None
        self._initialize_database()
        
    def _initialize_database(self):
        """Initialize database connection and create tables"""
        try:
            self.engine = create_engine(
                self.config.get_database_url(),
                pool_pre_ping=True,
                pool_recycle=3600,
                echo=self.config.logging.level == "DEBUG"
            )
            
            # Create all tables
            Base.metadata.create_all(bind=self.engine)
            
            # Create session factory
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )
            
            logging.info("Database initialized successfully")
            
        except Exception as e:
            logging.error(f"Database initialization failed: {e}")
            raise
            
    @contextmanager
    def get_session(self) -> Session:
        """Get database session with automatic cleanup"""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logging.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
            
    def create_admin_user(self, username: str, email: str, password_hash: str):
        """Create initial admin user"""
        with self.get_session() as session:
            # Check if admin already exists
            existing_admin = session.query(User).filter_by(role='admin').first()
            if existing_admin:
                logging.info("Admin user already exists")
                return existing_admin
                
            # Create new admin user
            admin_user = User(
                username=username,
                email=email,
                password_hash=password_hash,
                role='admin',
                is_active=True
            )
            
            session.add(admin_user)
            session.commit()
            logging.info(f"Admin user '{username}' created successfully")
            return admin_user
            
    def backup_database(self, backup_path: str = None):
        """Create database backup"""
        if not backup_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"data/backups/ccaf_backup_{timestamp}.db"
            
        try:
            import shutil
            import os
            
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            shutil.copy2(self.config.database.path, backup_path)
            logging.info(f"Database backed up to {backup_path}")
            return backup_path
            
        except Exception as e:
            logging.error(f"Database backup failed: {e}")
            raise
            
    def cleanup_old_logs(self, days_to_keep: int = 30):
        """Clean up old log entries"""
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        with self.get_session() as session:
            # Clean up old firewall logs
            deleted_firewall = session.query(FirewallLog).filter(
                FirewallLog.timestamp < cutoff_date
            ).delete()
            
            # Clean up old traffic logs
            deleted_traffic = session.query(TrafficLog).filter(
                TrafficLog.timestamp < cutoff_date
            ).delete()
            
            session.commit()
            logging.info(f"Cleaned up {deleted_firewall} firewall logs and {deleted_traffic} traffic logs")
            
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        with self.get_session() as session:
            stats = {
                'total_rules': session.query(FirewallRule).count(),
                'active_rules': session.query(FirewallRule).filter_by(status='active').count(),
                'total_devices': session.query(NetworkDevice).count(),
                'online_devices': session.query(NetworkDevice).filter_by(is_online=True).count(),
                'total_users': session.query(User).count(),
                'active_users': session.query(User).filter_by(is_active=True).count(),
                'firewall_logs_24h': session.query(FirewallLog).filter(
                    FirewallLog.timestamp > datetime.utcnow() - timedelta(hours=24)
                ).count(),
                'security_events_24h': session.query(SecurityEvent).filter(
                    SecurityEvent.timestamp > datetime.utcnow() - timedelta(hours=24)
                ).count(),
                'unresolved_security_events': session.query(SecurityEvent).filter_by(is_resolved=False).count()
            }
            
        return stats

# Repository classes for data access patterns
class UserRepository:
    """User data access layer"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        
    def get_by_username(self, username: str) -> Optional[User]:
        with self.db.get_session() as session:
            return session.query(User).filter_by(username=username).first()
            
    def get_by_email(self, email: str) -> Optional[User]:
        with self.db.get_session() as session:
            return session.query(User).filter_by(email=email).first()
            
    def create_user(self, username: str, email: str, password_hash: str, role: str = 'user') -> User:
        with self.db.get_session() as session:
            user = User(
                username=username,
                email=email,
                password_hash=password_hash,
                role=role
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            return user
            
    def update_last_login(self, user_id: int):
        with self.db.get_session() as session:
            user = session.query(User).get(user_id)
            if user:
                user.last_login = datetime.utcnow()
                user.failed_login_attempts = 0
                session.commit()
                
    def increment_failed_login(self, user_id: int):
        with self.db.get_session() as session:
            user = session.query(User).get(user_id)
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= self.db.config.security.max_login_attempts:
                    user.locked_until = datetime.utcnow() + timedelta(
                        seconds=self.db.config.security.lockout_duration
                    )
                session.commit()

class FirewallRuleRepository:
    """Firewall rule data access layer"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        
    def get_active_rules(self) -> List[FirewallRule]:
        with self.db.get_session() as session:
            return session.query(FirewallRule).filter_by(status='active').all()
            
    def get_scheduled_rules(self) -> List[FirewallRule]:
        now = datetime.utcnow()
        with self.db.get_session() as session:
            return session.query(FirewallRule).filter(
                FirewallRule.schedule_enabled == True,
                FirewallRule.schedule_start <= now,
                FirewallRule.schedule_end >= now
            ).all()
            
    def create_rule(self, **kwargs) -> FirewallRule:
        with self.db.get_session() as session:
            rule = FirewallRule(**kwargs)
            session.add(rule)
            session.commit()
            session.refresh(rule)
            return rule
            
    def update_rule_status(self, rule_id: int, status: str):
        with self.db.get_session() as session:
            rule = session.query(FirewallRule).get(rule_id)
            if rule:
                rule.status = status
                rule.updated_at = datetime.utcnow()
                session.commit()
                
    def log_rule_trigger(self, rule_id: int):
        with self.db.get_session() as session:
            rule = session.query(FirewallRule).get(rule_id)
            if rule:
                rule.last_triggered = datetime.utcnow()
                rule.trigger_count += 1
                session.commit()

class NetworkDeviceRepository:
    """Network device data access layer"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        
    def get_or_create_device(self, mac_address: str, **kwargs) -> NetworkDevice:
        with self.db.get_session() as session:
            device = session.query(NetworkDevice).filter_by(mac_address=mac_address).first()
            
            if not device:
                device = NetworkDevice(mac_address=mac_address, **kwargs)
                session.add(device)
            else:
                # Update existing device
                for key, value in kwargs.items():
                    if hasattr(device, key):
                        setattr(device, key, value)
                device.last_seen = datetime.utcnow()
                
            session.commit()
            session.refresh(device)
            return device
            
    def get_online_devices(self) -> List[NetworkDevice]:
        with self.db.get_session() as session:
            return session.query(NetworkDevice).filter_by(is_online=True).all()
            
    def mark_device_offline(self, mac_address: str):
        with self.db.get_session() as session:
            device = session.query(NetworkDevice).filter_by(mac_address=mac_address).first()
            if device:
                device.is_online = False
                device.last_seen = datetime.utcnow()
                session.commit()

class SecurityEventRepository:
    """Security event data access layer"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        
    def create_event(self, **kwargs) -> SecurityEvent:
        with self.db.get_session() as session:
            event = SecurityEvent(**kwargs)
            session.add(event)
            session.commit()
            session.refresh(event)
            return event
            
    def get_unresolved_events(self) -> List[SecurityEvent]:
        with self.db.get_session() as session:
            return session.query(SecurityEvent).filter_by(is_resolved=False).all()
            
    def resolve_event(self, event_id: int, resolved_by_user_id: int):
        with self.db.get_session() as session:
            event = session.query(SecurityEvent).get(event_id)
            if event:
                event.is_resolved = True
                event.resolved_at = datetime.utcnow()
                event.resolved_by = resolved_by_user_id
                session.commit()

# Global database manager instance
db_manager = None

def init_database() -> DatabaseManager:
    """Initialize global database manager"""
    global db_manager
    db_manager = DatabaseManager()
    return db_manager

def get_db_manager() -> DatabaseManager:
    """Get global database manager instance"""
    global db_manager
    if db_manager is None:
        db_manager = init_database()
    return db_manager

# Repository factory functions
def get_user_repository() -> UserRepository:
    return UserRepository(get_db_manager())

def get_firewall_rule_repository() -> FirewallRuleRepository:
    return FirewallRuleRepository(get_db_manager())

def get_network_device_repository() -> NetworkDeviceRepository:
    return NetworkDeviceRepository(get_db_manager())

def get_security_event_repository() -> SecurityEventRepository:
    return SecurityEventRepository(get_db_manager())


# core/database.py - Database models and management
