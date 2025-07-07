# api/routes/__init__.py
from .firewall import firewall_bp
from .monitoring import monitoring_bp
from .admin import admin_bp
from .auth import auth_bp

def register_routes(app):
    """Register all API routes"""
    app.register_blueprint(firewall_bp, url_prefix='/api/firewall')
    app.register_blueprint(monitoring_bp, url_prefix='/api/monitoring')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(auth_bp, url_prefix='/api/auth')

# api/routes/auth.py
from flask import Blueprint, request, jsonify, session
from functools import wraps
import logging

from core.database import get_user_repository
from utils.security import hash_password, verify_password, SecurityManager
from config import get_config

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger('ccaf.auth')

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        user_repo = get_user_repository()
        with user_repo.db.get_session() as db_session:
            user = db_session.query(user_repo.db.User).get(session['user_id'])
            if not user or user.role != 'admin':
                return jsonify({'error': 'Admin privileges required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        # Check rate limiting
        config = get_config()
        security_manager = SecurityManager(config)
        client_ip = request.remote_addr
        
        if security_manager.is_ip_blocked(client_ip):
            return jsonify({'error': 'Too many failed attempts. Try again later.'}), 429
        
        # Get user
        user_repo = get_user_repository()
        user = user_repo.get_by_username(username)
        
        if not user or not verify_password(password, user.password_hash):
            security_manager.record_failed_attempt(client_ip)
            logger.warning(f"Failed login attempt for username '{username}' from {client_ip}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Account is disabled'}), 401
        
        # Check account lockout
        if user.locked_until and user.locked_until > datetime.utcnow():
            return jsonify({'error': 'Account is temporarily locked'}), 423
        
        # Success - create session
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        
        # Update last login
        user_repo.update_last_login(user.id)
        security_manager.clear_failed_attempts(client_ip)
        
        logger.info(f"User '{username}' logged in successfully from {client_ip}")
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'email': user.email
            }
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """User logout endpoint"""
    username = session.get('username')
    session.clear()
    logger.info(f"User '{username}' logged out")
    return jsonify({'success': True})

@auth_bp.route('/profile', methods=['GET'])
@login_required
def get_profile():
    """Get current user profile"""
    try:
        user_repo = get_user_repository()
        with user_repo.db.get_session() as db_session:
            user = db_session.query(user_repo.db.User).get(session['user_id'])
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            return jsonify({
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'last_login': user.last_login.isoformat() if user.last_login else None,
                    'created_at': user.created_at.isoformat()
                }
            })
    except Exception as e:
        logger.error(f"Profile fetch error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# api/routes/firewall.py
from flask import Blueprint, request, jsonify
from datetime import datetime
import logging

from core.firewall_manager import get_firewall_manager, FirewallRuleRequest, RuleType, Action, Direction
from core.database import get_firewall_rule_repository
from .auth import login_required, admin_required

firewall_bp = Blueprint('firewall', __name__)
logger = logging.getLogger('ccaf.firewall')

@firewall_bp.route('/rules', methods=['GET'])
@login_required
def get_rules():
    """Get all firewall rules"""
    try:
        rule_repo = get_firewall_rule_repository()
        rules = rule_repo.get_active_rules()
        
        rules_data = []
        for rule in rules:
            rules_data.append({
                'id': rule.id,
                'name': rule.name,
                'target': rule.target,
                'rule_type': rule.rule_type,
                'action': rule.action,
                'status': rule.status,
                'priority': rule.priority,
                'reason': rule.reason,
                'created_at': rule.created_at.isoformat(),
                'trigger_count': rule.trigger_count or 0,
                'last_triggered': rule.last_triggered.isoformat() if rule.last_triggered else None
            })
        
        return jsonify({'rules': rules_data})
        
    except Exception as e:
        logger.error(f"Failed to get rules: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@firewall_bp.route('/rules', methods=['POST'])
@admin_required
def create_rule():
    """Create a new firewall rule"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'target', 'rule_type']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Field {field} is required'}), 400
        
        # Create rule request
        rule_request = FirewallRuleRequest(
            name=data['name'],
            target=data['target'],
            rule_type=RuleType(data['rule_type']),
            action=Action(data.get('action', 'block')),
            direction=Direction(data.get('direction', 'both')),
            protocol=data.get('protocol'),
            port_range=data.get('port_range'),
            priority=data.get('priority', 100),
            reason=data.get('reason'),
            schedule_enabled=data.get('schedule_enabled', False),
            schedule_start=datetime.fromisoformat(data['schedule_start']) if data.get('schedule_start') else None,
            schedule_end=datetime.fromisoformat(data['schedule_end']) if data.get('schedule_end') else None
        )
        
        # Create rule
        fw_manager = get_firewall_manager()
        rule = fw_manager.create_rule(rule_request, session.get('user_id'))
        
        if rule:
            logger.info(f"Created firewall rule: {rule.name}")
            return jsonify({
                'success': True,
                'rule': {
                    'id': rule.id,
                    'name': rule.name,
                    'target': rule.target,
                    'rule_type': rule.rule_type,
                    'status': rule.status
                }
            })
        else:
            return jsonify({'error': 'Failed to create rule'}), 400
            
    except ValueError as e:
        return jsonify({'error': f'Invalid value: {e}'}), 400
    except Exception as e:
        logger.error(f"Failed to create rule: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@firewall_bp.route('/rules/<int:rule_id>', methods=['DELETE'])
@admin_required
def delete_rule(rule_id):
    """Delete a firewall rule"""
    try:
        fw_manager = get_firewall_manager()
        success = fw_manager.delete_rule(rule_id)
        
        if success:
            logger.info(f"Deleted firewall rule ID: {rule_id}")
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Failed to delete rule'}), 400
            
    except Exception as e:
        logger.error(f"Failed to delete rule {rule_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@firewall_bp.route('/rules/<int:rule_id>/toggle', methods=['POST'])
@admin_required
def toggle_rule(rule_id):
    """Toggle a firewall rule on/off"""
    try:
        data = request.get_json()
        active = data.get('active', True)
        
        fw_manager = get_firewall_manager()
        success = fw_manager.toggle_rule(rule_id, active)
        
        if success:
            action = "enabled" if active else "disabled"
            logger.info(f"Firewall rule {rule_id} {action}")
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Failed to toggle rule'}), 400
            
    except Exception as e:
        logger.error(f"Failed to toggle rule {rule_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@firewall_bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    """Get firewall statistics"""
    try:
        fw_manager = get_firewall_manager()
        stats = fw_manager.get_rule_statistics()
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Failed to get firewall stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# api/routes/monitoring.py
from flask import Blueprint, jsonify
import logging

from core.firewall_manager import get_firewall_manager
from core.database import get_db_manager, get_network_device_repository
from .auth import login_required

monitoring_bp = Blueprint('monitoring', __name__)
logger = logging.getLogger('ccaf.monitoring')

@monitoring_bp.route('/connections', methods=['GET'])
@login_required
def get_connections():
    """Get active network connections"""
    try:
        fw_manager = get_firewall_manager()
        connections = fw_manager.get_active_connections()
        return jsonify({'connections': connections})
        
    except Exception as e:
        logger.error(f"Failed to get connections: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@monitoring_bp.route('/devices', methods=['GET'])
@login_required
def get_devices():
    """Get discovered network devices"""
    try:
        device_repo = get_network_device_repository()
        devices = device_repo.get_online_devices()
        
        devices_data = []
        for device in devices:
            devices_data.append({
                'id': device.id,
                'mac_address': device.mac_address,
                'ip_address': device.ip_address,
                'hostname': device.hostname,
                'vendor': device.vendor,
                'device_type': device.device_type,
                'is_trusted': device.is_trusted,
                'first_seen': device.first_seen.isoformat(),
                'last_seen': device.last_seen.isoformat(),
                'is_online': device.is_online
            })
        
        return jsonify({'devices': devices_data})
        
    except Exception as e:
        logger.error(f"Failed to get devices: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@monitoring_bp.route('/stats', methods=['GET'])
@login_required
def get_system_stats():
    """Get system statistics"""
    try:
        db_manager = get_db_manager()
        stats = db_manager.get_stats()
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Failed to get system stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# api/routes/admin.py
from flask import Blueprint, request, jsonify
import logging

from core.database import get_user_repository, get_db_manager
from utils.security import hash_password
from .auth import admin_required

admin_bp = Blueprint('admin', __name__)
logger = logging.getLogger('ccaf.admin')

@admin_bp.route('/users', methods=['GET'])
@admin_required
def get_users():
    """Get all users"""
    try:
        user_repo = get_user_repository()
        with user_repo.db.get_session() as db_session:
            users = db_session.query(user_repo.db.User).all()
            
            users_data = []
            for user in users:
                users_data.append({
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'is_active': user.is_active,
                    'last_login': user.last_login.isoformat() if user.last_login else None,
                    'created_at': user.created_at.isoformat()
                })
        
        return jsonify({'users': users_data})
        
    except Exception as e:
        logger.error(f"Failed to get users: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@admin_bp.route('/users', methods=['POST'])
@admin_required
def create_user():
    """Create a new user"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Field {field} is required'}), 400
        
        # Check if user exists
        user_repo = get_user_repository()
        if user_repo.get_by_username(data['username']):
            return jsonify({'error': 'Username already exists'}), 400
        
        if user_repo.get_by_email(data['email']):
            return jsonify({'error': 'Email already exists'}), 400
        
        # Create user
        password_hash = hash_password(data['password'])
        user = user_repo.create_user(
            username=data['username'],
            email=data['email'],
            password_hash=password_hash,
            role=data.get('role', 'user')
        )
        
        logger.info(f"Created user: {user.username}")
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@admin_bp.route('/system/backup', methods=['POST'])
@admin_required
def backup_database():
    """Create database backup"""
    try:
        db_manager = get_db_manager()
        backup_path = db_manager.backup_database()
        
        logger.info(f"Database backup created: {backup_path}")
        return jsonify({
            'success': True,
            'backup_path': backup_path
        })
        
    except Exception as e:
        logger.error(f"Failed to backup database: {e}")
        return jsonify({'error': 'Internal server error'}), 500