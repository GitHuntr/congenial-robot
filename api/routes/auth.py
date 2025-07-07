from flask import Blueprint, request, jsonify, session
from functools import wraps
import logging
from datetime import datetime

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
        from datetime import datetime
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
