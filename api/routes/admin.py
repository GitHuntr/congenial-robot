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