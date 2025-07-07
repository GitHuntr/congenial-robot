#!/usr/bin/env python3
"""
CCAF - Centralized Context-Aware Firewall
Clean version with authentication system
"""

import os
import sys
import json
import sqlite3
import subprocess
import platform
import threading
import time
import logging
import re
import socket
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for, flash
from flask_cors import CORS

# Configuration
class SimpleConfig:
    def __init__(self):
        self.SECRET_KEY = secrets.token_hex(32)
        self.DB_PATH = 'ccaf.db'
        self.LOG_FILE = 'ccaf.log'
        self.HOST = '127.0.0.1'
        self.PORT = 5000
        self.DEBUG = True
        self.SESSION_TIMEOUT = 3600

config = SimpleConfig()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler()
    ]
)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

CORS(
    app,
    supports_credentials=True,
    resources={
        r"/api/*": {
            "origins": ["http://localhost:3000", "http://127.0.0.1:5000"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True
        }
    }
)

# Authentication functions
def hash_password(password):
    """Hash password with salt"""
    salt = secrets.token_hex(32)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return salt + pwd_hash.hex()

def verify_password(password, hashed_password):
    """Verify password against hash"""
    if len(hashed_password) < 64:
        return False
    salt = hashed_password[:64]
    stored_hash = hashed_password[64:]
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return pwd_hash.hex() == stored_hash

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        is_api_request = request.path.startswith('/api/')
        
        # Check if user is logged in
        if 'user_id' not in session:
            if is_api_request:
                return jsonify({
                    'success': False,
                    'error': 'Authentication required',
                    'login_url': url_for('login', _external=True)
                }), 401
            return redirect(url_for('login'))
        
        # Check session timeout
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(seconds=config.SESSION_TIMEOUT):
                session.clear()
                if is_api_request:
                    return jsonify({
                        'success': False,
                        'error': 'Session expired',
                        'login_url': url_for('login', _external=True)
                    }), 401
                flash('Session expired. Please log in again.', 'warning')
                return redirect(url_for('login'))
        
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        if session.get('role') != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

# HTML Templates
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>CCAF - Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
        }
        .auth-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            width: 100%;
            max-width: 400px;
            margin: 20px;
        }
        .auth-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .auth-header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .auth-header p {
            color: #666;
            font-size: 1.1em;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
        }
        .form-group input {
            width: 100%;
            padding: 15px;
            border: 2px solid #e1e5e9;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s ease;
            background: rgba(255, 255, 255, 0.8);
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            background: rgba(255, 255, 255, 1);
        }
        .btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
        }
        .auth-links {
            text-align: center;
            margin-top: 20px;
        }
        .auth-links a {
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }
        .auth-links a:hover {
            color: #764ba2;
        }
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 10px;
            font-weight: 500;
        }
        .alert.success {
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
            color: #155724;
        }
        .alert.error {
            background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
            color: #721c24;
        }
        .alert.warning {
            background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
            color: #856404;
        }
        .checkbox-group {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }
        .checkbox-group input {
            width: auto;
            margin-right: 10px;
        }
        .system-info {
            text-align: center;
            margin-top: 30px;
            padding: 15px;
            background: rgba(102, 126, 234, 0.1);
            border-radius: 10px;
            font-size: 14px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="auth-header">
            <h1>🛡️ CCAF</h1>
            <p>Centralized Context-Aware Firewall</p>
        </div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required 
                       placeholder="Enter your username" value="{{ request.form.username or '' }}">
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required 
                       placeholder="Enter your password">
            </div>
            
            <div class="checkbox-group">
                <input type="checkbox" id="remember" name="remember">
                <label for="remember">Remember me for 30 days</label>
            </div>
            
            <button type="submit" class="btn">🔐 Sign In</button>
        </form>
        
        <div class="auth-links">
            <p>Don't have an account? <a href="{{ url_for('register') }}">Create one here</a></p>
        </div>
        
        <div class="system-info">
            <p>🖥️ {{ system_info.platform }} • 🌐 {{ system_info.server }}</p>
            <p>⚡ System Status: Active</p>
        </div>
    </div>
</body>
</html>
'''

REGISTER_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>CCAF - Register</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
            padding: 20px 0;
        }
        .auth-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            width: 100%;
            max-width: 450px;
            margin: 20px;
        }
        .auth-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .auth-header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
        }
        .form-group input, .form-group select {
            width: 100%;
            padding: 15px;
            border: 2px solid #e1e5e9;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s ease;
            background: rgba(255, 255, 255, 0.8);
        }
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            background: rgba(255, 255, 255, 1);
        }
        .btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
        }
        .auth-links {
            text-align: center;
            margin-top: 20px;
        }
        .auth-links a {
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 10px;
            font-weight: 500;
        }
        .alert.success {
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
            color: #155724;
        }
        .alert.error {
            background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
            color: #721c24;
        }
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }
        @media (max-width: 600px) {
            .form-row { grid-template-columns: 1fr; }
        }
        .password-strength {
            margin-top: 8px;
            font-size: 12px;
        }
        .strength-weak { color: #dc3545; }
        .strength-medium { color: #ffc107; }
        .strength-strong { color: #28a745; }
        .password-requirements {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
            line-height: 1.4;
        }
        .requirement {
            display: block;
            transition: color 0.3s ease;
        }
        .requirement.met {
            color: #28a745;
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="auth-header">
            <h1>🛡️ CCAF</h1>
            <p>Create Your Account</p>
        </div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST" onsubmit="return validateForm()">
            <div class="form-row">
                <div class="form-group">
                    <label for="first_name">First Name</label>
                    <input type="text" id="first_name" name="first_name" required 
                           placeholder="John" value="{{ request.form.first_name or '' }}">
                </div>
                
                <div class="form-group">
                    <label for="last_name">Last Name</label>
                    <input type="text" id="last_name" name="last_name" required 
                           placeholder="Doe" value="{{ request.form.last_name or '' }}">
                </div>
            </div>
            
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required 
                       placeholder="Choose a unique username" value="{{ request.form.username or '' }}"
                       minlength="3" maxlength="50">
            </div>
            
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" required 
                       placeholder="john.doe@example.com" value="{{ request.form.email or '' }}">
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required 
                       placeholder="Create a strong password" onkeyup="checkPasswordStrength()">
                <div id="password-strength" class="password-strength"></div>
                <div class="password-requirements">
                    <span class="requirement" id="length">• At least 8 characters</span>
                    <span class="requirement" id="uppercase">• One uppercase letter</span>
                    <span class="requirement" id="lowercase">• One lowercase letter</span>
                    <span class="requirement" id="number">• One number</span>
                    <span class="requirement" id="special">• One special character</span>
                </div>
            </div>
            
            <div class="form-group">
                <label for="confirm_password">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required 
                       placeholder="Confirm your password">
            </div>
            
            <div class="form-group">
                <label for="role">Account Type</label>
                <select id="role" name="role" required>
                    <option value="user" {{ 'selected' if request.form.role == 'user' else '' }}>User - Standard Access</option>
                    <option value="admin" {{ 'selected' if request.form.role == 'admin' else '' }}>Administrator - Full Access</option>
                </select>
            </div>
            
            <button type="submit" class="btn">🚀 Create Account</button>
        </form>
        
        <div class="auth-links">
            <p>Already have an account? <a href="{{ url_for('login') }}">Sign in here</a></p>
        </div>
    </div>
    
    <script>
        function checkPasswordStrength() {
            const password = document.getElementById('password').value;
            const strengthDiv = document.getElementById('password-strength');
            
            const requirements = {
                length: password.length >= 8,
                uppercase: /[A-Z]/.test(password),
                lowercase: /[a-z]/.test(password),
                number: /[0-9]/.test(password),
                special: /[^A-Za-z0-9]/.test(password)
            };
            
            // Update requirement indicators
            Object.keys(requirements).forEach(req => {
                const element = document.getElementById(req);
                if (requirements[req]) {
                    element.classList.add('met');
                } else {
                    element.classList.remove('met');
                }
            });
            
            // Calculate strength
            const metRequirements = Object.values(requirements).filter(Boolean).length;
            
            if (password.length === 0) {
                strengthDiv.textContent = '';
                strengthDiv.className = 'password-strength';
            } else if (metRequirements < 3) {
                strengthDiv.textContent = '⚠️ Weak password';
                strengthDiv.className = 'password-strength strength-weak';
            } else if (metRequirements < 5) {
                strengthDiv.textContent = '🔶 Medium strength';
                strengthDiv.className = 'password-strength strength-medium';
            } else {
                strengthDiv.textContent = '✅ Strong password';
                strengthDiv.className = 'password-strength strength-strong';
            }
        }
        
        function validateForm() {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            
            if (password !== confirmPassword) {
                alert('Passwords do not match!');
                return false;
            }
            
            if (password.length < 8) {
                alert('Password must be at least 8 characters long!');
                return false;
            }
            
            return true;
        }
    </script>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>CCAF - Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }
        .header-left h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .header-right {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        .user-info {
            text-align: right;
        }
        .logout-btn {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.3);
            padding: 10px 20px;
            border-radius: 25px;
            text-decoration: none;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        .logout-btn:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: translateY(-2px);
        }
        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        .card:hover {
            transform: translateY(-5px);
        }
        .control-panel {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        @media (max-width: 768px) {
            .control-panel { grid-template-columns: 1fr; }
            .header { flex-direction: column; text-align: center; }
        }
        input, select, button, textarea {
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s ease;
        }
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            cursor: pointer;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all 0.3s ease;
        }
        button:hover { 
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
        }
        button.danger { 
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
        }
        button.success { 
            background: linear-gradient(135deg, #51cf66 0%, #40c057 100%);
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-box {
            text-align: center;
            padding: 25px;
            background: rgba(255, 255, 255, 0.9);
            border-radius: 12px;
            transition: all 0.3s ease;
        }
        .stat-box:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }
        .stat-number { 
            font-size: 36px; 
            font-weight: bold; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .stat-label { 
            color: #6c757d; 
            margin-top: 8px;
            font-weight: 500;
            text-transform: uppercase;
        }
        .alert {
            padding: 15px;
            margin: 15px 0;
            border-radius: 8px;
            display: none;
            font-weight: 500;
        }
        .alert.success { 
            background: #d4edda;
            color: #155724;
        }
        .alert.error { 
            background: #f8d7da;
            color: #721c24;
        }
        .rule-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            margin: 15px 0;
            background: #f8f9fa;
            border-radius: 12px;
            border-left: 5px solid #667eea;
            transition: all 0.3s ease;
        }
        .rule-item:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .rule-item.blocked { border-left-color: #ff6b6b; }
        .status { 
            display: inline-block;
            padding: 6px 16px;
            border-radius: 25px;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .status.active { 
            background: #51cf66;
            color: white;
        }
        .status.inactive { 
            background: #ff6b6b;
            color: white;
        }
        .log-entry {
            padding: 15px;
            margin: 10px 0;
            background: #f8f9fa;
            border-radius: 8px;
            font-family: monospace;
            font-size: 14px;
            border-left: 4px solid #667eea;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-left">
                <h1>🛡️ CCAF Dashboard</h1>
                <p>Real-time network control and monitoring</p>
            </div>
            <div class="header-right">
                <div class="user-info">
                    <div>Welcome, {{ session.first_name or session.username }}!</div>
                    <div style="opacity: 0.8;">{{ session.role.title() }} Account</div>
                </div>
                <a href="{{ url_for('logout') }}" class="logout-btn">🚪 Logout</a>
            </div>
        </div>

        <div class="alert" id="alert"></div>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{{ stats.total_rules }}</div>
                <div class="stat-label">Total Rules</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{{ stats.active_blocks }}</div>
                <div class="stat-label">Active Blocks</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">🟢</div>
                <div class="stat-label">System Status</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{{ stats.log_count }}</div>
                <div class="stat-label">Recent Logs</div>
            </div>
        </div>

        <div class="control-panel">
            <div class="card">
                <h2>🚫 Block Website/Application</h2>
                <input type="text" id="blockTarget" placeholder="Enter domain (e.g., facebook.com) or app name">
                <select id="blockType">
                    <option value="domain">Website Domain</option>
                    <option value="application">Application</option>
                    <option value="ip">IP Address</option>
                </select>
                <textarea id="blockReason" placeholder="Reason for blocking (optional)" rows="3"></textarea>
                <button onclick="blockTarget()">🛡️ Block Now</button>
            </div>

            <div class="card">
                <h2>🔧 Quick Actions</h2>
                <button onclick="refreshRules()" class="success">🔄 Refresh Rules</button>
                <button onclick="exportRules()" class="success">📥 Export Rules</button>
                {% if session.role == 'admin' %}
                <button onclick="clearLogs()" class="danger">🗑️ Clear Logs</button>
                {% endif %}
                <button onclick="testConnection()">🌐 Test Connection</button>
            </div>
        </div>

        <div class="card">
            <h2>📋 Active Firewall Rules</h2>
            <div id="rulesList">
                {% for rule in rules %}
                <div class="rule-item {{ 'blocked' if rule.status == 'active' else '' }}">
                    <div>
                        <strong>{{ rule.target }}</strong> ({{ rule.type }})
                        <br><small>Added: {{ rule.created_at }}</small>
                        {% if rule.reason %}
                        <br><small>Reason: {{ rule.reason }}</small>
                        {% endif %}
                    </div>
                    <div>
                        <span class="status {{ rule.status }}">{{ rule.status.upper() }}</span>
                        {% if rule.status == 'active' %}
                        <button onclick="unblockTarget('{{ rule.target }}', '{{ rule.type }}')" 
                                class="danger" style="width: auto; margin-left: 10px;">Unblock</button>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>

        <div class="card">
            <h2>📊 Recent Activity Logs</h2>
            <div id="logsList">
                {% for log in logs %}
                <div class="log-entry">
                    [{{ log.timestamp }}] {{ log.action }} - {{ log.target }} ({{ log.type }})
                </div>
                {% endfor %}
            </div>
        </div>
    </div>

    <script>
        function showAlert(message, type) {
            const alert = document.getElementById('alert');
            alert.className = 'alert ' + type;
            alert.textContent = message;
            alert.style.display = 'block';
            setTimeout(() => alert.style.display = 'none', 5000);
        }

        async function blockTarget() {
            const target = document.getElementById('blockTarget').value;
            const type = document.getElementById('blockType').value;
            const reason = document.getElementById('blockReason').value;

            if (!target) {
                showAlert('Please enter a target to block', 'error');
                return;
            }

            try {
                const response = await fetch('/api/block', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target, type, reason})
                });
                const data = await response.json();
                
                if (data.success) {
                    showAlert(`Successfully blocked ${target}`, 'success');
                    document.getElementById('blockTarget').value = '';
                    document.getElementById('blockReason').value = '';
                    refreshRules();
                } else {
                    showAlert(data.error || 'Failed to block target', 'error');
                }
            } catch (error) {
                showAlert('Network error: ' + error.message, 'error');
            }
        }

        async function unblockTarget(target, type) {
            if (!confirm(`Are you sure you want to unblock ${target}?`)) return;

            try {
                const response = await fetch('/api/unblock', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target, type})
                });
                const data = await response.json();
                
                if (data.success) {
                    showAlert(`Successfully unblocked ${target}`, 'success');
                    refreshRules();
                } else {
                    showAlert(data.error || 'Failed to unblock target', 'error');
                }
            } catch (error) {
                showAlert('Network error: ' + error.message, 'error');
            }
        }

        async function refreshRules() {
            try {
                location.reload();
            } catch (error) {
                showAlert('Failed to refresh: ' + error.message, 'error');
            }
        }

        async function exportRules() {
            try {
                const response = await fetch('/api/export');
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `ccaf_rules_${new Date().toISOString().split('T')[0]}.json`;
                a.click();
                showAlert('Rules exported successfully', 'success');
            } catch (error) {
                showAlert('Failed to export rules: ' + error.message, 'error');
            }
        }

        async function clearLogs() {
            if (!confirm('Are you sure you want to clear all logs?')) return;
            
            try {
                const response = await fetch('/api/logs/clear', {method: 'POST'});
                const data = await response.json();
                
                if (data.success) {
                    showAlert('Logs cleared successfully', 'success');
                    location.reload();
                } else {
                    showAlert('Failed to clear logs', 'error');
                }
            } catch (error) {
                showAlert('Network error: ' + error.message, 'error');
            }
        }

        async function testConnection() {
            try {
                const response = await fetch('/api/health');
                const data = await response.json();
                if (data.status === 'healthy') {
                    showAlert('✅ Connection test successful!', 'success');
                } else {
                    showAlert('⚠️ Connection test failed', 'error');
                }
            } catch (error) {
                showAlert('❌ Connection test failed: ' + error.message, 'error');
            }
        }

        // Welcome message
        setTimeout(() => {
            showAlert('🎉 Welcome to CCAF Dashboard!', 'success');
        }, 1000);
    </script>
</body>
</html>
'''

# Database functions
def init_database():
    """Initialize SQLite database with user management"""
    conn = sqlite3.connect(config.DB_PATH)
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  first_name TEXT NOT NULL,
                  last_name TEXT NOT NULL,
                  password_hash TEXT NOT NULL,
                  role TEXT DEFAULT 'user',
                  is_active BOOLEAN DEFAULT 1,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  last_login TIMESTAMP,
                  login_attempts INTEGER DEFAULT 0,
                  locked_until TIMESTAMP)''')
    
    # Create rules table with proper schema
    c.execute('''CREATE TABLE IF NOT EXISTS rules
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  target TEXT NOT NULL,
                  type TEXT NOT NULL,
                  status TEXT DEFAULT 'active',
                  reason TEXT,
                  created_by INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL)''')
    
    # Create logs table with proper schema
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  action TEXT NOT NULL,
                  target TEXT NOT NULL,
                  type TEXT NOT NULL,
                  user_id INTEGER,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL)''')
    
    # Add created_by column to rules table if it doesn't exist
    c.execute('''PRAGMA table_info(rules)''')
    columns = [col[1] for col in c.fetchall()]
    if 'created_by' not in columns:
        c.execute('''ALTER TABLE rules ADD COLUMN created_by INTEGER REFERENCES users(id) ON DELETE SET NULL''')
    
    # Add user_id column to logs table if it doesn't exist
    c.execute('''PRAGMA table_info(logs)''')
    columns = [col[1] for col in c.fetchall()]
    if 'user_id' not in columns:
        c.execute('''ALTER TABLE logs ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL''')
    
    conn.commit()
    conn.close()

# User management functions
def create_user(username, email, first_name, last_name, password, role='user'):
    """Create a new user"""
    try:
        conn = sqlite3.connect(config.DB_PATH)
        c = conn.cursor()
        
        # Check if user already exists
        c.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if c.fetchone():
            return False, "Username or email already exists"
        
        password_hash = hash_password(password)
        
        c.execute("""INSERT INTO users (username, email, first_name, last_name, password_hash, role)
                     VALUES (?, ?, ?, ?, ?, ?)""",
                  (username, email, first_name, last_name, password_hash, role))
        
        conn.commit()
        user_id = c.lastrowid
        conn.close()
        
        logging.info(f"User created: {username} ({email}) with role {role}")
        return True, user_id
        
    except Exception as e:
        logging.error(f"Failed to create user: {e}")
        return False, str(e)

def authenticate_user(username, password):
    """Authenticate user login"""
    try:
        conn = sqlite3.connect(config.DB_PATH)
        c = conn.cursor()
        
        c.execute("""SELECT id, username, email, first_name, last_name, password_hash, role, is_active, 
                            login_attempts, locked_until FROM users WHERE username = ?""", (username,))
        user = c.fetchone()
        
        if not user or len(user) < 10:
            conn.close()
            return False, "Invalid username or password"
        
        user_id, username, email, first_name, last_name, password_hash, role, is_active, login_attempts, locked_until = user
        
        # Check if account is locked
        if locked_until:
            try:
                locked_until_dt = datetime.fromisoformat(locked_until)
                if datetime.now() < locked_until_dt:
                    conn.close()
                    return False, "Account is temporarily locked. Try again later."
            except ValueError:
                pass  # Invalid date format, continue
        
        # Check if account is active
        if not is_active:
            conn.close()
            return False, "Account is disabled"
        
        # Verify password
        if not verify_password(password, password_hash):
            # Increment failed attempts
            login_attempts = (login_attempts or 0) + 1
            locked_until = None
            
            if login_attempts >= 5:  # Lock after 5 failed attempts
                locked_until = (datetime.now() + timedelta(minutes=30)).isoformat()
            
            c.execute("UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?",
                      (login_attempts, locked_until, user_id))
            conn.commit()
            conn.close()
            
            return False, "Invalid username or password"
        
        # Successful login - reset failed attempts and update last login
        c.execute("""UPDATE users SET login_attempts = 0, locked_until = NULL, 
                     last_login = CURRENT_TIMESTAMP WHERE id = ?""", (user_id,))
        conn.commit()
        conn.close()
        
        user_data = {
            'id': user_id,
            'username': username or '',
            'email': email or '',
            'first_name': first_name or '',
            'last_name': last_name or '',
            'role': role or 'user'
        }
        
        logging.info(f"User authenticated: {username}")
        return True, user_data
        
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        return False, "Authentication error"

def create_default_admin():
    """Create default admin user if none exists"""
    try:
        conn = sqlite3.connect(config.DB_PATH)
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        result = c.fetchone()
        admin_count = result[0] if result else 0
        
        if admin_count == 0:
            success, result = create_user(
                username='admin',
                email='admin@ccaf.local',
                first_name='System',
                last_name='Administrator',
                password='admin123',
                role='admin'
            )
            
            if success:
                print("🔑 Default admin account created:")
                print("   Username: admin")
                print("   Password: admin123")
                print("   ⚠️  Please change this password after first login!")
                conn.close()
                return True
        
        conn.close()
        return False
        
    except Exception as e:
        logging.error(f"Failed to create default admin: {e}")
        return False
    
# Firewall manager
class SimpleFirewallManager:
    def __init__(self):
        self.system = platform.system()
        
    def block_domain(self, domain):
        """Block a domain"""
        try:
            domain = domain.strip().lower()
            domain = re.sub(r'^https?://', '', domain)
            domain = domain.split('/')[0]
            
            if self.system == "Windows":
                hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
            else:
                hosts_path = '/etc/hosts'
            
            try:
                with open(hosts_path, 'r') as f:
                    content = f.read()
                
                if domain not in content:
                    with open(hosts_path, 'a') as f:
                        f.write(f'\n# CCAF Block\n')
                        f.write(f'127.0.0.1 {domain}\n')
                        f.write(f'127.0.0.1 www.{domain}\n')
                        if self.system == "Windows":
                            f.write(f'0.0.0.0 {domain}\n')
                            f.write(f'0.0.0.0 www.{domain}\n')
                
                if self.system == "Windows":
                    subprocess.run(['ipconfig', '/flushdns'], check=False)
                    
                return True
            except PermissionError:
                logging.error("Permission denied to modify hosts file. Run as administrator/root.")
                return False
                
        except Exception as e:
            logging.error(f"Failed to block domain {domain}: {str(e)}")
            return False
    
    def unblock_domain(self, domain):
        """Unblock a domain"""
        try:
            domain = domain.strip().lower()
            
            if self.system == "Windows":
                hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
            else:
                hosts_path = '/etc/hosts'
            
            with open(hosts_path, 'r') as f:
                lines = f.readlines()
                
            with open(hosts_path, 'w') as f:
                for line in lines:
                    if domain not in line:
                        f.write(line)
                        
            if self.system == "Windows":
                subprocess.run(['ipconfig', '/flushdns'], check=False)
                
            return True
            
        except Exception as e:
            logging.error(f"Failed to unblock domain {domain}: {str(e)}")
            return False
    
    def block_application(self, app_name):
        """Block an application"""
        try:
            if self.system == "Windows":
                subprocess.run(['taskkill', '/F', '/IM', f'{app_name}.exe'], check=False)
            else:
                subprocess.run(['sudo', 'pkill', '-f', app_name], check=False)
            return True
        except Exception as e:
            logging.error(f"Failed to block application {app_name}: {str(e)}")
            return False

# Initialize firewall manager
fw_manager = SimpleFirewallManager()

# Database helper functions
def save_rule(target, rule_type, reason=""):
    """Save rule to database"""
    conn = sqlite3.connect(config.DB_PATH)
    c = conn.cursor()
    user_id = session.get('user_id')
    c.execute("INSERT INTO rules (target, type, reason, created_by) VALUES (?, ?, ?, ?)",
              (target, rule_type, reason, user_id))
    conn.commit()
    conn.close()

def log_action(action, target, rule_type):
    """Log firewall action"""
    conn = sqlite3.connect(config.DB_PATH)
    c = conn.cursor()
    user_id = session.get('user_id')
    c.execute("INSERT INTO logs (action, target, type, user_id) VALUES (?, ?, ?, ?)",
              (action, target, rule_type, user_id))
    conn.commit()
    conn.close()
    logging.info(f"{action}: {target} ({rule_type}) by user {user_id}")

def get_rules():
    """Get all rules from database"""
    try:
        conn = sqlite3.connect(config.DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, target, type, status, reason, created_by, created_at FROM rules ORDER BY created_at DESC")
        rules = []
        for row in c.fetchall():
            rules.append({
                'id': row[0] if len(row) > 0 else None,
                'target': row[1] if len(row) > 1 else '',
                'type': row[2] if len(row) > 2 else '',
                'status': row[3] if len(row) > 3 else 'inactive',
                'reason': row[4] if len(row) > 4 else '',
                'created_by': row[5] if len(row) > 5 else None,
                'created_at': row[6] if len(row) > 6 else ''
            })
        conn.close()
        return rules
    except Exception as e:
        logging.error(f"Error getting rules: {e}")
        return []
    
def get_logs():
    """Get recent logs from database"""
    try:
        conn = sqlite3.connect(config.DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, action, target, type, user_id, timestamp FROM logs ORDER BY timestamp DESC LIMIT 20")
        logs = []
        for row in c.fetchall():
            logs.append({
                'id': row[0] if len(row) > 0 else None,
                'action': row[1] if len(row) > 1 else '',
                'target': row[2] if len(row) > 2 else '',
                'type': row[3] if len(row) > 3 else '',
                'user_id': row[4] if len(row) > 4 else None,
                'timestamp': row[5] if len(row) > 5 else ''
            })
        conn.close()
        return logs
    except Exception as e:
        logging.error(f"Error getting logs: {e}")
        return []
    

def get_stats():
    """Get system statistics"""
    try:
        conn = sqlite3.connect(config.DB_PATH)
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM rules")
        total_result = c.fetchone()
        total_rules = total_result[0] if total_result else 0
        
        c.execute("SELECT COUNT(*) FROM rules WHERE status='active'")
        active_result = c.fetchone()
        active_blocks = active_result[0] if active_result else 0
        
        c.execute("SELECT COUNT(*) FROM logs WHERE timestamp > datetime('now', '-24 hours')")
        log_result = c.fetchone()
        log_count = log_result[0] if log_result else 0
        
        conn.close()
        
        return {
            'total_rules': total_rules,
            'active_blocks': active_blocks,
            'log_count': log_count
        }
    except Exception as e:
        logging.error(f"Error getting stats: {e}")
        return {
            'total_rules': 0,
            'active_blocks': 0,
            'log_count': 0
        }
        
def get_system_info():
    """Get system information for templates"""
    return {
        'platform': f"{platform.system()} {platform.release()}",
        'server': f"{config.HOST}:{config.PORT}"
    }

# Flask Routes
@app.route('/')
def index():
    """Redirect to dashboard if logged in, otherwise to login"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember')
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template_string(LOGIN_TEMPLATE, system_info=get_system_info())
        
        success, result = authenticate_user(username, password)
        
        if success:
            user_data = result
            session['user_id'] = user_data['id']
            session['username'] = user_data['username']
            session['email'] = user_data['email']
            session['first_name'] = user_data['first_name']
            session['last_name'] = user_data['last_name']
            session['role'] = user_data['role']
            session['last_activity'] = datetime.now().isoformat()
            
            if remember:
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=30)
            
            flash(f'Welcome back, {user_data["first_name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(result, 'error')
    
    return render_template_string(LOGIN_TEMPLATE, system_info=get_system_info())

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'user')
        
        # Validation
        errors = []
        
        if len(username) < 3:
            errors.append("Username must be at least 3 characters long.")
        
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        
        if password != confirm_password:
            errors.append("Passwords do not match.")
        
        if not all([username, email, first_name, last_name, password]):
            errors.append("All fields are required.")
        
        if '@' not in email:
            errors.append("Please enter a valid email address.")
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template_string(REGISTER_TEMPLATE)
        
        success, result = create_user(username, email, first_name, last_name, password, role)
        
        if success:
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash(result, 'error')
    
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    rules = get_rules()
    logs = get_logs()
    stats = get_stats()
    
    return render_template_string(DASHBOARD_TEMPLATE, 
                                rules=rules, 
                                logs=logs, 
                                stats=stats)

@app.route('/logout')
def logout():
    """Logout user"""
    username = session.get('username', 'Unknown')
    session.clear()
    flash(f'You have been logged out successfully. Goodbye, {username}!', 'success')
    return redirect(url_for('login'))

# API Routes
@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '2.0.0',
        'timestamp': datetime.now().isoformat(),
        'platform': platform.system(),
        'authenticated': 'user_id' in session
    })

@app.route('/api/stats')
@login_required
def api_stats():
    """Get statistics"""
    return jsonify(get_stats())

@app.route('/api/block', methods=['POST'])
@login_required
def block():
    """Block a target"""
    try:
        if not request.is_json:
            return jsonify({'success': False, 'error': 'Request must be JSON'}), 400
            
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        target = data.get('target', '').strip()
        rule_type = data.get('type', 'domain')
        reason = data.get('reason', '')
        
        if not target:
            return jsonify({'success': False, 'error': 'Target is required'}), 400
        
        success = False
        error_message = 'Unknown error occurred'
        
        try:
            if rule_type == 'domain':
                success = fw_manager.block_domain(target)
            elif rule_type == 'application':
                success = fw_manager.block_application(target)
            elif rule_type == 'ip':
                success = fw_manager.block_domain(target)
            else:
                return jsonify({
                    'success': False, 
                    'error': f'Invalid rule type: {rule_type}. Must be one of: domain, application, ip'
                }), 400
            
            if success:
                save_rule(target, rule_type, reason)
                log_action('BLOCKED', target, rule_type)
                return jsonify({
                    'success': True,
                    'message': f'Successfully blocked {target}'
                })
            else:
                error_message = 'Failed to block target. Make sure you are running as administrator/root.'
                logging.error(f'Block failed for {target} (type: {rule_type}): {error_message}')
                return jsonify({
                    'success': False, 
                    'error': error_message
                }), 500
                
        except Exception as e:
            error_message = f'Error processing block request: {str(e)}'
            logging.exception(f'Exception in block endpoint: {error_message}')
            return jsonify({
                'success': False,
                'error': error_message,
                'details': str(e)
            }), 500
            
    except Exception as e:
        # Catch any unexpected errors in the outer try block
        error_message = f'Unexpected error in block endpoint: {str(e)}'
        logging.exception(error_message)
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'details': str(e)
        }), 500

@app.route('/api/unblock', methods=['POST'])
@login_required
def unblock():
    """Unblock a target"""
    data = request.json
    target = data.get('target', '').strip()
    rule_type = data.get('type', 'domain')
    
    if not target:
        return jsonify({'success': False, 'error': 'Target is required'})
    
    success = fw_manager.unblock_domain(target)
    
    if success:
        conn = sqlite3.connect(config.DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE rules SET status='inactive' WHERE target=? AND type=?",
                  (target, rule_type))
        conn.commit()
        conn.close()
        
        log_action('UNBLOCKED', target, rule_type)
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Failed to unblock target'})

@app.route('/api/export')
@login_required
def export_rules():
    """Export rules as JSON"""
    rules = get_rules()
    response = app.response_class(
        response=json.dumps(rules, indent=2),
        mimetype='application/json'
    )
    response.headers['Content-Disposition'] = 'attachment; filename=ccaf_rules.json'
    return response

@app.route('/api/logs/clear', methods=['POST'])
@admin_required
def clear_logs():
    """Clear all logs (admin only)"""
    try:
        conn = sqlite3.connect(config.DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM logs")
        conn.commit()
        conn.close()
        log_action('CLEARED_LOGS', 'system', 'admin')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Utility functions
def check_privileges():
    """Check if running with required privileges"""
    if os.name == 'posix' and os.geteuid() != 0:
        print("⚠️  WARNING: Some features require root privileges.")
        print("For full functionality, run with: sudo python3 ccaf.py")
        return False
    elif os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠️  WARNING: Some features require administrator privileges.")
            print("For full functionality, run as administrator.")
            return False
    return True

def get_lan_ip():
    """Get the LAN IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

if __name__ == '__main__':
    print("=" * 70)
    print("🛡️  CCAF - Centralized Context-Aware Firewall v2.0")
    print("=" * 70)
    
    # Initialize database
    print("📊 Initializing database...")
    init_database()
    
    # Create default admin if needed
    print("👤 Checking for admin account...")
    create_default_admin()
    
    # Check privileges
    has_privileges = check_privileges()
    
    # Get network info
    lan_ip = get_lan_ip()
    
    print(f"🌐 Starting authentication-enabled web server...")
    print(f"📍 Local access: http://127.0.0.1:{config.PORT}")
    if lan_ip != "127.0.0.1":
        print(f"📍 Network access: http://{lan_ip}:{config.PORT}")
    print(f"🔧 Platform: {platform.system()} {platform.release()}")
    print(f"📁 Database: {config.DB_PATH}")
    print(f"📝 Logs: {config.LOG_FILE}")
    
    if has_privileges:
        print("✅ Running with required privileges")
    else:
        print("⚠️  Limited functionality due to insufficient privileges")
    
    print("\n🔐 Authentication Features:")
    print("   • User registration and login system")
    print("   • Role-based access control (Admin/User)")
    print("   • Session management with timeout")
    print("   • Password strength validation")
    print("   • Account lockout protection")
    
    print("=" * 70)
    print("🚀 Server starting... Access the login page in your browser")
    print("👤 Default admin: username='admin', password='admin123'")
    print("🔑 Create new accounts via the registration page")
    print("Press Ctrl+C to stop")
    print()
    
    try:
        # Run the Flask app
        app.run(
            host=config.HOST,
            port=config.PORT,
            debug=config.DEBUG,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n👋 CCAF server stopped. Goodbye!")
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)