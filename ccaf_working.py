#!/usr/bin/env python3
"""
CCAF - Centralized Context-Aware Firewall
Working version with web interface
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
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for
from flask_cors import CORS

# Simple configuration for immediate use
class SimpleConfig:
    def __init__(self):
        self.SECRET_KEY = 'your-secret-key-change-this'
        self.DB_PATH = 'ccaf.db'
        self.LOG_FILE = 'ccaf.log'
        self.HOST = '127.0.0.1'
        self.PORT = 5000
        self.DEBUG = True

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
CORS(app)

# HTML Template for Web GUI (Enhanced)
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>CCAF - Centralized Firewall Control</title>
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
            border: 1px solid rgba(255,255,255,0.2);
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 48px rgba(0,0,0,0.15);
        }
        .control-panel {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        @media (max-width: 768px) {
            .control-panel { grid-template-columns: 1fr; }
        }
        input, select, button, textarea {
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
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
        button.danger:hover { 
            box-shadow: 0 8px 25px rgba(255, 107, 107, 0.3);
        }
        button.success { 
            background: linear-gradient(135deg, #51cf66 0%, #40c057 100%);
        }
        button.success:hover { 
            box-shadow: 0 8px 25px rgba(81, 207, 102, 0.3);
        }
        .rule-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            margin: 15px 0;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
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
            letter-spacing: 0.5px;
        }
        .status.active { 
            background: linear-gradient(135deg, #51cf66 0%, #40c057 100%);
            color: white;
        }
        .status.inactive { 
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
            color: white;
        }
        .log-entry {
            padding: 15px;
            margin: 10px 0;
            background: #f8f9fa;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            border-left: 4px solid #667eea;
        }
        .alert {
            padding: 15px;
            margin: 15px 0;
            border-radius: 8px;
            display: none;
            font-weight: 500;
        }
        .alert.success { 
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .alert.error { 
            background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
            color: #721c24;
            border: 1px solid #f5c6cb;
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
            background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
            border-radius: 12px;
            border: 2px solid rgba(102, 126, 234, 0.1);
            transition: all 0.3s ease;
        }
        .stat-box:hover {
            transform: translateY(-3px);
            border-color: rgba(102, 126, 234, 0.3);
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }
        .stat-number { 
            font-size: 36px; 
            font-weight: bold; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .stat-label { 
            color: #6c757d; 
            margin-top: 8px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .system-info {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 10px;
            padding: 15px;
            margin-top: 15px;
            border: 1px solid rgba(255,255,255,0.2);
        }
        .system-info h3 {
            color: white;
            margin-bottom: 10px;
        }
        .system-info p {
            color: rgba(255,255,255,0.9);
            margin: 5px 0;
        }
        .pulse {
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CCAF - Centralized Context-Aware Firewall</h1>
            <p>Real-time network control and monitoring • Version 2.0</p>
            <div class="system-info">
                <h3>📊 System Information</h3>
                <p>🖥️ Platform: {{ system_info.platform }}</p>
                <p>🌐 Server: {{ system_info.server }}</p>
                <p>📅 Started: {{ system_info.start_time }}</p>
                <p>⚡ Status: <span class="pulse">🟢 Active</span></p>
            </div>
        </div>

        <div class="alert" id="alert"></div>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-number" id="totalRules">{{ stats.total_rules }}</div>
                <div class="stat-label">Total Rules</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" id="activeBlocks">{{ stats.active_blocks }}</div>
                <div class="stat-label">Active Blocks</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" id="systemStatus">🟢</div>
                <div class="stat-label">System Status</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" id="logCount">{{ stats.log_count }}</div>
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
                <button onclick="clearLogs()" class="danger">🗑️ Clear Logs</button>
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
                        <button onclick="unblockTarget('{{ rule.target }}', '{{ rule.type }}')" class="danger" style="width: auto; margin-left: 10px;">Unblock</button>
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
                location.reload(); // Simple refresh for now
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

        // Auto-refresh every 30 seconds
        setInterval(() => {
            // Auto-refresh stats without full page reload
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    if (data.total_rules !== undefined) {
                        document.getElementById('totalRules').textContent = data.total_rules;
                        document.getElementById('activeBlocks').textContent = data.active_blocks;
                        document.getElementById('logCount').textContent = data.log_count;
                    }
                })
                .catch(error => console.log('Stats refresh failed:', error));
        }, 30000);

        // Show welcome message
        setTimeout(() => {
            showAlert('🎉 Welcome to CCAF! System is ready for use.', 'success');
        }, 1000);
    </script>
</body>
</html>
'''

# Simple database setup
def init_database():
    """Initialize SQLite database"""
    conn = sqlite3.connect(config.DB_PATH)
    c = conn.cursor()
    
    # Create rules table
    c.execute('''CREATE TABLE IF NOT EXISTS rules
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  target TEXT NOT NULL,
                  type TEXT NOT NULL,
                  status TEXT DEFAULT 'active',
                  reason TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create logs table
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  action TEXT NOT NULL,
                  target TEXT NOT NULL,
                  type TEXT NOT NULL,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    conn.commit()
    conn.close()

# Simple firewall manager
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
            # Add to hosts file
            try:
                with open(hosts_path, 'r') as f:
                    content = f.read()
                # Check for both domain and www.domain
                already_blocked = (f'127.0.0.1 {domain}' in content or
                                   f'127.0.0.1 www.{domain}' in content or
                                   f'0.0.0.0 {domain}' in content or
                                   f'0.0.0.0 www.{domain}' in content)
                if not already_blocked:
                    with open(hosts_path, 'a') as f:
                        f.write(f'\n# CCAF Block for {domain}\n')
                        f.write(f'127.0.0.1 {domain}\n')
                        f.write(f'127.0.0.1 www.{domain}\n')
                        if self.system == "Windows":
                            f.write(f'0.0.0.0 {domain}\n')
                            f.write(f'0.0.0.0 www.{domain}\n')
                if self.system == "Windows":
                    subprocess.run(['ipconfig', '/flushdns'], check=False)
                return True
            except PermissionError:
                logging.error(f"Permission denied to modify hosts file. Run as administrator/root.")
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
            new_lines = []
            skip_next = False
            for i, line in enumerate(lines):
                # Remove CCAF Block comment and all lines for this domain and www.domain
                if skip_next:
                    skip_next = False
                    continue
                if line.strip().startswith(f"# CCAF Block for {domain}"):
                    # Skip this comment and the next 2-4 lines if they match the block pattern
                    for j in range(1, 5):
                        if i + j < len(lines):
                            next_line = lines[i + j].strip()
                            if (next_line == f"127.0.0.1 {domain}" or
                                next_line == f"127.0.0.1 www.{domain}" or
                                next_line == f"0.0.0.0 {domain}" or
                                next_line == f"0.0.0.0 www.{domain}"):
                                skip_next = True
                            else:
                                break
                    continue
                if (f"127.0.0.1 {domain}" in line or
                    f"127.0.0.1 www.{domain}" in line or
                    f"0.0.0.0 {domain}" in line or
                    f"0.0.0.0 www.{domain}" in line):
                    continue
                new_lines.append(line)
            with open(hosts_path, 'w') as f:
                f.writelines(new_lines)
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
    c.execute("INSERT INTO rules (target, type, reason) VALUES (?, ?, ?)",
              (target, rule_type, reason))
    conn.commit()
    conn.close()

def log_action(action, target, rule_type):
    """Log firewall action"""
    conn = sqlite3.connect(config.DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO logs (action, target, type) VALUES (?, ?, ?)",
              (action, target, rule_type))
    conn.commit()
    conn.close()
    logging.info(f"{action}: {target} ({rule_type})")

def get_rules():
    """Get all rules from database"""
    conn = sqlite3.connect(config.DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM rules ORDER BY created_at DESC")
    rules = []
    for row in c.fetchall():
        rules.append({
            'id': row[0],
            'target': row[1],
            'type': row[2],
            'status': row[3],
            'reason': row[4],
            'created_at': row[5]
        })
    conn.close()
    return rules

def get_logs():
    """Get recent logs from database"""
    conn = sqlite3.connect(config.DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 20")
    logs = []
    for row in c.fetchall():
        logs.append({
            'id': row[0],
            'action': row[1],
            'target': row[2],
            'type': row[3],
            'timestamp': row[4]
        })
    conn.close()
    return logs

def get_stats():
    """Get system statistics"""
    conn = sqlite3.connect(config.DB_PATH)
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM rules")
    total_rules = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM rules WHERE status='active'")
    active_blocks = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM logs WHERE timestamp > datetime('now', '-24 hours')")
    log_count = c.fetchone()[0]
    
    conn.close()
    
    return {
        'total_rules': total_rules,
        'active_blocks': active_blocks,
        'log_count': log_count
    }

# Flask Routes
@app.route('/')
def index():
    """Main dashboard"""
    rules = get_rules()
    logs = get_logs()
    stats = get_stats()
    
    system_info = {
        'platform': f"{platform.system()} {platform.release()}",
        'server': f"{config.HOST}:{config.PORT}",
        'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    return render_template_string(HTML_TEMPLATE, 
                                rules=rules, 
                                logs=logs, 
                                stats=stats,
                                system_info=system_info)

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '2.0.0',
        'timestamp': datetime.now().isoformat(),
        'platform': platform.system()
    })

@app.route('/api/stats')
def api_stats():
    """Get statistics"""
    return jsonify(get_stats())

@app.route('/api/block', methods=['POST'])
def block():
    """Block a target"""
    data = request.json
    target = data.get('target', '').strip()
    rule_type = data.get('type', 'domain')
    reason = data.get('reason', '')
    
    if not target:
        return jsonify({'success': False, 'error': 'Target is required'})
    
    success = False
    if rule_type == 'domain':
        success = fw_manager.block_domain(target)
    elif rule_type == 'application':
        success = fw_manager.block_application(target)
    elif rule_type == 'ip':
        # For IP blocking, we can use the same domain blocking method
        success = fw_manager.block_domain(target)
    
    if success:
        save_rule(target, rule_type, reason)
        log_action('BLOCKED', target, rule_type)
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Failed to block target. Make sure you are running as administrator/root.'})

@app.route('/api/unblock', methods=['POST'])
def unblock():
    """Unblock a target"""
    data = request.json
    target = data.get('target', '').strip()
    rule_type = data.get('type', 'domain')
    
    if not target:
        return jsonify({'success': False, 'error': 'Target is required'})
    
    success = fw_manager.unblock_domain(target)
    
    if success:
        # Update rule status in database
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
def clear_logs():
    """Clear all logs"""
    try:
        conn = sqlite3.connect(config.DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM logs")
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def check_privileges():
    """Check if running with required privileges"""
    if os.name == 'posix' and os.geteuid() != 0:
        print("⚠️  WARNING: Some features require root privileges.")
        print("For full functionality, run with: sudo python3 app.py")
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
    print("🛡️  CCAF - Centralized Context-Aware Firewall")
    print("=" * 70)
    
    # Initialize database
    init_database()
    
    # Check privileges
    has_privileges = check_privileges()
    
    # Get network info
    lan_ip = get_lan_ip()
    
    print(f"🌐 Starting web server...")
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
    
    print("=" * 70)
    print("🚀 Server starting... Press Ctrl+C to stop")
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