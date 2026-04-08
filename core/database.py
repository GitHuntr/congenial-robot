import sqlite3
import logging
from core.config import config
from werkzeug.security import generate_password_hash, check_password_hash

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
                  
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  fullname TEXT NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create default admin if not exists
    c.execute("SELECT id FROM users WHERE email='admin@ccaf.local'")
    if not c.fetchone():
        c.execute("INSERT INTO users (fullname, email, password_hash) VALUES (?, ?, ?)",
                  ('System Admin', 'admin@ccaf.local', generate_password_hash('admin123')))
    
    conn.commit()
    conn.close()

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

def create_user(fullname, email, password):
    """Create a new user"""
    conn = sqlite3.connect(config.DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (fullname, email, password_hash) VALUES (?, ?, ?)",
                  (fullname, email, generate_password_hash(password)))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False # Email already exists
    conn.close()
    return success

def verify_user(email, password):
    """Verify user credentials"""
    conn = sqlite3.connect(config.DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, fullname, password_hash FROM users WHERE email=?", (email,))
    user = c.fetchone()
    conn.close()
    
    if user and check_password_hash(user[2], password):
        return {'id': user[0], 'fullname': user[1], 'email': email}
    return None
