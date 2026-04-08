from flask import Blueprint, render_template, request, jsonify, send_file, json, session, redirect, url_for, flash
import platform
from datetime import datetime
from functools import wraps
from core.database import get_rules, get_logs, get_stats, save_rule, log_action, verify_user, create_user
from core.firewall import fw_manager
from core.config import config
from core.rule_engine import FirewallLogicEngine, packet_from_dict
import os

bp = Blueprint('main', __name__)
logic_engine = FirewallLogicEngine()

# --- Frontend Routes ---

def get_system_info():
    return {
        'platform': f"{platform.system()} {platform.release()}",
        'server': f"{config.HOST}:{config.PORT}",
        'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function

@bp.route('/dashboard')
@login_required
def dashboard():
    stats = get_stats()
    return render_template('dashboard.html', stats=stats, system_info=get_system_info())

@bp.route('/')
def landing():
    return render_template('landing.html', system_info=get_system_info())

@bp.route('/connections')
@login_required
def connections():
    return render_template('connections.html', system_info=get_system_info())

@bp.route('/rules')
@login_required
def rules():
    rules_list = get_rules()
    return render_template('rules.html', rules=rules_list, system_info=get_system_info())

@bp.route('/statistics')
@login_required
def statistics():
    stats = get_stats()
    return render_template('statistics.html', stats=stats, system_info=get_system_info())

@bp.route('/inspection')
@login_required
def inspection():
    return render_template('inspection.html', system_info=get_system_info())

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = verify_user(email, password)
        if user:
            session.permanent = True
            session['user_id'] = user['id']
            session['fullname'] = user['fullname']
            flash(f"Welcome back, {user['fullname']}!", 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid email or passphrase.", 'error')
    return render_template('auth/login.html', system_info=get_system_info())

@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if create_user(fullname, email, password):
            flash("Registration successful. You may now login.", 'success')
            return redirect(url_for('main.login'))
        else:
            flash("Email is already registered.", 'error')
    return render_template('auth/signup.html', system_info=get_system_info())

@bp.route('/logout')
def logout():
    session.clear()
    flash("Successfully logged out.", 'success')
    return redirect(url_for('main.login'))

# --- API Routes ---

@bp.route('/api/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'version': '2.0.0',
        'timestamp': datetime.now().isoformat(),
        'platform': platform.system()
    })

@bp.route('/api/stats')
@login_required
def api_stats():
    return jsonify(get_stats())

@bp.route('/api/block', methods=['POST'])
@login_required
def block():
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
        success = fw_manager.block_domain(target)
    
    if success:
        save_rule(target, rule_type, reason)
        log_action('BLOCKED', target, rule_type)
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Failed to block target. Run as administrator/root.'})

@bp.route('/api/unblock', methods=['POST'])
@login_required
def unblock():
    data = request.json
    target = data.get('target', '').strip()
    rule_type = data.get('type', 'domain')
    
    if not target:
        return jsonify({'success': False, 'error': 'Target is required'})
    
    success = fw_manager.unblock_domain(target)
    if success:
        import sqlite3
        conn = sqlite3.connect(config.DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE rules SET status='inactive' WHERE target=? AND type=?", (target, rule_type))
        conn.commit()
        conn.close()
        
        log_action('UNBLOCKED', target, rule_type)
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Failed to unblock target'})

@bp.route('/api/export')
@login_required
def export_rules():
    rules = get_rules()
    from flask import Response
    response = Response(
        response=json.dumps(rules, indent=2),
        mimetype='application/json'
    )
    response.headers['Content-Disposition'] = 'attachment; filename=ccaf_rules.json'
    return response

@bp.route('/api/logs/clear', methods=['POST'])
@login_required
def clear_logs():
    try:
        import sqlite3
        conn = sqlite3.connect(config.DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM logs")
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@bp.route('/api/logs')
@login_required
def get_recent_logs():
    return jsonify(get_logs())

@bp.app_errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@bp.app_errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500

@bp.route('/api/pcap')
@login_required
def api_pcap():
    from core.network_scanner import get_live_connections
    return jsonify(get_live_connections())

@bp.route('/api/engine/simulate', methods=['POST'])
@login_required
def simulate_packet_stream():
    """
    Process a stream of simulated packets through firewall filtering modules.
    Expected payload:
    {
      "packets": [
        {
          "src_ip":"192.168.1.10",
          "dst_ip":"8.8.8.8",
          "src_port":50000,
          "dst_port":443,
          "protocol":"TCP",
          "flags":["SYN"]
        }
      ]
    }
    """
    data = request.get_json(silent=True) or {}
    raw_packets = data.get('packets', [])
    if not isinstance(raw_packets, list):
        return jsonify({'success': False, 'error': '`packets` must be a list'}), 400

    try:
        packets = [packet_from_dict(item) for item in raw_packets]
    except (KeyError, TypeError, ValueError) as exc:
        return jsonify({'success': False, 'error': f'Invalid packet schema: {exc}'}), 400

    decisions = logic_engine.process_stream(packets)
    return jsonify({
        'success': True,
        'processed': len(decisions),
        'decisions': decisions,
        'state_table': logic_engine.get_state_table()
    })

@bp.route('/api/engine/state-table', methods=['GET', 'DELETE'])
@login_required
def state_table():
    if request.method == 'DELETE':
        logic_engine.reset()
        return jsonify({'success': True, 'message': 'State table cleared'})

    return jsonify({
        'success': True,
        'entries': logic_engine.get_state_table(),
        'count': len(logic_engine.get_state_table())
    })
