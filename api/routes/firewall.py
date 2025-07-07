from flask import Blueprint, request, jsonify
from datetime import datetime
import logging

from core.firewall_manager import get_firewall_manager, FirewallRuleRequest, RuleType, Action, Direction
from core.database import get_firewall_rule_repository
from .auth import login_required, admin_required
from flask import session

firewall_bp = Blueprint('firewall', __name__)
logger = logging.getLogger('ccaf.firewall')

@firewall_bp.route('/block', methods=['POST'])
@login_required
def block_legacy():
    """Legacy block endpoint for backward compatibility"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        rule_type = data.get('type', 'domain').lower()
        reason = data.get('reason', 'Manually blocked')
        
        if not target:
            return jsonify({'success': False, 'error': 'Target is required'}), 400
            
        # Map legacy rule types to RuleType enum
        type_mapping = {
            'domain': 'DOMAIN',
            'application': 'APPLICATION',
            'ip': 'IP_ADDRESS'
        }
        
        if rule_type not in type_mapping:
            return jsonify({'success': False, 'error': 'Invalid rule type'}), 400
            
        # Create a rule request
        rule_request = FirewallRuleRequest(
            name=f"Block {target}",
            target=target,
            rule_type=RuleType(type_mapping[rule_type]),
            action=Action.BLOCK,
            direction=Direction.BOTH,
            reason=reason,
            priority=100,
            schedule_enabled=False
        )
        
        # Create the rule
        fw_manager = get_firewall_manager()
        rule = fw_manager.create_rule(rule_request, session.get('user_id'))
        
        if rule:
            logger.info(f"Created block rule via legacy endpoint: {target} ({rule_type})")
            return jsonify({
                'success': True,
                'message': f'Successfully blocked {target}'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to create block rule'}), 400
            
    except Exception as e:
        logger.error(f"Error in legacy block endpoint: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

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
