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