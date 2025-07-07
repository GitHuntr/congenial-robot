# core/firewall_manager.py - Modular Firewall Management System
import os
import re
import json
import socket
import logging
import platform
import subprocess
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum

from config import get_config
from core.database import (
    get_firewall_rule_repository, 
    get_security_event_repository,
    FirewallRule, 
    SecurityEvent
)

class RuleType(Enum):
    DOMAIN = "domain"
    IP_ADDRESS = "ip"
    APPLICATION = "application"
    PORT = "port"
    PROTOCOL = "protocol"

class Action(Enum):
    BLOCK = "block"
    ALLOW = "allow"
    REDIRECT = "redirect"
    LOG_ONLY = "log_only"

class Direction(Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BOTH = "both"

@dataclass
class FirewallRuleRequest:
    """Firewall rule creation request"""
    name: str
    target: str
    rule_type: RuleType
    action: Action = Action.BLOCK
    direction: Direction = Direction.BOTH
    protocol: Optional[str] = None
    port_range: Optional[str] = None
    priority: int = 100
    reason: Optional[str] = None
    schedule_enabled: bool = False
    schedule_start: Optional[datetime] = None
    schedule_end: Optional[datetime] = None
    applies_to_users: Optional[List[int]] = None
    applies_to_devices: Optional[List[int]] = None

class FirewallBackend(ABC):
    """Abstract base class for firewall backends"""
    
    @abstractmethod
    def block_domain(self, domain: str, rule_id: int) -> bool:
        pass
    
    @abstractmethod
    def unblock_domain(self, domain: str, rule_id: int) -> bool:
        pass
    
    @abstractmethod
    def block_ip(self, ip_address: str, rule_id: int) -> bool:
        pass
    
    @abstractmethod
    def unblock_ip(self, ip_address: str, rule_id: int) -> bool:
        pass
    
    @abstractmethod
    def block_application(self, app_name: str, rule_id: int) -> bool:
        pass
    
    @abstractmethod
    def unblock_application(self, app_name: str, rule_id: int) -> bool:
        pass
    
    @abstractmethod
    def block_port(self, port: str, protocol: str, rule_id: int) -> bool:
        pass
    
    @abstractmethod
    def unblock_port(self, port: str, protocol: str, rule_id: int) -> bool:
        pass
    
    @abstractmethod
    def get_active_connections(self) -> List[Dict[str, Any]]:
        pass

class LinuxFirewallBackend(FirewallBackend):
    """Linux firewall backend using iptables"""
    
    def __init__(self):
        self.hosts_file = "/etc/hosts"
        self.iptables_chain = "CCAF_RULES"
        self._setup_iptables_chain()
        
    def _setup_iptables_chain(self):
        """Setup custom iptables chain for CCAF rules"""
        try:
            # Create custom chain if it doesn't exist
            subprocess.run(['sudo', 'iptables', '-N', self.iptables_chain], 
                         check=False, stderr=subprocess.DEVNULL)
            
            # Add jump to custom chain in INPUT and OUTPUT
            subprocess.run(['sudo', 'iptables', '-C', 'INPUT', '-j', self.iptables_chain], 
                         check=False, stderr=subprocess.DEVNULL)
            if subprocess.call(['sudo', 'iptables', '-C', 'INPUT', '-j', self.iptables_chain], 
                             stderr=subprocess.DEVNULL) != 0:
                subprocess.run(['sudo', 'iptables', '-I', 'INPUT', '1', '-j', self.iptables_chain])
                
            subprocess.run(['sudo', 'iptables', '-C', 'OUTPUT', '-j', self.iptables_chain], 
                         check=False, stderr=subprocess.DEVNULL)
            if subprocess.call(['sudo', 'iptables', '-C', 'OUTPUT', '-j', self.iptables_chain], 
                             stderr=subprocess.DEVNULL) != 0:
                subprocess.run(['sudo', 'iptables', '-I', 'OUTPUT', '1', '-j', self.iptables_chain])
                
        except Exception as e:
            logging.error(f"Failed to setup iptables chain: {e}")
    
    def block_domain(self, domain: str, rule_id: int) -> bool:
        try:
            domain = self._clean_domain(domain)
            
            # Add to hosts file
            self._add_to_hosts(domain)
            
            # Try to resolve and block IPs
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                for ip in ips:
                    self._add_iptables_rule(f"-A {self.iptables_chain} -d {ip} -j DROP -m comment --comment 'CCAF_RULE_{rule_id}'")
                    self._add_iptables_rule(f"-A {self.iptables_chain} -s {ip} -j DROP -m comment --comment 'CCAF_RULE_{rule_id}'")
            except socket.gaierror:
                logging.warning(f"Could not resolve domain {domain}")
                
            return True
        except Exception as e:
            logging.error(f"Failed to block domain {domain}: {e}")
            return False
    
    def unblock_domain(self, domain: str, rule_id: int) -> bool:
        try:
            domain = self._clean_domain(domain)
            
            # Remove from hosts file
            self._remove_from_hosts(domain)
            
            # Remove iptables rules
            self._remove_iptables_rules_by_comment(f"CCAF_RULE_{rule_id}")
            
            return True
        except Exception as e:
            logging.error(f"Failed to unblock domain {domain}: {e}")
            return False
    
    def block_ip(self, ip_address: str, rule_id: int) -> bool:
        try:
            self._add_iptables_rule(f"-A {self.iptables_chain} -d {ip_address} -j DROP -m comment --comment 'CCAF_RULE_{rule_id}'")
            self._add_iptables_rule(f"-A {self.iptables_chain} -s {ip_address} -j DROP -m comment --comment 'CCAF_RULE_{rule_id}'")
            return True
        except Exception as e:
            logging.error(f"Failed to block IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address: str, rule_id: int) -> bool:
        try:
            self._remove_iptables_rules_by_comment(f"CCAF_RULE_{rule_id}")
            return True
        except Exception as e:
            logging.error(f"Failed to unblock IP {ip_address}: {e}")
            return False
    
    def block_application(self, app_name: str, rule_id: int) -> bool:
        try:
            # Kill existing processes
            subprocess.run(['sudo', 'pkill', '-f', app_name], check=False)
            
            # Block using process name (requires additional monitoring)
            # This is a placeholder - real implementation would need process monitoring
            logging.info(f"Application {app_name} blocked (process killed)")
            return True
        except Exception as e:
            logging.error(f"Failed to block application {app_name}: {e}")
            return False
    
    def unblock_application(self, app_name: str, rule_id: int) -> bool:
        # For applications, we typically just remove the blocking mechanism
        # The application can be started again normally
        return True
    
    def block_port(self, port: str, protocol: str, rule_id: int) -> bool:
        try:
            protocol = protocol.lower() if protocol else "tcp"
            self._add_iptables_rule(f"-A {self.iptables_chain} -p {protocol} --dport {port} -j DROP -m comment --comment 'CCAF_RULE_{rule_id}'")
            return True
        except Exception as e:
            logging.error(f"Failed to block port {port}: {e}")
            return False
    
    def unblock_port(self, port: str, protocol: str, rule_id: int) -> bool:
        try:
            self._remove_iptables_rules_by_comment(f"CCAF_RULE_{rule_id}")
            return True
        except Exception as e:
            logging.error(f"Failed to unblock port {port}: {e}")
            return False
    
    def get_active_connections(self) -> List[Dict[str, Any]]:
        try:
            result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
            connections = []
            for line in result.stdout.split('\n')[1:]:  # Skip header
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        connections.append({
                            'proto': parts[0],
                            'state': parts[1],
                            'local_address': parts[4],
                            'peer_address': parts[5] if len(parts) > 5 else ''
                        })
            return connections
        except Exception as e:
            logging.error(f"Failed to get active connections: {e}")
            return []
    
    def _clean_domain(self, domain: str) -> str:
        domain = domain.strip().lower()
        domain = re.sub(r'^https?://', '', domain)
        return domain.split('/')[0]
    
    def _add_to_hosts(self, domain: str):
        try:
            with open(self.hosts_file, 'r') as f:
                content = f.read()
            
            if domain not in content:
                with open(self.hosts_file, 'a') as f:
                    f.write(f'\n# CCAF Block\n')
                    f.write(f'127.0.0.1 {domain}\n')
                    f.write(f'127.0.0.1 www.{domain}\n')
        except Exception as e:
            logging.error(f"Failed to add {domain} to hosts file: {e}")
    
    def _remove_from_hosts(self, domain: str):
        try:
            with open(self.hosts_file, 'r') as f:
                lines = f.readlines()
            
            with open(self.hosts_file, 'w') as f:
                for line in lines:
                    if domain not in line:
                        f.write(line)
        except Exception as e:
            logging.error(f"Failed to remove {domain} from hosts file: {e}")
    
    def _add_iptables_rule(self, rule: str):
        subprocess.run(f'sudo iptables {rule}'.split(), check=True)
    
    def _remove_iptables_rules_by_comment(self, comment: str):
        try:
            # List rules with line numbers
            result = subprocess.run(['sudo', 'iptables', '-L', self.iptables_chain, '--line-numbers', '-v'], 
                                  capture_output=True, text=True)
            
            # Find and remove rules with the specific comment
            lines_to_remove = []
            for line in result.stdout.split('\n'):
                if comment in line:
                    line_num = line.split()[0]
                    if line_num.isdigit():
                        lines_to_remove.append(int(line_num))
            
            # Remove rules in reverse order to maintain line numbers
            for line_num in sorted(lines_to_remove, reverse=True):
                subprocess.run(['sudo', 'iptables', '-D', self.iptables_chain, str(line_num)], check=False)
                
        except Exception as e:
            logging.error(f"Failed to remove iptables rules with comment {comment}: {e}")

class WindowsFirewallBackend(FirewallBackend):
    """Windows firewall backend using netsh and hosts file"""
    
    def __init__(self):
        self.hosts_file = r'C:\Windows\System32\drivers\etc\hosts'
    
    def block_domain(self, domain: str, rule_id: int) -> bool:
        try:
            domain = self._clean_domain(domain)
            
            # Add to hosts file
            self._add_to_hosts(domain)
            
            # Try to resolve and block IPs
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                for ip in ips:
                    self._add_netsh_rule(f'CCAF_Block_{rule_id}_{ip}', 'out', ip)
                    self._add_netsh_rule(f'CCAF_Block_{rule_id}_{ip}_in', 'in', ip)
            except socket.gaierror:
                logging.warning(f"Could not resolve domain {domain}")
            
            # Flush DNS cache
            subprocess.run(['ipconfig', '/flushdns'], check=False)
            return True
            
        except Exception as e:
            logging.error(f"Failed to block domain {domain}: {e}")
            return False
    
    def unblock_domain(self, domain: str, rule_id: int) -> bool:
        try:
            domain = self._clean_domain(domain)
            
            # Remove from hosts file
            self._remove_from_hosts(domain)
            
            # Remove firewall rules
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 
                           f'name=CCAF_Block_{rule_id}*'], check=False)
            
            subprocess.run(['ipconfig', '/flushdns'], check=False)
            return True
            
        except Exception as e:
            logging.error(f"Failed to unblock domain {domain}: {e}")
            return False
    
    def block_ip(self, ip_address: str, rule_id: int) -> bool:
        try:
            self._add_netsh_rule(f'CCAF_Block_IP_{rule_id}', 'out', ip_address)
            self._add_netsh_rule(f'CCAF_Block_IP_{rule_id}_in', 'in', ip_address)
            return True
        except Exception as e:
            logging.error(f"Failed to block IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address: str, rule_id: int) -> bool:
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 
                           f'name=CCAF_Block_IP_{rule_id}*'], check=False)
            return True
        except Exception as e:
            logging.error(f"Failed to unblock IP {ip_address}: {e}")
            return False
    
    def block_application(self, app_name: str, rule_id: int) -> bool:
        try:
            # Kill the process
            subprocess.run(['taskkill', '/F', '/IM', f'{app_name}.exe'], check=False)
            
            # Block using Windows Firewall
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                           f'name=CCAF_Block_App_{rule_id}', 'dir=out', 'program=any',
                           'action=block', f'description=Block {app_name}'], check=False)
            return True
        except Exception as e:
            logging.error(f"Failed to block application {app_name}: {e}")
            return False
    
    def unblock_application(self, app_name: str, rule_id: int) -> bool:
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                           f'name=CCAF_Block_App_{rule_id}'], check=False)
            return True
        except Exception as e:
            logging.error(f"Failed to unblock application {app_name}: {e}")
            return False
    
    def block_port(self, port: str, protocol: str, rule_id: int) -> bool:
        try:
            protocol = protocol.lower() if protocol else "tcp"
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                           f'name=CCAF_Block_Port_{rule_id}', 'dir=out', 'action=block',
                           f'protocol={protocol}', f'localport={port}'], check=False)
            return True
        except Exception as e:
            logging.error(f"Failed to block port {port}: {e}")
            return False
    
    def unblock_port(self, port: str, protocol: str, rule_id: int) -> bool:
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                           f'name=CCAF_Block_Port_{rule_id}'], check=False)
            return True
        except Exception as e:
            logging.error(f"Failed to unblock port {port}: {e}")
            return False
    
    def get_active_connections(self) -> List[Dict[str, Any]]:
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            connections = []
            for line in result.stdout.split('\n')[4:]:  # Skip headers
                if line.strip() and ('TCP' in line or 'UDP' in line):
                    parts = line.split()
                    if len(parts) >= 4:
                        connections.append({
                            'proto': parts[0],
                            'local_address': parts[1],
                            'peer_address': parts[2],
                            'state': parts[3] if len(parts) > 3 else ''
                        })
            return connections
        except Exception as e:
            logging.error(f"Failed to get active connections: {e}")
            return []
    
    def _clean_domain(self, domain: str) -> str:
        domain = domain.strip().lower()
        domain = re.sub(r'^https?://', '', domain)
        return domain.split('/')[0]
    
    def _add_to_hosts(self, domain: str):
        try:
            with open(self.hosts_file, 'r') as f:
                content = f.read()
            
            if domain not in content:
                with open(self.hosts_file, 'a') as f:
                    f.write(f'\n# CCAF Block\n')
                    f.write(f'127.0.0.1 {domain}\n')
                    f.write(f'127.0.0.1 www.{domain}\n')
                    f.write(f'0.0.0.0 {domain}\n')
                    f.write(f'0.0.0.0 www.{domain}\n')
        except Exception as e:
            logging.error(f"Failed to add {domain} to hosts file: {e}")
    
    def _remove_from_hosts(self, domain: str):
        try:
            with open(self.hosts_file, 'r') as f:
                lines = f.readlines()
            
            with open(self.hosts_file, 'w') as f:
                for line in lines:
                    if domain not in line:
                        f.write(line)
        except Exception as e:
            logging.error(f"Failed to remove {domain} from hosts file: {e}")
    
    def _add_netsh_rule(self, rule_name: str, direction: str, ip: str):
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                       f'name={rule_name}', f'dir={direction}', 'action=block',
                       f'remoteip={ip}'], check=False)

class MacOSFirewallBackend(FirewallBackend):
    """macOS firewall backend using pfctl and hosts file"""
    
    def __init__(self):
        self.hosts_file = "/etc/hosts"
        self.pf_anchor = "ccaf"
    
    def block_domain(self, domain: str, rule_id: int) -> bool:
        try:
            domain = self._clean_domain(domain)
            
            # Add to hosts file
            self._add_to_hosts(domain)
            
            # Add to pfctl table
            subprocess.run(['sudo', 'pfctl', '-t', 'blocked_domains', '-T', 'add', domain], check=False)
            
            return True
        except Exception as e:
            logging.error(f"Failed to block domain {domain}: {e}")
            return False
    
    def unblock_domain(self, domain: str, rule_id: int) -> bool:
        try:
            domain = self._clean_domain(domain)
            
            # Remove from hosts file
            self._remove_from_hosts(domain)
            
            # Remove from pfctl table
            subprocess.run(['sudo', 'pfctl', '-t', 'blocked_domains', '-T', 'delete', domain], check=False)
            
            return True
        except Exception as e:
            logging.error(f"Failed to unblock domain {domain}: {e}")
            return False
    
    def block_ip(self, ip_address: str, rule_id: int) -> bool:
        try:
            subprocess.run(['sudo', 'pfctl', '-t', 'blocked_ips', '-T', 'add', ip_address], check=False)
            return True
        except Exception as e:
            logging.error(f"Failed to block IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address: str, rule_id: int) -> bool:
        try:
            subprocess.run(['sudo', 'pfctl', '-t', 'blocked_ips', '-T', 'delete', ip_address], check=False)
            return True
        except Exception as e:
            logging.error(f"Failed to unblock IP {ip_address}: {e}")
            return False
    
    def block_application(self, app_name: str, rule_id: int) -> bool:
        try:
            subprocess.run(['sudo', 'pkill', '-f', app_name], check=False)
            return True
        except Exception as e:
            logging.error(f"Failed to block application {app_name}: {e}")
            return False
    
    def unblock_application(self, app_name: str, rule_id: int) -> bool:
        return True
    
    def block_port(self, port: str, protocol: str, rule_id: int) -> bool:
        # macOS port blocking would require more complex pfctl rules
        logging.warning("Port blocking not fully implemented for macOS")
        return False
    
    def unblock_port(self, port: str, protocol: str, rule_id: int) -> bool:
        return True
    
    def get_active_connections(self) -> List[Dict[str, Any]]:
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            connections = []
            for line in result.stdout.split('\n'):
                if 'tcp' in line or 'udp' in line:
                    parts = line.split()
                    if len(parts) >= 6:
                        connections.append({
                            'proto': parts[0],
                            'local_address': parts[3],
                            'peer_address': parts[4],
                            'state': parts[5] if len(parts) > 5 else ''
                        })
            return connections
        except Exception as e:
            logging.error(f"Failed to get active connections: {e}")
            return []
    
    def _clean_domain(self, domain: str) -> str:
        domain = domain.strip().lower()
        domain = re.sub(r'^https?://', '', domain)
        return domain.split('/')[0]
    
    def _add_to_hosts(self, domain: str):
        try:
            with open(self.hosts_file, 'r') as f:
                content = f.read()
            
            if domain not in content:
                with open(self.hosts_file, 'a') as f:
                    f.write(f'\n# CCAF Block\n')
                    f.write(f'127.0.0.1 {domain}\n')
                    f.write(f'127.0.0.1 www.{domain}\n')
        except Exception as e:
            logging.error(f"Failed to add {domain} to hosts file: {e}")
    
    def _remove_from_hosts(self, domain: str):
        try:
            with open(self.hosts_file, 'r') as f:
                lines = f.readlines()
            
            with open(self.hosts_file, 'w') as f:
                for line in lines:
                    if domain not in line:
                        f.write(line)
        except Exception as e:
            logging.error(f"Failed to remove {domain} from hosts file: {e}")

class FirewallManager:
    """Main firewall management class"""
    
    def __init__(self):
        self.config = get_config()
        self.rule_repo = get_firewall_rule_repository()
        self.security_repo = get_security_event_repository()
        self.backend = self._get_backend()
        self._schedule_thread = None
        self._running = False
        
        # Start background services
        self.start_background_services()
    
    def _get_backend(self) -> FirewallBackend:
        """Get appropriate firewall backend for the current OS"""
        system = platform.system()
        
        if system == "Linux":
            return LinuxFirewallBackend()
        elif system == "Windows":
            return WindowsFirewallBackend()
        elif system == "Darwin":
            return MacOSFirewallBackend()
        else:
            raise RuntimeError(f"Unsupported operating system: {system}")
    
    def create_rule(self, request: FirewallRuleRequest, created_by_user_id: int = None) -> Optional[FirewallRule]:
        """Create a new firewall rule"""
        try:
            # Validate rule
            if not self._validate_rule_request(request):
                return None
            
            # Convert request to database model
            rule_data = {
                'name': request.name,
                'target': request.target,
                'rule_type': request.rule_type.value,
                'action': request.action.value,
                'direction': request.direction.value,
                'protocol': request.protocol,
                'port_range': request.port_range,
                'priority': request.priority,
                'reason': request.reason,
                'schedule_enabled': request.schedule_enabled,
                'schedule_start': request.schedule_start,
                'schedule_end': request.schedule_end,
                'created_by': created_by_user_id
            }
            
            # Handle applies_to fields (convert lists to JSON)
            if request.applies_to_users:
                rule_data['applies_to_users'] = json.dumps(request.applies_to_users)
            if request.applies_to_devices:
                rule_data['applies_to_devices'] = json.dumps(request.applies_to_devices)
            
            # Create rule in database
            rule = self.rule_repo.create_rule(**rule_data)
            
            # Apply rule if it should be active
            if self._should_rule_be_active(rule):
                self._apply_rule(rule)
            
            logging.info(f"Created firewall rule: {rule.name} (ID: {rule.id})")
            return rule
            
        except Exception as e:
            logging.error(f"Failed to create firewall rule: {e}")
            return None
    
    def delete_rule(self, rule_id: int) -> bool:
        """Delete a firewall rule"""
        try:
            # First remove the rule from the system
            self._remove_rule(rule_id)
            
            # Then update the database
            self.rule_repo.update_rule_status(rule_id, 'deleted')
            
            logging.info(f"Deleted firewall rule ID: {rule_id}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to delete firewall rule {rule_id}: {e}")
            return False
    
    def toggle_rule(self, rule_id: int, active: bool) -> bool:
        """Enable or disable a firewall rule"""
        try:
            if active:
                rule = self._get_rule_by_id(rule_id)
                if rule and self._apply_rule(rule):
                    self.rule_repo.update_rule_status(rule_id, 'active')
                    return True
            else:
                if self._remove_rule(rule_id):
                    self.rule_repo.update_rule_status(rule_id, 'inactive')
                    return True
            
            return False
            
        except Exception as e:
            logging.error(f"Failed to toggle rule {rule_id}: {e}")
            return False
    
    def get_active_rules(self) -> List[FirewallRule]:
        """Get all active firewall rules"""
        return self.rule_repo.get_active_rules()
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get firewall rule statistics"""
        active_rules = self.get_active_rules()
        
        stats = {
            'total_active_rules': len(active_rules),
            'rules_by_type': {},
            'rules_by_action': {},
            'most_triggered_rules': []
        }
        
        # Count by type and action
        for rule in active_rules:
            stats['rules_by_type'][rule.rule_type] = stats['rules_by_type'].get(rule.rule_type, 0) + 1
            stats['rules_by_action'][rule.action] = stats['rules_by_action'].get(rule.action, 0) + 1
        
        # Get most triggered rules (top 10)
        sorted_rules = sorted(active_rules, key=lambda r: r.trigger_count or 0, reverse=True)
        stats['most_triggered_rules'] = [
            {
                'id': rule.id,
                'name': rule.name,
                'target': rule.target,
                'trigger_count': rule.trigger_count or 0,
                'last_triggered': rule.last_triggered.isoformat() if rule.last_triggered else None
            }
            for rule in sorted_rules[:10]
        ]
        
        return stats
    
    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get active network connections"""
        return self.backend.get_active_connections()
    
    def start_background_services(self):
        """Start background monitoring and scheduling services"""
        if not self._running:
            self._running = True
            self._schedule_thread = threading.Thread(target=self._schedule_worker, daemon=True)
            self._schedule_thread.start()
            logging.info("Background firewall services started")
    
    def stop_background_services(self):
        """Stop background services"""
        self._running = False
        if self._schedule_thread:
            self._schedule_thread.join(timeout=5)
        logging.info("Background firewall services stopped")
    
    def _validate_rule_request(self, request: FirewallRuleRequest) -> bool:
        """Validate firewall rule request"""
        if not request.name or not request.target:
            logging.error("Rule name and target are required")
            return False
        
        if request.rule_type == RuleType.IP_ADDRESS:
            try:
                socket.inet_aton(request.target)  # Validate IPv4
            except socket.error:
                try:
                    socket.inet_pton(socket.AF_INET6, request.target)  # Validate IPv6
                except socket.error:
                    logging.error(f"Invalid IP address: {request.target}")
                    return False
        
        if request.rule_type == RuleType.PORT:
            if not self._validate_port_range(request.target):
                logging.error(f"Invalid port range: {request.target}")
                return False
        
        return True
    
    def _validate_port_range(self, port_range: str) -> bool:
        """Validate port range format"""
        try:
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                return 1 <= start <= end <= 65535
            elif ',' in port_range:
                ports = [int(p.strip()) for p in port_range.split(',')]
                return all(1 <= p <= 65535 for p in ports)
            else:
                port = int(port_range)
                return 1 <= port <= 65535
        except ValueError:
            return False
    
    def _should_rule_be_active(self, rule: FirewallRule) -> bool:
        """Check if a rule should be currently active"""
        if rule.status != 'active':
            return False
        
        if rule.schedule_enabled:
            now = datetime.utcnow()
            if rule.schedule_start and rule.schedule_end:
                return rule.schedule_start <= now <= rule.schedule_end
            return False
        
        return True
    
    def _apply_rule(self, rule: FirewallRule) -> bool:
        """Apply a firewall rule using the appropriate backend"""
        try:
            rule_type = RuleType(rule.rule_type)
            
            if rule_type == RuleType.DOMAIN:
                success = self.backend.block_domain(rule.target, rule.id)
            elif rule_type == RuleType.IP_ADDRESS:
                success = self.backend.block_ip(rule.target, rule.id)
            elif rule_type == RuleType.APPLICATION:
                success = self.backend.block_application(rule.target, rule.id)
            elif rule_type == RuleType.PORT:
                success = self.backend.block_port(rule.target, rule.protocol, rule.id)
            else:
                logging.error(f"Unsupported rule type: {rule_type}")
                return False
            
            if success:
                self.rule_repo.log_rule_trigger(rule.id)
                self._log_security_event("rule_applied", rule)
            
            return success
            
        except Exception as e:
            logging.error(f"Failed to apply rule {rule.id}: {e}")
            return False
    
    def _remove_rule(self, rule_id: int) -> bool:
        """Remove a firewall rule from the system"""
        try:
            rule = self._get_rule_by_id(rule_id)
            if not rule:
                return False
            
            rule_type = RuleType(rule.rule_type)
            
            if rule_type == RuleType.DOMAIN:
                success = self.backend.unblock_domain(rule.target, rule.id)
            elif rule_type == RuleType.IP_ADDRESS:
                success = self.backend.unblock_ip(rule.target, rule.id)
            elif rule_type == RuleType.APPLICATION:
                success = self.backend.unblock_application(rule.target, rule.id)
            elif rule_type == RuleType.PORT:
                success = self.backend.unblock_port(rule.target, rule.protocol, rule.id)
            else:
                return False
            
            if success:
                self._log_security_event("rule_removed", rule)
            
            return success
            
        except Exception as e:
            logging.error(f"Failed to remove rule {rule_id}: {e}")
            return False
    
    def _get_rule_by_id(self, rule_id: int) -> Optional[FirewallRule]:
        """Get a firewall rule by ID"""
        # This would typically use the repository
        # For now, implementing a simple version
        try:
            from core.database import get_db_manager
            with get_db_manager().get_session() as session:
                return session.query(FirewallRule).get(rule_id)
        except Exception:
            return None
    
    def _schedule_worker(self):
        """Background worker for scheduled rules"""
        while self._running:
            try:
                # Check scheduled rules
                scheduled_rules = self.rule_repo.get_scheduled_rules()
                
                for rule in scheduled_rules:
                    if self._should_rule_be_active(rule):
                        if rule.status != 'active':
                            self._apply_rule(rule)
                            self.rule_repo.update_rule_status(rule.id, 'active')
                    else:
                        if rule.status == 'active':
                            self._remove_rule(rule.id)
                            self.rule_repo.update_rule_status(rule.id, 'scheduled')
                
                # Sleep for 60 seconds before next check
                for _ in range(60):
                    if not self._running:
                        break
                    threading.Event().wait(1)
                    
            except Exception as e:
                logging.error(f"Schedule worker error: {e}")
                threading.Event().wait(60)
    
    def _log_security_event(self, event_type: str, rule: FirewallRule):
        """Log a security event"""
        try:
            self.security_repo.create_event(
                event_type=event_type,
                severity='medium',
                description=f"Firewall rule {event_type}: {rule.name}",
                details=json.dumps({
                    'rule_id': rule.id,
                    'target': rule.target,
                    'rule_type': rule.rule_type,
                    'action': rule.action
                })
            )
        except Exception as e:
            logging.error(f"Failed to log security event: {e}")

# Global firewall manager instance
firewall_manager = None

def init_firewall_manager() -> FirewallManager:
    """Initialize global firewall manager"""
    global firewall_manager
    firewall_manager = FirewallManager()
    return firewall_manager

def get_firewall_manager() -> FirewallManager:
    """Get global firewall manager instance"""
    global firewall_manager
    if firewall_manager is None:
        firewall_manager = init_firewall_manager()
    return firewall_manager