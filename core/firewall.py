import platform
import subprocess
import logging
import re

class SimpleFirewallManager:
    def __init__(self):
        self.system = platform.system()
        
    def block_domain(self, domain):
        """Block a domain"""
        try:
            domain = domain.strip().lower()
            # Remove protocol
            domain = re.sub(r'^https?://', '', domain)
            domain = domain.split('/')[0]
            # Strip leading www. if present to avoid www.www.
            if domain.startswith('www.'):
                domain = domain[4:]
                
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
        """Unblock a domain by removing all CCAF-related entries from the hosts file."""
        try:
            domain = domain.strip().lower()
            # Strip protocol and path if user passes a URL
            domain = re.sub(r'^https?://', '', domain)
            domain = domain.split('/')[0]
            if domain.startswith('www.'):
                domain = domain[4:]

            if self.system == "Windows":
                hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
            else:
                hosts_path = '/etc/hosts'

            # Build a set of all line patterns we want to remove
            blocked_patterns = {
                f"# CCAF Block for {domain}",
                f"127.0.0.1 {domain}",
                f"127.0.0.1 www.{domain}",
                f"0.0.0.0 {domain}",
                f"0.0.0.0 www.{domain}",
            }

            with open(hosts_path, 'r') as f:
                lines = f.readlines()

            new_lines = []
            for line in lines:
                stripped = line.strip()
                # Skip any line that exactly matches one of the blocked patterns
                if stripped in blocked_patterns:
                    continue
                # Also skip empty lines that were left over between blocks
                new_lines.append(line)

            with open(hosts_path, 'w') as f:
                f.writelines(new_lines)

            # Flush DNS cache so the change takes effect immediately
            if self.system == "Windows":
                subprocess.run(['ipconfig', '/flushdns'], check=False)
            else:
                # Try systemd-resolved (Ubuntu/Debian), silently ignore if not available
                try:
                    subprocess.run(['systemd-resolve', '--flush-caches'], check=False,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except FileNotFoundError:
                    pass  # DNS flush tool not installed, that's fine

            logging.info(f"Successfully unblocked domain: {domain}")
            return True
        except PermissionError:
            logging.error("Permission denied to modify hosts file. Run as administrator/root.")
            return False
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

fw_manager = SimpleFirewallManager()
