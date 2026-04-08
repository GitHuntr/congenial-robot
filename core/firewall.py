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

fw_manager = SimpleFirewallManager()
