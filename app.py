# app.py - Enhanced CCAF Main Application
import os
import sys
import logging
import signal
from flask import Flask
from flask_cors import CORS

# Import configuration and core modules
from config import init_config, get_config
from core.database import init_database
from core.firewall_manager import init_firewall_manager
from utils.logger import setup_logging
from utils.security import SecurityManager

def register_routes(app):
    """Register all API routes - placeholder until web module is created"""
    from api.routes import register_routes as api_register_routes
    try:
        api_register_routes(app)
        
        # Add legacy /api/block endpoint
        from flask import request, jsonify, session
        from core.firewall_manager import get_firewall_manager, FirewallRuleRequest, RuleType, Action, Direction
        import logging
        
        logger = logging.getLogger('ccaf.legacy')
        
        @app.route('/api/block', methods=['POST'])
        def legacy_block():
            """Legacy block endpoint for backward compatibility"""
            try:
                if 'user_id' not in session:
                    return jsonify({'success': False, 'error': 'Authentication required'}), 401
                    
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
                
    except ImportError:
        # If API routes not available, create basic ones
        from flask import jsonify
        
        @app.route('/api/health')
        def health_check():
            return jsonify({'status': 'healthy'})
        
        @app.route('/')
        def index():
            return '''
            <!DOCTYPE html>
            <html>
            <head><title>CCAF - Centralized Context-Aware Firewall</title></head>
            <body>
                <h1>🛡️ CCAF System</h1>
                <p>Centralized Context-Aware Firewall is running!</p>
                <p>API Health: <a href="/api/health">/api/health</a></p>
            </body>
            </html>
            '''

def init_dashboard(app):
    """Initialize web dashboard - placeholder until web module is created"""
    try:
        from web.dashboard import init_dashboard as web_init_dashboard
        web_init_dashboard(app)
    except ImportError:
        # Basic dashboard placeholder
        pass

class CCCFApplication:
    """Main CCAF application class"""
    
    def __init__(self, config_file=None, environment=None):
        # Initialize configuration
        self.config = init_config(config_file, environment)
        
        # Setup logging
        setup_logging(self.config)
        
        # Initialize Flask app
        self.app = Flask(__name__)
        self.app.secret_key = self.config.security.secret_key
        
        # Enable CORS
        CORS(self.app)
        
        # Initialize components
        self.db_manager = None
        self.firewall_manager = None
        self.security_manager = None
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logging.info("CCAF Application initialized")
    
    def initialize_components(self):
        """Initialize all application components"""
        try:
            # Initialize database
            logging.info("Initializing database...")
            self.db_manager = init_database()
            
            # Initialize firewall manager
            logging.info("Initializing firewall manager...")
            self.firewall_manager = init_firewall_manager()
            
            # Initialize security manager
            logging.info("Initializing security manager...")
            self.security_manager = SecurityManager(self.config)
            
            # Register API routes
            logging.info("Registering API routes...")
            register_routes(self.app)
            
            # Initialize web dashboard
            logging.info("Initializing web dashboard...")
            init_dashboard(self.app)
            
            logging.info("All components initialized successfully")
            
        except Exception as e:
            logging.error(f"Failed to initialize components: {e}")
            sys.exit(1)
    
    def check_privileges(self):
        """Check if application has required privileges"""
        if os.name == 'posix' and os.geteuid() != 0:
            logging.error("CCAF requires root privileges to manage firewall rules")
            print("⚠️  ERROR: This application requires root privileges.")
            print("Please run with: sudo python3 app.py")
            sys.exit(1)
        elif os.name == 'nt':
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logging.error("CCAF requires administrator privileges")
                print("⚠️  ERROR: This application requires administrator privileges.")
                print("Please run as administrator.")
                sys.exit(1)
    
    def create_default_admin(self):
        """Create default admin user if none exists"""
        try:
            from utils.security import hash_password
            from core.database import get_user_repository
            
            user_repo = get_user_repository()
            
            # Check if admin exists
            admin = user_repo.get_by_username('admin')
            if not admin:
                # Create default admin
                password_hash = hash_password('admin123')  # Change this!
                user_repo.create_user('admin', 'admin@ccaf.local', password_hash, 'admin')
                
                logging.warning("Default admin user created with username: admin, password: admin123")
                print("⚠️  WARNING: Default admin user created!")
                print("   Username: admin")
                print("   Password: admin123")
                print("   Please change this password immediately after first login!")
                
        except Exception as e:
            logging.error(f"Failed to create default admin user: {e}")
    
    def run(self):
        """Run the CCAF application"""
        try:
            # Check privileges
            self.check_privileges()
            
            # Initialize all components
            self.initialize_components()
            
            # Create default admin if needed
            self.create_default_admin()
            
            # Get server configuration
            host = self.config.web.host
            port = self.config.web.port
            debug = self.config.web.debug
            ssl_context = self.config.get_ssl_context()
            
            # Print startup information
            self._print_startup_info(host, port, ssl_context is not None)
            
            # Run the Flask application
            self.app.run(
                host=host,
                port=port,
                debug=debug,
                ssl_context=ssl_context,
                threaded=True
            )
            
        except KeyboardInterrupt:
            logging.info("Application stopped by user")
        except Exception as e:
            logging.error(f"Application failed to start: {e}")
            sys.exit(1)
        finally:
            self._cleanup()
    
    def _print_startup_info(self, host, port, ssl_enabled):
        """Print application startup information"""
        protocol = "https" if ssl_enabled else "http"
        
        print("=" * 70)
        print("🛡️  CCAF - Centralized Context-Aware Firewall")
        print("=" * 70)
        print(f"🌐 Web Interface: {protocol}://{host}:{port}")
        
        if host == "0.0.0.0":
            # Get LAN IP for easier access
            try:
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                lan_ip = s.getsockname()[0]
                s.close()
                print(f"🏠 LAN Access: {protocol}://{lan_ip}:{port}")
            except:
                pass
        
        print(f"🔧 Environment: {self.config.environment.value}")
        print(f"📁 Database: {self.config.database.path}")
        print(f"📝 Logs: {self.config.logging.file_path}")
        
        if ssl_enabled:
            print("🔒 SSL Enabled")
        
        print("=" * 70)
        print("Press Ctrl+C to stop the server")
        print()
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logging.info(f"Received signal {signum}, shutting down...")
        self._cleanup()
        sys.exit(0)
    
    def _cleanup(self):
        """Cleanup resources on shutdown"""
        try:
            if self.firewall_manager:
                self.firewall_manager.stop_background_services()
            
            logging.info("Application cleanup completed")
            
        except Exception as e:
            logging.error(f"Error during cleanup: {e}")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='CCAF - Centralized Context-Aware Firewall')
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--env', '-e', choices=['development', 'production', 'testing'], 
                       default='production', help='Environment (default: production)')
    parser.add_argument('--host', help='Host to bind to (overrides config)')
    parser.add_argument('--port', type=int, help='Port to bind to (overrides config)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Create and configure application
    app = CCCFApplication(args.config, args.env)
    
    # Override configuration with command line arguments
    if args.host:
        app.config.web.host = args.host
    if args.port:
        app.config.web.port = args.port
    if args.debug:
        app.config.web.debug = True
        app.config.logging.level = "DEBUG"
    
    # Run the application
    app.run()

if __name__ == '__main__':
    main()