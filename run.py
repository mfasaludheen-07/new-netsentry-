import os
import sys

# Ensure current working directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import create_app

app = create_app(os.getenv('FLASK_CONFIG', 'default'))

if __name__ == '__main__':
    print("=" * 60)
    print("NetSentry — Network Threat Hunting & Attack Reconstruction Platform")
    print("=" * 60)
    print("NetSentry running at:\nhttp://127.0.0.1:5000")
    print("=" * 60)
    flask_env = os.getenv('FLASK_ENV', 'development').lower()
    debug_mode = (os.getenv('FLASK_DEBUG', 'true').lower() in ('true', '1')) and (flask_env != 'production')
    
    app.run(host='127.0.0.1', port=5000, debug=debug_mode, use_reloader=False)
