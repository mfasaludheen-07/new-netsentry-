import os
import urllib.parse
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Base application configuration."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'netsentry-threat-hunting-default-soc-secret-2026')
    
    # Database Configuration
    DB_HOST = os.getenv('DB_HOST', '127.0.0.1')
    DB_PORT = os.getenv('DB_PORT', '3306')
    DB_NAME = os.getenv('DB_NAME', 'netsentry')
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')

    # Safe URL encoding for database password if needed
    _encoded_password = urllib.parse.quote_plus(DB_PASSWORD) if DB_PASSWORD else ''
    
    # Prefer explicit DATABASE_URL if provided, else construct MySQL connection string
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL',
        f"mysql+pymysql://{DB_USER}:{_encoded_password}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
    )
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # Uploads & Storage Paths
    STORAGE_PATH = os.path.join(BASE_DIR, 'storage')
    UPLOAD_FOLDER = os.path.join(STORAGE_PATH, 'uploads')
    EVIDENCE_FOLDER = os.path.join(STORAGE_PATH, 'evidence')
    REPORTS_FOLDER = os.path.join(STORAGE_PATH, 'reports')
    LOGS_FOLDER = os.path.join(STORAGE_PATH, 'logs')

    MAX_UPLOAD_MB = int(os.getenv('MAX_UPLOAD_MB', 20))
    MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024

    SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 3600))
    PERMANENT_SESSION_LIFETIME = SESSION_TIMEOUT

    # Security settings
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    ALLOWED_LOG_EXTENSIONS = {'csv', 'json', 'txt', 'log'}
    ALLOWED_EVIDENCE_EXTENSIONS = {'csv', 'json', 'txt', 'log', 'pdf', 'png', 'jpg', 'jpeg', 'pcap', 'pcapng'}


class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SERVER_NAME = 'localhost'


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    @classmethod
    def init_app(cls, app):
        secret = os.getenv('SECRET_KEY')
        if not secret or secret == 'netsentry-threat-hunting-default-soc-secret-2026' or len(secret) < 32:
            raise RuntimeError("CRITICAL SECURITY ERROR: Production deployment requires a strong, unique SECRET_KEY (min 32 characters) set in the environment.")


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
