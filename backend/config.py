"""
Configuration du système IDS Intelligent
"""
import os
from datetime import timedelta

class Config:
    """Configuration générale du système"""
    
    # Application
    APP_NAME = "IDS Intelligent"
    VERSION = "2.0.0"
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Serveur
    HOST = '0.0.0.0'
    PORT = int(os.environ.get('PORT', 5000))
    
    # Base de données SQLite
    DATABASE_PATH = os.environ.get('DATABASE_PATH', 'database/ids.db')
    DATABASE_BACKUP_PATH = 'database/backups'
    
    # Sécurité
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
    SESSION_TIMEOUT = timedelta(hours=24)
    
    # ML Configuration
    ML_MODEL_PATH = 'ml_models/anomaly_detector.pkl'
    ML_TRAINING_THRESHOLD = 100  # Nombre d'exemples avant réentraînement
    ML_DETECTION_THRESHOLD = 0.7  # Seuil de détection d'anomalie
    ML_CONTAMINATION = 0.1  # Pourcentage d'anomalies attendues
    
    # Capture réseau
    CAPTURE_INTERFACE = 'lo'  # Interface par défaut (localhost pour démo)
    CAPTURE_BUFFER_SIZE = 1000  # Taille du buffer de paquets
    SIMULATION_MODE = True  # Mode simulation (pas besoin de root)
    
    # Détection
    DETECTION_TYPES = [
        'DDoS',
        'Port Scan',
        'Malware',
        'SQL Injection',
        'XSS',
        'Brute Force',
        'Intrusion',
        'Unknown'
    ]
    
    # Sévérité
    SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    
    # Alertes
    MAX_ALERTS_DISPLAY = 50  # Nombre max d'alertes affichées
    ALERT_RETENTION_DAYS = 30  # Rétention des alertes en jours
    AUTO_CLEANUP_ENABLED = True  # Nettoyage automatique des vieilles données
    
    # Performance
    MAX_PACKETS_PER_SECOND = 1000
    STATS_UPDATE_INTERVAL = 5  # Intervalle de mise à jour des stats (secondes)
    
    # IPs malveillantes connues (pour simulation)
    MALICIOUS_IPS = [
        '203.0.113.1',
        '198.51.100.42',
        '192.0.2.123',
        '10.0.0.666'
    ]
    
    # Ports suspects
    SUSPICIOUS_PORTS = [
        23,    # Telnet
        135,   # Windows RPC
        139,   # NetBIOS
        445,   # SMB
        1433,  # SQL Server
        3389,  # RDP
        4444,  # Metasploit
        5900,  # VNC
        6667,  # IRC
        31337  # Back Orifice
    ]
    
    # Ports Command & Control
    C2_PORTS = [4444, 6667, 31337, 8080, 9999]
    
    # CORS
    CORS_ORIGINS = ['*']  # En production, spécifier les domaines autorisés
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = 'logs/ids.log'
    LOG_MAX_SIZE = 10 * 1024 * 1024  # 10 MB
    LOG_BACKUP_COUNT = 5
    
    # Export
    EXPORT_FORMATS = ['json', 'csv', 'txt', 'pdf']
    # Export vers le dossier Téléchargements de l'utilisateur
    import os
    EXPORT_DIR = os.path.join(os.path.expanduser('~'), 'Downloads', 'IDS_Exports')
        
    # Render.com specific
    IS_RENDER = os.environ.get('RENDER', 'False').lower() == 'true'
    
    @classmethod
    def init_directories(cls):
        """Créer les répertoires nécessaires"""
        directories = [
            os.path.dirname(cls.DATABASE_PATH),
            cls.DATABASE_BACKUP_PATH,
            os.path.dirname(cls.ML_MODEL_PATH),
            os.path.dirname(cls.LOG_FILE),
            cls.EXPORT_DIR
        ]
        
        for directory in directories:
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                print(f"[Config] Répertoire créé : {directory}")
    
    @classmethod
    def get_database_url(cls):
        """Obtenir l'URL de la base de données"""
        # SQLite uniquement
        db_path = cls.DATABASE_PATH
        if not os.path.isabs(db_path):
            db_path = os.path.join(os.path.dirname(__file__), '..', db_path)
        return f'sqlite:///{db_path}'
    
    @classmethod
    def validate_config(cls):
        """Valider la configuration"""
        errors = []
        
        # Vérifier les valeurs critiques
        if cls.ML_DETECTION_THRESHOLD < 0 or cls.ML_DETECTION_THRESHOLD > 1:
            errors.append("ML_DETECTION_THRESHOLD doit être entre 0 et 1")
        
        if cls.ML_CONTAMINATION < 0 or cls.ML_CONTAMINATION > 0.5:
            errors.append("ML_CONTAMINATION doit être entre 0 et 0.5")
        
        if cls.PORT < 1 or cls.PORT > 65535:
            errors.append("PORT doit être entre 1 et 65535")
        
        if errors:
            raise ValueError(f"Erreurs de configuration : {', '.join(errors)}")
        
        return True
    
    @classmethod
    def display_config(cls):
        """Afficher la configuration au démarrage"""
        print("\n" + "="*60)
        print(f"  {cls.APP_NAME} v{cls.VERSION}")
        print("="*60)
        print(f"🌐 Serveur      : {cls.HOST}:{cls.PORT}")
        print(f"💾 Base données : SQLite ({cls.DATABASE_PATH})")
        print(f"🤖 Modèle ML    : {cls.ML_MODEL_PATH}")
        print(f"📊 Seuil détect.: {cls.ML_DETECTION_THRESHOLD}")
        print(f"🔍 Mode simul.  : {'Activé' if cls.SIMULATION_MODE else 'Désactivé'}")
        print(f"🐛 Debug        : {'Activé' if cls.DEBUG else 'Désactivé'}")
        if cls.IS_RENDER:
            print(f"☁️  Plateforme   : Render.com")
        print("="*60 + "\n")


# Configuration de développement
class DevelopmentConfig(Config):
    """Configuration pour développement"""
    DEBUG = True
    SIMULATION_MODE = True


# Configuration de production
class ProductionConfig(Config):
    """Configuration pour production"""
    DEBUG = False
    # En production, charger SECRET_KEY depuis variable d'environnement
    _secret = os.environ.get('SECRET_KEY')
    if _secret:
        SECRET_KEY = _secret
    # Sinon, utiliser la clé par défaut héritée de Config


# Sélectionner la configuration selon l'environnement
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Obtenir la configuration appropriée"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config_by_name.get(env, DevelopmentConfig)