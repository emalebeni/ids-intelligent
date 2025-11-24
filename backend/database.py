"""
Gestionnaire de base de données SQLite pour le système IDS
Version améliorée avec plus de fonctionnalités
"""

import sqlite3
import os
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from contextlib import contextmanager


class DatabaseManager:
    """Gère toutes les interactions avec SQLite"""
    
    def __init__(self, db_path='../database/ids.db'):
        self.db_path = db_path
        self.conn = None
        
    @contextmanager
    def get_connection(self):
        """Context manager pour gérer les connexions"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def connect(self):
        """Établit la connexion à la base de données"""
        try:
            # Créer le dossier si nécessaire
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
            
            # Connexion SQLite
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            
            # Optimisations SQLite
            self.conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA cache_size=10000")
            self.conn.execute("PRAGMA temp_store=MEMORY")
            
            print(f"[DatabaseManager] Connexion SQLite établie : {self.db_path}")
            return True
            
        except Exception as e:
            print(f"[DatabaseManager] Erreur de connexion: {e}")
            return False
    
    def disconnect(self):
        """Ferme la connexion"""
        if self.conn:
            self.conn.close()
            print("[DatabaseManager] Connexion fermée")
    
    def init_database(self):
        """Initialise le schéma de la base de données"""
        cursor = self.conn.cursor()
        
        # Table des alertes (améliorée)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                type TEXT NOT NULL,
                description TEXT,
                source_ip TEXT,
                target_ip TEXT,
                source_port INTEGER,
                target_port INTEGER,
                protocol TEXT,
                confidence_score REAL,
                status TEXT DEFAULT 'NEW',
                assigned_to TEXT,
                is_notified INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Index pour les requêtes fréquentes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type)")
        
        # Table des incidents
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT NOT NULL,
                priority TEXT NOT NULL,
                root_cause TEXT,
                alert_ids TEXT,
                affected_systems TEXT,
                remediation_steps TEXT,
                notes TEXT
            )
        """)
        
        # Table des paquets (échantillonnage seulement)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                packet_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                payload_size INTEGER,
                is_threat INTEGER DEFAULT 0,
                threat_type TEXT
            )
        """)
        
        # Table des utilisateurs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                last_login TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table des règles de sécurité
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_rules (
                rule_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                condition TEXT,
                action TEXT,
                is_active INTEGER DEFAULT 1,
                priority INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table des statistiques (nouvelle)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                packets_analyzed INTEGER DEFAULT 0,
                threats_detected INTEGER DEFAULT 0,
                alerts_generated INTEGER DEFAULT 0,
                false_positives INTEGER DEFAULT 0,
                detection_rate REAL DEFAULT 0.0,
                period TEXT DEFAULT 'hour'
            )
        """)
        
        # Table des logs système (nouvelle)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                category TEXT,
                message TEXT,
                details TEXT
            )
        """)
        
        # Table de configuration (nouvelle)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT,
                type TEXT,
                description TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        self.conn.commit()
        print("[DatabaseManager] Base de données initialisée")
        
        # Insérer des données de test
        self._insert_test_data(cursor)
    
    def _insert_test_data(self, cursor):
        """Insère des données de test"""
        try:
            # Utilisateur admin par défaut
            cursor.execute("""
                INSERT OR IGNORE INTO users (user_id, username, email, role, is_active)
                VALUES ('admin_001', 'admin', 'admin@ids.local', 'admin', 1)
            """)
            
            # Règles de sécurité par défaut
            rules = [
                ('rule_001', 'Block DDoS', 'Bloque les attaques DDoS détectées', 'packets > 1000/sec', 'BLOCK', 1, 1),
                ('rule_002', 'Alert Port Scan', 'Alerte lors de scan de ports', 'sequential_ports', 'ALERT', 1, 2),
                ('rule_003', 'Block Malware C2', 'Bloque les communications C&C', 'suspicious_dest', 'BLOCK', 1, 1),
                ('rule_004', 'Alert SQL Injection', 'Détecte les tentatives SQL Injection', 'sql_pattern', 'ALERT', 1, 3),
                ('rule_005', 'Block Brute Force', 'Bloque les attaques brute force', 'failed_logins > 5', 'BLOCK', 1, 2)
            ]
            
            for rule in rules:
                cursor.execute("""
                    INSERT OR IGNORE INTO security_rules 
                    (rule_id, name, description, condition, action, is_active, priority)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, rule)
            
            # Configuration par défaut
            configs = [
                ('ml_threshold', '0.7', 'float', 'Seuil de détection ML'),
                ('max_alerts', '1000', 'int', 'Nombre max d\'alertes à garder'),
                ('auto_block', 'true', 'bool', 'Blocage automatique activé'),
                ('notification_enabled', 'true', 'bool', 'Notifications activées')
            ]
            
            for config in configs:
                cursor.execute("""
                    INSERT OR IGNORE INTO config (key, value, type, description)
                    VALUES (?, ?, ?, ?)
                """, config)
            
            self.conn.commit()
            print("[DatabaseManager] Données de test insérées")
            
        except Exception as e:
            print(f"[DatabaseManager] Erreur insertion données: {e}")
    
    # ========== MÉTHODES POUR LES ALERTES ==========
    
    def save_alert(self, alert_dict: Dict) -> bool:
        """Sauvegarde une alerte"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO alerts (
                        alert_id, timestamp, severity, type, description,
                        source_ip, target_ip, source_port, target_port,
                        protocol, confidence_score, status, assigned_to, is_notified
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_dict['alert_id'],
                    alert_dict['timestamp'],
                    alert_dict['severity'],
                    alert_dict['type'],
                    alert_dict['description'],
                    alert_dict.get('source_ip'),
                    alert_dict.get('target_ip'),
                    alert_dict.get('source_port'),
                    alert_dict.get('target_port'),
                    alert_dict.get('protocol'),
                    alert_dict.get('confidence_score', 0.0),
                    alert_dict.get('status', 'NEW'),
                    alert_dict.get('assigned_to'),
                    1 if alert_dict.get('is_notified') else 0
                ))
            return True
        except Exception as e:
            print(f"[DatabaseManager] Erreur sauvegarde alerte: {e}")
            return False
    
    def get_alerts(self, limit: int = 100, status: Optional[str] = None, 
                   severity: Optional[str] = None, type: Optional[str] = None,
                   start_date: Optional[str] = None, end_date: Optional[str] = None) -> List[Dict]:
        """Récupère les alertes avec filtres"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM alerts WHERE 1=1"
                params = []
                
                if status:
                    query += " AND status = ?"
                    params.append(status)
                
                if severity:
                    query += " AND severity = ?"
                    params.append(severity)
                
                if type:
                    query += " AND type = ?"
                    params.append(type)
                
                if start_date:
                    query += " AND timestamp >= ?"
                    params.append(start_date)
                
                if end_date:
                    query += " AND timestamp <= ?"
                    params.append(end_date)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
                
        except Exception as e:
            print(f"[DatabaseManager] Erreur récupération alertes: {e}")
            return []
    
    def get_alert_by_id(self, alert_id: str) -> Optional[Dict]:
        """Récupère une alerte par son ID"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            print(f"[DatabaseManager] Erreur: {e}")
            return None
    
    def update_alert_status(self, alert_id: str, new_status: str) -> bool:
        """Met à jour le statut d'une alerte"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE alerts 
                    SET status = ?, updated_at = ? 
                    WHERE alert_id = ?
                """, (new_status, datetime.now().isoformat(), alert_id))
            return True
        except Exception as e:
            print(f"[DatabaseManager] Erreur mise à jour alerte: {e}")
            return False
    
    def delete_old_alerts(self, days: int = 30) -> int:
        """Supprime les alertes plus vieilles que X jours"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    DELETE FROM alerts WHERE timestamp < ? AND status = 'RESOLVED'
                """, (cutoff_date,))
                deleted = cursor.rowcount
                print(f"[DatabaseManager] {deleted} alertes supprimées")
            return deleted
        except Exception as e:
            print(f"[DatabaseManager] Erreur suppression alertes: {e}")
            return 0
    
    # ========== MÉTHODES POUR LES STATISTIQUES ==========
    
    def save_statistics(self, stats: Dict) -> bool:
        """Sauvegarde les statistiques"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO statistics (
                        timestamp, packets_analyzed, threats_detected,
                        alerts_generated, false_positives, detection_rate, period
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().isoformat(),
                    stats.get('packets_analyzed', 0),
                    stats.get('threats_detected', 0),
                    stats.get('alerts_generated', 0),
                    stats.get('false_positives', 0),
                    stats.get('detection_rate', 0.0),
                    stats.get('period', 'hour')
                ))
            return True
        except Exception as e:
            print(f"[DatabaseManager] Erreur sauvegarde stats: {e}")
            return False
    
    def get_statistics(self, period: str = 'day', limit: int = 24) -> List[Dict]:
        """Récupère les statistiques par période"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM statistics 
                    WHERE period = ?
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (period, limit))
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            print(f"[DatabaseManager] Erreur: {e}")
            return []
    
    def get_dashboard_stats(self) -> Dict:
        """Récupère les statistiques pour le dashboard"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Total alertes
                cursor.execute("SELECT COUNT(*) as count FROM alerts")
                total_alerts = cursor.fetchone()['count']
                
                # Alertes actives
                cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE status IN ('NEW', 'INVESTIGATING')")
                active_alerts = cursor.fetchone()['count']
                
                # Incidents ouverts
                cursor.execute("SELECT COUNT(*) as count FROM incidents WHERE status IN ('OPEN', 'INVESTIGATING')")
                open_incidents = cursor.fetchone()['count']
                
                # Alertes par sévérité
                cursor.execute("""
                    SELECT severity, COUNT(*) as count 
                    FROM alerts 
                    GROUP BY severity
                """)
                alerts_by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
                
                # Alertes par type
                cursor.execute("""
                    SELECT type, COUNT(*) as count 
                    FROM alerts 
                    GROUP BY type
                    ORDER BY count DESC
                    LIMIT 10
                """)
                alerts_by_type = {row['type']: row['count'] for row in cursor.fetchall()}
                
                # Top IPs sources
                cursor.execute("""
                    SELECT source_ip, COUNT(*) as count 
                    FROM alerts 
                    WHERE source_ip IS NOT NULL
                    GROUP BY source_ip
                    ORDER BY count DESC
                    LIMIT 10
                """)
                top_source_ips = [dict(row) for row in cursor.fetchall()]
                
                # Statistiques dernières 24h
                last_24h = (datetime.now() - timedelta(hours=24)).isoformat()
                cursor.execute("""
                    SELECT 
                        COUNT(*) as alerts_24h,
                        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_24h
                    FROM alerts 
                    WHERE timestamp >= ?
                """, (last_24h,))
                stats_24h = dict(cursor.fetchone())
                
                return {
                    'total_alerts': total_alerts,
                    'active_alerts': active_alerts,
                    'open_incidents': open_incidents,
                    'alerts_by_severity': alerts_by_severity,
                    'alerts_by_type': alerts_by_type,
                    'top_source_ips': top_source_ips,
                    'stats_24h': stats_24h,
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            print(f"[DatabaseManager] Erreur stats dashboard: {e}")
            return {
                'total_alerts': 0,
                'active_alerts': 0,
                'open_incidents': 0,
                'alerts_by_severity': {},
                'alerts_by_type': {},
                'top_source_ips': [],
                'stats_24h': {}
            }
    
    # ========== MÉTHODES POUR LES LOGS ==========
    
    def add_log(self, level: str, category: str, message: str, details: str = None):
        """Ajoute un log système"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO system_logs (timestamp, level, category, message, details)
                    VALUES (?, ?, ?, ?, ?)
                """, (datetime.now().isoformat(), level, category, message, details))
        except Exception as e:
            print(f"[DatabaseManager] Erreur log: {e}")
    
    def get_logs(self, limit: int = 100, level: Optional[str] = None) -> List[Dict]:
        """Récupère les logs système"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                if level:
                    cursor.execute("""
                        SELECT * FROM system_logs 
                        WHERE level = ?
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """, (level, limit))
                else:
                    cursor.execute("""
                        SELECT * FROM system_logs 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """, (limit,))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            print(f"[DatabaseManager] Erreur: {e}")
            return []
    
    # ========== UTILITAIRES ==========
    
    def vacuum(self):
        """Optimise la base de données"""
        try:
            self.conn.execute("VACUUM")
            print("[DatabaseManager] Base de données optimisée")
        except Exception as e:
            print(f"[DatabaseManager] Erreur vacuum: {e}")
    
    def get_database_size(self) -> float:
        """Retourne la taille de la base en MB"""
        try:
            size = os.path.getsize(self.db_path)
            return round(size / (1024 * 1024), 2)
        except:
            return 0.0