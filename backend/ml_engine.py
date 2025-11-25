"""
Module ML Engine pour la détection d'anomalies et l'analyse de menaces
Version améliorée avec gestion de l'absence de scikit-learn
"""

# Imports standards
from typing import Dict, List, Tuple
import random
import time
from datetime import datetime

# Imports ML (avec gestion d'absence)
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    import pandas as pd
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("⚠️ Scikit-learn non disponible - Mode détection heuristique activé")


class AnomalyDetector:
    """
    Détecteur d'anomalies utilisant Isolation Forest
    Fonctionne en mode heuristique si scikit-learn n'est pas disponible
    """
    
    def __init__(self, contamination=0.1, n_estimators=100):
        """
        Initialise le détecteur d'anomalies
        
        Args:
            contamination: Proportion d'anomalies attendues
            n_estimators: Nombre d'arbres dans la forêt
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.is_trained = False
        
        if SKLEARN_AVAILABLE:
            self.model = IsolationForest(
                contamination=contamination,
                n_estimators=n_estimators,
                random_state=42
            )
        else:
            self.model = None
            print("[AnomalyDetector] Mode heuristique - Pas de modèle ML")
    
    def train(self, data: List[Dict]):
        """
        Entraîne le modèle sur des données
        
        Args:
            data: Liste de dictionnaires contenant les features
        """
        if not SKLEARN_AVAILABLE or len(data) < 10:
            print("[AnomalyDetector] Entraînement impossible - Mode heuristique")
            return
        
        try:
            # Convertir en DataFrame
            df = pd.DataFrame(data)
            
            # Sélectionner les features numériques
            features = ['payload_size', 'source_port', 'destination_port']
            X = df[features].values
            
            # Entraîner le modèle
            self.model.fit(X)
            self.is_trained = True
            
            print(f"[AnomalyDetector] Modèle entraîné sur {len(data)} échantillons")
        except Exception as e:
            print(f"[AnomalyDetector] Erreur entraînement: {e}")
    
    def predict(self, features: Dict) -> Tuple[bool, float]:
        """
        Prédit si un paquet est anormal
        
        Args:
            features: Dictionnaire avec payload_size, source_port, destination_port, etc.
            
        Returns:
            (is_anomaly, confidence_score)
        """
        # Mode heuristique si sklearn absent ou modèle non entraîné
        if not SKLEARN_AVAILABLE or not self.is_trained:
            return self._heuristic_detection(features)
        
        try:
            # Préparer les features
            X = [[
                features.get('payload_size', 0),
                features.get('source_port', 0),
                features.get('destination_port', 0)
            ]]
            
            # Prédiction
            prediction = self.model.predict(X)[0]
            is_anomaly = (prediction == -1)
            
            # Score de confiance (approximation)
            score = self.model.score_samples(X)[0]
            confidence = abs(score) * 0.5 + 0.5
            confidence = min(max(confidence, 0.0), 1.0)
            
            return is_anomaly, confidence
            
        except Exception as e:
            print(f"[AnomalyDetector] Erreur prédiction: {e}")
            return self._heuristic_detection(features)
    
    def _heuristic_detection(self, features: Dict) -> Tuple[bool, float]:
        """
        Détection heuristique sans ML
        Basée sur des règles simples mais efficaces
        
        Args:
            features: Dictionnaire des caractéristiques du paquet
            
        Returns:
            (is_anomaly, confidence_score)
        """
        confidence = 0.0
        
        # Ports suspects (services connus pour attaques)
        suspicious_ports = [23, 135, 139, 445, 1433, 3389, 4444, 5900, 6667, 31337]
        
        dest_port = features.get('destination_port', 0)
        source_port = features.get('source_port', 0)
        payload_size = features.get('payload_size', 0)
        
        # Règle 1: Port de destination suspect
        if dest_port in suspicious_ports:
            confidence += 0.3
        
        # Règle 2: Payload anormalement grand ou petit
        if payload_size > 10000 or payload_size < 10:
            confidence += 0.15
        
        # Règle 3: Port source élevé + port dest système
        if source_port > 49152 and dest_port < 1024:
            confidence += 0.1
        
        # Règle 4: Port source privilégié (suspect)
        if source_port < 1024 and source_port not in [80, 443, 22]:
            confidence += 0.2
        
        # Règle 5: Pattern aléatoire
        confidence += random.uniform(0, 0.1)
        
        is_anomaly = confidence >= 0.4
        
        return is_anomaly, min(confidence, 1.0)
    
    def save(self, filepath: str):
        """Sauvegarde le modèle"""
        if not SKLEARN_AVAILABLE:
            print("[AnomalyDetector] Sauvegarde impossible - Pas de sklearn")
            return
        
        try:
            import joblib
            joblib.dump(self.model, filepath)
            print(f"[AnomalyDetector] Modèle sauvegardé: {filepath}")
        except Exception as e:
            print(f"[AnomalyDetector] Erreur sauvegarde: {e}")
    
    def load(self, filepath: str):
        """Charge un modèle sauvegardé"""
        if not SKLEARN_AVAILABLE:
            print("[AnomalyDetector] Chargement impossible - Pas de sklearn")
            return
        
        try:
            import joblib
            self.model = joblib.load(filepath)
            self.is_trained = True
            print(f"[AnomalyDetector] Modèle chargé: {filepath}")
        except Exception as e:
            print(f"[AnomalyDetector] Erreur chargement: {e}")


class TrafficAnalyzer:
    """
    Analyseur de trafic réseau pour détecter des patterns
    """
    
    def __init__(self, buffer_size=1000):
        """
        Initialise l'analyseur
        
        Args:
            buffer_size: Taille du buffer pour l'historique
        """
        self.buffer_size = buffer_size
        self.packet_buffer = []
        self.ip_counter = {}
        self.port_counter = {}
        self.protocol_counter = {}
    
    def add_packet(self, packet: Dict):
        """
        Ajoute un paquet à l'analyse
        
        Args:
            packet: Dictionnaire contenant les infos du paquet
        """
        self.packet_buffer.append(packet)
        
        # Garder seulement les N derniers paquets
        if len(self.packet_buffer) > self.buffer_size:
            self.packet_buffer.pop(0)
        
        # Compter les IPs sources
        source_ip = packet.get('source_ip', 'unknown')
        self.ip_counter[source_ip] = self.ip_counter.get(source_ip, 0) + 1
        
        # Compter les ports
        dest_port = packet.get('destination_port', 0)
        self.port_counter[dest_port] = self.port_counter.get(dest_port, 0) + 1
        
        # Compter les protocoles
        protocol = packet.get('protocol', 'unknown')
        self.protocol_counter[protocol] = self.protocol_counter.get(protocol, 0) + 1
    
    def detect_ddos(self, threshold=100) -> Dict:
        """
        Détecte une attaque DDoS potentielle
        
        Args:
            threshold: Nombre de paquets d'une IP pour considérer DDoS
            
        Returns:
            Dictionnaire avec les détails de l'attaque ou None
        """
        for ip, count in self.ip_counter.items():
            if count > threshold:
                return {
                    'type': 'DDoS',
                    'source_ip': ip,
                    'packet_count': count,
                    'severity': 'CRITICAL' if count > 200 else 'HIGH'
                }
        return None
    
    def detect_port_scan(self, threshold=20) -> Dict:
        """
        Détecte un scan de ports
        
        Args:
            threshold: Nombre de ports différents pour considérer scan
            
        Returns:
            Dictionnaire avec les détails ou None
        """
        # Compter les ports uniques par IP source
        ip_ports = {}
        for packet in self.packet_buffer:
            source = packet.get('source_ip', 'unknown')
            dest_port = packet.get('destination_port', 0)
            
            if source not in ip_ports:
                ip_ports[source] = set()
            ip_ports[source].add(dest_port)
        
        # Vérifier si une IP scanne beaucoup de ports
        for ip, ports in ip_ports.items():
            if len(ports) > threshold:
                return {
                    'type': 'Port Scan',
                    'source_ip': ip,
                    'ports_scanned': len(ports),
                    'severity': 'HIGH'
                }
        return None
    
    def get_statistics(self) -> Dict:
        """
        Retourne les statistiques du trafic
        
        Returns:
            Dictionnaire avec les stats
        """
        return {
            'total_packets': len(self.packet_buffer),
            'unique_ips': len(self.ip_counter),
            'unique_ports': len(self.port_counter),
            'top_ips': sorted(self.ip_counter.items(), key=lambda x: x[1], reverse=True)[:5],
            'top_ports': sorted(self.port_counter.items(), key=lambda x: x[1], reverse=True)[:5],
            'protocols': dict(self.protocol_counter)
        }
    
    def reset(self):
        """Réinitialise les compteurs"""
        self.packet_buffer = []
        self.ip_counter = {}
        self.port_counter = {}
        self.protocol_counter = {}


class ThreatIntelligence:
    """
    Base de connaissances des menaces
    """
    
    def __init__(self):
        """Initialise la base de connaissances"""
        # IPs malveillantes connues (exemples)
        self.malicious_ips = {
            '203.0.113.1': 'Botnet C&C Server',
            '198.51.100.42': 'Known Malware Distribution',
            '192.0.2.123': 'Phishing Campaign Source',
            '10.0.0.666': 'Suspicious Internal Activity'
        }
        
        # Ports C&C connus
        self.c2_ports = {
            4444: 'Metasploit Default',
            6667: 'IRC Botnet',
            31337: 'Back Orifice',
            8080: 'HTTP Proxy/C2',
            9999: 'Generic C2'
        }
    
    def is_malicious_ip(self, ip: str) -> Tuple[bool, str]:
        """
        Vérifie si une IP est malveillante
        
        Args:
            ip: Adresse IP à vérifier
            
        Returns:
            (is_malicious, description)
        """
        if ip in self.malicious_ips:
            return True, self.malicious_ips[ip]
        return False, ""
    
    def is_c2_port(self, port: int) -> Tuple[bool, str]:
        """
        Vérifie si un port est utilisé pour C&C
        
        Args:
            port: Numéro de port
            
        Returns:
            (is_c2, description)
        """
        if port in self.c2_ports:
            return True, self.c2_ports[port]
        return False, ""
    
    def add_malicious_ip(self, ip: str, description: str):
        """Ajoute une IP à la liste des menaces"""
        self.malicious_ips[ip] = description
    
    def get_threat_info(self, ip: str = None, port: int = None) -> Dict:
        """
        Récupère les infos de menace
        
        Args:
            ip: IP à rechercher (optionnel)
            port: Port à rechercher (optionnel)
            
        Returns:
            Dictionnaire avec les infos
        """
        info = {}
        
        if ip:
            is_mal, desc = self.is_malicious_ip(ip)
            info['ip'] = {'is_malicious': is_mal, 'description': desc}
        
        if port:
            is_c2, desc = self.is_c2_port(port)
            info['port'] = {'is_c2': is_c2, 'description': desc}
        
        return info


class PatternRecognizer:
    """
    Reconnaissance de patterns d'attaque dans les payloads
    """
    
    def __init__(self):
        """Initialise les patterns"""
        self.patterns = {
            'sql_injection': [
                "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP",
                "OR 1=1", "' OR '", "EXEC", "--"
            ],
            'xss': [
                "<script", "javascript:", "onerror=", "onload=", "alert(",
                "<iframe", "document.cookie"
            ],
            'directory_traversal': [
                "../", "..\\", "%2e%2e/", "%2e%2e%5c"
            ],
            'command_injection': [
                ";cat", "|ls", "`whoami`", "$(uname)", "&net"
            ]
        }
    
    def detect_pattern(self, payload: str) -> Dict:
        """
        Détecte des patterns dans un payload
        
        Args:
            payload: Contenu à analyser
            
        Returns:
            Dictionnaire avec le type et la confiance ou None
        """
        if not payload:
            return None
        
        payload_upper = payload.upper()
        
        for attack_type, patterns in self.patterns.items():
            for pattern in patterns:
                if pattern.upper() in payload_upper:
                    return {
                        'type': attack_type,
                        'pattern': pattern,
                        'confidence': 0.8
                    }
        
        return None
    
    def add_pattern(self, attack_type: str, pattern: str):
        """
        Ajoute un nouveau pattern
        
        Args:
            attack_type: Type d'attaque
            pattern: Pattern à détecter
        """
        if attack_type not in self.patterns:
            self.patterns[attack_type] = []
        self.patterns[attack_type].append(pattern)