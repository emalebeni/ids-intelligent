"""
Moteur de Machine Learning pour la détection d'anomalies
Version améliorée avec plus d'algorithmes
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple, Optional
import pickle
import os
from datetime import datetime
from collections import Counter


class AnomalyDetector:
    """Détecteur d'anomalies utilisant Isolation Forest"""
    
    def __init__(self, contamination=0.1, n_estimators=100):
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = [
            'payload_size',
            'source_port',
            'destination_port',
            'is_encrypted',
            'port_category_system',
            'port_category_registered',
            'port_category_dynamic'
        ]
    
    def _extract_features(self, packet_data: Dict) -> np.array:
        """Extrait les features d'un paquet"""
        # Port category one-hot encoding
        port_cat = packet_data.get('port_category', 'dynamic')
        port_system = 1 if port_cat == 'system' else 0
        port_registered = 1 if port_cat == 'registered' else 0
        port_dynamic = 1 if port_cat == 'dynamic' else 0
        
        features = [
            packet_data.get('payload_size', 0),
            packet_data.get('source_port', 0),
            packet_data.get('destination_port', 0),
            1 if packet_data.get('is_encrypted', False) else 0,
            port_system,
            port_registered,
            port_dynamic
        ]
        
        return np.array(features).reshape(1, -1)
    
    def train(self, training_data: List[Dict]):
        """Entraîne le modèle"""
        if len(training_data) < 10:
            print("[AnomalyDetector] Pas assez de données pour l'entraînement")
            return False
        
        print(f"[AnomalyDetector] Entraînement avec {len(training_data)} exemples...")
        
        # Extraire les features
        X = np.array([self._extract_features(d).flatten() for d in training_data])
        
        # Normaliser
        X_scaled = self.scaler.fit_transform(X)
        
        # Entraîner
        self.model.fit(X_scaled)
        self.is_trained = True
        
        print("[AnomalyDetector] Entraînement terminé")
        return True
    
    def predict(self, packet_data: Dict) -> Tuple[bool, float]:
        """
        Prédit si un paquet est une anomalie
        Retourne: (is_anomaly, confidence_score)
        """
        features = self._extract_features(packet_data)
        
        if self.is_trained:
            # Normaliser
            features_scaled = self.scaler.transform(features)
            
            # Prédire
            prediction = self.model.predict(features_scaled)[0]
            score = self.model.score_samples(features_scaled)[0]
            
            # -1 = anomalie, 1 = normal
            is_anomaly = (prediction == -1)
            
            # Convertir le score en confiance (0-1)
            confidence = self._score_to_confidence(score)
            
            return is_anomaly, confidence
        else:
            # Si pas entraîné, utiliser des heuristiques
            return self._heuristic_detection(packet_data)
    
    def _score_to_confidence(self, score: float) -> float:
        """Convertit le score Isolation Forest en confiance"""
        # Score typique: -0.5 à 0.5
        # On normalise entre 0 et 1
        confidence = max(0, min(1, (0.5 - score) / 1.0))
        return round(confidence, 3)
    
    def _heuristic_detection(self, packet_data: Dict) -> Tuple[bool, float]:
        """Détection heuristique si le modèle n'est pas entraîné"""
        confidence = 0.5
        
        # Ports suspects
        suspicious_ports = [23, 135, 139, 445, 1433, 3389, 4444, 5900, 6667, 31337]
        if packet_data.get('destination_port', 0) in suspicious_ports:
            confidence += 0.3
        
        # Payload anormal
        payload_size = packet_data.get('payload_size', 0)
        if payload_size > 5000 or payload_size == 0:
            confidence += 0.15
        
        # Port source élevé + port dest système
        if packet_data.get('source_port', 0) > 49152 and packet_data.get('port_category') == 'system':
            confidence += 0.1
        
        is_anomaly = confidence >= 0.7
        return is_anomaly, min(confidence, 1.0)
    
    def save(self, filepath: str) -> bool:
        """Sauvegarde le modèle"""
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'is_trained': self.is_trained,
                'feature_names': self.feature_names,
                'timestamp': datetime.now().isoformat()
            }
            
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            
            print(f"[AnomalyDetector] Modèle sauvegardé: {filepath}")
            return True
        except Exception as e:
            print(f"[AnomalyDetector] Erreur sauvegarde: {e}")
            return False
    
    def load(self, filepath: str) -> bool:
        """Charge le modèle"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.is_trained = model_data['is_trained']
            self.feature_names = model_data['feature_names']
            
            print(f"[AnomalyDetector] Modèle chargé: {filepath}")
            return True
        except Exception as e:
            print(f"[AnomalyDetector] Erreur chargement: {e}")
            return False


class TrafficAnalyzer:
    """Analyse les patterns de trafic"""
    
    def __init__(self, buffer_size=1000):
        self.buffer_size = buffer_size
        self.packet_buffer = []
        self.ip_counter = Counter()
        self.port_counter = Counter()
        self.protocol_counter = Counter()
    
    def add_packet(self, packet_data: Dict):
        """Ajoute un paquet au buffer d'analyse"""
        self.packet_buffer.append(packet_data)
        
        # Garder seulement les N derniers paquets
        if len(self.packet_buffer) > self.buffer_size:
            self.packet_buffer.pop(0)
        
        # Mettre à jour les compteurs
        self.ip_counter[packet_data.get('source_ip', 'unknown')] += 1
        self.port_counter[packet_data.get('destination_port', 0)] += 1
        self.protocol_counter[packet_data.get('protocol', 'unknown')] += 1
    
    def detect_ddos(self, threshold=100) -> Optional[Dict]:
        """Détecte une attaque DDoS"""
        for ip, count in self.ip_counter.most_common(5):
            if count > threshold:
                return {
                    'type': 'DDoS',
                    'source_ip': ip,
                    'packet_count': count,
                    'confidence': min(count / threshold, 1.0)
                }
        return None
    
    def detect_port_scan(self, threshold=20) -> Optional[Dict]:
        """Détecte un scan de ports"""
        # Vérifier si une IP contacte beaucoup de ports différents
        ip_ports = {}
        for packet in self.packet_buffer:
            ip = packet.get('source_ip', 'unknown')
            port = packet.get('destination_port', 0)
            
            if ip not in ip_ports:
                ip_ports[ip] = set()
            ip_ports[ip].add(port)
        
        for ip, ports in ip_ports.items():
            if len(ports) > threshold:
                return {
                    'type': 'Port Scan',
                    'source_ip': ip,
                    'ports_scanned': len(ports),
                    'confidence': min(len(ports) / threshold, 1.0)
                }
        return None
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques d'analyse"""
        return {
            'buffer_size': len(self.packet_buffer),
            'top_ips': dict(self.ip_counter.most_common(10)),
            'top_ports': dict(self.port_counter.most_common(10)),
            'protocols': dict(self.protocol_counter)
        }
    
    def reset(self):
        """Réinitialise l'analyseur"""
        self.packet_buffer.clear()
        self.ip_counter.clear()
        self.port_counter.clear()
        self.protocol_counter.clear()


class ThreatIntelligence:
    """Base de connaissances sur les menaces"""
    
    def __init__(self):
        # IPs malveillantes connues
        self.malicious_ips = {
            '203.0.113.1': 'Botnet C2 Server',
            '198.51.100.42': 'Malware Distribution',
            '192.0.2.123': 'DDoS Source',
            '10.0.0.666': 'Test Malicious IP'
        }
        
        # Ports Command & Control connus
        self.c2_ports = {
            4444: 'Metasploit',
            6667: 'IRC Botnet',
            31337: 'Back Orifice',
            8080: 'HTTP Proxy/C2',
            9999: 'Generic C2'
        }
        
        # Signatures d'attaques
        self.attack_signatures = {}
    
    def is_malicious_ip(self, ip: str) -> Tuple[bool, str]:
        """Vérifie si une IP est malveillante"""
        if ip in self.malicious_ips:
            return True, self.malicious_ips[ip]
        return False, ""
    
    def is_c2_port(self, port: int) -> Tuple[bool, str]:
        """Vérifie si un port est utilisé pour C2"""
        if port in self.c2_ports:
            return True, self.c2_ports[port]
        return False, ""
    
    def add_malicious_ip(self, ip: str, description: str):
        """Ajoute une IP malveillante"""
        self.malicious_ips[ip] = description
        print(f"[ThreatIntel] IP ajoutée: {ip} - {description}")
    
    def get_threat_info(self, ip: str = None, port: int = None) -> Dict:
        """Retourne les informations sur une menace"""
        info = {'threats': []}
        
        if ip:
            is_malicious, desc = self.is_malicious_ip(ip)
            if is_malicious:
                info['threats'].append({
                    'type': 'Malicious IP',
                    'value': ip,
                    'description': desc
                })
        
        if port:
            is_c2, desc = self.is_c2_port(port)
            if is_c2:
                info['threats'].append({
                    'type': 'C2 Port',
                    'value': port,
                    'description': desc
                })
        
        return info


class PatternRecognizer:
    """Reconnaît les patterns d'attaques"""
    
    def __init__(self):
        self.patterns = {
            'sql_injection': [
                'SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE',
                'DROP', "OR 1=1", "' OR '", 'EXEC', '--'
            ],
            'xss': [
                '<script', 'javascript:', 'onerror=', 'onload=',
                'alert(', '<iframe', 'document.cookie'
            ],
            'directory_traversal': [
                '../', '..\\', '%2e%2e/', '%2e%2e%5c'
            ],
            'command_injection': [
                ';cat ', '|ls ', '`whoami`', '$(uname)', '&net '
            ]
        }
    
    def detect_pattern(self, payload: str) -> Optional[Dict]:
        """Détecte un pattern d'attaque dans le payload"""
        if not payload:
            return None
        
        payload_lower = payload.lower()
        
        for attack_type, keywords in self.patterns.items():
            for keyword in keywords:
                if keyword.lower() in payload_lower:
                    return {
                        'type': attack_type,
                        'keyword': keyword,
                        'confidence': 0.8
                    }
        
        return None
    
    def add_pattern(self, attack_type: str, keywords: List[str]):
        """Ajoute un nouveau pattern"""
        if attack_type not in self.patterns:
            self.patterns[attack_type] = []
        self.patterns[attack_type].extend(keywords)