"""
Classes du modèle UML implémentées
Version améliorée avec plus de fonctionnalités
"""

from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum
import uuid


# ========== ENUMS ==========

class SeverityLevel(Enum):
    """Niveaux de sévérité"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AlertStatus(Enum):
    """Statuts d'alerte"""
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class IncidentStatus(Enum):
    """Statuts d'incident"""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class Priority(Enum):
    """Priorités d'incident"""
    P1 = "P1"  # Critique - Résoudre immédiatement
    P2 = "P2"  # Haute - Résoudre dans les 4h
    P3 = "P3"  # Moyenne - Résoudre dans les 24h
    P4 = "P4"  # Basse - Résoudre quand possible


class ThreatType(Enum):
    """Types de menaces détectées"""
    DDOS = "DDoS"
    MALWARE = "Malware"
    PORT_SCAN = "Port Scan"
    INTRUSION = "Intrusion"
    SQL_INJECTION = "SQL Injection"
    XSS = "XSS"
    BRUTE_FORCE = "Brute Force"
    UNKNOWN = "Unknown"


class UserRole(Enum):
    """Rôles utilisateur"""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# ========== CLASSES PRINCIPALES ==========

class NetworkPacket:
    """Représente un paquet réseau capturé"""
    
    def __init__(self, source_ip: str, destination_ip: str, 
                 source_port: int = 0, destination_port: int = 0,
                 protocol: str = "TCP", payload_size: int = 0,
                 flags: str = "", raw_data: bytes = b''):
        self.packet_id = str(uuid.uuid4())[:8]
        self.timestamp = datetime.now()
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.source_port = source_port
        self.destination_port = destination_port
        self.protocol = protocol
        self.payload_size = payload_size
        self.flags = flags
        self.raw_data = raw_data
    
    def extract_headers(self) -> Dict:
        """Extrait les headers du paquet"""
        return {
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'flags': self.flags
        }
    
    def is_encrypted(self) -> bool:
        """Vérifie si le paquet est chiffré (HTTPS, SSH, etc.)"""
        encrypted_ports = [443, 22, 993, 995, 8443]
        return self.destination_port in encrypted_ports
    
    def get_protocol_info(self) -> str:
        """Retourne des infos sur le protocole"""
        protocol_names = {
            'TCP': 'Transmission Control Protocol',
            'UDP': 'User Datagram Protocol',
            'ICMP': 'Internet Control Message Protocol',
            'HTTP': 'HyperText Transfer Protocol',
            'HTTPS': 'HTTP Secure'
        }
        return protocol_names.get(self.protocol, self.protocol)
    
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire"""
        return {
            'packet_id': self.packet_id,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'payload_size': self.payload_size,
            'flags': self.flags,
            'is_encrypted': self.is_encrypted()
        }


class TrafficMonitor:
    """Capture et prétraite le trafic réseau"""
    
    def __init__(self, interface: str = "lo", capture_filter: str = ""):
        self.monitor_id = str(uuid.uuid4())[:8]
        self.interface = interface
        self.is_active = False
        self.capture_filter = capture_filter
        self.buffer_size = 1000
        self.packets_per_second = 0
        self.total_packets_captured = 0
    
    def start_capture(self):
        """Démarre la capture"""
        self.is_active = True
        print(f"[TrafficMonitor {self.monitor_id}] Capture démarrée sur {self.interface}")
    
    def stop_capture(self):
        """Arrête la capture"""
        self.is_active = False
        print(f"[TrafficMonitor {self.monitor_id}] Capture arrêtée")
    
    def apply_filter(self, filter_str: str):
        """Applique un filtre de capture"""
        self.capture_filter = filter_str
        print(f"[TrafficMonitor] Filtre appliqué : {filter_str}")
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques de capture"""
        return {
            'monitor_id': self.monitor_id,
            'interface': self.interface,
            'is_active': self.is_active,
            'total_packets': self.total_packets_captured,
            'packets_per_second': self.packets_per_second,
            'buffer_size': self.buffer_size
        }


class AIDetectionEngine:
    """Analyse les paquets avec l'intelligence artificielle"""
    
    def __init__(self):
        self.engine_id = str(uuid.uuid4())[:8]
        self.model_version = "2.0.0"
        self.accuracy_score = 0.95
        self.last_training_date = datetime.now()
        self.is_learning = False
        self.detection_threshold = 0.7
        self.packets_analyzed = 0
        self.threats_detected = 0
    
    def analyze_packet(self, packet: NetworkPacket) -> Dict:
        """Analyse un paquet et retourne une évaluation"""
        self.packets_analyzed += 1
        
        # Extraction des features
        features = self._extract_features(packet)
        
        # Prédiction (simulée pour la démo)
        is_threat, confidence = self._predict(features)
        
        if is_threat:
            self.threats_detected += 1
        
        return {
            'is_threat': is_threat,
            'confidence': confidence,
            'threat_type': self._classify_threat_type(features) if is_threat else None,
            'features': features
        }
    
    def _extract_features(self, packet: NetworkPacket) -> Dict:
        """Extrait les features d'un paquet"""
        return {
            'payload_size': packet.payload_size,
            'source_port': packet.source_port,
            'destination_port': packet.destination_port,
            'is_encrypted': packet.is_encrypted(),
            'protocol': packet.protocol,
            'port_category': self._categorize_port(packet.destination_port)
        }
    
    def _categorize_port(self, port: int) -> str:
        """Catégorise un port"""
        if port < 1024:
            return 'system'
        elif port < 49152:
            return 'registered'
        else:
            return 'dynamic'
    
    def _predict(self, features: Dict) -> tuple:
        """Prédit si c'est une menace (simulation)"""
        # Simulation de prédiction ML
        suspicious_ports = [23, 135, 139, 445, 1433, 3389, 4444, 5900, 6667, 31337]
        
        confidence = 0.5
        
        # Augmenter la confiance si port suspect
        if features['destination_port'] in suspicious_ports:
            confidence += 0.3
        
        # Augmenter si payload anormal
        if features['payload_size'] > 5000 or features['payload_size'] == 0:
            confidence += 0.2
        
        is_threat = confidence >= self.detection_threshold
        
        return is_threat, min(confidence, 1.0)
    
    def _classify_threat_type(self, features: Dict) -> str:
        """Classifie le type de menace"""
        port = features['destination_port']
        
        # Malware C2 ports
        if port in [4444, 6667, 31337]:
            return ThreatType.MALWARE.value
        
        # Ports système vulnérables
        if port in [23, 135, 139, 445]:
            return ThreatType.INTRUSION.value
        
        # RDP/VNC (brute force)
        if port in [3389, 5900]:
            return ThreatType.BRUTE_FORCE.value
        
        return ThreatType.UNKNOWN.value
    
    def train_model(self, training_data: List[Dict]):
        """Entraîne le modèle (simulation)"""
        self.is_learning = True
        print(f"[AI Engine] Entraînement avec {len(training_data)} exemples...")
        self.last_training_date = datetime.now()
        self.is_learning = False
        print("[AI Engine] Entraînement terminé")
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques du moteur"""
        detection_rate = (self.threats_detected / self.packets_analyzed * 100) if self.packets_analyzed > 0 else 0
        
        return {
            'engine_id': self.engine_id,
            'model_version': self.model_version,
            'accuracy_score': self.accuracy_score,
            'packets_analyzed': self.packets_analyzed,
            'threats_detected': self.threats_detected,
            'detection_rate': round(detection_rate, 2),
            'last_training': self.last_training_date.isoformat()
        }


class ThreatClassifier:
    """Classe les menaces détectées"""
    
    def __init__(self):
        self.classifier_id = str(uuid.uuid4())[:8]
        self.threat_types = [t.value for t in ThreatType]
        self.classification_rules = {}
    
    def classify_threat(self, assessment: Dict) -> str:
        """Classifie le type de menace"""
        if 'threat_type' in assessment and assessment['threat_type']:
            return assessment['threat_type']
        return ThreatType.UNKNOWN.value
    
    def determine_severity(self, threat_type: str, confidence: float) -> str:
        """Détermine la sévérité"""
        critical_threats = [ThreatType.DDOS.value, ThreatType.MALWARE.value, 
                          ThreatType.SQL_INJECTION.value]
        
        if threat_type in critical_threats and confidence > 0.8:
            return SeverityLevel.CRITICAL.value
        elif confidence > 0.7:
            return SeverityLevel.HIGH.value
        elif confidence > 0.5:
            return SeverityLevel.MEDIUM.value
        else:
            return SeverityLevel.LOW.value


class Alert:
    """Représente une alerte de sécurité"""
    
    def __init__(self, severity: str, threat_type: str, description: str,
                 source_ip: str, target_ip: str, confidence: float = 0.0,
                 source_port: int = 0, target_port: int = 0, protocol: str = "TCP"):
        self.alert_id = f"alert_{uuid.uuid4().hex[:8]}"
        self.timestamp = datetime.now()
        self.severity = severity
        self.type = threat_type
        self.description = description
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.source_port = source_port
        self.target_port = target_port
        self.protocol = protocol
        self.confidence_score = confidence
        self.status = AlertStatus.NEW.value
        self.assigned_to = None
        self.is_notified = False
    
    def send(self):
        """Envoie l'alerte"""
        self.is_notified = True
        print(f"[Alert {self.alert_id}] Alerte envoyée: {self.type} de {self.source_ip} vers {self.target_ip}")
    
    def escalate(self):
        """Escalade l'alerte"""
        if self.severity == SeverityLevel.MEDIUM.value:
            self.severity = SeverityLevel.HIGH.value
        elif self.severity == SeverityLevel.HIGH.value:
            self.severity = SeverityLevel.CRITICAL.value
        print(f"[Alert {self.alert_id}] Escaladée à {self.severity}")
    
    def mark_as_resolved(self):
        """Marque comme résolue"""
        self.status = AlertStatus.RESOLVED.value
        print(f"[Alert {self.alert_id}] Marquée comme résolue")
    
    def mark_as_false_positive(self):
        """Marque comme faux positif"""
        self.status = AlertStatus.FALSE_POSITIVE.value
        print(f"[Alert {self.alert_id}] Marquée comme faux positif")
    
    def assign_to_analyst(self, analyst_name: str):
        """Assigne à un analyste"""
        self.assigned_to = analyst_name
        self.status = AlertStatus.INVESTIGATING.value
        print(f"[Alert {self.alert_id}] Assignée à {analyst_name}")
    
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire"""
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity,
            'type': self.type,
            'description': self.description,
            'source_ip': self.source_ip,
            'target_ip': self.target_ip,
            'source_port': self.source_port,
            'target_port': self.target_port,
            'protocol': self.protocol,
            'confidence_score': self.confidence_score,
            'status': self.status,
            'assigned_to': self.assigned_to,
            'is_notified': self.is_notified
        }


class Incident:
    """Gère le cycle de vie complet d'un incident"""
    
    def __init__(self, alert: Alert):
        self.incident_id = f"incident_{uuid.uuid4().hex[:8]}"
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        self.status = IncidentStatus.OPEN.value
        self.priority = self._determine_priority(alert.severity)
        self.affected_systems = []
        self.root_cause = ""
        self.remediation_steps = []
        self.investigation_notes = []
        self.related_alerts = [alert.alert_id]
    
    def _determine_priority(self, severity: str) -> str:
        """Détermine la priorité basée sur la sévérité"""
        priority_map = {
            SeverityLevel.CRITICAL.value: Priority.P1.value,
            SeverityLevel.HIGH.value: Priority.P2.value,
            SeverityLevel.MEDIUM.value: Priority.P3.value,
            SeverityLevel.LOW.value: Priority.P4.value
        }
        return priority_map.get(severity, Priority.P4.value)
    
    def investigate(self):
        """Démarre l'investigation"""
        self.status = IncidentStatus.INVESTIGATING.value
        self.updated_at = datetime.now()
        print(f"[Incident {self.incident_id}] Investigation démarrée")
    
    def contain(self):
        """Contient l'incident"""
        self.status = IncidentStatus.CONTAINED.value
        self.updated_at = datetime.now()
        print(f"[Incident {self.incident_id}] Incident contenu")
    
    def remediate(self):
        """Applique la remédiation"""
        self.status = IncidentStatus.RESOLVED.value
        self.updated_at = datetime.now()
        print(f"[Incident {self.incident_id}] Remédiation appliquée")
    
    def close(self):
        """Clôture l'incident"""
        self.status = IncidentStatus.CLOSED.value
        self.updated_at = datetime.now()
        print(f"[Incident {self.incident_id}] Incident clôturé")
    
    def add_note(self, note: str):
        """Ajoute une note d'investigation"""
        timestamp = datetime.now().isoformat()
        self.investigation_notes.append(f"[{timestamp}] {note}")
        self.updated_at = datetime.now()
    
    def to_dict(self) -> Dict:
        """Convertit en dictionnaire"""
        return {
            'incident_id': self.incident_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'status': self.status,
            'priority': self.priority,
            'affected_systems': self.affected_systems,
            'root_cause': self.root_cause,
            'alert_ids': ','.join(self.related_alerts)
        }


class User:
    """Représente un utilisateur du système"""
    
    def __init__(self, username: str, email: str, role: str):
        self.user_id = str(uuid.uuid4())[:8]
        self.username = username
        self.email = email
        self.role = role
        self.is_active = True
        self.last_login = None
        self.preferences = {}
    
    def authenticate(self, password: str) -> bool:
        """Authentifie l'utilisateur (simulation)"""
        # En production, utiliser un hash sécurisé
        self.last_login = datetime.now()
        return True
    
    def has_permission(self, permission: str) -> bool:
        """Vérifie les permissions"""
        admin_permissions = ['all']
        analyst_permissions = ['view_alerts', 'manage_incidents', 'investigate']
        viewer_permissions = ['view_alerts', 'view_reports']
        
        if self.role == UserRole.ADMIN.value:
            return True
        elif self.role == UserRole.ANALYST.value:
            return permission in analyst_permissions
        elif self.role == UserRole.VIEWER.value:
            return permission in viewer_permissions
        
        return False


class SecurityRule:
    """Définit une règle de sécurité"""
    
    def __init__(self, name: str, condition: str, action: str):
        self.rule_id = f"rule_{uuid.uuid4().hex[:6]}"
        self.name = name
        self.description = ""
        self.condition = condition
        self.action = action
        self.is_active = True
        self.priority = 1
        self.created_at = datetime.now()
    
    def evaluate(self, context: Dict) -> bool:
        """Évalue si la règle s'applique (simulation)"""
        # En production, implémenter un moteur de règles complet
        return True
    
    def execute(self):
        """Exécute l'action de la règle"""
        print(f"[Rule {self.rule_id}] Action exécutée: {self.action}")
    
    def enable(self):
        """Active la règle"""
        self.is_active = True
    
    def disable(self):
        """Désactive la règle"""
        self.is_active = False