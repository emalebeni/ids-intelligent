"""
Fonctions utilitaires pour le système IDS
"""

import uuid
import hashlib
import json
import csv
from datetime import datetime
from typing import List, Dict, Any
import os


def generate_id(prefix: str = '') -> str:
    """Génère un ID unique"""
    unique_id = str(uuid.uuid4())[:8]
    if prefix:
        return f"{prefix}_{unique_id}"
    return unique_id


def hash_string(text: str) -> str:
    """Hash une chaîne de caractères avec SHA256"""
    return hashlib.sha256(text.encode()).hexdigest()


def format_timestamp(dt: datetime = None) -> str:
    """Formate un timestamp ISO"""
    if dt is None:
        dt = datetime.now()
    return dt.isoformat()


def parse_timestamp(timestamp_str: str) -> datetime:
    """Parse un timestamp ISO"""
    return datetime.fromisoformat(timestamp_str)


def calculate_confidence_score(features: Dict) -> float:
    """Calcule un score de confiance basé sur les features"""
    score = 0.0
    weights = {
        'anomaly_score': 0.4,
        'pattern_match': 0.3,
        'historical_threat': 0.2,
        'context': 0.1
    }
    
    for key, weight in weights.items():
        if key in features:
            score += features[key] * weight
    
    return round(min(max(score, 0.0), 1.0), 3)


def classify_severity(confidence: float, threat_type: str) -> str:
    """Détermine la sévérité basée sur la confiance et le type"""
    critical_types = ['DDoS', 'Malware', 'SQL Injection']
    
    if threat_type in critical_types and confidence > 0.8:
        return 'CRITICAL'
    elif confidence > 0.7:
        return 'HIGH'
    elif confidence > 0.5:
        return 'MEDIUM'
    else:
        return 'LOW'


def export_to_json(data: List[Dict], filepath: str) -> bool:
    """Exporte des données en JSON"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[Utils] Erreur export JSON: {e}")
        return False


def export_to_csv(data: List[Dict], filepath: str) -> bool:
    """Exporte des données en CSV"""
    try:
        if not data:
            return False
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        return True
    except Exception as e:
        print(f"[Utils] Erreur export CSV: {e}")
        return False


def format_bytes(bytes: int) -> str:
    """Formate une taille en bytes de manière lisible"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024.0:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.2f} PB"


def truncate_string(text: str, max_length: int = 100) -> str:
    """Tronque une chaîne si trop longue"""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."


def validate_ip(ip: str) -> bool:
    """Valide une adresse IP"""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except:
        return False


def validate_port(port: int) -> bool:
    """Valide un numéro de port"""
    return 0 <= port <= 65535


def sanitize_input(text: str) -> str:
    """Nettoie une entrée utilisateur"""
    # Retirer les caractères dangereux
    dangerous = ['<', '>', '"', "'", '&', ';', '|', '`']
    for char in dangerous:
        text = text.replace(char, '')
    return text.strip()


def get_time_ago(timestamp_str: str) -> str:
    """Retourne un temps relatif (il y a X minutes)"""
    try:
        dt = parse_timestamp(timestamp_str)
        now = datetime.now()
        diff = now - dt
        
        seconds = diff.total_seconds()
        
        if seconds < 60:
            return f"il y a {int(seconds)} secondes"
        elif seconds < 3600:
            return f"il y a {int(seconds/60)} minutes"
        elif seconds < 86400:
            return f"il y a {int(seconds/3600)} heures"
        else:
            return f"il y a {int(seconds/86400)} jours"
    except:
        return "date inconnue"


def create_alert_description(threat_type: str, source_ip: str, target_ip: str, 
                            confidence: float, details: str = "") -> str:
    """Crée une description d'alerte formatée"""
    desc = f"Menace {threat_type} détectée"
    desc += f" de {source_ip} vers {target_ip}"
    desc += f" (confiance: {confidence*100:.1f}%)"
    
    if details:
        desc += f". {details}"
    
    return desc


def format_alert_for_display(alert: Dict) -> Dict:
    """Formate une alerte pour l'affichage"""
    return {
        'id': alert['alert_id'],
        'time': get_time_ago(alert['timestamp']),
        'severity': alert['severity'],
        'type': alert['type'],
        'description': truncate_string(alert.get('description', ''), 150),
        'source': alert.get('source_ip', 'Unknown'),
        'target': alert.get('target_ip', 'Unknown'),
        'status': alert.get('status', 'NEW'),
        'confidence': f"{alert.get('confidence_score', 0)*100:.1f}%"
    }


def aggregate_stats_by_hour(alerts: List[Dict]) -> List[Dict]:
    """Agrège les alertes par heure"""
    hourly_stats = {}
    
    for alert in alerts:
        try:
            dt = parse_timestamp(alert['timestamp'])
            hour_key = dt.strftime('%Y-%m-%d %H:00')
            
            if hour_key not in hourly_stats:
                hourly_stats[hour_key] = {
                    'hour': hour_key,
                    'total': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                }
            
            hourly_stats[hour_key]['total'] += 1
            severity = alert.get('severity', 'LOW').lower()
            if severity in hourly_stats[hour_key]:
                hourly_stats[hour_key][severity] += 1
        except:
            continue
    
    return sorted(hourly_stats.values(), key=lambda x: x['hour'])


def calculate_detection_rate(threats_detected: int, total_packets: int) -> float:
    """Calcule le taux de détection"""
    if total_packets == 0:
        return 0.0
    return round((threats_detected / total_packets) * 100, 2)


def is_suspicious_port(port: int, protocol: str = 'TCP') -> bool:
    """Vérifie si un port est suspect"""
    suspicious_tcp = [23, 135, 139, 445, 1433, 3389, 4444, 5900, 6667, 31337]
    suspicious_udp = [69, 135, 137, 138, 161, 162]
    
    if protocol.upper() == 'TCP':
        return port in suspicious_tcp
    elif protocol.upper() == 'UDP':
        return port in suspicious_udp
    
    return False


def detect_sql_injection_pattern(payload: str) -> bool:
    """Détecte des patterns de SQL Injection"""
    sql_keywords = [
        'SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
        'OR 1=1', "' OR '1'='1", 'EXEC', '--', '/*', '*/'
    ]
    
    payload_upper = payload.upper()
    return any(keyword in payload_upper for keyword in sql_keywords)


def detect_xss_pattern(payload: str) -> bool:
    """Détecte des patterns de XSS"""
    xss_patterns = [
        '<script', 'javascript:', 'onerror=', 'onload=',
        'alert(', 'prompt(', 'confirm(', '<iframe'
    ]
    
    payload_lower = payload.lower()
    return any(pattern in payload_lower for pattern in xss_patterns)


def ensure_directory(path: str) -> bool:
    """S'assure qu'un répertoire existe"""
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception as e:
        print(f"[Utils] Erreur création répertoire: {e}")
        return False


def cleanup_old_files(directory: str, days: int = 7) -> int:
    """Nettoie les fichiers plus vieux que X jours"""
    try:
        count = 0
        cutoff_time = datetime.now().timestamp() - (days * 86400)
        
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):
                file_time = os.path.getmtime(filepath)
                if file_time < cutoff_time:
                    os.remove(filepath)
                    count += 1
        
        return count
    except Exception as e:
        print(f"[Utils] Erreur nettoyage fichiers: {e}")
        return 0