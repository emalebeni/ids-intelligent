"""
Application Flask principale pour le système IDS Intelligent
Version 3.0 - Avec Scanner Réel, Explications Simples et Remédiation
"""

from flask import Flask, jsonify, request, send_from_directory, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
import sys
import threading
import time
import json
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# Ajouter le répertoire parent au path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Imports des modules du système (✅ CORRIGÉ - sans "backend.")
from config import Config
from database import DatabaseManager
from models import (
    NetworkPacket, Alert, Incident, TrafficMonitor,
    AIDetectionEngine, ThreatClassifier, SeverityLevel
)
from ml_engine import AnomalyDetector, TrafficAnalyzer, ThreatIntelligence, PatternRecognizer
from packet_capture import PacketCapture, AttackSimulator
from utils import (
    generate_id, format_timestamp, calculate_confidence_score,
    classify_severity, export_to_json, export_to_csv,
    create_alert_description, format_alert_for_display
)
from real_scanner import real_scanner
from explanations import threat_explainer
from remediation import security_remediator

# Création du dossier d'export
os.makedirs(Config.EXPORT_DIR, exist_ok=True)
print(f"[Export] Dossier d'export : {Config.EXPORT_DIR}")

# Initialisation de la configuration
Config.init_directories()
Config.validate_config()

# Initialisation Flask
app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.config['SECRET_KEY'] = Config.SECRET_KEY
CORS(app, resources={r"/*": {"origins": Config.CORS_ORIGINS}})

# Initialisation SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialisation des composants
db = DatabaseManager(Config.DATABASE_PATH)
db.connect()
db.init_database()

# Composants ML (avec variable globale pour accès dans packet_callback)
ml_engine = type('obj', (object,), {
    'anomaly_detector': AnomalyDetector(contamination=Config.ML_CONTAMINATION, n_estimators=100),
    'traffic_analyzer': TrafficAnalyzer(buffer_size=Config.CAPTURE_BUFFER_SIZE),
    'threat_intel': ThreatIntelligence(),
    'pattern_recognizer': PatternRecognizer()
})()

# Composants IDS
ai_engine = AIDetectionEngine()
threat_classifier = ThreatClassifier()
traffic_monitor = TrafficMonitor(interface=Config.CAPTURE_INTERFACE)
packet_capture = PacketCapture(interface=Config.CAPTURE_INTERFACE)
attack_simulator = AttackSimulator()

# Statistiques en temps réel (buffer pour le dashboard)
current_stats = {
    'total_packets': 0,
    'threats_detected': 0,
    'normal_traffic': 0,
    'threats_by_type': {
        'DDoS': 0,
        'Port Scan': 0,
        'Malware C&C': 0,
        'SQL Injection': 0,
        'XSS': 0,
        'Brute Force': 0,
        'Suspicious Activity': 0,
        'Unknown': 0
    },
    'timestamp': datetime.now().isoformat()
}

# Historique des alertes (pour le dashboard)
alert_history = []

# Buffer de trafic (pour les graphiques)
traffic_buffer = []

# Thread-safe lock
stats_lock = threading.Lock()

# État du système
system_state = {
    'is_capturing': False,
    'capture_thread': None,
    'stats_thread': None
}


# ========== CALLBACK POUR TRAITEMENT DES PAQUETS ==========

def packet_callback(packet):
    """
    Callback appelé pour chaque paquet capturé
    ✅ VERSION CORRIGÉE - Classification correcte
    """
    global current_stats, alert_history, traffic_buffer
    
    try:
        # Mise à jour des stats globales
        current_stats['total_packets'] += 1
        current_stats['timestamp'] = datetime.now().isoformat()
        
        # Conversion du paquet en dictionnaire
        packet_dict = packet.to_dict() if hasattr(packet, 'to_dict') else packet
        
        # Ajout au buffer de trafic (pour graphiques)
        traffic_buffer.append(packet_dict)
        if len(traffic_buffer) > 100:
            traffic_buffer.pop(0)
        
        # ✅ CLASSIFICATION DE LA MENACE (retourne un Dict ou None)
        alert = classify_threat(packet_dict)
        
        # Si une menace est détectée
        if alert:
            # Extraire le type de menace
            threat_type = alert['type']
            
            # Mise à jour des statistiques
            current_stats['threats_detected'] += 1
            
            # ✅ CORRECTION: Utiliser .get() pour éviter KeyError
            current_stats['threats_by_type'][threat_type] = \
                current_stats['threats_by_type'].get(threat_type, 0) + 1
            
            # Sauvegarde dans la base de données
            try:
                if db.add_alert(alert):
                    print(f"✅ Alerte sauvegardée: {threat_type}")
            except Exception as e:
                print(f"❌ Erreur sauvegarde alerte: {e}")
            
            # Ajout à l'historique (limité à 100)
            alert_history.append(alert)
            if len(alert_history) > 100:
                alert_history.pop(0)
            
            # ✅ Émission WebSocket vers tous les clients
            socketio.emit('new_alert', alert)
            socketio.emit('stats_update', current_stats)
            
            print(f"⚠️  ALERTE {alert['severity']}: {threat_type} - {alert['source_ip']} → {alert['destination_ip']}:{alert['destination_port']}")
        
        else:
            # Paquet normal
            current_stats['normal_traffic'] += 1
        
    except Exception as e:
        print(f"❌ Erreur dans packet_callback: {e}")
        import traceback
        traceback.print_exc()


def classify_threat(packet_info: Dict) -> Optional[Dict]:
    """
    Classifie une menace potentielle basée sur les paquets capturés
    ✅ VERSION COMPLÈTE - Détecte 6 types d'attaques
    """
    
    threat_type = None
    severity = "LOW"
    confidence = 0.5
    description = ""
    
    # ✅ CORRECTION: Utiliser les bons noms de clés
    src_ip = packet_info.get('source_ip', '')
    dst_ip = packet_info.get('destination_ip', '')
    src_port = packet_info.get('source_port', 0)
    dst_port = packet_info.get('destination_port', 0)
    protocol = packet_info.get('protocol', '')
    payload = packet_info.get('raw_data', '')  # ✅ CHANGÉ
    packet_size = packet_info.get('payload_size', 0)  # ✅ CHANGÉ
    flags = packet_info.get('flags', '')
    
    # ========== 1. DÉTECTION PORT SCAN ==========
    if protocol == 'TCP' and 'S' in flags and 'A' not in flags:
        threat_type = "Port Scan"
        severity = "MEDIUM"
        confidence = 0.7
        description = f"Tentative de scan du port {dst_port}"
    
    # ========== 2. DÉTECTION DDoS ==========
    elif protocol in ['ICMP', 'UDP']:
        threat_type = "DDoS"
        severity = "HIGH"
        confidence = 0.8
        description = f"Trafic {protocol} suspect vers {dst_ip}:{dst_port}"
    
    # ========== 3. DÉTECTION MALWARE C2 ==========
    malware_ports = [4444, 6667, 31337, 12345, 1337]
    if dst_port in malware_ports or src_port in malware_ports:
        threat_type = "Malware C&C"
        severity = "CRITICAL"
        confidence = 0.9
        description = f"Communication C2 détectée sur port {dst_port}"
    
    # ========== 4. DÉTECTION SQL INJECTION ==========
    elif protocol == 'TCP' and (dst_port == 80 or dst_port == 443):
        sql_patterns = [
            'union select', 'or 1=1', 'drop table', 
            'insert into', '--', 'xp_cmdshell',
            'exec(', 'execute(', '; drop', ';drop'
        ]
        
        payload_lower = str(payload).lower() if payload else ''
        
        for pattern in sql_patterns:
            if pattern in payload_lower:
                threat_type = "SQL Injection"
                severity = "CRITICAL"
                confidence = 0.85
                description = f"Pattern SQL détecté: {pattern}"
                break
    
    # ========== 5. DÉTECTION XSS ==========
    elif protocol == 'TCP' and (dst_port == 80 or dst_port == 443):
        xss_patterns = [
            '<script>', 'javascript:', 'onerror=', 'onload=',
            'alert(', 'document.cookie', '<iframe', 'eval('
        ]
        
        payload_lower = str(payload).lower() if payload else ''
        
        for pattern in xss_patterns:
            if pattern in payload_lower:
                threat_type = "XSS"
                severity = "HIGH"
                confidence = 0.8
                description = f"Pattern XSS détecté: {pattern}"
                break
    
    # ========== 6. DÉTECTION BRUTE FORCE ==========
    brute_force_ports = [21, 22, 23, 80, 443, 3389, 8080]
    if dst_port in brute_force_ports and protocol == 'TCP' and not threat_type:
        threat_type = "Brute Force"
        severity = "HIGH"
        confidence = 0.75
        description = f"Tentative de force brute sur {dst_ip}:{dst_port}"
    
    # ========== CRÉATION DE L'ALERTE ==========
    if threat_type:
        alert = {
            'id': f"alert_{int(time.time() * 1000)}_{random.randint(1000, 9999)}",
            'timestamp': datetime.now().isoformat(),
            'type': threat_type,
            'severity': severity,
            'confidence': confidence,
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'source_port': src_port,
            'destination_port': dst_port,
            'protocol': protocol,
            'description': description,
            'status': 'active'
        }
        
        print(f"⚠️  ALERTE GÉNÉRÉE: {threat_type} ({severity}) - {description}")
        
        return alert
    
    return None


def generate_alert_description(threat_type: str, features: Dict) -> str:
    """
    Génère une description lisible de l'alerte
    NOUVELLE FONCTION - Descriptions claires
    """
    
    source_ip = features.get('source_ip', 'Unknown')
    dest_ip = features.get('destination_ip', 'Unknown')
    dest_port = features.get('destination_port', 0)
    
    descriptions = {
        "DDoS": f"Attaque par déni de service détectée depuis {source_ip} vers {dest_ip}:{dest_port}. Flux massif de paquets SYN.",
        "Port Scan": f"Scan de ports détecté depuis {source_ip} vers {dest_ip}. Tentative de reconnaissance du réseau.",
        "Malware C&C": f"Communication malware détectée depuis {source_ip} vers serveur C&C {dest_ip}:{dest_port}. Possible infection.",
        "SQL Injection": f"Tentative d'injection SQL détectée depuis {source_ip} vers {dest_ip}:{dest_port}. Attaque de base de données.",
        "XSS": f"Attaque XSS (Cross-Site Scripting) détectée depuis {source_ip} vers {dest_ip}:{dest_port}. Injection de code JavaScript.",
        "Brute Force": f"Attaque par force brute détectée depuis {source_ip} vers {dest_ip}:{dest_port}. Tentatives multiples de connexion.",
        "Suspicious Activity": f"Activité suspecte détectée depuis {source_ip} vers {dest_ip}:{dest_port}.",
        "Unknown": f"Anomalie détectée dans le trafic entre {source_ip} et {dest_ip}:{dest_port}."
    }
    
    return descriptions.get(threat_type, f"Menace détectée: {source_ip} → {dest_ip}:{dest_port}")


# ========== ROUTES HTTP ==========

@app.route('/')
def index():
    """Page d'accueil - Dashboard"""
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/api/status')
def get_status():
    """Retourne le statut du système"""
    return jsonify({
        'status': 'online',
        'version': Config.VERSION,
        'is_capturing': system_state['is_capturing'],
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/stats')
def get_stats():
    """Retourne les statistiques en temps réel"""
    with stats_lock:
        stats_copy = current_stats.copy()
    
    return jsonify({
        'stats': stats_copy,
        'alerts_count': len(alert_history),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/alerts')
def get_alerts():
    """Récupère les alertes récentes"""
    limit = request.args.get('limit', 100, type=int)
    
    with stats_lock:
        alerts = alert_history[-limit:] if len(alert_history) > limit else alert_history.copy()
    
    return jsonify({
        'alerts': alerts,
        'count': len(alerts),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/export/alerts')
def export_alerts():
    """Exporte les alertes en PDF"""
    format_type = request.args.get('format', 'pdf')
    
    with stats_lock:
        alerts = alert_history.copy()
    
    if format_type == 'pdf':
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        
        filename = f'alertes_ids_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        filepath = os.path.join(Config.EXPORT_DIR, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
        elements = []
        styles = getSampleStyleSheet()
        
        # Titre
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#667eea'), alignment=TA_CENTER, spaceAfter=30)
        elements.append(Paragraph('RAPPORT D\'ALERTES IDS', title_style))
        
        # Info
        info_style = ParagraphStyle('InfoStyle', parent=styles['Normal'], fontSize=10, alignment=TA_CENTER, textColor=colors.grey)
        elements.append(Paragraph(f'Généré le {datetime.now().strftime("%d/%m/%Y à %H:%M:%S")}', info_style))
        elements.append(Paragraph(f'Nombre d\'alertes : {len(alerts)}', info_style))
        elements.append(Spacer(1, 1*cm))
        
        # Statistiques
        stats_title = ParagraphStyle('StatsTitle', parent=styles['Heading2'], fontSize=16, textColor=colors.HexColor('#667eea'), spaceAfter=10)
        elements.append(Paragraph('STATISTIQUES GLOBALES', stats_title))
        
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        type_counts = {}
        
        for alert in alerts:
            severity = alert.get('severity', 'LOW')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            alert_type = alert.get('type', 'Unknown')
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
        
        stats_data = [
            ['Sévérité', 'Nombre'],
            ['CRITICAL', str(severity_counts['CRITICAL'])],
            ['HIGH', str(severity_counts['HIGH'])],
            ['MEDIUM', str(severity_counts['MEDIUM'])],
            ['LOW', str(severity_counts['LOW'])]
        ]
        
        stats_table = Table(stats_data, colWidths=[8*cm, 4*cm])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#fee2e2')),
            ('TEXTCOLOR', (0, 1), (-1, 1), colors.HexColor('#ef4444')),
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#ffedd5')),
            ('TEXTCOLOR', (0, 2), (-1, 2), colors.HexColor('#f97316')),
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#fef3c7')),
            ('TEXTCOLOR', (0, 3), (-1, 3), colors.HexColor('#eab308')),
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#dbeafe')),
            ('TEXTCOLOR', (0, 4), (-1, 4), colors.HexColor('#3b82f6')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 1*cm))
        
        # Types de menaces
        elements.append(Paragraph('TOP 5 TYPES DE MENACES', stats_title))
        
        top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        types_data = [['Type de Menace', 'Nombre']]
        for threat_type, count in top_types:
            types_data.append([threat_type, str(count)])
        
        types_table = Table(types_data, colWidths=[8*cm, 4*cm])
        types_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(types_table)
        elements.append(Spacer(1, 1*cm))
        
        # Liste des alertes
        elements.append(Paragraph('DETAIL DES ALERTES', stats_title))
        elements.append(Spacer(1, 0.5*cm))
        
        displayed_alerts = alerts[:50]
        alert_data = [['Date/Heure', 'Sévérité', 'Type', 'Source → Destination']]
        
        for alert in displayed_alerts:
            timestamp = alert.get('timestamp', '')
            if 'T' in timestamp:
                timestamp = timestamp.split('T')[1][:8]
            
            severity = alert.get('severity', 'LOW')
            alert_type = alert.get('type', 'Unknown')
            source = alert.get('source_ip', 'N/A')
            dest = alert.get('destination_ip', 'N/A')
            
            alert_data.append([timestamp, severity, alert_type[:15], f"{source} → {dest}"])
        
        alert_table = Table(alert_data, colWidths=[3*cm, 2.5*cm, 3*cm, 7.5*cm])
        alert_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))
        elements.append(alert_table)
        
        if len(alerts) > 50:
            elements.append(Spacer(1, 0.5*cm))
            note_style = ParagraphStyle('NoteStyle', parent=styles['Normal'], fontSize=9, textColor=colors.grey, alignment=TA_CENTER)
            elements.append(Paragraph(f'Note : Seules les 50 premières alertes sont affichées. Total : {len(alerts)} alertes.', note_style))
        
        doc.build(elements)
        
        return jsonify({
            'message': 'Export PDF réussi',
            'filepath': filepath,
            'filename': filename,
            'count': len(alerts),
            'format': 'pdf'
        })
    
    return jsonify({'error': 'Format non supporté'}), 400


@app.route('/api/download/<filename>')
def download_file(filename):
    """Télécharge un fichier exporté"""
    try:
        filepath = os.path.join(Config.EXPORT_DIR, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'Fichier non trouvé'}), 404
        
        if not filepath.startswith(os.path.abspath(Config.EXPORT_DIR)):
            return jsonify({'error': 'Accès refusé'}), 403
        
        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        print(f"[Download] Erreur: {e}")
        return jsonify({'error': str(e)}), 500


# ========== ROUTES CAPTURE ==========

@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    """Démarre la capture de paquets"""
    if system_state['is_capturing']:
        return jsonify({'message': 'Capture déjà en cours'}), 400
    
    packet_capture.callback = packet_callback
    attack_simulator.callback = packet_callback
    
    packet_capture.start_capture()
    traffic_monitor.start_capture()
    
    def capture_loop():
        packet_capture.generate_traffic(duration_seconds=3600, packets_per_second=10)
    
    capture_thread = threading.Thread(target=capture_loop, daemon=True)
    capture_thread.start()
    
    system_state['is_capturing'] = True
    system_state['capture_thread'] = capture_thread
    
    db.add_log('INFO', 'System', 'Capture démarrée')
    
    return jsonify({
        'message': 'Capture démarrée',
        'interface': Config.CAPTURE_INTERFACE,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    """Arrête la capture de paquets"""
    if not system_state['is_capturing']:
        return jsonify({'message': 'Aucune capture en cours'}), 400
    
    packet_capture.stop_capture()
    traffic_monitor.stop_capture()
    
    system_state['is_capturing'] = False
    
    db.add_log('INFO', 'System', 'Capture arrêtée')
    
    return jsonify({
        'message': 'Capture arrêtée',
        'packets_captured': packet_capture.packets_captured,
        'timestamp': datetime.now().isoformat()
    })


# ========== ROUTES SIMULATION D'ATTAQUES ==========

@app.route('/api/simulate/ddos', methods=['POST'])
def simulate_ddos():
    """Simule une attaque DDoS"""
    data = request.json or {}
    target_ip = data.get('target_ip', '192.168.1.1')
    duration = data.get('duration', 10)
    intensity = data.get('intensity', 100)
    
    def run_attack():
        result = attack_simulator.simulate_ddos(target_ip=target_ip, duration=duration, intensity=intensity)
        socketio.emit('attack_completed', result)
    
    thread = threading.Thread(target=run_attack, daemon=True)
    thread.start()
    
    db.add_log('INFO', 'Simulation', f'Simulation DDoS lancée vers {target_ip}')
    
    return jsonify({'message': 'Simulation DDoS lancée', 'target': target_ip, 'duration': duration, 'intensity': intensity})


@app.route('/api/simulate/port_scan', methods=['POST'])
def simulate_port_scan():
    """Simule un scan de ports"""
    data = request.json or {}
    target_ip = data.get('target_ip', '192.168.1.1')
    start_port = data.get('start_port', 1)
    end_port = data.get('end_port', 1024)
    
    def run_attack():
        result = attack_simulator.simulate_port_scan(target_ip=target_ip, start_port=start_port, end_port=end_port)
        socketio.emit('attack_completed', result)
    
    thread = threading.Thread(target=run_attack, daemon=True)
    thread.start()
    
    db.add_log('INFO', 'Simulation', f'Simulation Port Scan lancée vers {target_ip}')
    
    return jsonify({'message': 'Simulation Port Scan lancée', 'target': target_ip, 'ports': f'{start_port}-{end_port}'})


@app.route('/api/simulate/malware', methods=['POST'])
def simulate_malware():
    """Simule une communication malware C2"""
    data = request.json or {}
    infected_ip = data.get('infected_ip', '192.168.1.100')
    connections = data.get('connections', 20)
    
    def run_attack():
        result = attack_simulator.simulate_malware_c2(infected_ip=infected_ip, connections=connections)
        socketio.emit('attack_completed', result)
    
    thread = threading.Thread(target=run_attack, daemon=True)
    thread.start()
    
    db.add_log('INFO', 'Simulation', f'Simulation Malware C2 lancée depuis {infected_ip}')
    
    return jsonify({'message': 'Simulation Malware C2 lancée', 'infected_ip': infected_ip, 'connections': connections})


@app.route('/api/simulate/sql_injection', methods=['POST'])
def simulate_sql_injection():
    """Simule des attaques SQL Injection"""
    data = request.json or {}
    attacker_ip = data.get('attacker_ip', '203.0.113.1')
    target_ip = data.get('target_ip', '192.168.1.10')
    attempts = data.get('attempts', 10)
    
    def run_attack():
        result = attack_simulator.simulate_sql_injection(attacker_ip=attacker_ip, target_ip=target_ip, attempts=attempts)
        socketio.emit('attack_completed', result)
    
    thread = threading.Thread(target=run_attack, daemon=True)
    thread.start()
    
    db.add_log('INFO', 'Simulation', f'Simulation SQL Injection lancée: {attacker_ip} -> {target_ip}')
    
    return jsonify({'message': 'Simulation SQL Injection lancée', 'attacker': attacker_ip, 'target': target_ip, 'attempts': attempts})


@app.route('/api/simulate/brute_force', methods=['POST'])
def simulate_brute_force():
    """Simule une attaque brute force"""
    data = request.json or {}
    attacker_ip = data.get('attacker_ip', '203.0.113.1')
    target_ip = data.get('target_ip', '192.168.1.1')
    service = data.get('service', 'ssh')
    attempts = data.get('attempts', 50)
    
    def run_attack():
        result = attack_simulator.simulate_brute_force(attacker_ip=attacker_ip, target_ip=target_ip, service=service, attempts=attempts)
        socketio.emit('attack_completed', result)
    
    thread = threading.Thread(target=run_attack, daemon=True)
    thread.start()
    
    db.add_log('INFO', 'Simulation', f'Simulation Brute Force {service} lancée')
    
    return jsonify({'message': f'Simulation Brute Force {service} lancée', 'attacker': attacker_ip, 'target': target_ip, 'attempts': attempts})


@app.route('/api/simulate/xss', methods=['POST'])
def simulate_xss():
    """Simule des attaques XSS"""
    data = request.json or {}
    attacker_ip = data.get('attacker_ip', '203.0.113.1')
    target_ip = data.get('target_ip', '192.168.1.10')
    attempts = data.get('attempts', 10)
    
    def run_attack():
        result = attack_simulator.simulate_xss_attack(attacker_ip=attacker_ip, target_ip=target_ip, attempts=attempts)
        socketio.emit('attack_completed', result)
    
    thread = threading.Thread(target=run_attack, daemon=True)
    thread.start()
    
    db.add_log('INFO', 'Simulation', f'Simulation XSS lancée: {attacker_ip} -> {target_ip}')
    
    return jsonify({'message': 'Simulation XSS lancée', 'attacker': attacker_ip, 'target': target_ip, 'attempts': attempts})


# ==================== ENDPOINTS SCAN RÉEL ====================

@app.route('/api/scan/full', methods=['POST'])
def start_full_scan():
    """Lance un scan complet de sécurité du système - VRAIE DÉTECTION"""
    try:
        if real_scanner.is_scanning:
            return jsonify({'success': False, 'message': 'Un scan est déjà en cours'}), 409
        
        def run_scan():
            try:
                print("[API] Démarrage du scan complet...")
                results = real_scanner.perform_full_scan()
                socketio.emit('scan_completed', results)
                print(f"[API] Scan terminé - Score de risque: {results['risk_score']}/100")
            except Exception as e:
                print(f"[API] Erreur lors du scan: {e}")
                socketio.emit('scan_error', {'error': str(e)})
        
        scan_thread = threading.Thread(target=run_scan, daemon=True)
        scan_thread.start()
        
        return jsonify({'success': True, 'message': 'Scan de sécurité démarré', 'status': 'scanning'}), 202
    except Exception as e:
        print(f"Erreur démarrage scan: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/status', methods=['GET'])
def get_scan_status():
    """Retourne l'état actuel du scan"""
    try:
        return jsonify({
            'is_scanning': real_scanner.is_scanning,
            'hostname': real_scanner.hostname,
            'local_ip': real_scanner.local_ip,
            'os': real_scanner.os_type
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/results', methods=['GET'])
def get_scan_results():
    """Retourne les résultats du dernier scan"""
    try:
        if not real_scanner.scan_results:
            return jsonify({'success': False, 'message': 'Aucun scan disponible. Lancez un scan complet.'}), 404
        return jsonify({'success': True, 'results': real_scanner.scan_results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/ports', methods=['GET'])
def get_open_ports():
    """Scan rapide des ports ouverts uniquement"""
    try:
        ports = real_scanner.scan_open_ports()
        return jsonify({'success': True, 'open_ports': ports, 'total': len(ports), 'timestamp': datetime.now().isoformat()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/connections', methods=['GET'])
def get_suspicious_connections():
    """Vérifie les connexions réseau suspectes"""
    try:
        connections = real_scanner.check_network_connections()
        return jsonify({'success': True, 'suspicious_connections': connections, 'total': len(connections), 'timestamp': datetime.now().isoformat()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/firewall', methods=['GET'])
def check_firewall():
    """Vérifie l'état du pare-feu"""
    try:
        firewall_status = real_scanner.check_firewall_status()
        return jsonify({'success': True, 'firewall': firewall_status, 'timestamp': datetime.now().isoformat()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/processes', methods=['GET'])
def get_suspicious_processes():
    """Détecte les processus suspects"""
    try:
        processes = real_scanner.check_suspicious_processes()
        return jsonify({'success': True, 'suspicious_processes': processes, 'total': len(processes), 'timestamp': datetime.now().isoformat()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/system/info', methods=['GET'])
def get_system_info():
    """Récupère les informations système"""
    try:
        info = real_scanner.get_system_info()
        return jsonify({'success': True, 'system': info})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== ENDPOINTS EXPLICATIONS ====================

@app.route('/api/explain/threat/<threat_type>', methods=['GET'])
def explain_threat(threat_type: str):
    """
    Retourne une explication simple d'un type de menace
    🆕 NOUVELLE FONCTIONNALITÉ - Explications accessibles
    """
    try:
        detail_level = request.args.get('detail', 'medium')
        explanation = threat_explainer.explain_threat(threat_type, detail_level)
        
        return jsonify({
            'success': True,
            'threat_type': threat_type,
            'explanation': explanation
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/explain/severity/<severity>', methods=['GET'])
def explain_severity(severity: str):
    """
    Retourne une explication d'un niveau de sévérité
    🆕 NOUVELLE FONCTIONNALITÉ
    """
    try:
        explanation = threat_explainer.explain_severity(severity)
        
        return jsonify({
            'success': True,
            'severity': severity,
            'explanation': explanation
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/explain/port/<int:port>', methods=['GET'])
def explain_port(port: int):
    """
    Retourne une explication d'un port réseau
    🆕 NOUVELLE FONCTIONNALITÉ
    """
    try:
        explanation = threat_explainer.explain_port(port)
        
        return jsonify({
            'success': True,
            'port': port,
            'explanation': explanation
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/explain/alert/<alert_id>', methods=['GET'])
def explain_alert(alert_id: str):
    """
    Transforme une alerte technique en version accessible
    🆕 NOUVELLE FONCTIONNALITÉ - Alerte simplifiée
    """
    try:
        # Trouver l'alerte dans l'historique
        alert = None
        with stats_lock:
            for a in alert_history:
                if a.get('id') == alert_id:
                    alert = a
                    break
        
        if not alert:
            return jsonify({
                'success': False,
                'message': 'Alerte non trouvée'
            }), 404
        
        # Créer version accessible
        simple_alert = threat_explainer.create_user_friendly_alert(alert)
        
        return jsonify({
            'success': True,
            'simple_alert': simple_alert
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== ENDPOINTS REMÉDIATION ====================

@app.route('/api/remediation/plan', methods=['POST'])
def get_remediation_plan():
    """
    Génère un plan de remédiation complet pour une menace
    🆕 NOUVELLE FONCTIONNALITÉ - Plan d'action
    """
    try:
        data = request.json
        threat_type = data.get('threat_type', 'Unknown')
        severity = data.get('severity', 'MEDIUM')
        alert_details = data.get('alert_details', {})
        
        plan = security_remediator.get_remediation_plan(
            threat_type=threat_type,
            severity=severity,
            alert_details=alert_details
        )
        
        return jsonify({
            'success': True,
            'plan': plan
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/remediation/execute', methods=['POST'])
def execute_remediation():
    """
    Exécute une action de remédiation
    🆕 NOUVELLE FONCTIONNALITÉ - Actions correctives
    ⚠️ ATTENTION: Peut modifier la configuration système
    """
    try:
        data = request.json
        action_id = data.get('action_id', '')
        alert_details = data.get('alert_details', {})
        
        if not action_id:
            return jsonify({
                'success': False,
                'message': 'ID d\'action requis'
            }), 400
        
        result = security_remediator.execute_action(action_id, alert_details)
        
        # Émettre notification via WebSocket
        socketio.emit('remediation_executed', result)
        
        return jsonify({
            'success': result['success'],
            'result': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/remediation/history', methods=['GET'])
def get_remediation_history():
    """
    Retourne l'historique des actions de remédiation
    🆕 NOUVELLE FONCTIONNALITÉ
    """
    try:
        history = security_remediator.get_remediation_history()
        
        return jsonify({
            'success': True,
            'history': history,
            'count': len(history)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ========== FONCTION SCAN AU DÉMARRAGE ==========

def perform_startup_scan():
    """Effectue un scan de sécurité automatique au démarrage"""
    print("\n" + "="*60)
    print("🔍 SCAN DE SÉCURITÉ AU DÉMARRAGE")
    print("="*60)
    
    time.sleep(3)
    
    try:
        results = real_scanner.perform_full_scan()
        
        print("\n📊 RÉSUMÉ DU SCAN:")
        print(f"   • Score de risque: {results['risk_score']}/100")
        print(f"   • Ports ouverts: {len(results['open_ports'])}")
        print(f"   • Connexions suspectes: {len(results['suspicious_connections'])}")
        print(f"   • Processus suspects: {len(results['suspicious_processes'])}")
        print(f"   • Vulnérabilités: {len(results['vulnerabilities'])}")
        
        if results['risk_score'] > 50:
            print("\n⚠️  ATTENTION: Niveau de risque ÉLEVÉ détecté!")
        else:
            print("\n✅ Système relativement sécurisé")
        
        print("="*60 + "\n")
        
        socketio.emit('startup_scan_completed', results)
    except Exception as e:
        print(f"❌ Erreur lors du scan de démarrage: {e}")


# ========== WEBSOCKET EVENTS ==========

@socketio.on('connect')
def handle_connect():
    """Client connecté via WebSocket"""
    print('[WebSocket] Client connecté')
    emit('connection_status', {'status': 'connected', 'timestamp': datetime.now().isoformat()})


@socketio.on('disconnect')
def handle_disconnect():
    """Client déconnecté"""
    print('[WebSocket] Client déconnecté')


@socketio.on('request_stats')
def handle_stats_request():
    """Client demande les stats"""
    with stats_lock:
        emit('stats_update', current_stats)


# ========== DÉMARRAGE ==========

if __name__ == '__main__':
    print("""
    ╔════════════════════════════════════════════════════════════════╗
    ║         🛡️  IDS INTELLIGENT - SYSTÈME DE DÉTECTION             ║
    ║        Version 3.0 - Scan Réel + Explications + Remédiation    ║
    ╚════════════════════════════════════════════════════════════════╝
    """)
    
    # Démarrer le scan de sécurité en arrière-plan
    startup_scan_thread = threading.Thread(target=perform_startup_scan, daemon=True)
    startup_scan_thread.start()
    
    # Démarrer la capture automatiquement (SANS génération de trafic)
    def auto_start_capture():
        time.sleep(2)
        print("\n🔄 Démarrage automatique de la capture...")
        packet_capture.callback = packet_callback
        attack_simulator.callback = packet_callback
        packet_capture.start_capture()
        traffic_monitor.start_capture()
        system_state['is_capturing'] = True
        db.add_log('INFO', 'System', 'Capture démarrée automatiquement')
        print("✅ Capture active - Prêt à analyser les simulations d'attaques\n")
    
    auto_capture_thread = threading.Thread(target=auto_start_capture, daemon=True)
    auto_capture_thread.start()
    
    db.add_log('INFO', 'System', 'Système IDS démarré')
    
    port = int(os.environ.get('PORT', 5000))
    print(f"\n🚀 Système IDS Intelligent démarré!")
    print(f"📊 Dashboard: http://localhost:{port}")
    print(f"🔌 WebSocket: ws://localhost:{port}")
    print("🎯 La capture démarre automatiquement dans 2 secondes...")
    print("🔍 Scan de sécurité en cours d'exécution...")
    print("\n📋 NOUVEAUX ENDPOINTS:")
    print("   • /api/explain/threat/<type> - Explications simples")
    print("   • /api/explain/alert/<id> - Alerte accessible")
    print("   • /api/remediation/plan - Plan de correction")
    print("   • /api/remediation/execute - Exécuter action")
    print("\nAppuyez sur Ctrl+C pour arrêter\n")
    
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)