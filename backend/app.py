"""
Application Flask principale pour le système IDS Intelligent
Version améliorée avec API REST complète et WebSocket
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
import sys
import threading
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List

# Ajouter le répertoire parent au path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Imports des modules du système
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
import os
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

# Composants ML
anomaly_detector = AnomalyDetector(
    contamination=Config.ML_CONTAMINATION,
    n_estimators=100
)
traffic_analyzer = TrafficAnalyzer(buffer_size=Config.CAPTURE_BUFFER_SIZE)
threat_intel = ThreatIntelligence()
pattern_recognizer = PatternRecognizer()

# Composants IDS
ai_engine = AIDetectionEngine()
threat_classifier = ThreatClassifier()
traffic_monitor = TrafficMonitor(interface=Config.CAPTURE_INTERFACE)
packet_capture = PacketCapture(interface=Config.CAPTURE_INTERFACE)
attack_simulator = AttackSimulator()

# Statistiques en temps réel
stats = {
    'packets_analyzed': 0,
    'threats_detected': 0,
    'alerts_generated': 0,
    'false_positives': 0,
    'system_start_time': datetime.now().isoformat(),
    'last_alert_time': None,
    'detection_rate': 0.0,
    'threat_types': {},
    'active_threats': []
}

# Thread-safe lock pour les stats
stats_lock = threading.Lock()

# État du système
system_state = {
    'is_capturing': False,
    'capture_thread': None,
    'stats_thread': None
}


# ========== CALLBACK POUR TRAITEMENT DES PAQUETS ==========

def packet_callback(packet: NetworkPacket):
    """
    Callback appelé pour chaque paquet capturé
    Analyse le paquet et génère des alertes si nécessaire
    """
    try:
        # 1. Extraction des features
        packet_dict = packet.to_dict()
        features = {
            'payload_size': packet.payload_size,
            'source_port': packet.source_port,
            'destination_port': packet.destination_port,
            'is_encrypted': packet.is_encrypted(),
            'protocol': packet.protocol,
            'port_category': 'system' if packet.destination_port < 1024 else 'dynamic'
        }
        
        # 2. Analyse ML
        is_anomaly, confidence = anomaly_detector.predict(features)
        
        # 3. Ajouter au Traffic Analyzer
        traffic_analyzer.add_packet(packet_dict)
        
        # 4. Vérifier Threat Intelligence
        is_malicious_ip, ip_desc = threat_intel.is_malicious_ip(packet.source_ip)
        is_c2_port, port_desc = threat_intel.is_c2_port(packet.destination_port)
        
        # Augmenter la confiance si IP ou port malveillant connu
        if is_malicious_ip:
            confidence = max(confidence, 0.9)
        if is_c2_port:
            confidence = max(confidence, 0.85)
        
        # 5. Détection de patterns dans le payload
        if packet.raw_data:
            payload_str = packet.raw_data.decode('utf-8', errors='ignore')
            pattern_match = pattern_recognizer.detect_pattern(payload_str)
            if pattern_match:
                confidence = max(confidence, pattern_match['confidence'])
                is_anomaly = True
        
        # 6. Mise à jour des statistiques
        with stats_lock:
            stats['packets_analyzed'] += 1
        
        # 7. Si menace détectée
        if is_anomaly or is_malicious_ip or is_c2_port:
            # Classifier le type de menace
            threat_type = threat_classifier.classify_threat({
                'threat_type': ai_engine._classify_threat_type(features),
                'is_malicious_ip': is_malicious_ip,
                'is_c2_port': is_c2_port
            })
            
            # Déterminer la sévérité
            severity = threat_classifier.determine_severity(threat_type, confidence)
            
            # Créer la description
            description = create_alert_description(
                threat_type,
                packet.source_ip,
                packet.destination_ip,
                confidence,
                details=f"{ip_desc} {port_desc}".strip()
            )
            
            # Créer l'alerte
            alert = Alert(
                severity=severity,
                threat_type=threat_type,
                description=description,
                source_ip=packet.source_ip,
                target_ip=packet.destination_ip,
                confidence=confidence,
                source_port=packet.source_port,
                target_port=packet.destination_port,
                protocol=packet.protocol
            )
            
            # Sauvegarder l'alerte
            db.save_alert(alert.to_dict())
            
            # Envoyer l'alerte
            alert.send()
            
            # Mise à jour des stats
            with stats_lock:
                stats['threats_detected'] += 1
                stats['alerts_generated'] += 1
                stats['last_alert_time'] = datetime.now().isoformat()
                stats['threat_types'][threat_type] = stats['threat_types'].get(threat_type, 0) + 1
                stats['detection_rate'] = round(
                    (stats['threats_detected'] / stats['packets_analyzed']) * 100, 2
                )
            
            # Créer un incident si sévérité élevée
            if severity in ['CRITICAL', 'HIGH']:
                incident = Incident(alert)
                incident.investigate()
                db.save_statistics({
                    'packets_analyzed': stats['packets_analyzed'],
                    'threats_detected': stats['threats_detected'],
                    'alerts_generated': stats['alerts_generated'],
                    'false_positives': stats['false_positives'],
                    'detection_rate': stats['detection_rate']
                })
            
            # Envoyer via WebSocket
            socketio.emit('new_alert', format_alert_for_display(alert.to_dict()))
            
            # Log
            db.add_log('INFO', 'Detection', f"Menace détectée: {threat_type}", 
                      json.dumps(alert.to_dict()))
        
    except Exception as e:
        print(f"[PacketCallback] Erreur: {e}")
        db.add_log('ERROR', 'Processing', f"Erreur traitement paquet: {e}")


# ========== ROUTES HTTP ==========

@app.route('/')
def index():
    """Page d'accueil - Dashboard"""
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/api/status')
def get_status():
    """Retourne le statut du système"""
    uptime = datetime.now() - datetime.fromisoformat(stats['system_start_time'])
    
    return jsonify({
        'status': 'online',
        'version': Config.VERSION,
        'uptime_seconds': int(uptime.total_seconds()),
        'is_capturing': system_state['is_capturing'],
        'database_size_mb': db.get_database_size(),
        'ml_model_trained': anomaly_detector.is_trained,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/stats')
def get_stats():
    """Retourne les statistiques complètes"""
    with stats_lock:
        current_stats = stats.copy()
    
    # Stats dashboard
    dashboard_stats = db.get_dashboard_stats()
    
    # Stats traffic analyzer
    traffic_stats = traffic_analyzer.get_statistics()
    
    # Détection DDoS et Port Scan
    ddos_detection = traffic_analyzer.detect_ddos()
    port_scan_detection = traffic_analyzer.detect_port_scan()
    
    active_attacks = []
    if ddos_detection:
        active_attacks.append(ddos_detection)
    if port_scan_detection:
        active_attacks.append(port_scan_detection)
    
    return jsonify({
        'realtime': current_stats,
        'dashboard': dashboard_stats,
        'traffic': traffic_stats,
        'active_attacks': active_attacks,
        'ai_engine': ai_engine.get_statistics(),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/alerts')
def get_alerts():
    """Récupère les alertes avec filtres"""
    limit = request.args.get('limit', 100, type=int)
    status = request.args.get('status', None)
    severity = request.args.get('severity', None)
    threat_type = request.args.get('type', None)
    start_date = request.args.get('start_date', None)
    end_date = request.args.get('end_date', None)
    
    alerts = db.get_alerts(
        limit=limit,
        status=status,
        severity=severity,
        type=threat_type,
        start_date=start_date,
        end_date=end_date
    )
    
    return jsonify({
        'alerts': alerts,
        'count': len(alerts),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/alerts/<alert_id>')
def get_alert_detail(alert_id):
    """Récupère les détails d'une alerte"""
    alert = db.get_alert_by_id(alert_id)
    
    if not alert:
        return jsonify({'error': 'Alerte non trouvée'}), 404
    
    return jsonify({
        'alert': alert,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/alerts/<alert_id>', methods=['PUT'])
def update_alert(alert_id):
    """Met à jour une alerte"""
    data = request.json
    new_status = data.get('status')
    
    if not new_status:
        return jsonify({'error': 'Statut requis'}), 400
    
    success = db.update_alert_status(alert_id, new_status)
    
    if success:
        return jsonify({
            'message': 'Alerte mise à jour',
            'alert_id': alert_id,
            'new_status': new_status
        })
    else:
        return jsonify({'error': 'Échec mise à jour'}), 500


@app.route('/api/incidents')
def get_incidents():
    """Récupère les incidents"""
    limit = request.args.get('limit', 50, type=int)
    
    # Simulé pour l'instant
    return jsonify({
        'incidents': [],
        'count': 0,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/logs')
def get_logs():
    """Récupère les logs système"""
    limit = request.args.get('limit', 100, type=int)
    level = request.args.get('level', None)
    
    logs = db.get_logs(limit=limit, level=level)
    
    return jsonify({
        'logs': logs,
        'count': len(logs),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/export/alerts')
def export_alerts():
    """Exporte les alertes en PDF"""
    format_type = request.args.get('format', 'pdf')
    limit = request.args.get('limit', 1000, type=int)
    
    alerts = db.get_alerts(limit=limit)
    
    if format_type == 'pdf':
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        from datetime import datetime
        
        filename = f'alertes_ids_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        filepath = os.path.join(Config.EXPORT_DIR, filename)
        
        # Créer le PDF
        doc = SimpleDocTemplate(filepath, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
        elements = []
        styles = getSampleStyleSheet()
        
        # Titre
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#667eea'),
            alignment=TA_CENTER,
            spaceAfter=30
        )
        elements.append(Paragraph('RAPPORT D\'ALERTES IDS', title_style))
        
        # Informations du rapport
        info_style = ParagraphStyle(
            'InfoStyle',
            parent=styles['Normal'],
            fontSize=10,
            alignment=TA_CENTER,
            textColor=colors.grey
        )
        elements.append(Paragraph(f'Généré le {datetime.now().strftime("%d/%m/%Y à %H:%M:%S")}', info_style))
        elements.append(Paragraph(f'Nombre d\'alertes : {len(alerts)}', info_style))
        elements.append(Spacer(1, 1*cm))
        
        # Statistiques globales
        stats_title = ParagraphStyle(
            'StatsTitle',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=10
        )
        elements.append(Paragraph('STATISTIQUES GLOBALES', stats_title))
        
        # Compter par sévérité
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        type_counts = {}
        
        for alert in alerts:
            severity = alert.get('severity', 'LOW')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            alert_type = alert.get('type', 'Unknown')
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
        
        # Table des stats
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
            # Couleurs par sévérité
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#fee2e2')),  # CRITICAL - rouge clair
            ('TEXTCOLOR', (0, 1), (-1, 1), colors.HexColor('#ef4444')),    # CRITICAL - rouge foncé
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#ffedd5')),  # HIGH - orange clair
            ('TEXTCOLOR', (0, 2), (-1, 2), colors.HexColor('#f97316')),    # HIGH - orange foncé
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#fef3c7')),  # MEDIUM - jaune clair
            ('TEXTCOLOR', (0, 3), (-1, 3), colors.HexColor('#eab308')),    # MEDIUM - jaune foncé
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#dbeafe')),  # LOW - bleu clair
            ('TEXTCOLOR', (0, 4), (-1, 4), colors.HexColor('#3b82f6')),    # LOW - bleu foncé
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
        
        # Limiter à 50 alertes pour le PDF
        displayed_alerts = alerts[:50]
        
        alert_data = [['Date/Heure', 'Sévérité', 'Type', 'Source → Destination']]
        
        for alert in displayed_alerts:
            timestamp = alert.get('timestamp', '')
            if 'T' in timestamp:
                timestamp = timestamp.split('T')[1][:8]  # Garder juste HH:MM:SS
            
            severity = alert.get('severity', 'LOW')
            alert_type = alert.get('type', 'Unknown')
            source = alert.get('source_ip', 'N/A')
            target = alert.get('target_ip', 'N/A')
            
            alert_data.append([
                timestamp,
                severity,
                alert_type[:15],  # Tronquer si trop long
                f"{source} → {target}"
            ])
        
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
            note_style = ParagraphStyle(
                'NoteStyle',
                parent=styles['Normal'],
                fontSize=9,
                textColor=colors.grey,
                alignment=TA_CENTER
            )
            elements.append(Paragraph(f'Note : Seules les 50 premières alertes sont affichées. Total : {len(alerts)} alertes.', note_style))
        
        # Générer le PDF
        doc.build(elements)
        
        return jsonify({
            'message': 'Export PDF réussi',
            'filepath': filepath,
            'filename': filename,
            'count': len(alerts),
            'format': 'pdf'
        })
    
    elif format_type == 'csv':
        filepath = os.path.join(Config.EXPORT_DIR, f'alerts_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv')
        export_to_csv(alerts, filepath)
    else:
        filepath = os.path.join(Config.EXPORT_DIR, f'alerts_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
        export_to_json(alerts, filepath)
    
    return jsonify({
        'message': 'Export réussi',
        'filepath': filepath,
        'count': len(alerts),
        'format': format_type
    })


@app.route('/api/download/<filename>')
def download_file(filename):
    """Télécharge un fichier exporté"""
    try:
        from flask import send_file
        
        filepath = os.path.join(Config.EXPORT_DIR, filename)
        
        # Vérifier que le fichier existe et est dans le bon répertoire
        if not os.path.exists(filepath):
            return jsonify({'error': 'Fichier non trouvé'}), 404
        
        if not filepath.startswith(os.path.abspath(Config.EXPORT_DIR)):
            return jsonify({'error': 'Accès refusé'}), 403
        
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        print(f"[Download] Erreur: {e}")
        return jsonify({'error': str(e)}), 500
    

# ========== ROUTES CAPTURE ==========

@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    """Démarre la capture de paquets"""
    if system_state['is_capturing']:
        return jsonify({'message': 'Capture déjà en cours'}), 400
    
    # Configurer le callback
    packet_capture.callback = packet_callback
    attack_simulator.callback = packet_callback
    
    # Démarrer la capture
    packet_capture.start_capture()
    traffic_monitor.start_capture()
    
    # Thread de génération de trafic
    def capture_loop():
        packet_capture.generate_traffic(
            duration_seconds=3600,  # 1 heure
            packets_per_second=10
        )
    
    capture_thread = threading.Thread(target=capture_loop, daemon=True)
    capture_thread.start()
    
    system_state['is_capturing'] = True
    system_state['capture_thread'] = capture_thread
    
    db.add_log('INFO', 'System', 'Capture démarrée')
    
    return jsonify({
        'message': 'Capture démarrée',
        'interface': Config.CAPTURE_INTERFACE,
        'mode': 'simulation' if Config.SIMULATION_MODE else 'real',
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
    
    # Lancer dans un thread
    def run_attack():
        result = attack_simulator.simulate_ddos(
            target_ip=target_ip,
            duration=duration,
            intensity=intensity
        )
        socketio.emit('attack_completed', result)
    
    thread = threading.Thread(target=run_attack, daemon=True)
    thread.start()
    
    db.add_log('INFO', 'Simulation', f'Simulation DDoS lancée vers {target_ip}')
    
    return jsonify({
        'message': 'Simulation DDoS lancée',
        'target': target_ip,
        'duration': duration,
        'intensity': intensity
    })


@app.route('/api/simulate/port_scan', methods=['POST'])
def simulate_port_scan():
    """Simule un scan de ports"""
    data = request.json or {}
    
    target_ip = data.get('target_ip', '192.168.1.1')
    start_port = data.get('start_port', 1)
    end_port = data.get('end_port', 1024)
    
    def run_attack():
        result = attack_simulator.simulate_port_scan(
            target_ip=target_ip,
            start_port=start_port,
            end_port=end_port
        )
        socketio.emit('attack_completed', result)
    
    thread = threading.Thread(target=run_attack, daemon=True)
    thread.start()
    
    db.add_log('INFO', 'Simulation', f'Simulation Port Scan lancée vers {target_ip}')
    
    return jsonify({
        'message': 'Simulation Port Scan lancée',
        'target': target_ip,
        'ports': f'{start_port}-{end_port}'
    })


@app.route('/api/simulate/malware', methods=['POST'])
def simulate_malware():
    """Simule une communication malware C2"""
    data = request.json or {}
    
    infected_ip = data.get('infected_ip', '192.168.1.100')
    connections = data.get('connections', 20)
    
    def run_attack():
        result = attack_simulator.simulate_malware_c2(
            infected_ip=infected_ip,
            connections=connections
        )
        socketio.emit('attack_completed', result)
    
    thread = threading.Thread(target=run_attack, daemon=True)
    thread.start()
    
    db.add_log('INFO', 'Simulation', f'Simulation Malware C2 lancée depuis {infected_ip}')
    
    return jsonify({
        'message': 'Simulation Malware C2 lancée',
        'infected_ip': infected_ip,
        'connections': connections
    })


@app.route('/api/simulate/sql_injection', methods=['POST'])
def simulate_sql_injection():
    """Simule des attaques SQL Injection"""
    data = request.json or {}
    
    attacker_ip = data.get('attacker_ip', '203.0.113.1')
    target_ip = data.get('target_ip', '192.168.1.10')
    attempts = data.get('attempts', 10)
    
    def run_attack():
        result = attack_simulator.simulate_sql_injection(
            attacker_ip=attacker_ip,
            target_ip=target_ip,
            attempts=attempts
        )
        socketio.emit('attack_completed', result)
    
    thread = threading.Thread(target=run_attack, daemon=True)
    thread.start()
    
    db.add_log('INFO', 'Simulation', f'Simulation SQL Injection lancée: {attacker_ip} -> {target_ip}')
    
    return jsonify({
        'message': 'Simulation SQL Injection lancée',
        'attacker': attacker_ip,
        'target': target_ip,
        'attempts': attempts
    })


@app.route('/api/simulate/brute_force', methods=['POST'])
def simulate_brute_force():
    """Simule une attaque brute force"""
    data = request.json or {}
    
    attacker_ip = data.get('attacker_ip', '203.0.113.1')
    target_ip = data.get('target_ip', '192.168.1.1')
    service = data.get('service', 'ssh')
    attempts = data.get('attempts', 50)
    
    def run_attack():
        result = attack_simulator.simulate_brute_force(
            attacker_ip=attacker_ip,
            target_ip=target_ip,
            service=service,
            attempts=attempts
        )
        socketio.emit('attack_completed', result)
    
    thread = threading.Thread(target=run_attack, daemon=True)
    thread.start()
    
    db.add_log('INFO', 'Simulation', f'Simulation Brute Force {service} lancée')
    
    return jsonify({
        'message': f'Simulation Brute Force {service} lancée',
        'attacker': attacker_ip,
        'target': target_ip,
        'attempts': attempts
    })


@app.route('/api/simulate/xss', methods=['POST'])
def simulate_xss():
    """Simule des attaques XSS"""
    data = request.json or {}
    
    attacker_ip = data.get('attacker_ip', '203.0.113.1')
    target_ip = data.get('target_ip', '192.168.1.10')
    attempts = data.get('attempts', 10)
    
    def run_attack():
        result = attack_simulator.simulate_xss_attack(
            attacker_ip=attacker_ip,
            target_ip=target_ip,
            attempts=attempts
        )
        socketio.emit('attack_completed', result)
    
    thread = threading.Thread(target=run_attack, daemon=True)
    thread.start()
    
    db.add_log('INFO', 'Simulation', f'Simulation XSS lancée: {attacker_ip} -> {target_ip}')
    
    return jsonify({
        'message': 'Simulation XSS lancée',
        'attacker': attacker_ip,
        'target': target_ip,
        'attempts': attempts
    })


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
        emit('stats_update', stats)


# Thread pour envoyer les stats périodiquement
def stats_updater():
    """Envoie les stats toutes les 5 secondes"""
    while True:
        time.sleep(Config.STATS_UPDATE_INTERVAL)
        
        with stats_lock:
            current_stats = stats.copy()
        
        socketio.emit('stats_update', current_stats)


# ========== DÉMARRAGE ==========

if __name__ == '__main__':
    # Afficher la configuration
    Config.display_config()
    
    # Démarrer le thread de stats
    stats_thread = threading.Thread(target=stats_updater, daemon=True)
    stats_thread.start()
    system_state['stats_thread'] = stats_thread
    
    # 🆕 DÉMARRER LA CAPTURE AUTOMATIQUEMENT (SANS trafic automatique)
    def auto_start_capture():
        """Démarre la capture automatiquement après 2 secondes"""
        time.sleep(2)  # Attendre que le serveur démarre
        
        print("\n🔄 Démarrage automatique de la capture...")
        
        # Configurer les callbacks
        packet_capture.callback = packet_callback
        attack_simulator.callback = packet_callback
        
        # Démarrer la capture (SANS génération de trafic)
        packet_capture.start_capture()
        traffic_monitor.start_capture()
        
        system_state['is_capturing'] = True
        
        db.add_log('INFO', 'System', 'Capture démarrée automatiquement')
        print("✅ Capture active - Prêt à analyser les simulations d'attaques\n")
    
    # Lancer la capture automatique dans un thread
    auto_capture_thread = threading.Thread(target=auto_start_capture, daemon=True)
    auto_capture_thread.start()
    
    # Log de démarrage
    db.add_log('INFO', 'System', 'Système IDS démarré')
    
    print("\n🚀 Système IDS Intelligent démarré!")
    print(f"📊 Dashboard: http://{Config.HOST}:{Config.PORT}")
    print(f"🔌 WebSocket: ws://{Config.HOST}:{Config.PORT}")
    print("🎯 La capture démarre automatiquement dans 2 secondes...")
    print("\nAppuyez sur Ctrl+C pour arrêter\n")
    
    # Démarrer le serveur
    socketio.run(
        app,
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        allow_unsafe_werkzeug=True
    )