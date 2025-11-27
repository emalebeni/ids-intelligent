"""
Module de scan réel de sécurité réseau
Détecte les vraies vulnérabilités sur l'appareil et le réseau local
"""

import socket
import subprocess
import platform
import psutil
import threading
import time
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import re


class RealNetworkScanner:
    """Scanner réseau pour détection réelle de vulnérabilités"""
    
    def __init__(self):
        self.os_type = platform.system()
        self.hostname = socket.gethostname()
        self.local_ip = self._get_local_ip()
        self.scan_results = {}
        self.is_scanning = False
        
    def _get_local_ip(self) -> str:
        """Obtient l'adresse IP locale"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def get_system_info(self) -> Dict:
        """Collecte les informations système"""
        
        print(f"[RealScanner] Collecte des informations système...")
        
        try:
            cpu_count = psutil.cpu_count()
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            info = {
                'timestamp': datetime.now().isoformat(),
                'hostname': self.hostname,
                'local_ip': self.local_ip,
                'os': self.os_type,
                'os_version': platform.version(),
                'architecture': platform.machine(),
                'cpu_cores': cpu_count,
                'cpu_usage': cpu_percent,
                'memory_total_gb': round(memory.total / (1024**3), 2),
                'memory_used_gb': round(memory.used / (1024**3), 2),
                'memory_percent': memory.percent,
                'disk_total_gb': round(disk.total / (1024**3), 2),
                'disk_used_gb': round(disk.used / (1024**3), 2),
                'disk_percent': disk.percent
            }
            
            print(f"✅ Système: {info['os']} - IP: {info['local_ip']}")
            return info
            
        except Exception as e:
            print(f"❌ Erreur collecte système: {e}")
            return {'error': str(e)}
    
    def scan_open_ports(self, ports_to_scan: List[int] = None) -> List[Dict]:
        """
        Scan des ports ouverts sur la machine locale
        VRAIE DÉTECTION - Pas de simulation !
        """
        
        if ports_to_scan is None:
            # Ports critiques à scanner
            ports_to_scan = [
                21,    # FTP
                22,    # SSH
                23,    # Telnet (DANGER)
                25,    # SMTP
                53,    # DNS
                80,    # HTTP
                110,   # POP3
                135,   # RPC (DANGER)
                139,   # NetBIOS (DANGER)
                143,   # IMAP
                443,   # HTTPS
                445,   # SMB (DANGER)
                3306,  # MySQL
                3389,  # RDP (DANGER)
                5432,  # PostgreSQL
                5900,  # VNC (DANGER)
                8080,  # HTTP-Alt
                27017  # MongoDB
            ]
        
        print(f"[RealScanner] Scan de {len(ports_to_scan)} ports sur {self.local_ip}...")
        
        open_ports = []
        
        for port in ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self.local_ip, port))
                
                if result == 0:
                    # Port ouvert détecté !
                    service_name = self._identify_service(port)
                    risk_level = self._assess_port_risk(port)
                    
                    port_info = {
                        'port': port,
                        'status': 'OPEN',
                        'service': service_name,
                        'risk_level': risk_level,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    open_ports.append(port_info)
                    
                    # Alerte si port dangereux
                    if risk_level in ['HIGH', 'CRITICAL']:
                        print(f"⚠️  PORT DANGEREUX OUVERT: {port} ({service_name}) - Risque {risk_level}")
                    else:
                        print(f"✓ Port ouvert: {port} ({service_name})")
                
                sock.close()
                
            except Exception as e:
                pass
        
        print(f"✅ Scan terminé: {len(open_ports)} ports ouverts détectés")
        
        return open_ports
    
    def _identify_service(self, port: int) -> str:
        """Identifie le service associé au port"""
        
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Alt",
            27017: "MongoDB"
        }
        
        return services.get(port, f"Unknown-{port}")
    
    def _assess_port_risk(self, port: int) -> str:
        """Évalue le niveau de risque d'un port ouvert"""
        
        # Ports CRITIQUES - Jamais exposés
        critical_ports = [23, 135, 139, 445, 3389, 5900]
        
        # Ports ÉLEVÉS - Très sensibles
        high_risk_ports = [21, 22, 3306, 5432, 27017]
        
        # Ports MOYENS - Attention requise
        medium_risk_ports = [25, 110, 143, 8080]
        
        if port in critical_ports:
            return "CRITICAL"
        elif port in high_risk_ports:
            return "HIGH"
        elif port in medium_risk_ports:
            return "MEDIUM"
        else:
            return "LOW"
    
    def check_network_connections(self) -> List[Dict]:
        """
        Vérifie les connexions réseau actives
        Détecte les connexions suspectes
        """
        
        print(f"[RealScanner] Analyse des connexions réseau actives...")
        
        suspicious_connections = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                # Ignorer les connexions locales
                if conn.status == 'LISTEN':
                    continue
                
                # Analyse des connexions établies
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    local_port = conn.laddr.port
                    
                    # Détection de connexions suspectes
                    is_suspicious = False
                    reason = ""
                    
                    # Vérification 1 : Ports suspects
                    suspicious_ports = [4444, 6667, 31337, 12345, 1337]
                    if remote_port in suspicious_ports:
                        is_suspicious = True
                        reason = f"Connexion vers port suspect {remote_port}"
                    
                    # Vérification 2 : IP non privée vers port système
                    if not self._is_private_ip(remote_ip) and remote_port < 1024:
                        is_suspicious = True
                        reason = f"Connexion externe vers port système {remote_port}"
                    
                    # Vérification 3 : Connexions multiples même IP
                    # (À implémenter avec compteur)
                    
                    if is_suspicious:
                        conn_info = {
                            'local_port': local_port,
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'status': conn.status,
                            'reason': reason,
                            'risk_level': 'HIGH',
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        suspicious_connections.append(conn_info)
                        print(f"⚠️  CONNEXION SUSPECTE: {remote_ip}:{remote_port} - {reason}")
            
            print(f"✅ {len(suspicious_connections)} connexions suspectes détectées")
            
        except Exception as e:
            print(f"❌ Erreur analyse connexions: {e}")
        
        return suspicious_connections
    
    def _is_private_ip(self, ip: str) -> bool:
        """Vérifie si une IP est privée"""
        
        private_ranges = [
            '10.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
            '192.168.',
            '127.'
        ]
        
        return any(ip.startswith(prefix) for prefix in private_ranges)
    
    def check_firewall_status(self) -> Dict:
        """
        Vérifie l'état du pare-feu système
        """
        
        print(f"[RealScanner] Vérification du pare-feu...")
        
        firewall_status = {
            'enabled': False,
            'details': '',
            'risk_level': 'UNKNOWN'
        }
        
        try:
            if self.os_type == "Windows":
                # Commande Windows Firewall
                result = subprocess.run(
                    ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                output = result.stdout
                
                if 'State' in output and 'ON' in output.upper():
                    firewall_status['enabled'] = True
                    firewall_status['details'] = "Pare-feu Windows actif"
                    firewall_status['risk_level'] = "LOW"
                    print("✅ Pare-feu Windows: ACTIF")
                else:
                    firewall_status['enabled'] = False
                    firewall_status['details'] = "Pare-feu Windows désactivé"
                    firewall_status['risk_level'] = "CRITICAL"
                    print("⚠️  PARE-FEU DÉSACTIVÉ - RISQUE CRITIQUE!")
            
            elif self.os_type == "Linux":
                # Vérification iptables/ufw
                result = subprocess.run(
                    ['sudo', 'ufw', 'status'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if 'Status: active' in result.stdout:
                    firewall_status['enabled'] = True
                    firewall_status['details'] = "UFW actif"
                    firewall_status['risk_level'] = "LOW"
                    print("✅ Pare-feu UFW: ACTIF")
                else:
                    firewall_status['enabled'] = False
                    firewall_status['details'] = "UFW inactif"
                    firewall_status['risk_level'] = "CRITICAL"
                    print("⚠️  PARE-FEU DÉSACTIVÉ - RISQUE CRITIQUE!")
            
        except Exception as e:
            firewall_status['details'] = f"Erreur vérification: {str(e)}"
            print(f"❌ Erreur vérification pare-feu: {e}")
        
        return firewall_status
    
    def check_suspicious_processes(self) -> List[Dict]:
        """
        Détecte les processus suspects en cours d'exécution
        """
        
        print(f"[RealScanner] Analyse des processus suspects...")
        
        suspicious_processes = []
        
        # Noms de processus malveillants connus
        suspicious_names = [
            'keylogger', 'trojan', 'backdoor', 'rootkit',
            'cryptolocker', 'ransomware', 'miner',
            'netcat', 'nc.exe', 'pwdump'
        ]
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'connections']):
                try:
                    proc_name = proc.info['name'].lower()
                    
                    # Vérification 1 : Nom suspect
                    if any(suspect in proc_name for suspect in suspicious_names):
                        
                        proc_info = {
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'user': proc.info['username'],
                            'reason': 'Nom de processus suspect',
                            'risk_level': 'CRITICAL',
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        suspicious_processes.append(proc_info)
                        print(f"⚠️  PROCESSUS SUSPECT: {proc.info['name']} (PID: {proc.info['pid']})")
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            print(f"✅ {len(suspicious_processes)} processus suspects détectés")
            
        except Exception as e:
            print(f"❌ Erreur analyse processus: {e}")
        
        return suspicious_processes
    
    def perform_full_scan(self) -> Dict:
        """
        Effectue un scan complet de sécurité
        C'EST LA FONCTION PRINCIPALE !
        """
        
        print("\n" + "="*60)
        print("🔍 DÉMARRAGE DU SCAN COMPLET DE SÉCURITÉ")
        print("="*60 + "\n")
        
        self.is_scanning = True
        start_time = time.time()
        
        results = {
            'scan_id': f"scan_{int(time.time())}",
            'timestamp': datetime.now().isoformat(),
            'system_info': {},
            'open_ports': [],
            'suspicious_connections': [],
            'firewall_status': {},
            'suspicious_processes': [],
            'vulnerabilities': [],
            'risk_score': 0,
            'recommendations': []
        }
        
        # 1. Informations système
        results['system_info'] = self.get_system_info()
        
        # 2. Scan des ports ouverts
        results['open_ports'] = self.scan_open_ports()
        
        # 3. Analyse des connexions
        results['suspicious_connections'] = self.check_network_connections()
        
        # 4. État du pare-feu
        results['firewall_status'] = self.check_firewall_status()
        
        # 5. Processus suspects
        results['suspicious_processes'] = self.check_suspicious_processes()
        
        # 6. Calcul du score de risque
        results['risk_score'] = self._calculate_risk_score(results)
        
        # 7. Génération des recommandations
        results['recommendations'] = self._generate_recommendations(results)
        
        # 8. Synthèse des vulnérabilités
        results['vulnerabilities'] = self._identify_vulnerabilities(results)
        
        scan_duration = round(time.time() - start_time, 2)
        results['scan_duration_seconds'] = scan_duration
        
        self.is_scanning = False
        self.scan_results = results
        
        print("\n" + "="*60)
        print(f"✅ SCAN TERMINÉ EN {scan_duration}s")
        print(f"📊 Score de risque: {results['risk_score']}/100")
        print(f"⚠️  {len(results['vulnerabilities'])} vulnérabilités détectées")
        print("="*60 + "\n")
        
        return results
    
    def _calculate_risk_score(self, results: Dict) -> int:
        """Calcule un score de risque global (0-100)"""
        
        score = 0
        
        # Ports ouverts critiques (+20 par port)
        for port in results['open_ports']:
            if port['risk_level'] == 'CRITICAL':
                score += 20
            elif port['risk_level'] == 'HIGH':
                score += 10
            elif port['risk_level'] == 'MEDIUM':
                score += 5
        
        # Connexions suspectes (+15 par connexion)
        score += len(results['suspicious_connections']) * 15
        
        # Pare-feu désactivé (+30)
        if not results['firewall_status'].get('enabled', False):
            score += 30
        
        # Processus suspects (+25 par processus)
        score += len(results['suspicious_processes']) * 25
        
        return min(score, 100)  # Max 100
    
    def _identify_vulnerabilities(self, results: Dict) -> List[Dict]:
        """Identifie les vulnérabilités critiques"""
        
        vulnerabilities = []
        
        # Ports critiques ouverts
        for port in results['open_ports']:
            if port['risk_level'] in ['CRITICAL', 'HIGH']:
                vulnerabilities.append({
                    'type': 'Open Critical Port',
                    'severity': port['risk_level'],
                    'description': f"Port {port['port']} ({port['service']}) est ouvert",
                    'port': port['port']
                })
        
        # Pare-feu désactivé
        if not results['firewall_status'].get('enabled', False):
            vulnerabilities.append({
                'type': 'Firewall Disabled',
                'severity': 'CRITICAL',
                'description': "Le pare-feu système est désactivé"
            })
        
        # Connexions suspectes
        for conn in results['suspicious_connections']:
            vulnerabilities.append({
                'type': 'Suspicious Connection',
                'severity': conn['risk_level'],
                'description': conn['reason'],
                'remote_ip': conn['remote_ip']
            })
        
        # Processus suspects
        for proc in results['suspicious_processes']:
            vulnerabilities.append({
                'type': 'Suspicious Process',
                'severity': proc['risk_level'],
                'description': f"Processus suspect: {proc['name']}",
                'pid': proc['pid']
            })
        
        return vulnerabilities
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Génère des recommandations de sécurité"""
        
        recommendations = []
        
        # Recommandations basées sur les ports
        for port in results['open_ports']:
            if port['risk_level'] == 'CRITICAL':
                recommendations.append(
                    f"🔴 URGENT: Fermez le port {port['port']} ({port['service']}) immédiatement"
                )
        
        # Recommandation pare-feu
        if not results['firewall_status'].get('enabled', False):
            recommendations.append(
                "🔴 URGENT: Activez le pare-feu système immédiatement"
            )
        
        # Recommandations connexions
        if results['suspicious_connections']:
            recommendations.append(
                f"⚠️  Vérifiez les {len(results['suspicious_connections'])} connexions suspectes détectées"
            )
        
        # Recommandations processus
        if results['suspicious_processes']:
            recommendations.append(
                f"🔴 URGENT: Terminez les {len(results['suspicious_processes'])} processus suspects détectés"
            )
        
        # Recommandations générales
        if results['risk_score'] > 50:
            recommendations.append(
                "⚠️  Votre système présente des risques de sécurité importants"
            )
        
        return recommendations


# Instance globale
real_scanner = RealNetworkScanner()