"""
Module de capture de paquets et simulation d'attaques
Version améliorée avec classification correcte
"""

from typing import Dict, List, Callable, Optional
import random
import time
import threading
from datetime import datetime


class NetworkPacket:
    """Représente un paquet réseau"""
    
    def __init__(self, source_ip: str, destination_ip: str, 
                 source_port: int, destination_port: int,
                 protocol: str = "TCP", payload_size: int = 0,
                 flags: str = "", raw_data: bytes = b""):
        self.packet_id = self._generate_packet_id()
        self.timestamp = datetime.now()
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.source_port = source_port
        self.destination_port = destination_port
        self.protocol = protocol
        self.payload_size = payload_size
        self.flags = flags
        self.raw_data = raw_data
    
    def _generate_packet_id(self) -> str:
        """Génère un ID unique pour le paquet"""
        return f"pkt_{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
    
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
            'raw_data': self.raw_data.decode('utf-8', errors='ignore') if self.raw_data else ""
        }
    
    def is_encrypted(self) -> bool:
        """Vérifie si le paquet est chiffré"""
        return self.destination_port in [443, 8443, 22, 990, 992, 993, 995]
    
    def extract_headers(self) -> Dict:
        """Extrait les headers du paquet"""
        return {
            'ip_version': 4,
            'ttl': 64,
            'protocol': self.protocol,
            'source': self.source_ip,
            'destination': self.destination_ip
        }
    
    def get_protocol_info(self) -> Dict:
        """Retourne des infos sur le protocole"""
        protocol_info = {
            'TCP': {'reliable': True, 'connection_oriented': True},
            'UDP': {'reliable': False, 'connection_oriented': False},
            'ICMP': {'reliable': False, 'connection_oriented': False}
        }
        return protocol_info.get(self.protocol, {})


class PacketCapture:
    """Système de capture de paquets réseau"""
    
    def __init__(self, interface: str = "lo"):
        self.interface = interface
        self.is_capturing = False
        self.callback: Optional[Callable] = None
        self.packets_captured = 0
        
        # IPs normales et malveillantes
        self.normal_ips = [
            '192.168.1.10', '192.168.1.11', '192.168.1.12',
            '10.0.0.5', '10.0.0.6', '10.0.0.7'
        ]
        
        self.malicious_ips = [
            '203.0.113.1',    # IP test malveillante
            '198.51.100.42',  # IP test malveillante
            '192.0.2.123',    # IP test malveillante
            '10.0.0.666'      # IP suspecte
        ]
        
        self.common_destinations = [
            '192.168.1.1',      # Gateway
            '8.8.8.8',          # Google DNS
            '1.1.1.1',          # Cloudflare DNS
            '93.184.216.34'     # example.com
        ]
        
        # Ports normaux et suspects
        self.normal_ports = [80, 443, 53, 22, 25, 110, 143, 3306, 5432, 27017]
        self.suspicious_ports = [23, 135, 139, 445, 1433, 3389, 4444, 5900, 6667, 31337]
    
    def start_capture(self):
        """Démarre la capture"""
        self.is_capturing = True
        print(f"[PacketCapture] Capture démarrée sur {self.interface}")
    
    def stop_capture(self):
        """Arrête la capture"""
        self.is_capturing = False
        print(f"[PacketCapture] Capture arrêtée")
    
    def generate_traffic(self, duration_seconds: int = 3600, packets_per_second: int = 10):
        """Génère du trafic réseau simulé"""
        print(f"[PacketCapture] Génération de trafic: {packets_per_second} pkt/s pendant {duration_seconds}s")
        
        start_time = time.time()
        
        while self.is_capturing and (time.time() - start_time) < duration_seconds:
            packet = self._generate_random_packet()
            
            if self.callback and packet:
                try:
                    self.callback(packet)
                    self.packets_captured += 1
                except Exception as e:
                    print(f"[PacketCapture] Erreur callback: {e}")
            
            time.sleep(1 / packets_per_second)
    
    def _generate_random_packet(self) -> Optional[NetworkPacket]:
        """Génère un paquet aléatoire (normal ou suspect)"""
        
        # 90% trafic normal, 10% suspect, 5% attaque claire
        rand = random.random()
        
        if rand < 0.90:
            # Trafic normal
            return self._generate_normal_packet()
        elif rand < 0.95:
            # Trafic suspect
            return self._generate_suspicious_packet()
        else:
            # Attaque claire
            return self._generate_attack_packet()
    
    def _generate_normal_packet(self) -> NetworkPacket:
        """Génère un paquet normal"""
        source_ip = random.choice(self.normal_ips)
        dest_ip = random.choice(self.common_destinations)
        source_port = random.randint(49152, 65535)
        dest_port = random.choice(self.normal_ports)
        
        payload_size = random.randint(64, 1500)
        flags = "PSH,ACK" if random.random() > 0.5 else "ACK"
        
        return NetworkPacket(
            source_ip=source_ip,
            destination_ip=dest_ip,
            source_port=source_port,
            destination_port=dest_port,
            protocol="TCP",
            payload_size=payload_size,
            flags=flags,
            raw_data=b"Normal HTTP request data"
        )
    
    def _generate_suspicious_packet(self) -> NetworkPacket:
        """Génère un paquet suspect"""
        source_ip = random.choice(self.normal_ips + self.malicious_ips[:1])
        dest_ip = random.choice(self.common_destinations)
        source_port = random.randint(1024, 65535)
        dest_port = random.choice(self.suspicious_ports)
        
        payload_size = random.randint(100, 5000)
        flags = "SYN"
        
        return NetworkPacket(
            source_ip=source_ip,
            destination_ip=dest_ip,
            source_port=source_port,
            destination_port=dest_port,
            protocol="TCP",
            payload_size=payload_size,
            flags=flags,
            raw_data=b"Suspicious port scan attempt"
        )
    
    def _generate_attack_packet(self) -> NetworkPacket:
        """Génère un paquet d'attaque"""
        attack_types = ['ddos', 'port_scan', 'malware', 'sql_injection', 'xss']
        attack_type = random.choice(attack_types)
        
        source_ip = random.choice(self.malicious_ips)
        dest_ip = random.choice(self.common_destinations)
        
        if attack_type == 'ddos':
            return NetworkPacket(
                source_ip=source_ip,
                destination_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                destination_port=80,
                protocol="TCP",
                payload_size=random.randint(10, 100),
                flags="SYN",
                raw_data=b"DDoS flood attack"
            )
        
        elif attack_type == 'port_scan':
            return NetworkPacket(
                source_ip=source_ip,
                destination_ip=dest_ip,
                source_port=random.randint(49152, 65535),
                destination_port=random.randint(1, 1024),
                protocol="TCP",
                payload_size=0,
                flags="SYN",
                raw_data=b"Port scanning"
            )
        
        elif attack_type == 'malware':
            return NetworkPacket(
                source_ip=source_ip,
                destination_ip=dest_ip,
                source_port=random.randint(49152, 65535),
                destination_port=random.choice([4444, 6667, 31337]),
                protocol="TCP",
                payload_size=random.randint(500, 2000),
                flags="PSH,ACK",
                raw_data=b"C&C communication attempt"
            )
        
        elif attack_type == 'sql_injection':
            payload = b"GET /login.php?user=admin' OR '1'='1"
            return NetworkPacket(
                source_ip=source_ip,
                destination_ip=dest_ip,
                source_port=random.randint(49152, 65535),
                destination_port=80,
                protocol="TCP",
                payload_size=len(payload),
                flags="PSH,ACK",
                raw_data=payload
            )
        
        else:  # xss
            payload = b"<script>alert('XSS')</script>"
            return NetworkPacket(
                source_ip=source_ip,
                destination_ip=dest_ip,
                source_port=random.randint(49152, 65535),
                destination_port=80,
                protocol="TCP",
                payload_size=len(payload),
                flags="PSH,ACK",
                raw_data=payload
            )
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques de capture"""
        return {
            'interface': self.interface,
            'is_capturing': self.is_capturing,
            'packets_captured': self.packets_captured
        }


class AttackSimulator:
    """Simulateur d'attaques"""
    
    def __init__(self):
        self.callback: Optional[Callable] = None
        self.is_simulating = False
    
    def simulate_ddos(self, target_ip: str = "192.168.1.1",
                     source_ips: List[str] = None,
                     duration: int = 10,
                     intensity: int = 100) -> Dict:
        """Simule une attaque DDoS"""
        
        if source_ips is None:
            source_ips = [
                '203.0.113.1', '198.51.100.42', '192.0.2.123',
                '10.0.0.66', '172.16.0.99'
            ]
        
        print(f"[AttackSimulator] Simulation DDoS vers {target_ip} - {intensity} pkt/s pendant {duration}s")
        
        packets_sent = 0
        start_time = time.time()
        
        while time.time() - start_time < duration:
            source_ip = random.choice(source_ips)
            
            packet = NetworkPacket(
                source_ip=source_ip,
                destination_ip=target_ip,
                source_port=random.randint(1024, 65535),
                destination_port=80,
                protocol="TCP",
                payload_size=random.randint(10, 100),
                flags="SYN",
                raw_data=b"DDoS SYN flood"
            )
            
            if self.callback:
                self.callback(packet)
            
            packets_sent += 1
            time.sleep(1 / intensity)
        
        print(f"[AttackSimulator] Attaque DDoS terminée: {packets_sent} paquets envoyés")
        
        return {
            'type': 'DDoS',
            'target': target_ip,
            'packets_sent': packets_sent,
            'duration': duration,
            'status': 'completed'
        }
    
    def simulate_port_scan(self, target_ip: str = "192.168.1.1",
                          source_ip: str = "203.0.113.1",
                          start_port: int = 1,
                          end_port: int = 1024,
                          scan_speed: float = 0.01) -> Dict:
        """Simule un scan de ports"""
        
        print(f"[AttackSimulator] Simulation Port Scan: {source_ip} -> {target_ip} (ports {start_port}-{end_port})")
        
        packets_sent = 0
        
        for port in range(start_port, end_port + 1):
            packet = NetworkPacket(
                source_ip=source_ip,
                destination_ip=target_ip,
                source_port=random.randint(49152, 65535),
                destination_port=port,
                protocol="TCP",
                payload_size=0,
                flags="SYN",
                raw_data=f"Port scan: {port}".encode()
            )
            
            if self.callback:
                self.callback(packet)
            
            packets_sent += 1
            time.sleep(scan_speed)
        
        print(f"[AttackSimulator] Port Scan terminé: {packets_sent} paquets envoyés")
        
        return {
            'type': 'Port Scan',
            'target': target_ip,
            'ports_scanned': end_port - start_port + 1,
            'packets_sent': packets_sent,
            'status': 'completed'
        }
    
    def simulate_malware_c2(self, infected_ip: str = "192.168.1.100",
                           c2_servers: List[str] = None,
                           connections: int = 20,
                           interval: float = 0.5) -> Dict:
        """Simule une communication malware vers serveurs C&C"""
        
        if c2_servers is None:
            c2_servers = ['203.0.113.1', '198.51.100.42']
        
        print(f"[AttackSimulator] Simulation Malware C2: {infected_ip} -> Serveurs C&C")
        
        packets_sent = 0
        
        for _ in range(connections):
            c2_server = random.choice(c2_servers)
            c2_port = random.choice([4444, 6667, 31337, 8080])
            
            packet = NetworkPacket(
                source_ip=infected_ip,
                destination_ip=c2_server,
                source_port=random.randint(49152, 65535),
                destination_port=c2_port,
                protocol="TCP",
                payload_size=random.randint(500, 2000),
                flags="PSH,ACK",
                raw_data=b"Encrypted C&C beacon"
            )
            
            if self.callback:
                self.callback(packet)
            
            packets_sent += 1
            time.sleep(interval)
        
        print(f"[AttackSimulator] Malware C2 terminé: {packets_sent} paquets envoyés")
        
        return {
            'type': 'Malware C&C',
            'infected_host': infected_ip,
            'c2_servers': c2_servers,
            'connections': connections,
            'packets_sent': packets_sent,
            'status': 'completed'
        }
    
    def simulate_sql_injection(self, attacker_ip: str = "203.0.113.1",
                              target_ip: str = "192.168.1.10",
                              attempts: int = 10) -> Dict:
        """Simule des attaques SQL Injection"""
        
        print(f"[AttackSimulator] Simulation SQL Injection: {attacker_ip} -> {target_ip}")
        
        sql_payloads = [
            b"' OR '1'='1",
            b"admin'--",
            b"1' UNION SELECT * FROM users--",
            b"'; DROP TABLE users--",
            b"1' OR '1'='1' /*"
        ]
        
        packets_sent = 0
        
        for _ in range(attempts):
            payload = random.choice(sql_payloads)
            
            packet = NetworkPacket(
                source_ip=attacker_ip,
                destination_ip=target_ip,
                source_port=random.randint(49152, 65535),
                destination_port=80,
                protocol="TCP",
                payload_size=len(payload),
                flags="PSH,ACK",
                raw_data=payload
            )
            
            if self.callback:
                self.callback(packet)
            
            packets_sent += 1
            time.sleep(0.2)
        
        print(f"[AttackSimulator] SQL Injection terminé: {attempts} tentatives")
        
        return {
            'type': 'SQL Injection',
            'attacker': attacker_ip,
            'target': target_ip,
            'attempts': attempts,
            'packets_sent': packets_sent,
            'status': 'completed'
        }
    
    def simulate_brute_force(self, attacker_ip: str = "203.0.113.1",
                            target_ip: str = "192.168.1.1",
                            service: str = "ssh",
                            attempts: int = 50) -> Dict:
        """Simule une attaque brute force"""
        
        service_ports = {
            'ssh': 22,
            'rdp': 3389,
            'ftp': 21,
            'telnet': 23,
            'vnc': 5900
        }
        
        port = service_ports.get(service, 22)
        
        print(f"[AttackSimulator] Simulation Brute Force {service}: {attacker_ip} -> {target_ip}")
        
        packets_sent = 0
        
        for i in range(attempts):
            packet = NetworkPacket(
                source_ip=attacker_ip,
                destination_ip=target_ip,
                source_port=random.randint(49152, 65535),
                destination_port=port,
                protocol="TCP",
                payload_size=random.randint(100, 500),
                flags="PSH,ACK",
                raw_data=f"Login attempt #{i+1}".encode()
            )
            
            if self.callback:
                self.callback(packet)
            
            packets_sent += 1
            time.sleep(0.1)
        
        print(f"[AttackSimulator] Brute Force terminé: {attempts} tentatives")
        
        return {
            'type': 'Brute Force',
            'service': service,
            'attacker': attacker_ip,
            'target': target_ip,
            'attempts': attempts,
            'packets_sent': packets_sent,
            'status': 'completed'
        }
    
    def simulate_xss_attack(self, attacker_ip: str = "203.0.113.1",
                           target_ip: str = "192.168.1.10",
                           attempts: int = 10) -> Dict:
        """Simule des attaques XSS"""
        
        print(f"[AttackSimulator] Simulation XSS: {attacker_ip} -> {target_ip}")
        
        xss_payloads = [
            b"<script>alert('XSS')</script>",
            b"<img src=x onerror=alert('XSS')>",
            b"<iframe src='javascript:alert(1)'>",
            b"javascript:alert(document.cookie)",
            b"<body onload=alert('XSS')>"
        ]
        
        packets_sent = 0
        
        for _ in range(attempts):
            payload = random.choice(xss_payloads)
            
            packet = NetworkPacket(
                source_ip=attacker_ip,
                destination_ip=target_ip,
                source_port=random.randint(49152, 65535),
                destination_port=80,
                protocol="TCP",
                payload_size=len(payload),
                flags="PSH,ACK",
                raw_data=payload
            )
            
            if self.callback:
                self.callback(packet)
            
            packets_sent += 1
            time.sleep(0.2)
        
        print(f"[AttackSimulator] XSS terminé: {attempts} tentatives")
        
        return {
            'type': 'XSS',
            'attacker': attacker_ip,
            'target': target_ip,
            'attempts': attempts,
            'packets_sent': packets_sent,
            'status': 'completed'
        }
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques du simulateur"""
        return {
            'is_simulating': self.is_simulating
        }