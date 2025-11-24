"""
Capture de paquets réseau et simulation d'attaques
Version améliorée avec plus de types d'attaques
"""

import random
import time
from datetime import datetime
from typing import Callable, List, Dict
from models import NetworkPacket


class PacketCapture:
    """Capture les paquets réseau (mode simulation pour démo)"""
    
    def __init__(self, interface="lo", callback=None):
        self.interface = interface
        self.callback = callback
        self.is_capturing = False
        self.packets_captured = 0
        self.simulation_mode = True  # Mode simulation par défaut
        
        # Configurations pour simulation
        self.normal_ips = [
            f"192.168.1.{i}" for i in range(2, 50)
        ] + [
            f"10.0.0.{i}" for i in range(10, 100)
        ]
        
        self.malicious_ips = [
            '203.0.113.1',
            '198.51.100.42', 
            '192.0.2.123',
            '10.0.0.666'
        ]
        
        self.common_destinations = [
            '192.168.1.1',      # Gateway
            '8.8.8.8',          # Google DNS
            '1.1.1.1',          # Cloudflare DNS
            '93.184.216.34',    # example.com
            '172.217.14.206'    # Google
        ]
        
        self.normal_ports = [80, 443, 53, 22, 25, 110, 143, 3306, 5432, 27017]
        self.suspicious_ports = [23, 135, 139, 445, 1433, 3389, 4444, 5900, 6667, 31337]
        self.protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
    
    def start_capture(self):
        """Démarre la capture"""
        self.is_capturing = True
        print(f"[PacketCapture] Capture démarrée sur {self.interface}")
        
        if self.simulation_mode:
            print("[PacketCapture] Mode simulation activé")
    
    def stop_capture(self):
        """Arrête la capture"""
        self.is_capturing = False
        print(f"[PacketCapture] Capture arrêtée - {self.packets_captured} paquets capturés")
    
    def generate_traffic(self, duration_seconds=60, packets_per_second=10):
        """Génère du trafic simulé"""
        print(f"[PacketCapture] Génération de trafic: {packets_per_second} paquets/sec pendant {duration_seconds}s")
        
        start_time = time.time()
        
        while self.is_capturing and (time.time() - start_time) < duration_seconds:
            packet = self._generate_random_packet()
            
            if self.callback:
                self.callback(packet)
            
            self.packets_captured += 1
            time.sleep(1.0 / packets_per_second)
    
    def _generate_random_packet(self) -> NetworkPacket:
        """Génère un paquet aléatoire réaliste"""
        # 90% de trafic normal, 10% suspect
        is_suspicious = random.random() < 0.1
        
        if is_suspicious:
            source_ip = random.choice(self.malicious_ips + self.normal_ips)
            dest_port = random.choice(self.suspicious_ports)
            payload_size = random.choice([0, random.randint(100, 10000)])
        else:
            source_ip = random.choice(self.normal_ips)
            dest_port = random.choice(self.normal_ports)
            payload_size = random.randint(64, 1500)
        
        dest_ip = random.choice(self.common_destinations)
        source_port = random.randint(49152, 65535)
        protocol = random.choice(self.protocols)
        
        # 5% de chance d'attaque réelle
        if random.random() < 0.05:
            return self._generate_attack_packet()
        
        packet = NetworkPacket(
            source_ip=source_ip,
            destination_ip=dest_ip,
            source_port=source_port,
            destination_port=dest_port,
            protocol=protocol,
            payload_size=payload_size
        )
        
        return packet
    
    def _generate_attack_packet(self) -> NetworkPacket:
        """Génère un paquet d'attaque"""
        attack_types = ['ddos', 'port_scan', 'malware', 'sql_injection', 'brute_force']
        attack_type = random.choice(attack_types)
        
        if attack_type == 'ddos':
            source_ip = random.choice(self.malicious_ips)
            dest_ip = self.common_destinations[0]  # Gateway
            source_port = random.randint(1024, 65535)
            dest_port = 80
            payload_size = random.randint(1, 100)
        
        elif attack_type == 'port_scan':
            source_ip = random.choice(self.malicious_ips)
            dest_ip = self.common_destinations[0]
            source_port = random.randint(49152, 65535)
            dest_port = random.randint(1, 1024)
            payload_size = 0
        
        elif attack_type == 'malware':
            source_ip = random.choice(self.normal_ips)
            dest_ip = random.choice(self.malicious_ips)
            source_port = random.randint(49152, 65535)
            dest_port = random.choice([4444, 6667, 31337])
            payload_size = random.randint(100, 5000)
        
        elif attack_type == 'sql_injection':
            source_ip = random.choice(self.malicious_ips)
            dest_ip = self.common_destinations[0]
            source_port = random.randint(49152, 65535)
            dest_port = 80
            payload_size = random.randint(200, 1000)
        
        else:  # brute_force
            source_ip = random.choice(self.malicious_ips)
            dest_ip = self.common_destinations[0]
            source_port = random.randint(49152, 65535)
            dest_port = random.choice([22, 3389, 5900])
            payload_size = random.randint(50, 200)
        
        packet = NetworkPacket(
            source_ip=source_ip,
            destination_ip=dest_ip,
            source_port=source_port,
            destination_port=dest_port,
            protocol='TCP',
            payload_size=payload_size
        )
        
        return packet


class AttackSimulator:
    """Simule différents types d'attaques pour la démo"""
    
    def __init__(self, callback: Callable = None):
        self.callback = callback
        self.attacks_simulated = 0
    
    def simulate_ddos(self, target_ip: str = "192.168.1.1", 
                     source_ips: List[str] = None, 
                     duration: int = 10,
                     intensity: int = 100) -> Dict:
        """
        Simule une attaque DDoS
        
        Args:
            target_ip: IP cible
            source_ips: Liste d'IPs sources (botnet)
            duration: Durée en secondes
            intensity: Paquets par seconde
        """
        print(f"[AttackSimulator] Simulation DDoS vers {target_ip} - {intensity} pkt/s pendant {duration}s")
        
        if not source_ips:
            source_ips = [
                '203.0.113.1',
                '198.51.100.42',
                '192.0.2.123',
                f'10.0.0.{random.randint(100, 250)}',
                f'172.16.0.{random.randint(100, 250)}'
            ]
        
        packets_sent = 0
        start_time = time.time()
        
        while time.time() - start_time < duration:
            source_ip = random.choice(source_ips)
            
            packet = NetworkPacket(
                source_ip=source_ip,
                destination_ip=target_ip,
                source_port=random.randint(1024, 65535),
                destination_port=80,
                protocol='TCP',
                payload_size=random.randint(1, 100),
                flags='SYN'
            )
            
            if self.callback:
                self.callback(packet)
            
            packets_sent += 1
            time.sleep(1.0 / intensity)
        
        self.attacks_simulated += 1
        
        result = {
            'type': 'DDoS',
            'target': target_ip,
            'packets_sent': packets_sent,
            'duration': duration,
            'intensity': intensity,
            'source_ips': len(source_ips)
        }
        
        print(f"[AttackSimulator] Attaque DDoS terminée: {packets_sent} paquets envoyés")
        return result
    
    def simulate_port_scan(self, target_ip: str = "192.168.1.1",
                          source_ip: str = "203.0.113.1",
                          start_port: int = 1,
                          end_port: int = 1024,
                          scan_speed: float = 0.01) -> Dict:
        """
        Simule un scan de ports
        
        Args:
            target_ip: IP cible
            source_ip: IP source
            start_port: Port de début
            end_port: Port de fin
            scan_speed: Délai entre chaque paquet (secondes)
        """
        print(f"[AttackSimulator] Simulation Port Scan: {source_ip} -> {target_ip} (ports {start_port}-{end_port})")
        
        packets_sent = 0
        open_ports = []
        
        for port in range(start_port, end_port + 1):
            packet = NetworkPacket(
                source_ip=source_ip,
                destination_ip=target_ip,
                source_port=random.randint(49152, 65535),
                destination_port=port,
                protocol='TCP',
                payload_size=0,
                flags='SYN'
            )
            
            if self.callback:
                self.callback(packet)
            
            packets_sent += 1
            
            # Simuler des ports ouverts
            if port in [22, 80, 443, 3306]:
                open_ports.append(port)
            
            time.sleep(scan_speed)
        
        self.attacks_simulated += 1
        
        result = {
            'type': 'Port Scan',
            'target': target_ip,
            'source': source_ip,
            'ports_scanned': end_port - start_port + 1,
            'packets_sent': packets_sent,
            'open_ports': open_ports
        }
        
        print(f"[AttackSimulator] Port Scan terminé: {packets_sent} paquets envoyés")
        return result
    
    def simulate_malware_c2(self, infected_ip: str = "192.168.1.100",
                           c2_servers: List[str] = None,
                           connections: int = 20,
                           interval: float = 0.5) -> Dict:
        """
        Simule une communication Malware vers serveur C&C
        
        Args:
            infected_ip: IP de la machine infectée
            c2_servers: Serveurs C&C
            connections: Nombre de connexions
            interval: Intervalle entre connexions
        """
        print(f"[AttackSimulator] Simulation Malware C2: {infected_ip} -> Serveurs C&C")
        
        if not c2_servers:
            c2_servers = [
                '203.0.113.1',
                '198.51.100.42',
                '192.0.2.123'
            ]
        
        c2_ports = [4444, 6667, 31337, 8080, 9999]
        packets_sent = 0
        
        for i in range(connections):
            c2_server = random.choice(c2_servers)
            c2_port = random.choice(c2_ports)
            
            # Beacon sortant
            packet = NetworkPacket(
                source_ip=infected_ip,
                destination_ip=c2_server,
                source_port=random.randint(49152, 65535),
                destination_port=c2_port,
                protocol='TCP',
                payload_size=random.randint(100, 5000)
            )
            
            if self.callback:
                self.callback(packet)
            
            packets_sent += 1
            time.sleep(interval)
        
        self.attacks_simulated += 1
        
        result = {
            'type': 'Malware C2',
            'infected_host': infected_ip,
            'c2_servers': c2_servers,
            'connections': connections,
            'packets_sent': packets_sent
        }
        
        print(f"[AttackSimulator] Malware C2 terminé: {packets_sent} paquets envoyés")
        return result
    
    def simulate_sql_injection(self, attacker_ip: str = "203.0.113.1",
                              target_ip: str = "192.168.1.10",
                              attempts: int = 10) -> Dict:
        """
        Simule des tentatives d'injection SQL
        """
        print(f"[AttackSimulator] Simulation SQL Injection: {attacker_ip} -> {target_ip}")
        
        sql_payloads = [
            "' OR '1'='1",
            "UNION SELECT * FROM users",
            "'; DROP TABLE users--",
            "admin'--",
            "1' OR '1'='1' /*"
        ]
        
        packets_sent = 0
        
        for i in range(attempts):
            payload = random.choice(sql_payloads)
            
            packet = NetworkPacket(
                source_ip=attacker_ip,
                destination_ip=target_ip,
                source_port=random.randint(49152, 65535),
                destination_port=80,
                protocol='HTTP',
                payload_size=len(payload.encode()),
                raw_data=payload.encode()
            )
            
            if self.callback:
                self.callback(packet)
            
            packets_sent += 1
            time.sleep(random.uniform(0.5, 2.0))
        
        self.attacks_simulated += 1
        
        result = {
            'type': 'SQL Injection',
            'attacker': attacker_ip,
            'target': target_ip,
            'attempts': attempts,
            'packets_sent': packets_sent
        }
        
        print(f"[AttackSimulator] SQL Injection terminé: {packets_sent} tentatives")
        return result
    
    def simulate_brute_force(self, attacker_ip: str = "203.0.113.1",
                            target_ip: str = "192.168.1.1",
                            service: str = "ssh",
                            attempts: int = 50) -> Dict:
        """
        Simule une attaque brute force
        """
        print(f"[AttackSimulator] Simulation Brute Force {service}: {attacker_ip} -> {target_ip}")
        
        service_ports = {
            'ssh': 22,
            'rdp': 3389,
            'ftp': 21,
            'telnet': 23,
            'vnc': 5900
        }
        
        port = service_ports.get(service, 22)
        packets_sent = 0
        
        for i in range(attempts):
            packet = NetworkPacket(
                source_ip=attacker_ip,
                destination_ip=target_ip,
                source_port=random.randint(49152, 65535),
                destination_port=port,
                protocol='TCP',
                payload_size=random.randint(50, 200)
            )
            
            if self.callback:
                self.callback(packet)
            
            packets_sent += 1
            time.sleep(random.uniform(0.1, 0.5))
        
        self.attacks_simulated += 1
        
        result = {
            'type': 'Brute Force',
            'service': service,
            'attacker': attacker_ip,
            'target': target_ip,
            'attempts': attempts,
            'packets_sent': packets_sent
        }
        
        print(f"[AttackSimulator] Brute Force terminé: {packets_sent} tentatives")
        return result
    
    def simulate_xss_attack(self, attacker_ip: str = "203.0.113.1",
                           target_ip: str = "192.168.1.10",
                           attempts: int = 10) -> Dict:
        """
        Simule des tentatives XSS
        """
        print(f"[AttackSimulator] Simulation XSS: {attacker_ip} -> {target_ip}")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<iframe src='javascript:alert(1)'>",
            "javascript:alert(document.cookie)",
            "<body onload=alert('XSS')>"
        ]
        
        packets_sent = 0
        
        for i in range(attempts):
            payload = random.choice(xss_payloads)
            
            packet = NetworkPacket(
                source_ip=attacker_ip,
                destination_ip=target_ip,
                source_port=random.randint(49152, 65535),
                destination_port=80,
                protocol='HTTP',
                payload_size=len(payload.encode()),
                raw_data=payload.encode()
            )
            
            if self.callback:
                self.callback(packet)
            
            packets_sent += 1
            time.sleep(random.uniform(0.5, 2.0))
        
        self.attacks_simulated += 1
        
        result = {
            'type': 'XSS',
            'attacker': attacker_ip,
            'target': target_ip,
            'attempts': attempts,
            'packets_sent': packets_sent
        }
        
        print(f"[AttackSimulator] XSS terminé: {packets_sent} tentatives")
        return result
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques de simulation"""
        return {
            'attacks_simulated': self.attacks_simulated,
            'available_attacks': [
                'DDoS',
                'Port Scan',
                'Malware C2',
                'SQL Injection',
                'XSS',
                'Brute Force'
            ]
        }