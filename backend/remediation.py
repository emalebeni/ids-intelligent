"""
Module de remédiation et actions correctives
Propose et exécute des mesures de sécurité automatiques
"""

import subprocess
import platform
import os
from typing import Dict, List, Tuple, Optional
from datetime import datetime


class SecurityRemediator:
    """Gestionnaire des actions de remédiation de sécurité"""
    
    def __init__(self):
        self.os_type = platform.system()
        self.remediation_history = []
        self.available_actions = self._initialize_actions()
    
    def _initialize_actions(self) -> Dict:
        """Initialise les actions de remédiation disponibles par menace"""
        
        return {
            "DDoS": {
                "actions_automatiques": [
                    {
                        'id': 'ddos_rate_limit',
                        'nom': 'Activer la limitation de débit',
                        'description': 'Limiter le nombre de connexions par seconde',
                        'risque': 'LOW',
                        'impact': 'Peut ralentir temporairement le trafic légitime'
                    },
                    {
                        'id': 'ddos_block_ip',
                        'nom': 'Bloquer les IPs malveillantes',
                        'description': 'Ajouter les IPs attaquantes à la liste de blocage',
                        'risque': 'LOW',
                        'impact': 'Bloque définitivement certaines IPs'
                    }
                ],
                "actions_manuelles": [
                    "Contacter votre fournisseur d'accès internet pour activer la protection DDoS",
                    "Augmenter la capacité du serveur temporairement",
                    "Activer un service anti-DDoS (Cloudflare, AWS Shield, etc.)"
                ]
            },
            
            "Port Scan": {
                "actions_automatiques": [
                    {
                        'id': 'port_close_unused',
                        'nom': 'Fermer les ports inutilisés',
                        'description': 'Désactiver les services sur les ports non essentiels',
                        'risque': 'MEDIUM',
                        'impact': 'Peut désactiver des services que vous utilisez'
                    },
                    {
                        'id': 'firewall_enable',
                        'nom': 'Activer le pare-feu',
                        'description': 'Activer le pare-feu système s\'il est désactivé',
                        'risque': 'LOW',
                        'impact': 'Aucun impact négatif'
                    },
                    {
                        'id': 'port_block_scanner',
                        'nom': 'Bloquer l\'IP du scanner',
                        'description': 'Ajouter l\'IP source à la liste de blocage',
                        'risque': 'LOW',
                        'impact': 'Bloque une IP spécifique'
                    }
                ],
                "actions_manuelles": [
                    "Vérifier quels services écoutent sur les ports ouverts",
                    "Désactiver les services non nécessaires",
                    "Configurer le pare-feu pour n'autoriser que les connexions légitimes"
                ]
            },
            
            "Malware C&C": {
                "actions_automatiques": [
                    {
                        'id': 'malware_block_c2',
                        'nom': 'Bloquer les serveurs C&C',
                        'description': 'Bloquer toute communication vers les serveurs de commande',
                        'risque': 'LOW',
                        'impact': 'Empêche le malware de recevoir des ordres'
                    },
                    {
                        'id': 'malware_isolate',
                        'nom': 'Isoler l\'appareil',
                        'description': 'Déconnecter l\'appareil du réseau',
                        'risque': 'HIGH',
                        'impact': 'Perte totale de connectivité réseau'
                    },
                    {
                        'id': 'malware_kill_process',
                        'nom': 'Terminer les processus suspects',
                        'description': 'Arrêter les processus identifiés comme malveillants',
                        'risque': 'MEDIUM',
                        'impact': 'Peut arrêter des processus légitimes par erreur'
                    }
                ],
                "actions_manuelles": [
                    "Lancer un scan antivirus complet immédiatement",
                    "Sauvegarder vos fichiers importants sur un support externe",
                    "Réinstaller le système d'exploitation si nécessaire",
                    "Changer TOUS vos mots de passe depuis un autre appareil sûr"
                ]
            },
            
            "SQL Injection": {
                "actions_automatiques": [
                    {
                        'id': 'sql_block_ip',
                        'nom': 'Bloquer l\'IP attaquante',
                        'description': 'Bloquer immédiatement l\'IP source de l\'injection',
                        'risque': 'LOW',
                        'impact': 'Bloque une IP spécifique'
                    },
                    {
                        'id': 'sql_disable_endpoint',
                        'nom': 'Désactiver l\'endpoint vulnérable',
                        'description': 'Désactiver temporairement le formulaire/page vulnérable',
                        'risque': 'HIGH',
                        'impact': 'Rend une partie du site inaccessible'
                    }
                ],
                "actions_manuelles": [
                    "Vérifier les logs de base de données pour voir ce qui a été accédé",
                    "Patcher le code vulnérable avec des requêtes préparées",
                    "Changer tous les mots de passe de base de données",
                    "Restaurer la base de données depuis une sauvegarde si compromise"
                ]
            },
            
            "XSS": {
                "actions_automatiques": [
                    {
                        'id': 'xss_sanitize_input',
                        'nom': 'Activer la sanitisation',
                        'description': 'Nettoyer automatiquement les entrées utilisateur',
                        'risque': 'LOW',
                        'impact': 'Peut casser certains affichages de texte'
                    },
                    {
                        'id': 'xss_block_ip',
                        'nom': 'Bloquer l\'IP attaquante',
                        'description': 'Bloquer l\'IP qui a injecté le code malveillant',
                        'risque': 'LOW',
                        'impact': 'Bloque une IP spécifique'
                    }
                ],
                "actions_manuelles": [
                    "Supprimer le contenu malveillant injecté",
                    "Patcher le code pour échapper les caractères spéciaux HTML",
                    "Implémenter Content Security Policy (CSP)",
                    "Vérifier tous les commentaires/posts récents"
                ]
            },
            
            "Brute Force": {
                "actions_automatiques": [
                    {
                        'id': 'bruteforce_block_ip',
                        'nom': 'Bloquer l\'IP attaquante',
                        'description': 'Bloquer l\'IP après X tentatives échouées',
                        'risque': 'LOW',
                        'impact': 'Bloque une IP spécifique'
                    },
                    {
                        'id': 'bruteforce_rate_limit',
                        'nom': 'Limiter les tentatives',
                        'description': 'Ralentir les tentatives de connexion (1 par 5 secondes)',
                        'risque': 'LOW',
                        'impact': 'Ralentit les connexions pour tous'
                    },
                    {
                        'id': 'bruteforce_lock_account',
                        'nom': 'Verrouiller le compte ciblé',
                        'description': 'Verrouiller temporairement le compte attaqué',
                        'risque': 'MEDIUM',
                        'impact': 'L\'utilisateur légitime ne peut plus se connecter'
                    }
                ],
                "actions_manuelles": [
                    "Forcer le changement de mot de passe du compte ciblé",
                    "Activer l'authentification à deux facteurs",
                    "Vérifier les connexions récentes au compte",
                    "Notifier l'utilisateur de l'attaque"
                ]
            }
        }
    
    def get_remediation_plan(self, threat_type: str, severity: str, 
                            alert_details: Dict) -> Dict:
        """
        Génère un plan de remédiation complet pour une menace
        """
        
        if threat_type not in self.available_actions:
            return self._generic_remediation_plan(severity)
        
        actions = self.available_actions[threat_type]
        
        plan = {
            'threat_type': threat_type,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'alert_id': alert_details.get('id', ''),
            
            # Actions immédiates (automatiques)
            'actions_immediates': {
                'description': 'Actions que le système peut effectuer automatiquement',
                'actions': actions['actions_automatiques'],
                'recommandation': self._get_auto_action_recommendation(severity)
            },
            
            # Actions manuelles recommandées
            'actions_manuelles': {
                'description': 'Actions que vous devez effectuer manuellement',
                'actions': actions['actions_manuelles'],
                'priorite': self._get_manual_action_priority(severity)
            },
            
            # Scripts générés
            'scripts': self._generate_remediation_scripts(threat_type, alert_details),
            
            # Prévention future
            'prevention': self._get_prevention_measures(threat_type)
        }
        
        return plan
    
    def _get_auto_action_recommendation(self, severity: str) -> str:
        """Recommandation sur l'activation des actions auto"""
        
        if severity == "CRITICAL":
            return "RECOMMANDÉ : Exécuter immédiatement toutes les actions automatiques"
        elif severity == "HIGH":
            return "RECOMMANDÉ : Exécuter les actions automatiques à faible risque"
        elif severity == "MEDIUM":
            return "OPTIONNEL : Examiner les actions avant de les exécuter"
        else:
            return "OPTIONNEL : Actions automatiques non urgentes"
    
    def _get_manual_action_priority(self, severity: str) -> str:
        """Priorité des actions manuelles"""
        
        if severity == "CRITICAL":
            return "URGENT - À faire dans les 15 minutes"
        elif severity == "HIGH":
            return "ÉLEVÉ - À faire dans l'heure"
        elif severity == "MEDIUM":
            return "MODÉRÉ - À faire dans les 24 heures"
        else:
            return "FAIBLE - À faire quand possible"
    
    def _generate_remediation_scripts(self, threat_type: str, 
                                     alert_details: Dict) -> Dict:
        """
        Génère des scripts de correction prêts à l'emploi
        """
        
        scripts = {}
        source_ip = alert_details.get('source_ip', '')
        dest_port = alert_details.get('destination_port', 0)
        
        # Script pour bloquer une IP (Windows)
        if self.os_type == "Windows" and source_ip:
            scripts['block_ip_windows'] = {
                'nom': 'Bloquer IP sur Windows',
                'description': f'Bloque l\'IP {source_ip} via le pare-feu Windows',
                'commande': f'netsh advfirewall firewall add rule name="Block_{source_ip}" dir=in action=block remoteip={source_ip}',
                'reversible': True,
                'commande_annulation': f'netsh advfirewall firewall delete rule name="Block_{source_ip}"'
            }
        
        # Script pour bloquer une IP (Linux)
        if self.os_type == "Linux" and source_ip:
            scripts['block_ip_linux'] = {
                'nom': 'Bloquer IP sur Linux',
                'description': f'Bloque l\'IP {source_ip} via iptables',
                'commande': f'sudo iptables -A INPUT -s {source_ip} -j DROP',
                'reversible': True,
                'commande_annulation': f'sudo iptables -D INPUT -s {source_ip} -j DROP'
            }
        
        # Script pour fermer un port (Windows)
        if self.os_type == "Windows" and dest_port:
            scripts['close_port_windows'] = {
                'nom': 'Fermer un port sur Windows',
                'description': f'Bloque les connexions entrantes sur le port {dest_port}',
                'commande': f'netsh advfirewall firewall add rule name="Block_Port_{dest_port}" dir=in action=block protocol=TCP localport={dest_port}',
                'reversible': True,
                'commande_annulation': f'netsh advfirewall firewall delete rule name="Block_Port_{dest_port}"'
            }
        
        # Script pour fermer un port (Linux)
        if self.os_type == "Linux" and dest_port:
            scripts['close_port_linux'] = {
                'nom': 'Fermer un port sur Linux',
                'description': f'Bloque les connexions entrantes sur le port {dest_port}',
                'commande': f'sudo iptables -A INPUT -p tcp --dport {dest_port} -j DROP',
                'reversible': True,
                'commande_annulation': f'sudo iptables -D INPUT -p tcp --dport {dest_port} -j DROP'
            }
        
        # Script pour activer le pare-feu (Windows)
        if self.os_type == "Windows":
            scripts['enable_firewall_windows'] = {
                'nom': 'Activer le pare-feu Windows',
                'description': 'Active le pare-feu Windows Defender',
                'commande': 'netsh advfirewall set allprofiles state on',
                'reversible': True,
                'commande_annulation': 'netsh advfirewall set allprofiles state off'
            }
        
        # Script pour activer le pare-feu (Linux)
        if self.os_type == "Linux":
            scripts['enable_firewall_linux'] = {
                'nom': 'Activer le pare-feu UFW',
                'description': 'Active le pare-feu UFW sur Linux',
                'commande': 'sudo ufw enable',
                'reversible': True,
                'commande_annulation': 'sudo ufw disable'
            }
        
        return scripts
    
    def _get_prevention_measures(self, threat_type: str) -> List[str]:
        """Mesures de prévention pour éviter de futures attaques"""
        
        prevention = {
            "DDoS": [
                "Utiliser un service de protection DDoS (Cloudflare, AWS Shield)",
                "Configurer la limitation de débit sur votre serveur",
                "Augmenter la capacité de bande passante",
                "Mettre en place un CDN (Content Delivery Network)",
                "Surveiller le trafic en temps réel"
            ],
            
            "Port Scan": [
                "Fermer tous les ports non utilisés",
                "Utiliser un VPN pour les accès à distance",
                "Configurer le pare-feu pour bloquer les scans",
                "Désactiver les services inutiles",
                "Changer les ports par défaut des services critiques"
            ],
            
            "Malware C&C": [
                "Installer et maintenir à jour un antivirus",
                "Ne jamais ouvrir de pièces jointes suspectes",
                "Maintenir tous les logiciels à jour",
                "Utiliser un bloqueur de publicités",
                "Sauvegarder régulièrement vos données",
                "Former les utilisateurs à la cybersécurité"
            ],
            
            "SQL Injection": [
                "Utiliser des requêtes préparées (prepared statements)",
                "Valider et échapper toutes les entrées utilisateur",
                "Utiliser un WAF (Web Application Firewall)",
                "Appliquer le principe du moindre privilège pour la BDD",
                "Faire des audits de sécurité réguliers du code"
            ],
            
            "XSS": [
                "Échapper tous les caractères spéciaux HTML",
                "Implémenter Content Security Policy (CSP)",
                "Valider toutes les entrées utilisateur côté serveur",
                "Utiliser des frameworks avec protection XSS intégrée",
                "Nettoyer les données avant affichage"
            ],
            
            "Brute Force": [
                "Utiliser des mots de passe forts (12+ caractères)",
                "Activer l'authentification à deux facteurs (2FA)",
                "Limiter le nombre de tentatives de connexion",
                "Utiliser CAPTCHA après X tentatives échouées",
                "Surveiller les tentatives de connexion suspectes",
                "Bloquer temporairement les IPs après échecs répétés"
            ]
        }
        
        return prevention.get(threat_type, [
            "Maintenir tous les systèmes à jour",
            "Utiliser des mots de passe forts",
            "Activer le pare-feu",
            "Installer un antivirus",
            "Faire des sauvegardes régulières"
        ])
    
    def _generic_remediation_plan(self, severity: str) -> Dict:
        """Plan de remédiation générique pour menaces inconnues"""
        
        return {
            'threat_type': 'Unknown',
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            
            'actions_immediates': {
                'description': 'Actions de sécurité générales',
                'actions': [
                    {
                        'id': 'generic_monitor',
                        'nom': 'Surveillance accrue',
                        'description': 'Surveiller l\'activité réseau de près',
                        'risque': 'LOW',
                        'impact': 'Aucun'
                    }
                ],
                'recommandation': 'Surveiller la situation'
            },
            
            'actions_manuelles': {
                'description': 'Actions recommandées',
                'actions': [
                    "Vérifier les logs système pour plus d'informations",
                    "Consulter un expert en sécurité si nécessaire",
                    "Documenter l'incident"
                ],
                'priorite': self._get_manual_action_priority(severity)
            },
            
            'scripts': {},
            
            'prevention': [
                "Maintenir le système à jour",
                "Renforcer les paramètres de sécurité",
                "Surveiller régulièrement l'activité réseau"
            ]
        }
    
    def execute_action(self, action_id: str, alert_details: Dict) -> Dict:
        """
        Exécute une action de remédiation
        ATTENTION: Cette fonction peut modifier la configuration système
        """
        
        result = {
            'action_id': action_id,
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'message': '',
            'details': {}
        }
        
        try:
            # Bloquer une IP
            if action_id in ['ddos_block_ip', 'port_block_scanner', 
                            'sql_block_ip', 'xss_block_ip', 'bruteforce_block_ip']:
                result = self._block_ip(alert_details.get('source_ip', ''))
            
            # Activer le pare-feu
            elif action_id == 'firewall_enable':
                result = self._enable_firewall()
            
            # Bloquer un port
            elif action_id == 'port_close_unused':
                result = self._block_port(alert_details.get('destination_port', 0))
            
            # Actions qui nécessitent plus de détails
            else:
                result['message'] = "Action non implémentée ou nécessite une intervention manuelle"
            
            # Enregistrer dans l'historique
            self.remediation_history.append(result)
            
        except Exception as e:
            result['success'] = False
            result['message'] = f"Erreur lors de l'exécution: {str(e)}"
        
        return result
    
    def _block_ip(self, ip_address: str) -> Dict:
        """Bloque une adresse IP via le pare-feu"""
        
        if not ip_address:
            return {
                'success': False,
                'message': 'Adresse IP manquante'
            }
        
        try:
            if self.os_type == "Windows":
                # Commande Windows Firewall
                cmd = f'netsh advfirewall firewall add rule name="IDS_Block_{ip_address}" dir=in action=block remoteip={ip_address}'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                
                return {
                    'success': True,
                    'message': f'IP {ip_address} bloquée avec succès (Windows)',
                    'details': {
                        'ip': ip_address,
                        'method': 'Windows Firewall',
                        'reversible': True,
                        'undo_command': f'netsh advfirewall firewall delete rule name="IDS_Block_{ip_address}"'
                    }
                }
            
            elif self.os_type == "Linux":
                # Commande iptables
                cmd = f'sudo iptables -A INPUT -s {ip_address} -j DROP'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                
                return {
                    'success': True,
                    'message': f'IP {ip_address} bloquée avec succès (Linux)',
                    'details': {
                        'ip': ip_address,
                        'method': 'iptables',
                        'reversible': True,
                        'undo_command': f'sudo iptables -D INPUT -s {ip_address} -j DROP'
                    }
                }
            
            else:
                return {
                    'success': False,
                    'message': f'Système d\'exploitation non supporté: {self.os_type}'
                }
        
        except subprocess.CalledProcessError as e:
            return {
                'success': False,
                'message': f'Échec du blocage IP: {str(e)}'
            }
    
    def _enable_firewall(self) -> Dict:
        """Active le pare-feu système"""
        
        try:
            if self.os_type == "Windows":
                cmd = 'netsh advfirewall set allprofiles state on'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                
                return {
                    'success': True,
                    'message': 'Pare-feu Windows activé avec succès',
                    'details': {
                        'method': 'Windows Firewall',
                        'profiles': 'all'
                    }
                }
            
            elif self.os_type == "Linux":
                cmd = 'sudo ufw enable'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                
                return {
                    'success': True,
                    'message': 'Pare-feu UFW activé avec succès',
                    'details': {
                        'method': 'UFW'
                    }
                }
            
            else:
                return {
                    'success': False,
                    'message': f'Système d\'exploitation non supporté: {self.os_type}'
                }
        
        except subprocess.CalledProcessError as e:
            return {
                'success': False,
                'message': f'Échec de l\'activation du pare-feu: {str(e)}'
            }
    
    def _block_port(self, port: int) -> Dict:
        """Bloque un port spécifique"""
        
        if port <= 0 or port > 65535:
            return {
                'success': False,
                'message': 'Numéro de port invalide'
            }
        
        try:
            if self.os_type == "Windows":
                cmd = f'netsh advfirewall firewall add rule name="IDS_Block_Port_{port}" dir=in action=block protocol=TCP localport={port}'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                
                return {
                    'success': True,
                    'message': f'Port {port} bloqué avec succès (Windows)',
                    'details': {
                        'port': port,
                        'method': 'Windows Firewall',
                        'reversible': True,
                        'undo_command': f'netsh advfirewall firewall delete rule name="IDS_Block_Port_{port}"'
                    }
                }
            
            elif self.os_type == "Linux":
                cmd = f'sudo iptables -A INPUT -p tcp --dport {port} -j DROP'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                
                return {
                    'success': True,
                    'message': f'Port {port} bloqué avec succès (Linux)',
                    'details': {
                        'port': port,
                        'method': 'iptables',
                        'reversible': True,
                        'undo_command': f'sudo iptables -D INPUT -p tcp --dport {port} -j DROP'
                    }
                }
            
            else:
                return {
                    'success': False,
                    'message': f'Système d\'exploitation non supporté: {self.os_type}'
                }
        
        except subprocess.CalledProcessError as e:
            return {
                'success': False,
                'message': f'Échec du blocage du port: {str(e)}'
            }
    
    def get_remediation_history(self) -> List[Dict]:
        """Retourne l'historique des actions de remédiation"""
        return self.remediation_history.copy()


# Instance globale
security_remediator = SecurityRemediator()