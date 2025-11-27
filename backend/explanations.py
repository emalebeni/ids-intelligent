"""
Module d'explications simples et accessibles
Transforme les termes techniques en langage clair pour tous
"""

from typing import Dict, List


class ThreatExplainer:
    """Explique les menaces en langage simple et accessible"""
    
    def __init__(self):
        self.threat_explanations = self._initialize_explanations()
        self.severity_explanations = self._initialize_severity_explanations()
        self.port_explanations = self._initialize_port_explanations()
    
    def _initialize_explanations(self) -> Dict:
        """Initialise les explications pour chaque type de menace"""
        
        return {
            "DDoS": {
                "nom_simple": "Attaque par Saturation",
                "description_courte": "Des milliers de fausses demandes pour bloquer un service",
                "description_longue": """
                    Imaginez un restaurant qui reçoit soudainement des milliers de réservations 
                    bidons en même temps. Le personnel est tellement débordé qu'il ne peut plus 
                    servir les vrais clients. C'est exactement ce qu'est une attaque DDoS : 
                    l'attaquant envoie une quantité massive de fausses demandes pour saturer 
                    le système et le rendre inutilisable.
                """,
                "comment_ca_marche": """
                    1. L'attaquant utilise des centaines ou milliers d'ordinateurs infectés
                    2. Tous ces ordinateurs envoient des demandes simultanées vers la même cible
                    3. Le serveur ciblé est submergé et ne peut plus répondre
                    4. Les utilisateurs légitimes ne peuvent plus accéder au service
                """,
                "signes_visibles": [
                    "Site web ou service très lent ou inaccessible",
                    "Impossible de se connecter à internet",
                    "Applications qui ne répondent plus",
                    "Connexion qui se coupe régulièrement"
                ],
                "niveau_danger": "ÉLEVÉ - Peut paralyser complètement un service",
                "qui_est_vise": "Sites web, serveurs, services en ligne",
                "motivation_attaquant": "Extorsion, sabotage, activisme politique, concurrence déloyale"
            },
            
            "Port Scan": {
                "nom_simple": "Reconnaissance du Terrain",
                "description_courte": "Un pirate teste toutes les portes pour voir lesquelles sont ouvertes",
                "description_longue": """
                    Imaginez un cambrioleur qui fait le tour d'une maison en testant chaque 
                    porte et fenêtre pour voir ce qui est ouvert. Un scan de ports fonctionne 
                    de la même manière : l'attaquant vérifie tous les points d'entrée possibles 
                    de votre système pour trouver les failles. C'est souvent la première étape 
                    avant une vraie attaque.
                """,
                "comment_ca_marche": """
                    1. L'attaquant envoie des messages à tous les "ports" (portes d'entrée) de votre système
                    2. Il note quels ports répondent (= portes ouvertes)
                    3. Il identifie quels services tournent derrière ces ports
                    4. Il cherche ensuite des vulnérabilités connues pour ces services
                """,
                "signes_visibles": [
                    "Ralentissements inexpliqués de la connexion",
                    "Logs montrant de nombreuses connexions échouées",
                    "Activité réseau inhabituelle",
                    "Pare-feu qui bloque beaucoup de tentatives"
                ],
                "niveau_danger": "MOYEN - Préparation d'une attaque plus grave",
                "qui_est_vise": "N'importe quel appareil connecté à internet",
                "motivation_attaquant": "Reconnaissance avant attaque, recherche de vulnérabilités"
            },
            
            "Malware C&C": {
                "nom_simple": "Logiciel Espion Actif",
                "description_courte": "Un virus sur votre appareil qui communique avec son créateur",
                "description_longue": """
                    C'est comme si quelqu'un avait planté un micro espion dans votre maison 
                    qui transmet tout ce qui se passe à un pirate. Un malware C&C (Command & 
                    Control) est un logiciel malveillant qui s'est installé sur votre appareil 
                    et qui communique régulièrement avec le serveur du pirate pour recevoir des 
                    ordres et envoyer vos données personnelles.
                """,
                "comment_ca_marche": """
                    1. Un logiciel malveillant s'installe sur votre appareil (via email, téléchargement, etc.)
                    2. Il se connecte régulièrement à un serveur contrôlé par le pirate
                    3. Il reçoit des commandes : voler des mots de passe, espionner, etc.
                    4. Il envoie vos données sensibles au pirate
                """,
                "signes_visibles": [
                    "Appareil qui ralentit sans raison",
                    "Consommation de données internet inexpliquée",
                    "Programmes qui démarrent tout seuls",
                    "Antivirus qui détecte des menaces",
                    "Ventilateur qui tourne beaucoup même au repos"
                ],
                "niveau_danger": "CRITIQUE - Votre appareil est compromis",
                "qui_est_vise": "Tous les appareils : ordinateurs, smartphones, tablettes",
                "motivation_attaquant": "Vol de données personnelles, espionnage, utilisation de votre appareil pour attaquer d'autres"
            },
            
            "SQL Injection": {
                "nom_simple": "Piratage de Base de Données",
                "description_courte": "Manipulation d'un formulaire pour accéder à toute la base de données",
                "description_longue": """
                    Imaginez un formulaire de connexion où au lieu de taper votre nom, vous 
                    tapez une phrase magique qui trompe le système et vous donne accès à tous 
                    les comptes. C'est une injection SQL : le pirate envoie du code malveillant 
                    dans un formulaire web (login, recherche, etc.) pour manipuler la base de 
                    données et accéder à des informations confidentielles.
                """,
                "comment_ca_marche": """
                    1. L'attaquant trouve un formulaire web mal protégé
                    2. Au lieu de données normales, il envoie du code SQL malveillant
                    3. Le site web exécute ce code sans vérifier
                    4. L'attaquant peut lire, modifier ou supprimer toute la base de données
                """,
                "signes_visibles": [
                    "Messages d'erreur bizarres sur un site web",
                    "Comportement anormal d'un formulaire",
                    "Accès à des données qu'on ne devrait pas voir",
                    "Site qui affiche des informations de base de données"
                ],
                "niveau_danger": "CRITIQUE - Peut exposer toutes les données utilisateurs",
                "qui_est_vise": "Sites web avec formulaires (login, recherche, commentaires)",
                "motivation_attaquant": "Vol de données personnelles, cartes bancaires, mots de passe"
            },
            
            "XSS": {
                "nom_simple": "Code Piégé dans une Page Web",
                "description_courte": "Injection de code malveillant qui s'exécute chez les visiteurs",
                "description_longue": """
                    C'est comme si quelqu'un glissait un tract piégé dans un journal légitime. 
                    Quand vous lisez le journal, le tract piégé vous fait faire des actions 
                    dangereuses à votre insu. Le XSS fonctionne pareil : le pirate injecte du 
                    code JavaScript malveillant dans un site web, et ce code s'exécute dans 
                    le navigateur de tous les visiteurs.
                """,
                "comment_ca_marche": """
                    1. L'attaquant trouve un endroit où il peut poster du contenu (commentaire, profil, etc.)
                    2. Il y insère du code JavaScript malveillant déguisé
                    3. Le site web affiche ce contenu sans le vérifier
                    4. Le code s'exécute chez tous les visiteurs qui voient cette page
                    5. Le code peut voler des cookies, mots de passe, rediriger vers des sites malveillants
                """,
                "signes_visibles": [
                    "Pop-ups bizarres sur un site normalement sûr",
                    "Redirections automatiques vers d'autres sites",
                    "Comportement étrange de votre navigateur",
                    "Demandes de mot de passe inattendues"
                ],
                "niveau_danger": "ÉLEVÉ - Peut voler vos identifiants et données",
                "qui_est_vise": "Utilisateurs de sites web, réseaux sociaux, forums",
                "motivation_attaquant": "Vol de cookies de session, redirection vers sites de phishing, défacement"
            },
            
            "Brute Force": {
                "nom_simple": "Tentatives Massives de Connexion",
                "description_courte": "Essayer des milliers de mots de passe jusqu'à trouver le bon",
                "description_longue": """
                    C'est comme un voleur qui essaierait toutes les combinaisons possibles 
                    d'un cadenas. Une attaque par force brute consiste à tester 
                    automatiquement des milliers ou millions de mots de passe différents 
                    jusqu'à trouver le bon. Les logiciels de piratage peuvent tester des 
                    milliers de combinaisons par seconde.
                """,
                "comment_ca_marche": """
                    1. L'attaquant utilise un logiciel automatisé
                    2. Le logiciel teste des listes de mots de passe courants (123456, password, etc.)
                    3. Il essaie aussi des combinaisons de lettres/chiffres/symboles
                    4. Dès qu'un mot de passe fonctionne, l'attaquant a accès au compte
                """,
                "signes_visibles": [
                    "Notifications d'échecs de connexion multiples",
                    "Compte verrouillé pour tentatives échouées",
                    "Emails d'alerte de connexions suspectes",
                    "Ralentissement du service de connexion"
                ],
                "niveau_danger": "ÉLEVÉ - Peut compromettre votre compte",
                "qui_est_vise": "Comptes utilisateurs, services SSH, RDP, FTP, panneaux d'administration",
                "motivation_attaquant": "Accès non autorisé, vol de compte, installation de backdoors"
            },
            
            "Suspicious Activity": {
                "nom_simple": "Activité Inhabituelle",
                "description_courte": "Comportement suspect détecté mais pas encore identifié",
                "description_longue": """
                    C'est comme voir quelqu'un rôder autour de votre maison de manière 
                    suspecte, sans être sûr de ses intentions. Notre système a détecté un 
                    comportement qui ne correspond pas aux patterns normaux, mais qui ne 
                    correspond pas non plus à une attaque connue. Cela peut être un signe 
                    précurseur d'attaque ou une nouvelle forme de menace.
                """,
                "comment_ca_marche": """
                    1. Le système détecte un trafic anormal
                    2. Ce trafic ne correspond à aucune attaque connue
                    3. Mais il présente des caractéristiques suspectes (IP malveillante, ports inhabituels, etc.)
                    4. Nécessite une surveillance accrue
                """,
                "signes_visibles": [
                    "Connexions depuis des pays inhabituels",
                    "Activité réseau à des heures étranges",
                    "Tentatives d'accès à des services inhabituels",
                    "Trafic vers des IPs connues pour être malveillantes"
                ],
                "niveau_danger": "MOYEN - Surveillance recommandée",
                "qui_est_vise": "Variable selon l'activité détectée",
                "motivation_attaquant": "Reconnaissance, test de sécurité, nouvelle forme d'attaque"
            },
            
            "Unknown": {
                "nom_simple": "Anomalie Non Identifiée",
                "description_courte": "Quelque chose d'anormal détecté mais non classifié",
                "description_longue": """
                    Notre système a détecté que quelque chose ne va pas, mais ne peut pas 
                    encore déterminer exactement de quoi il s'agit. C'est comme entendre 
                    un bruit suspect dans votre maison sans savoir ce qui l'a causé. Cela 
                    nécessite une investigation plus approfondie.
                """,
                "comment_ca_marche": """
                    1. L'intelligence artificielle détecte une anomalie
                    2. Les caractéristiques ne correspondent à aucun pattern connu
                    3. Peut être une fausse alerte ou une nouvelle menace
                    4. Analyse manuelle recommandée
                """,
                "signes_visibles": [
                    "Variables selon la nature de l'anomalie",
                    "Comportement inhabituel du réseau",
                    "Trafic avec des caractéristiques étranges"
                ],
                "niveau_danger": "VARIABLE - Investigation nécessaire",
                "qui_est_vise": "À déterminer",
                "motivation_attaquant": "À déterminer"
            }
        }
    
    def _initialize_severity_explanations(self) -> Dict:
        """Explications des niveaux de sévérité"""
        
        return {
            "CRITICAL": {
                "emoji": "🔴",
                "nom": "CRITIQUE",
                "description": "Danger immédiat - Action immédiate requise",
                "explication": """
                    C'est une urgence absolue, comme un incendie dans votre maison. 
                    Votre système est en danger imminent. Vous devez agir MAINTENANT 
                    pour éviter des dégâts importants (vol de données, prise de contrôle 
                    de votre appareil, etc.).
                """,
                "actions": [
                    "Déconnecter l'appareil d'internet immédiatement",
                    "Changer tous vos mots de passe depuis un autre appareil",
                    "Lancer un scan antivirus complet",
                    "Contacter un professionnel si nécessaire",
                    "Ne PAS utiliser l'appareil pour des opérations sensibles"
                ],
                "delai_action": "IMMÉDIAT (dans les minutes qui suivent)"
            },
            
            "HIGH": {
                "emoji": "🟠",
                "nom": "ÉLEVÉ",
                "description": "Menace sérieuse - Action rapide nécessaire",
                "explication": """
                    C'est comme voir de la fumée sortir d'une pièce. Ce n'est peut-être 
                    pas encore un incendie, mais ça peut le devenir rapidement. La menace 
                    est réelle et nécessite votre attention dans les prochaines heures.
                """,
                "actions": [
                    "Vérifier les connexions actives",
                    "Renforcer les mots de passe faibles",
                    "Activer l'authentification à deux facteurs",
                    "Scanner l'appareil avec un antivirus",
                    "Surveiller l'activité réseau"
                ],
                "delai_action": "RAPIDE (dans les heures qui suivent)"
            },
            
            "MEDIUM": {
                "emoji": "🟡",
                "nom": "MOYEN",
                "description": "Attention requise - Planifier des corrections",
                "explication": """
                    C'est comme une fenêtre laissée ouverte la nuit. Ce n'est pas une 
                    urgence, mais c'est une vulnérabilité qu'il faut corriger pour éviter 
                    qu'elle soit exploitée. Prenez le temps de bien sécuriser votre système.
                """,
                "actions": [
                    "Vérifier les paramètres de sécurité",
                    "Mettre à jour les logiciels",
                    "Fermer les ports inutilisés",
                    "Réviser les permissions d'accès",
                    "Planifier une maintenance de sécurité"
                ],
                "delai_action": "MODÉRÉ (dans les 24-48 heures)"
            },
            
            "LOW": {
                "emoji": "🔵",
                "nom": "FAIBLE",
                "description": "Surveillance - Pas d'urgence mais à noter",
                "explication": """
                    C'est comme remarquer qu'un voisin inconnu est dans le quartier. 
                    Ce n'est probablement rien de grave, mais c'est bon à savoir et à 
                    garder à l'œil. Prenez le temps d'améliorer votre sécurité quand vous le pouvez.
                """,
                "actions": [
                    "Prendre note de l'événement",
                    "Vérifier occasionnellement",
                    "Améliorer la sécurité quand possible",
                    "Documenter pour référence future"
                ],
                "delai_action": "PAS D'URGENCE (quand vous avez le temps)"
            }
        }
    
    def _initialize_port_explanations(self) -> Dict:
        """Explications simples pour les ports communs"""
        
        return {
            21: {
                "service": "FTP",
                "nom_simple": "Transfert de Fichiers",
                "description": "Comme une boîte aux lettres pour envoyer/recevoir des fichiers. Peu sécurisé car les mots de passe passent en clair.",
                "pourquoi_dangereux": "Les pirates peuvent intercepter vos identifiants facilement"
            },
            22: {
                "service": "SSH",
                "nom_simple": "Connexion à Distance Sécurisée",
                "description": "Comme une ligne téléphonique chiffrée pour contrôler un ordinateur à distance.",
                "pourquoi_dangereux": "Si le mot de passe est faible, les pirates peuvent prendre le contrôle total"
            },
            23: {
                "service": "Telnet",
                "nom_simple": "Connexion à Distance (OBSOLÈTE)",
                "description": "Ancienne méthode de connexion à distance, totalement non sécurisée.",
                "pourquoi_dangereux": "TOUT passe en clair, y compris les mots de passe. À FERMER IMMÉDIATEMENT!"
            },
            80: {
                "service": "HTTP",
                "nom_simple": "Sites Web Non Sécurisés",
                "description": "Port pour accéder aux sites web normaux (sans cadenas).",
                "pourquoi_dangereux": "Les données ne sont pas chiffrées, peuvent être interceptées"
            },
            443: {
                "service": "HTTPS",
                "nom_simple": "Sites Web Sécurisés",
                "description": "Port pour les sites web avec le cadenas (connexion chiffrée).",
                "pourquoi_dangereux": "Relativement sûr, mais peut être exploité si mal configuré"
            },
            445: {
                "service": "SMB",
                "nom_simple": "Partage de Fichiers Windows",
                "description": "Permet de partager des fichiers entre ordinateurs Windows.",
                "pourquoi_dangereux": "Très ciblé par les ransomwares et vers informatiques"
            },
            3306: {
                "service": "MySQL",
                "nom_simple": "Base de Données MySQL",
                "description": "Port d'accès direct à une base de données MySQL.",
                "pourquoi_dangereux": "Donne accès à toutes vos données si compromis"
            },
            3389: {
                "service": "RDP",
                "nom_simple": "Bureau à Distance Windows",
                "description": "Permet de contrôler un PC Windows à distance comme si vous étiez devant.",
                "pourquoi_dangereux": "Cible favorite des ransomwares, donne accès total au système"
            },
            5900: {
                "service": "VNC",
                "nom_simple": "Contrôle à Distance",
                "description": "Permet de voir et contrôler l'écran d'un autre ordinateur.",
                "pourquoi_dangereux": "Le pirate peut voir tout ce que vous faites en temps réel"
            }
        }
    
    def explain_threat(self, threat_type: str, detail_level: str = "medium") -> Dict:
        """
        Retourne une explication adaptée au niveau de détail demandé
        
        Args:
            threat_type: Type de menace (DDoS, Port Scan, etc.)
            detail_level: "short", "medium", "full"
        """
        
        if threat_type not in self.threat_explanations:
            threat_type = "Unknown"
        
        explanation = self.threat_explanations[threat_type]
        
        if detail_level == "short":
            return {
                'nom_simple': explanation['nom_simple'],
                'description': explanation['description_courte']
            }
        
        elif detail_level == "medium":
            return {
                'nom_simple': explanation['nom_simple'],
                'description': explanation['description_longue'],
                'niveau_danger': explanation['niveau_danger'],
                'signes_visibles': explanation['signes_visibles']
            }
        
        else:  # full
            return explanation
    
    def explain_severity(self, severity: str) -> Dict:
        """Explique un niveau de sévérité"""
        
        severity_upper = severity.upper()
        
        if severity_upper not in self.severity_explanations:
            severity_upper = "MEDIUM"
        
        return self.severity_explanations[severity_upper]
    
    def explain_port(self, port: int) -> Dict:
        """Explique à quoi sert un port"""
        
        if port in self.port_explanations:
            return self.port_explanations[port]
        
        return {
            'service': f"Port {port}",
            'nom_simple': "Service Non Identifié",
            'description': f"Port numéro {port}. Usage spécifique non documenté.",
            'pourquoi_dangereux': "Tout port ouvert peut être une porte d'entrée potentielle"
        }
    
    def get_simple_recommendations(self, threat_type: str, severity: str) -> List[str]:
        """
        Retourne des recommandations simples et actionnables
        """
        
        recommendations = []
        
        # Recommandations générales par sévérité
        if severity == "CRITICAL":
            recommendations.extend([
                "🔴 URGENCE : Déconnectez votre appareil d'internet IMMÉDIATEMENT",
                "🔴 Changez TOUS vos mots de passe depuis un autre appareil sûr",
                "🔴 Lancez un scan antivirus complet",
                "🔴 Contactez votre service informatique ou un professionnel"
            ])
        
        elif severity == "HIGH":
            recommendations.extend([
                "🟠 Vérifiez quels programmes sont connectés à internet",
                "🟠 Changez vos mots de passe importants",
                "🟠 Activez l'authentification à deux facteurs partout",
                "🟠 Mettez à jour votre antivirus et lancez un scan"
            ])
        
        elif severity == "MEDIUM":
            recommendations.extend([
                "🟡 Vérifiez vos paramètres de sécurité",
                "🟡 Fermez les applications que vous n'utilisez pas",
                "🟡 Vérifiez que votre pare-feu est activé",
                "🟡 Pensez à changer vos mots de passe faibles"
            ])
        
        else:  # LOW
            recommendations.extend([
                "🔵 Gardez un œil sur votre activité réseau",
                "🔵 Pensez à améliorer votre sécurité quand vous avez le temps",
                "🔵 Documentez cet événement pour référence future"
            ])
        
        # Recommandations spécifiques par type de menace
        threat_specific = {
            "DDoS": [
                "Contactez votre fournisseur d'accès internet",
                "Activez la protection anti-DDoS si disponible"
            ],
            "Port Scan": [
                "Fermez tous les ports non utilisés",
                "Activez ou renforcez votre pare-feu",
                "Désactivez les services inutiles"
            ],
            "Malware C&C": [
                "Déconnectez IMMÉDIATEMENT l'appareil d'internet",
                "Sauvegardez vos fichiers importants",
                "Réinstallez le système si possible",
                "Changez TOUS vos mots de passe depuis un autre appareil"
            ],
            "SQL Injection": [
                "Si vous gérez un site web, contactez votre hébergeur",
                "Ne vous connectez pas au site affecté",
                "Changez vos mots de passe du site concerné"
            ],
            "XSS": [
                "Videz le cache de votre navigateur",
                "Déconnectez-vous du site affecté",
                "Changez votre mot de passe du site",
                "Évitez le site jusqu'à ce qu'il soit corrigé"
            ],
            "Brute Force": [
                "Changez immédiatement votre mot de passe",
                "Utilisez un mot de passe fort (12+ caractères, mélangés)",
                "Activez l'authentification à deux facteurs",
                "Vérifiez les connexions récentes à votre compte"
            ]
        }
        
        if threat_type in threat_specific:
            recommendations.extend(threat_specific[threat_type])
        
        return recommendations
    
    def create_user_friendly_alert(self, alert: Dict) -> Dict:
        """
        Transforme une alerte technique en version accessible
        """
        
        threat_type = alert.get('type', 'Unknown')
        severity = alert.get('severity', 'MEDIUM')
        
        # Explications
        threat_explain = self.explain_threat(threat_type, detail_level="medium")
        severity_explain = self.explain_severity(severity)
        
        # Recommandations
        recommendations = self.get_simple_recommendations(threat_type, severity)
        
        # Port concerné
        dest_port = alert.get('destination_port', 0)
        port_explain = self.explain_port(dest_port) if dest_port > 0 else None
        
        return {
            'alert_id': alert.get('id', ''),
            'timestamp': alert.get('timestamp', ''),
            
            # Version simple
            'titre_simple': f"{severity_explain['emoji']} {threat_explain['nom_simple']} détecté",
            'description_simple': threat_explain['description'],
            
            # Niveau de danger
            'niveau_danger': {
                'texte': severity_explain['nom'],
                'emoji': severity_explain['emoji'],
                'explication': severity_explain['explication'],
                'delai_action': severity_explain['delai_action']
            },
            
            # Ce qui se passe
            'que_se_passe_t_il': threat_explain['description'],
            'signes_visibles': threat_explain.get('signes_visibles', []),
            
            # Port concerné (si applicable)
            'port_info': port_explain,
            
            # Détails techniques (simplifiés)
            'details': {
                'depuis': alert.get('source_ip', 'Inconnu'),
                'vers': alert.get('destination_ip', 'Inconnu'),
                'service_vise': port_explain['nom_simple'] if port_explain else 'Non spécifié',
                'confiance': f"{int(alert.get('confidence', 0) * 100)}%"
            },
            
            # Actions recommandées
            'que_faire': recommendations,
            
            # Données originales (pour référence technique)
            'donnees_techniques': alert
        }


# Instance globale
threat_explainer = ThreatExplainer()