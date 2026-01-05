#!/usr/bin/env python3
"""
Keycloak Security Scanner - Complete Edition
Scanner exhaustif basé sur les méthodologies CSA Cyber
Pentesting Keycloak Part 1 & 2

Affiche TOUS les détails de chaque vulnérabilité trouvée
Tests basés sur les vraies techniques de pentest Keycloak
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

class KeycloakScanner:
    def __init__(self, base_url: str, timeout: int = 10, verbose: bool = False):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Listes étendues depuis les articles CSA
        self.default_realms = [
            'master', 'main', 'app', 'application', 'prod', 'production',
            'dev', 'development', 'test', 'staging', 'demo', 'admin',
            'api', 'web', 'mobile', 'internal', 'external', 'public', 'pentest'
        ]
        
        # Clients IDs par défaut (depuis l'article)
        self.default_client_ids = [
            'account', 'account-console', 'admin-cli', 'broker', 
            'realm-management', 'security-admin-console',
            'app', 'webapp', 'api', 'frontend', 'backend', 
            'mobile-app', 'spa', 'react-app', 'vue-app'
        ]
        
        # Scopes par défaut (depuis l'article)
        self.default_scopes = [
            'openid', 'profile', 'email', 'address', 'phone', 
            'offline_access', 'roles', 'web-origins', 'microprofile-jwt',
            'uma_authorization'
        ]
        
        # Identity Providers (depuis l'article)
        self.default_idps = [
            'google', 'github', 'facebook', 'twitter', 'linkedin',
            'microsoft', 'bitbucket', 'gitlab', 'instagram', 'paypal',
            'openshift-v3', 'openshift-v4', 'stackoverflow', 
            'oidc', 'saml', 'azure', 'okta', 'auth0', 'apple'
        ]
        
        # Credentials par défaut
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
        
        # Ports additionnels Keycloak (depuis article Part 2)
        self.additional_ports = [8080, 8443, 9990, 9993, 8009]
        
        self.results = {
            'scan_info': {
                'target': base_url,
                'scan_date': datetime.now().isoformat(),
                'scanner_version': '3.0-complete'
            },
            'is_keycloak': False,
            'version': None,
            'realms': [],
            'client_ids': {},
            'scopes': {},
            'idps': {},
            'roles': {},
            'users_enumerated': [],
            'vulnerabilities': [],
            'misconfigurations': [],
            'info': []
        }

    def print_banner(self):
        """Affiche la bannière"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
║     Keycloak Security Scanner v3.0 - Complete Edition           ║
║            Basé sur CSA Cyber Pentesting Keycloak               ║
║           Affichage COMPLET de toutes les découvertes           ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)

    def log(self, message: str, level: str = "INFO"):
        """Affiche un message avec code couleur"""
        colors = {
            "INFO": Fore.BLUE,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "VULN": Fore.MAGENTA,
            "CRITICAL": Fore.RED,
            "DETAIL": Fore.CYAN
        }
        color = colors.get(level, Fore.WHITE)
        prefix = {
            "INFO": "[*]",
            "SUCCESS": "[+]",
            "WARNING": "[!]",
            "ERROR": "[-]",
            "VULN": "[VULN]",
            "CRITICAL": "[CRITICAL]",
            "DETAIL": "[→]"
        }
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.WHITE}[{timestamp}]{Style.RESET_ALL} {color}{prefix.get(level, '[*]')} {message}{Style.RESET_ALL}")

    def print_section(self, title: str):
        """Affiche un séparateur de section"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{title:^70}")
        print(f"{'='*70}{Style.RESET_ALL}\n")

    def print_details(self, details: Dict, indent: int = 2):
        """Affiche les détails d'une découverte de manière structurée"""
        indent_str = " " * indent
        for key, value in details.items():
            if isinstance(value, dict):
                print(f"{indent_str}{Fore.YELLOW}{key}:{Style.RESET_ALL}")
                self.print_details(value, indent + 2)
            elif isinstance(value, list):
                print(f"{indent_str}{Fore.YELLOW}{key}:{Style.RESET_ALL}")
                for item in value:
                    if isinstance(item, dict):
                        self.print_details(item, indent + 2)
                    else:
                        print(f"{indent_str}  • {item}")
            else:
                print(f"{indent_str}{Fore.YELLOW}{key}:{Style.RESET_ALL} {value}")

    def detect_version(self) -> Optional[str]:
        """Détecte la version de Keycloak (Article: Version Information)"""
        self.log("Détection de la version Keycloak...", "INFO")
        
        try:
            # Via serverinfo endpoint (nécessite auth mais on teste quand même)
            admin_url = f"{self.base_url}/auth/admin/serverinfo"
            response = self.session.get(admin_url, timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'systemInfo' in data and 'version' in data['systemInfo']:
                        version = data['systemInfo']['version']
                        self.results['version'] = version
                        self.log(f"Version détectée: {version}", "SUCCESS")
                        
                        # Afficher les détails complets
                        print(f"\n{Fore.GREEN}╔═══ VERSION KEYCLOAK DÉTECTÉE ═══╗{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}Version: {version}{Style.RESET_ALL}")
                        print(f"Endpoint: {admin_url}")
                        print(f"⚠️  Serverinfo accessible sans authentification!")
                        print(f"\n{Fore.YELLOW}Recommandations:{Style.RESET_ALL}")
                        print("  • Vérifier les CVEs pour cette version:")
                        print("    - https://repology.org/project/keycloak/cves")
                        print("    - https://www.cvedetails.com/version-list/16498/37999/1/Keycloak-Keycloak.html")
                        print(f"  • Mettre à jour vers la dernière version stable")
                        print(f"{Fore.GREEN}╚═══════════════════════════════════╝{Style.RESET_ALL}\n")
                        return version
                except:
                    pass
            
            # Via fichiers JS
            js_urls = ['/auth/js/keycloak.js', '/js/keycloak.js']
            
            for js_path in js_urls:
                url = urljoin(self.base_url, js_path)
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    version_match = re.search(r'version["\']?\s*:\s*["\']([0-9.]+)["\']', response.text)
                    if version_match:
                        version = version_match.group(1)
                        self.results['version'] = version
                        self.log(f"Version détectée (via JS): {version}", "SUCCESS")
                        return version
                    
        except Exception as e:
            if self.verbose:
                self.log(f"Erreur détection version: {str(e)}", "ERROR")
        
        self.log("Version non détectée (normal si non authentifié)", "INFO")
        return None

    def is_keycloak(self) -> bool:
        """Détecte si l'URL cible utilise Keycloak (Article: Am I Testing Keycloak?)"""
        self.print_section("DÉTECTION KEYCLOAK")
        self.log("Vérification si la cible utilise Keycloak...", "INFO")
        
        indicators = {
            'urls': [],
            'cookies': [],
            'keywords': [],
            'headers': []
        }
        
        # Test 1: URLs caractéristiques
        keycloak_paths = [
            '/auth/realms/',
            '/auth/admin/',
            '/realms/',
            '/auth/js/keycloak.js',
            '/auth/realms/master/.well-known/openid-configuration'
        ]
        
        for path in keycloak_paths:
            try:
                url = urljoin(self.base_url, path)
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if response.status_code in [200, 401, 403]:
                    indicators['urls'].append({
                        'path': path,
                        'status': response.status_code,
                        'url': url
                    })
            except:
                pass
        
        # Test 2: Contenu HTML
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            content = response.text.lower()
            
            keycloak_keywords = [
                'keycloak',
                '/auth/realms/',
                'kc-login',
                'kc-form',
                'resource_access'
            ]
            
            for keyword in keycloak_keywords:
                if keyword in content:
                    indicators['keywords'].append(keyword)
        except:
            pass
        
        # Test 3: Cookies Keycloak
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            for cookie in response.cookies:
                if any(kc in cookie.name.upper() for kc in ['KEYCLOAK', 'AUTH_SESSION_ID', 'KC_RESTART']):
                    indicators['cookies'].append({
                        'name': cookie.name,
                        'domain': cookie.domain,
                        'secure': cookie.secure
                    })
        except:
            pass
        
        # Test 4: Headers
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            for header, value in response.headers.items():
                if 'keycloak' in header.lower() or 'keycloak' in str(value).lower():
                    indicators['headers'].append({
                        'header': header,
                        'value': value
                    })
        except:
            pass
        
        # Calculer si Keycloak est détecté
        total_indicators = sum(len(v) for v in indicators.values())
        is_kc = total_indicators > 0
        self.results['is_keycloak'] = is_kc
        
        # Afficher les résultats détaillés
        if is_kc:
            print(f"\n{Fore.GREEN}╔═══ KEYCLOAK DÉTECTÉ ═══╗{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Total d'indicateurs: {total_indicators}{Style.RESET_ALL}\n")
            
            if indicators['urls']:
                print(f"{Fore.CYAN}URLs Keycloak trouvées:{Style.RESET_ALL}")
                for url_info in indicators['urls']:
                    print(f"  • {url_info['path']} [{url_info['status']}]")
                    print(f"    → {url_info['url']}")
            
            if indicators['cookies']:
                print(f"\n{Fore.CYAN}Cookies Keycloak:{Style.RESET_ALL}")
                for cookie in indicators['cookies']:
                    print(f"  • {cookie['name']}")
                    print(f"    Domain: {cookie['domain']}")
                    print(f"    Secure: {cookie['secure']}")
            
            if indicators['keywords']:
                print(f"\n{Fore.CYAN}Keywords trouvés dans HTML:{Style.RESET_ALL}")
                for kw in indicators['keywords']:
                    print(f"  • {kw}")
            
            if indicators['headers']:
                print(f"\n{Fore.CYAN}Headers Keycloak:{Style.RESET_ALL}")
                for hdr in indicators['headers']:
                    print(f"  • {hdr['header']}: {hdr['value']}")
            
            print(f"{Fore.GREEN}╚═════════════════════════╝{Style.RESET_ALL}\n")
            
            # Détecter la version
            self.detect_version()
        else:
            self.log("✗ Keycloak NON détecté", "ERROR")
            print(f"Aucun indicateur Keycloak trouvé sur {self.base_url}")
        
        return is_kc

    def enumerate_realms(self) -> List[str]:
        """Énumère les realms (Article: Realms Enumeration)"""
        self.print_section("ÉNUMÉRATION DES REALMS")
        self.log("Énumération des realms...", "INFO")
        
        valid_realms = []
        
        for realm in self.default_realms:
            try:
                # Test avec .well-known/openid-configuration
                url = f"{self.base_url}/auth/realms/{realm}/.well-known/openid-configuration"
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'issuer' in data:
                            valid_realms.append({
                                'name': realm,
                                'issuer': data.get('issuer'),
                                'authorization_endpoint': data.get('authorization_endpoint'),
                                'token_endpoint': data.get('token_endpoint'),
                                'userinfo_endpoint': data.get('userinfo_endpoint'),
                                'jwks_uri': data.get('jwks_uri'),
                                'grant_types_supported': data.get('grant_types_supported', []),
                                'response_types_supported': data.get('response_types_supported', []),
                                'scopes_supported': data.get('scopes_supported', []),
                                'id_token_signing_alg_values_supported': data.get('id_token_signing_alg_values_supported', [])
                            })
                            
                            # Afficher les détails immédiatement
                            print(f"\n{Fore.GREEN}╔═══ REALM TROUVÉ: {realm} ═══╗{Style.RESET_ALL}")
                            print(f"{Fore.YELLOW}Issuer:{Style.RESET_ALL} {data.get('issuer')}")
                            print(f"{Fore.YELLOW}Authorization:{Style.RESET_ALL} {data.get('authorization_endpoint')}")
                            print(f"{Fore.YELLOW}Token:{Style.RESET_ALL} {data.get('token_endpoint')}")
                            print(f"{Fore.YELLOW}UserInfo:{Style.RESET_ALL} {data.get('userinfo_endpoint')}")
                            print(f"{Fore.YELLOW}JWKS URI:{Style.RESET_ALL} {data.get('jwks_uri')}")
                            
                            if data.get('grant_types_supported'):
                                print(f"\n{Fore.CYAN}Grant Types supportés:{Style.RESET_ALL}")
                                for gt in data.get('grant_types_supported'):
                                    print(f"  • {gt}")
                            
                            if data.get('scopes_supported'):
                                print(f"\n{Fore.CYAN}Scopes supportés (config):{Style.RESET_ALL}")
                                for scope in data.get('scopes_supported'):
                                    print(f"  • {scope}")
                            
                            # Vérifier les algorithmes de signature
                            algs = data.get('id_token_signing_alg_values_supported', [])
                            if algs:
                                print(f"\n{Fore.CYAN}Algorithmes JWT supportés:{Style.RESET_ALL}")
                                for alg in algs:
                                    if alg.startswith('HS'):
                                        print(f"  • {alg} {Fore.RED}(HMAC - secret partagé){Style.RESET_ALL}")
                                    elif alg in ['RS256', 'ES256']:
                                        print(f"  • {alg} {Fore.YELLOW}(Acceptable mais pas optimal){Style.RESET_ALL}")
                                    elif alg in ['RS512', 'ES512', 'PS512']:
                                        print(f"  • {alg} {Fore.GREEN}(Fort - Recommandé){Style.RESET_ALL}")
                                    else:
                                        print(f"  • {alg}")
                            
                            print(f"{Fore.GREEN}╚{'═'*(len(realm)+22)}╝{Style.RESET_ALL}\n")
                            
                            # Tester la self-registration
                            self.test_self_registration(realm)
                            
                    except Exception as e:
                        if self.verbose:
                            self.log(f"Erreur parsing realm {realm}: {str(e)}", "ERROR")
            except:
                pass
        
        self.results['realms'] = [r['name'] for r in valid_realms]
        
        print(f"\n{Fore.CYAN}═══ RÉSUMÉ REALMS ═══{Style.RESET_ALL}")
        print(f"Total realms trouvés: {Fore.GREEN}{len(valid_realms)}{Style.RESET_ALL}")
        if valid_realms:
            print("Liste: " + ", ".join([r['name'] for r in valid_realms]))
        print()
        
        return [r['name'] for r in valid_realms]

    def test_self_registration(self, realm: str):
        """Test Self-Registration (Article: Realms Self-Registration Enabled)"""
        try:
            # Essayer d'accéder à la page de registration
            reg_url = f"{self.base_url}/auth/realms/{realm}/login-actions/registration"
            response = self.session.get(reg_url, timeout=self.timeout, allow_redirects=False)
            
            if response.status_code in [200, 302]:
                print(f"{Fore.YELLOW}⚠️  Self-Registration ACTIVÉE{Style.RESET_ALL}")
                print(f"   URL: {reg_url}")
                print(f"   Status: {response.status_code}")
                print(f"\n   {Fore.RED}Risque:{Style.RESET_ALL} N'importe qui peut créer un compte")
                print(f"   {Fore.GREEN}Recommandation:{Style.RESET_ALL} Désactiver si non nécessaire en production")
                print()
                
                self.results['misconfigurations'].append({
                    'type': 'self_registration_enabled',
                    'realm': realm,
                    'severity': 'medium',
                    'url': reg_url,
                    'status_code': response.status_code,
                    'description': f"Self-registration activée pour realm '{realm}'",
                    'impact': "N'importe qui peut créer un compte utilisateur",
                    'remediation': "Désactiver dans Realm Settings → Login → User Registration"
                })
        except:
            pass

    def enumerate_client_ids(self, realm: str) -> List[Dict]:
        """Énumère les Client IDs (Article: Client IDs Enumeration)"""
        self.log(f"Énumération des Client IDs pour realm: {realm}", "INFO")
        
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
                content_length = len(response.content)
                
                # Stocker les longueurs pour analyse
                if content_length not in response_lengths:
                    response_lengths[content_length] = []
                response_lengths[content_length].append(client_id)
                
            except:
                pass
        
        # Identifier les clients valides (longueur différente de la majorité)
        # La technique CSA: la majorité aura une longueur, les valides une autre
        if response_lengths:
            lengths_sorted = sorted(response_lengths.items(), key=lambda x: len(x[1]), reverse=True)
            most_common_length = lengths_sorted[0][0]
            
            for length, clients in response_lengths.items():
                if length != most_common_length:
                    for client_id in clients:
                        client_info = {
                            'client_id': client_id,
                            'realm': realm,
                            'response_length': length,
                            'detection_method': 'content_length_diff'
                        }
                        valid_clients.append(client_info)
                        
                        print(f"\n{Fore.GREEN}✓ Client ID trouvé: {client_id}{Style.RESET_ALL}")
                        print(f"  Realm: {realm}")
                        print(f"  Response Length: {length} (vs {most_common_length} pour invalides)")
                        print(f"  Auth URL: {url}?client_id={client_id}")
        
        if valid_clients:
            print(f"\n{Fore.CYAN}═══ Client IDs pour {realm} ═══{Style.RESET_ALL}")
            print(f"Total: {Fore.GREEN}{len(valid_clients)}{Style.RESET_ALL}")
            for client in valid_clients:
                print(f"  • {client['client_id']}")
            print()
        
        return valid_clients

    def enumerate_scopes(self, realm: str, client_id: str) -> List[Dict]:
        """Énumère les Scopes (Article: Scopes Enumeration)"""
        self.log(f"Énumération des Scopes pour {realm}/{client_id}", "INFO")
        
        valid_scopes = []
        
        print(f"\n{Fore.CYAN}Testing Scopes pour client '{client_id}'...{Style.RESET_ALL}")
        
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
                
                # Un scope valide ne retourne pas d'erreur 400
                if response.status_code != 400:
                    scope_info = {
                        'scope': scope,
                        'realm': realm,
                        'client_id': client_id,
                        'status_code': response.status_code
                    }
                    valid_scopes.append(scope_info)
                    
                    # Déterminer la sévérité selon le scope
                    severity = 'info'
                    warning = ''
                    details = ''
                    
                    if scope == 'offline_access':
                        severity = 'high'
                        warning = '⚠️  SCOPE SENSIBLE'
                        details = """
    ┌─ OFFLINE_ACCESS DÉTECTÉ ─────────────────────────────────────────┐
    │ Ce scope génère des refresh tokens qui N'EXPIRENT JAMAIS          │
    │                                                                    │
    │ Impact:                                                            │
    │  • Accès permanent même après déconnexion                         │
    │  • Accès maintenu après changement de mot de passe                │
    │  • Persiste tant que non révoqué manuellement                     │
    │                                                                    │
    │ Exploitation:                                                      │
    │  1. Ajouter 'offline_access' à l'URL d'auth                       │
    │  2. Se connecter et autoriser                                     │
    │  3. Récupérer le code puis échanger contre tokens                 │
    │  4. Le refresh_token obtenu est permanent                         │
    │                                                                    │
    │ Commande:                                                          │
    │  curl -X POST '{0}/auth/realms/{1}/protocol/openid-connect/token' │
    │       -d 'grant_type=refresh_token'                               │
    │       -d 'refresh_token=OFFLINE_TOKEN'                            │
    │       -d 'client_id={2}'                                          │
    │                                                                    │
    │ Recommandation:                                                    │
    │  • Désactiver pour les clients Public                             │
    │  • Réserver aux applications serveur-à-serveur                    │
    │  • Implémenter une expiration forcée                              │
    └────────────────────────────────────────────────────────────────────┘
    """.format(self.base_url, realm, client_id)
                    
                    elif scope == 'uma_authorization':
                        severity = 'high'
                        warning = '⚠️  SCOPE SENSIBLE'
                        details = """
    ┌─ UMA_AUTHORIZATION DÉTECTÉ ───────────────────────────────────────┐
    │ User-Managed Access - Permet gestion de ressources partagées      │
    │                                                                    │
    │ Impact:                                                            │
    │  • Création de ressources avec permissions custom                 │
    │  • Partage de ressources entre utilisateurs                       │
    │  • Risque d'élévation de privilèges                               │
    │                                                                    │
    │ Exploitation:                                                      │
    │  Créer une ressource UMA:                                         │
    │  POST /auth/realms/{0}/authz/protection/resource_set             │
    │  Authorization: Bearer ACCESS_TOKEN                               │
    │  {{                                                                │
    │    "name": "malicious_resource",                                  │
    │    "scopes": ["read", "write", "delete"],                         │
    │    "owner": "victim_user_id"                                      │
    │  }}                                                                │
    │                                                                    │
    │ Recommandation:                                                    │
    │  • Désactiver si UMA non utilisé                                  │
    │  • Restreindre aux clients de confiance uniquement                │
    │  • Auditer les permissions UMA régulièrement                      │
    └────────────────────────────────────────────────────────────────────┘
    """.format(realm)
                    
                    elif scope == 'profile':
                        details = """
    ┌─ PROFILE SCOPE ────────────────────────────────────────────────────┐
    │ Donne accès aux informations de profil de l'utilisateur           │
    │                                                                    │
    │ Claims accessibles:                                                │
    │  • name, family_name, given_name, middle_name                     │
    │  • nickname, preferred_username                                   │
    │  • profile, picture, website                                      │
    │  • gender, birthdate, zoneinfo, locale, updated_at                │
    │                                                                    │
    │ API Endpoint:                                                      │
    │  PUT /auth/realms/{0}/account/                                    │
    │  (Permet de modifier ces informations si autorisé)                │
    └────────────────────────────────────────────────────────────────────┘
    """.format(realm)
                    
                    elif scope == 'address':
                        details = "    Donne accès aux claims d'adresse de l'utilisateur"
                    
                    elif scope == 'phone':
                        details = "    Donne accès aux claims de téléphone (phone_number, phone_number_verified)"
                    
                    print(f"\n{Fore.GREEN}✓ Scope trouvé: {scope}{Style.RESET_ALL} {warning}")
                    print(f"  Realm: {realm}")
                    print(f"  Client: {client_id}")
                    print(f"  Status: {response.status_code}")
                    if details:
                        print(details)
                    
                    if severity == 'high':
                        self.results['vulnerabilities'].append({
                            'type': f'sensitive_scope_{scope}',
                            'realm': realm,
                            'client_id': client_id,
                            'scope': scope,
                            'severity': severity,
                            'description': f"Scope sensible '{scope}' disponible pour {client_id}",
                            'details': details
                        })
                    
            except:
                pass
        
        if valid_scopes:
            print(f"\n{Fore.CYAN}═══ Scopes pour {realm}/{client_id} ═══{Style.RESET_ALL}")
            print(f"Total: {Fore.GREEN}{len(valid_scopes)}{Style.RESET_ALL}")
            for s in valid_scopes:
                print(f"  • {s['scope']}")
            print()
        
        return valid_scopes

    def enumerate_identity_providers(self, realm: str) -> List[Dict]:
        """Énumère les Identity Providers (Article: Identity Provider Enumeration)"""
        self.log(f"Énumération des Identity Providers pour realm: {realm}", "INFO")
        
        valid_idps = []
        
        print(f"\n{Fore.CYAN}Testing Identity Providers...{Style.RESET_ALL}")
        
        for idp in self.default_idps:
            try:
                url = f"{self.base_url}/auth/realms/{realm}/broker/{idp}/endpoint"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                
                # Un IDP valide retourne 400 ou redirect, pas 404
                if response.status_code != 404:
                    idp_info = {
                        'provider': idp,
                        'realm': realm,
                        'endpoint': url,
                        'status_code': response.status_code
                    }
                    valid_idps.append(idp_info)
                    
                    print(f"\n{Fore.GREEN}✓ Identity Provider trouvé: {idp}{Style.RESET_ALL}")
                    print(f"  Realm: {realm}")
                    print(f"  Endpoint: {url}")
                    print(f"  Status: {response.status_code}")
                    print(f"  {Fore.YELLOW}Info:{Style.RESET_ALL} Authentification déléguée à {idp}")
                    
            except:
                pass
        
        if valid_idps:
            print(f"\n{Fore.CYAN}═══ Identity Providers pour {realm} ═══{Style.RESET_ALL}")
            print(f"Total: {Fore.GREEN}{len(valid_idps)}{Style.RESET_ALL}")
            for idp in valid_idps:
                print(f"  • {idp['provider']}")
            print()
        
        return valid_idps

    def test_default_credentials(self) -> List[Dict]:
        """Test des credentials par défaut"""
        self.print_section("TEST DES CREDENTIALS PAR DÉFAUT")
        
        vulnerabilities = []
        login_url = f"{self.base_url}/auth/realms/master/protocol/openid-connect/token"
        
        print(f"Testing credentials sur realm 'master'...")
        print(f"Endpoint: {login_url}\n")
        
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
                            print(f"╔═══ VULNÉRABILITÉ CRITIQUE ═══╗")
                            print(f"║  CREDENTIALS PAR DÉFAUT VALIDES  ║")
                            print(f"╚{'═'*34}╝{Style.RESET_ALL}\n")
                            
                            print(f"{Fore.RED}Username: {username}")
                            print(f"Password: {password}{Style.RESET_ALL}")
                            print(f"Realm: master")
                            print(f"Client: admin-cli")
                            print(f"\nAccess Token obtenu: {token_data['access_token'][:50]}...")
                            print(f"Token Type: {token_data.get('token_type')}")
                            print(f"Expires In: {token_data.get('expires_in')} secondes")
                            
                            if 'refresh_token' in token_data:
                                print(f"Refresh Token: {token_data['refresh_token'][:50]}...")
                            
                            print(f"\n{Fore.RED}IMPACT CRITIQUE:{Style.RESET_ALL}")
                            print("  • Accès COMPLET à l'administration Keycloak")
                            print("  • Contrôle total de tous les realms")
                            print("  • Capacité de créer/modifier/supprimer utilisateurs")
                            print("  • Accès aux secrets et configurations")
                            print("  • Possibilité d'élévation de privilèges sur toutes les applications")
                            
                            print(f"\n{Fore.GREEN}ACTIONS IMMÉDIATES:{Style.RESET_ALL}")
                            print("  1. Changer le mot de passe admin IMMÉDIATEMENT")
                            print("  2. Auditer tous les comptes créés récemment")
                            print("  3. Vérifier les logs d'accès admin")
                            print("  4. Révoquer tous les tokens existants")
                            print("  5. Activer l'authentification multi-facteurs (MFA)")
                            
                            print(f"\n{Fore.YELLOW}Exploitation manuelle:{Style.RESET_ALL}")
                            print(f"curl -X POST '{login_url}' \\")
                            print(f"     -d 'client_id=admin-cli' \\")
                            print(f"     -d 'username={username}' \\")
                            print(f"     -d 'password={password}' \\")
                            print(f"     -d 'grant_type=password'")
                            
                            print(f"\n{Fore.RED}{'!'*70}{Style.RESET_ALL}\n")
                            
                            vuln = {
                                'type': 'default_credentials',
                                'severity': 'critical',
                                'username': username,
                                'password': password,
                                'realm': 'master',
                                'endpoint': login_url,
                                'access_token': token_data['access_token'][:100],
                                'description': f"Credentials par défaut valides: {username}:{password}"
                            }
                            vulnerabilities.append(vuln)
                            return vulnerabilities
                    except:
                        pass
                else:
                    pass
                    #print(f"  ✗ {username}:{password} - Invalid (Status: {response.status_code})")
                    
            except Exception as e:
                if self.verbose:
                    self.log(f"Erreur test credentials: {str(e)}", "ERROR")
        
        if not vulnerabilities:
            print(f"\n{Fore.GREEN}✓ Aucun credential par défaut valide{Style.RESET_ALL}\n")
        
        return vulnerabilities

    def test_user_enumeration(self, realm: str) -> List[Dict]:
        """Test User Enumeration (Article: User Email Enumeration)"""
        self.log(f"Test énumération utilisateurs pour realm: {realm}", "INFO")
        
        # Note: Ce test nécessite normalement d'être authentifié
        # On teste quand même l'accessibilité de l'endpoint account
        
        vulnerabilities = []
        
        try:
            account_url = f"{self.base_url}/auth/realms/{realm}/account"
            response = self.session.get(account_url, timeout=self.timeout, allow_redirects=False)
            
            if response.status_code in [200, 302]:
                print(f"\n{Fore.YELLOW}⚠️  Endpoint Account accessible{Style.RESET_ALL}")
                print(f"URL: {account_url}")
                print(f"Status: {response.status_code}")
                print(f"\n{Fore.YELLOW}Risque:{Style.RESET_ALL}")
                print("  Si authentifié, possibilité d'énumérer les emails via:")
                print(f"  POST {self.base_url}/auth/realms/{realm}/account/")
                print("  Body: {{\"email\": \"test@example.com\"}}")
                print("\n  Réponse 409 Conflict = email existe")
                print("  Réponse 204 No Content = email disponible")
                print(f"\n{Fore.GREEN}Recommandation:{Style.RESET_ALL}")
                print("  • Désactiver l'accès à la console Account si non nécessaire")
                print("  • Activer la vérification d'email obligatoire")
                print("  • Implémenter un rate limiting sur les changements d'email")
                
                vuln = {
                    'type': 'user_enumeration_possible',
                    'realm': realm,
                    'severity': 'medium',
                    'endpoint': account_url,
                    'description': f"Endpoint account accessible - Énumération d'utilisateurs possible si authentifié"
                }
                vulnerabilities.append(vuln)
        except:
            pass
        
        return vulnerabilities

    def test_client_registration_open(self, realm: str) -> List[Dict]:
        """Test Client Registration (Article Part 1)"""
        self.log(f"Test Client Registration pour realm: {realm}", "INFO")
        
        vulnerabilities = []
        
        registration_endpoints = [
            f"/auth/realms/{realm}/clients-registrations/default",
            f"/auth/realms/{realm}/clients-registrations/openid-connect"
        ]
        
        for endpoint in registration_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                
                test_client = {
                    "clientId": f"pentest-{secrets.token_hex(4)}",
                    "enabled": True,
                    "publicClient": True,
                    "redirectUris": ["http://localhost/*"],
                    "webOrigins": ["*"]
                }
                
                headers = {'Content-Type': 'application/json'}
                response = self.session.post(url, json=test_client, headers=headers, timeout=self.timeout)
                
                if response.status_code in [200, 201]:
                    print(f"\n{Fore.RED}╔═══ VULNÉRABILITÉ DÉTECTÉE ═══╗{Style.RESET_ALL}")
                    print(f"{Fore.RED}CLIENT REGISTRATION OUVERT{Style.RESET_ALL}\n")
                    
                    print(f"Realm: {realm}")
                    print(f"Endpoint: {url}")
                    print(f"Status: {response.status_code}")
                    
                    if response.status_code == 201:
                        try:
                            created_client = response.json()
                            print(f"\n{Fore.YELLOW}Client créé avec succès:{Style.RESET_ALL}")
                            print(f"  Client ID: {created_client.get('clientId')}")
                            print(f"  Registration Access Token: {created_client.get('registrationAccessToken', 'N/A')[:50]}...")
                        except:
                            pass
                    
                    print(f"\n{Fore.RED}IMPACT:{Style.RESET_ALL}")
                    print("  • N'importe qui peut créer des clients OAuth malveilleux")
                    print("  • Possibilité de créer des clients avec redirect_uri malveilleux")
                    print("  • Risque de phishing et vol de tokens")
                    print("  • Clients peuvent être configurés pour voler des credentials")
                    
                    print(f"\n{Fore.YELLOW}Exploitation:{Style.RESET_ALL}")
                    print(f"curl -X POST '{url}' \\")
                    print("     -H 'Content-Type: application/json' \\")
                    print("     -d '{")
                    print('       "clientId": "malicious-client",')
                    print('       "enabled": true,')
                    print('       "publicClient": true,')
                    print('       "redirectUris": ["https://attacker.com/callback"],')
                    print('       "webOrigins": ["*"]')
                    print("     }'")
                    
                    print(f"\n{Fore.GREEN}REMÉDIATION:{Style.RESET_ALL}")
                    print("  1. Désactiver Client Registration dans Realm Settings")
                    print("  2. OU exiger un Initial Access Token")
                    print("  3. Valider strictement tous les nouveaux clients")
                    print(f"{Fore.RED}╚{'═'*31}╝{Style.RESET_ALL}\n")
                    
                    # Nettoyer le client de test
                    if response.status_code == 201:
                        try:
                            location = response.headers.get('Location')
                            if location:
                                self.session.delete(location, timeout=self.timeout)
                                print(f"{Fore.GREEN}✓ Client de test supprimé{Style.RESET_ALL}\n")
                        except:
                            print(f"{Fore.YELLOW}⚠️  Client de test non supprimé - Le supprimer manuellement{Style.RESET_ALL}\n")
                    
                    vuln = {
                        'type': 'open_client_registration',
                        'realm': realm,
                        'severity': 'high',
                        'endpoint': endpoint,
                        'description': f"Client Registration ouvert pour {realm}"
                    }
                    vulnerabilities.append(vuln)
                    break
                    
            except Exception as e:
                if self.verbose:
                    self.log(f"Erreur test registration: {str(e)}", "ERROR")
        
        return vulnerabilities

    def test_brute_force_protection(self, realm: str):
        """Test Brute Force Protection (Article Part 2)"""
        self.log(f"Test Protection Brute Force pour realm: {realm}", "INFO")
        
        print(f"\nTesting brute force protection...")
        print(f"Realm: {realm}")
        print(f"Test: 5 tentatives de login échouées\n")
        
        try:
            url = f"{self.base_url}/auth/realms/{realm}/login-actions/authenticate"
            
            test_results = []
            for i in range(5):
                data = {
                    'username': f'testuser_{secrets.token_hex(4)}',
                    'password': 'wrongpassword'
                }
                
                start_time = time.time()
                response = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=False)
                elapsed = time.time() - start_time
                
                test_results.append({
                    'attempt': i + 1,
                    'status': response.status_code,
                    'time': elapsed
                })
                
                print(f"  Tentative {i+1}: Status {response.status_code} - {elapsed:.3f}s")
                time.sleep(0.2)
            
            # Analyser les résultats
            time_increases = sum(1 for i in range(1, len(test_results))
                               if test_results[i]['time'] > test_results[i-1]['time'] * 1.5)
            
            if time_increases == 0:
                print(f"\n{Fore.RED}⚠️  PROTECTION BRUTE FORCE NON DÉTECTÉE{Style.RESET_ALL}")
                print("\nAucun ralentissement détecté après 5 tentatives échouées")
                print("Toutes les requêtes ont été traitées à vitesse normale")
                
                print(f"\n{Fore.RED}IMPACT:{Style.RESET_ALL}")
                print("  • Attaques par force brute possibles")
                print("  • Aucun délai entre les tentatives")
                print("  • Aucun blocage de compte après échecs répétés")
                print("  • Possibilité de tester des milliers de mots de passe")
                
                print(f"\n{Fore.YELLOW}Exploitation avec Hydra:{Style.RESET_ALL}")
                print(f"hydra -l admin -P /usr/share/wordlists/rockyou.txt \\")
                print(f"      {urlparse(self.base_url).netloc} \\")
                print(f"      https-post-form '/{realm}/login-actions/authenticate:username=^USER^&password=^PASS^:F=error'")
                
                print(f"\n{Fore.GREEN}REMÉDIATION:{Style.RESET_ALL}")
                print("  1. Activer dans: Realm Settings → Security Defenses")
                print("  2. Cocher 'Brute Force Detection'")
                print("  3. Configuration recommandée:")
                print("     • Max Login Failures: 5-10")
                print("     • Wait Increment: 60 seconds")
                print("     • Max Wait: 900 seconds (15 min)")
                print("     • Failure Reset Time: 43200 seconds (12h)")
                print("  4. Implémenter un CAPTCHA après plusieurs échecs")
                print()
                
                self.results['misconfigurations'].append({
                    'type': 'no_brute_force_protection',
                    'realm': realm,
                    'severity': 'high',
                    'test_results': test_results,
                    'description': f"Protection brute force non activée pour {realm}"
                })
            else:
                print(f"\n{Fore.GREEN}✓ Protection brute force semble activée{Style.RESET_ALL}")
                print(f"Ralentissements détectés: {time_increases}/4\n")
                
        except Exception as e:
            if self.verbose:
                self.log(f"Erreur test brute force: {str(e)}", "ERROR")

    def scan_realm(self, realm: str):
        """Scan complet d'un realm"""
        self.print_section(f"SCAN DU REALM: {realm}")
        
        # Énumération Client IDs
        clients = self.enumerate_client_ids(realm)
        self.results['client_ids'][realm] = clients
        
        # Énumération Scopes (sur les 2 premiers clients pour perf)
        if clients:
            for client in clients[:2]:
                client_id = client['client_id']
                scopes = self.enumerate_scopes(realm, client_id)
                if realm not in self.results['scopes']:
                    self.results['scopes'][realm] = {}
                self.results['scopes'][realm][client_id] = scopes
        
        # Énumération Identity Providers
        idps = self.enumerate_identity_providers(realm)
        self.results['idps'][realm] = idps
        
        # Tests de sécurité
        vulns = []
        vulns.extend(self.test_client_registration_open(realm))
        vulns.extend(self.test_user_enumeration(realm))
        self.test_brute_force_protection(realm)
        
        self.results['vulnerabilities'].extend(vulns)

    def full_scan(self):
        """Lance un scan complet avec affichage détaillé"""
        self.print_banner()
        
        print(f"{Fore.CYAN}Target: {self.base_url}")
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Scanner: v3.0 Complete Edition{Style.RESET_ALL}\n")
        
        # 1. Détection Keycloak
        if not self.is_keycloak():
            self.log("La cible ne semble pas utiliser Keycloak", "ERROR")
            return self.results
        
        # 2. Tests globaux
        self.print_section("TESTS DE SÉCURITÉ GLOBAUX")
        global_vulns = self.test_default_credentials()
        self.results['vulnerabilities'].extend(global_vulns)
        
        # 3. Énumération realms
        realms = self.enumerate_realms()
        
        if not realms:
            self.log("Aucun realm trouvé", "WARNING")
            return self.results
        
        # 4. Scan de chaque realm
        for realm in realms:
            self.scan_realm(realm)
        
        return self.results

    def print_final_summary(self):
        """Affiche le résumé final complet"""
        self.print_section("RÉSUMÉ FINAL DU SCAN")
        
        total_vulns = len(self.results['vulnerabilities'])
        total_misconfigs = len(self.results['misconfigurations'])
        
        critical = sum(1 for v in self.results['vulnerabilities'] + self.results['misconfigurations']
                      if v.get('severity') == 'critical')
        high = sum(1 for v in self.results['vulnerabilities'] + self.results['misconfigurations']
                  if v.get('severity') == 'high')
        medium = sum(1 for v in self.results['vulnerabilities'] + self.results['misconfigurations']
                    if v.get('severity') == 'medium')
        
        print(f"{Fore.YELLOW}Target:{Style.RESET_ALL} {self.results['scan_info']['target']}")
        if self.results['version']:
            print(f"{Fore.YELLOW}Version Keycloak:{Style.RESET_ALL} {self.results['version']}")
        print(f"{Fore.YELLOW}Realms trouvés:{Style.RESET_ALL} {len(self.results['realms'])}")
        print(f"{Fore.YELLOW}Total problèmes:{Style.RESET_ALL} {total_vulns + total_misconfigs}")
        print()
        
        if critical > 0:
            print(f"{Fore.RED}╔════════════════════════════════════╗")
            print(f"║  {critical} VULNÉRABILITÉS CRITIQUES  ║")
            print(f"╚════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        if high > 0:
            print(f"{Fore.RED}⚠️  {high} vulnérabilités HIGH{Style.RESET_ALL}")
        if medium > 0:
            print(f"{Fore.YELLOW}⚠️  {medium} vulnérabilités MEDIUM{Style.RESET_ALL}")
        
        if total_vulns + total_misconfigs == 0:
            print(f"{Fore.GREEN}✓ Aucun problème majeur détecté{Style.RESET_ALL}")
        
        print()

    def export_results(self, filename: str = "keycloak_scan_detailed.json"):
        """Exporte les résultats complets"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            self.log(f"Résultats exportés: {filename}", "SUCCESS")
            print(f"  Format: JSON complet avec tous les détails")
            print(f"  Taille: {len(json.dumps(self.results))} bytes\n")
        except Exception as e:
            self.log(f"Erreur export: {str(e)}", "ERROR")


def main():
    parser = argparse.ArgumentParser(
        description='Keycloak Security Scanner v3.0 - Complete Edition (CSA Cyber Methodology)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Basé sur les articles CSA Cyber:
  • Pentesting Keycloak Part 1: Identifying Misconfiguration
  • Pentesting Keycloak Part 2: Exploitation

Fonctionnalités:
  ✓ Affichage DÉTAILLÉ de toutes les découvertes
  ✓ Détails complets pour chaque vulnérabilité
  ✓ POC et commandes d'exploitation
  ✓ Recommandations de remédiation
  ✓ Analyse basée sur méthodologie CSA
  ✓ Export JSON complet

Exemples:
  python3 keycloak_scanner.py -u https://keycloak.example.com
  python3 keycloak_scanner.py -u https://keycloak.example.com -v -o report.json
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='URL cible Keycloak')
    parser.add_argument('-o', '--output', help='Fichier JSON de sortie')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout requêtes (défaut: 10s)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Mode verbose')
    
    args = parser.parse_args()
    
    try:
        scanner = KeycloakScanner(args.url, timeout=args.timeout, verbose=args.verbose)
        scanner.full_scan()
        scanner.print_final_summary()
        
        if args.output:
            scanner.export_results(args.output)
    
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrompu{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[-] Erreur: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()