import requests
import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

class GetVersion:
    def __init__(self, url_realm):
        self.realm_url = url_realm.rstrip('/') + '/'
        self.base_url = self._extract_base_url(url_realm)
        self.data = {}
        self.version_indicators = []

    def _extract_base_url(self, url):
        if '/realms/' in url:
            return url.split('/realms/')[0]
        if '/auth/realms/' in url:
            return url.split('/auth/realms/')[0]
        return url.rsplit('/', 1)[0]

    def fetch(self, url, allow_redirects=True):
        try:
            return requests.get(url, verify=False, timeout=8, allow_redirects=allow_redirects)
        except:
            return None

    def check_openid_config(self):
        url = urljoin(self.realm_url, ".well-known/openid-configuration")
        r = self.fetch(url)
        if r and r.status_code == 200:
            try:
                self.data['openid'] = r.json()
            except:
                pass

    def check_headers(self):
        r = self.fetch(self.realm_url)
        if r:
            self.data['headers'] = dict(r.headers)

    def check_admin_version(self):
        endpoints = [
            f"{self.base_url}/admin/serverinfo",
            f"{self.base_url}/auth/admin/serverinfo",
            f"{self.base_url}/admin/master/console/",
            f"{self.base_url}/auth/admin/master/console/",
        ]
        for ep in endpoints:
            r = self.fetch(ep)
            if r and r.status_code == 200:
                try:
                    j = r.json()
                    if 'systemInfo' in j and 'version' in j['systemInfo']:
                        self.data['exact_version'] = j['systemInfo']['version']
                        return
                except:
                    pass
                match = re.search(r'keycloak[.-](\d+\.\d+\.\d+)', r.text, re.I)
                if match:
                    self.data['exact_version'] = match.group(1)
                    return

    def check_js_resources(self):
        paths = [
            f"{self.base_url}/js/keycloak.js",
            f"{self.base_url}/auth/js/keycloak.js",
        ]
        for path in paths:
            r = self.fetch(path)
            if r and r.status_code == 200:
                for pattern in [r'version["\s:=]+["\']?(\d+\.\d+\.\d+)', r'keycloak[/-](\d+\.\d+\.\d+)']:
                    match = re.search(pattern, r.text, re.I)
                    if match:
                        self.data['exact_version'] = match.group(1)
                        return

    def check_theme_resources(self):
        for path in [f"{self.base_url}/resources/", f"{self.base_url}/auth/resources/"]:
            r = self.fetch(path, allow_redirects=False)
            if r:
                location = r.headers.get('Location', '')
                match = re.search(r'/(\d+\.\d+\.\d+)/', location)
                if match:
                    self.data['exact_version'] = match.group(1)
                    return

    def check_welcome_page(self):
        for path in [self.base_url, f"{self.base_url}/", f"{self.base_url}/auth/"]:
            r = self.fetch(path)
            if r and r.status_code == 200:
                for pattern in [r'<span[^>]*>(\d+\.\d+\.\d+)</span>', r'Keycloak\s+(\d+\.\d+\.\d+)']:
                    match = re.search(pattern, r.text, re.I)
                    if match:
                        self.data['exact_version'] = match.group(1)
                        return

    def detect_features(self):
        oidc = self.data.get("openid", {})
        headers = self.data.get("headers", {})
        grant_types = oidc.get("grant_types_supported", [])
        signing_algs = oidc.get("id_token_signing_alg_values_supported", [])
        response_types = oidc.get("response_types_supported", [])

        # Features avec versions minimum
        if "dpop_signing_alg_values_supported" in oidc:
            self.version_indicators.append(("22.0.0", True))
        if oidc.get("require_pushed_authorization_requests"):
            self.version_indicators.append(("21.0.0", True))
        if any("jwt" in rt.lower() for rt in response_types):
            self.version_indicators.append(("21.0.0", True))
        if "EdDSA" in signing_algs:
            self.version_indicators.append(("20.0.0", True))
        if oidc.get("authorization_response_iss_parameter_supported"):
            self.version_indicators.append(("20.0.0", True))
        if "mtls_endpoint_aliases" in oidc:
            self.version_indicators.append(("18.0.0", True))
        if "pushed_authorization_request_endpoint" in oidc:
            self.version_indicators.append(("17.0.0", True))
        if oidc.get("acr_values_supported"):
            self.version_indicators.append(("15.0.0", True))
        if any("ciba" in g.lower() for g in grant_types):
            self.version_indicators.append(("12.0.0", True))
        if "revocation_endpoint" in oidc:
            self.version_indicators.append(("10.0.0", True))
        if "S256" in oidc.get("code_challenge_methods_supported", []):
            self.version_indicators.append(("7.0.0", True))
        if "device_authorization_endpoint" in oidc:
            self.version_indicators.append(("7.0.0", True))

        # WildFly = version max
        server = headers.get("Server", "").lower()
        if "undertow" in server or "wildfly" in server:
            self.version_indicators.append(("16.1.1", False))

    def calculate_version(self):
        if 'exact_version' in self.data:
            return self.data['exact_version']

        def ver_tuple(v):
            return tuple(int(p) for p in v.split('.'))

        min_versions = [v for v, is_min in self.version_indicators if is_min]
        max_versions = [v for v, is_min in self.version_indicators if not is_min]

        highest_min = max(min_versions, key=ver_tuple) if min_versions else None
        lowest_max = min(max_versions, key=ver_tuple) if max_versions else None

        if highest_min and lowest_max:
            if ver_tuple(highest_min) > ver_tuple(lowest_max):
                return f"{highest_min}+"
            return f"{highest_min} - {lowest_max}"
        elif highest_min:
            return f"{highest_min}+"
        elif lowest_max:
            return f"<= {lowest_max}"
        
        return None

    def run(self):
        self.check_admin_version()
        if 'exact_version' in self.data:
            return self.data['exact_version']
        
        self.check_js_resources()
        if 'exact_version' in self.data:
            return self.data['exact_version']
        
        self.check_theme_resources()
        if 'exact_version' in self.data:
            return self.data['exact_version']
        
        self.check_welcome_page()
        if 'exact_version' in self.data:
            return self.data['exact_version']

        self.check_headers()
        self.check_openid_config()
        self.detect_features()
        
        return self.calculate_version()
