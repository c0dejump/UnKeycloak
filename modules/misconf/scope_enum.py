#!/usr/bin/env python3

from utils.style import Colors, Identify
from utils.output import get_reporter
from modules.defaultkeycloak import default_scopes

# Scopes that grant dangerous capabilities
_SENSITIVE_SCOPES = {
    "offline_access": (
        "high",
        "Generates refresh tokens that NEVER EXPIRE — "
        "persistent access even after password change or logout",
    ),
    "uma_authorization": (
        "high",
        "User-Managed Access — allows resource sharing, potential privilege escalation",
    ),
    "microprofile-jwt": (
        "medium",
        "Exposes MicroProfile groups/roles inside the JWT — role enumeration possible",
    ),
    "roles": (
        "low",
        "Exposes realm and client roles inside tokens",
    ),
}


def check_scopes(s, realms, client_ids):
    print(f"{Colors.CYAN} ├ Scope Enumeration {Colors.RESET}")
    reporter = get_reporter()

    if not client_ids:
        print(f"  └── {Colors.THISTLE}No client IDs — skipping scope enumeration{Colors.RESET}")
        return

    for realm in realms:
        realm = realm.rstrip('/')
        # Use first available client to probe scopes
        client_id = client_ids[0]
        auth_url = f"{realm}/protocol/openid-connect/auth"
        callback = f"{realm}/callback"

        # Baseline: invalid scope response length
        try:
            invalid_req = s.get(
                auth_url,
                params={
                    "client_id": client_id,
                    "redirect_uri": callback,
                    "response_type": "code",
                    "scope": f"__invalid_scope_{id(object())}__",
                },
                allow_redirects=False,
            )
            invalid_len = len(invalid_req.content)
        except Exception:
            invalid_len = -1

        found_scopes = []

        for scope in default_scopes:
            try:
                req = s.get(
                    auth_url,
                    params={
                        "client_id": client_id,
                        "redirect_uri": callback,
                        "response_type": "code",
                        "scope": scope,
                    },
                    allow_redirects=False,
                )
                # A valid scope produces a different response than invalid one
                if req.status_code != 400 and len(req.content) != invalid_len:
                    found_scopes.append(scope)
            except Exception:
                pass

        if not found_scopes:
            print(f"  └── {Colors.THISTLE}No scopes confirmed for {realm}{Colors.RESET}")
            continue

        print(f"  ├── Available scopes on {realm}:")
        for sc in found_scopes:
            if sc in _SENSITIVE_SCOPES:
                sev, desc = _SENSITIVE_SCOPES[sc]
                color = Colors.RED if sev == "high" else (Colors.YELLOW if sev == "medium" else Colors.BLUE)
                print(f"  │   └── {color}[{sev.upper()}]{Colors.RESET} {sc}")
                print(f"  │         {desc}")
                if sc == "offline_access":
                    print(f"  │         {Colors.THISTLE}PoC:{Colors.RESET} Add 'offline_access' to scope param → "
                          f"exchange code for a never-expiring refresh_token")
                if reporter:
                    reporter.add("ScopeEnum", sev,
                                 f"Sensitive scope available: {sc}", realm, desc)
            else:
                print(f"  │   └── {Colors.THISTLE}[INFO]{Colors.RESET} {sc}")
