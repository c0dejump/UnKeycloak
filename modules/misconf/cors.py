#!/usr/bin/env python3

from utils.style import Colors, Identify
from utils.output import get_reporter

_EVIL_ORIGIN = "https://evil.attacker.com"

# Public/unauthenticated endpoints — CORS on these is expected behavior
_PUBLIC_ENDPOINTS = {
    "/.well-known/openid-configuration",
    "/.well-known/uma2-configuration",
    "/protocol/openid-connect/certs",
}

# Sensitive endpoints where CORS with credentials is a real risk
_SENSITIVE_ENDPOINTS = [
    "/protocol/openid-connect/token",
    "/protocol/openid-connect/userinfo",
    "/protocol/openid-connect/token/introspect",
]


def _is_public(ep: str) -> bool:
    return any(ep.endswith(pub) for pub in _PUBLIC_ENDPOINTS)


def check_cors(s, realms):
    print(f"{Colors.CYAN} ├ CORS Configuration {Colors.RESET}")
    reporter = get_reporter()
    found_any = False

    for realm in realms:
        realm = realm.rstrip('/')

        for suffix in _SENSITIVE_ENDPOINTS:
            ep = f"{realm}{suffix}"
            already_reported = False

            try:
                # 1. Actual request with evil Origin
                req = s.get(ep, headers={"Origin": _EVIL_ORIGIN}, allow_redirects=False)
                acao = req.headers.get("Access-Control-Allow-Origin", "")
                acac = req.headers.get("Access-Control-Allow-Credentials", "").lower()

                if acao == "*":
                    print(f"  └── {Identify.confirmed}")
                    print(f"       Wildcard CORS (Access-Control-Allow-Origin: *)")
                    print(f"       {ep}")
                    print(f"       {Colors.THISTLE}PoC:{Colors.RESET} Any cross-origin JS can read responses from this endpoint")
                    found_any = True
                    already_reported = True
                    if reporter:
                        reporter.add("CORS", "high", "Wildcard CORS origin", ep)

                elif acao == _EVIL_ORIGIN and acac == "true":
                    print(f"  └── {Identify.confirmed}")
                    print(f"       CORS: evil origin reflected WITH credentials on:")
                    print(f"       {ep}")
                    print(f"       {Colors.THISTLE}PoC:{Colors.RESET}")
                    print(f"         fetch('{ep}', {{")
                    print(f"           credentials: 'include',")
                    print(f"           headers: {{Authorization: 'Bearer VICTIM_TOKEN'}}")
                    print(f"         }}).then(r => r.text()).then(console.log)")
                    found_any = True
                    already_reported = True
                    if reporter:
                        reporter.add("CORS", "high",
                                     "CORS: evil origin reflected with credentials", ep)

                elif acao == _EVIL_ORIGIN:
                    print(f"  └── {Identify.behavior}")
                    print(f"       CORS: evil origin reflected (no credentials) on: {ep}")
                    found_any = True
                    already_reported = True
                    if reporter:
                        reporter.add("CORS", "medium",
                                     "CORS: evil origin reflected (no credentials)", ep)

            except Exception:
                pass

            # 2. Preflight — only report if not already flagged above
            if not already_reported:
                try:
                    pre = s.options(ep, headers={
                        "Origin": _EVIL_ORIGIN,
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers": "Authorization",
                    }, allow_redirects=False)
                    pre_acao = pre.headers.get("Access-Control-Allow-Origin", "")
                    if pre_acao == _EVIL_ORIGIN:
                        print(f"  └── {Identify.behavior}")
                        print(f"       CORS preflight allows evil origin on: {ep}")
                        found_any = True
                        if reporter:
                            reporter.add("CORS", "medium",
                                         "CORS preflight allows evil origin", ep)
                except Exception:
                    pass

    if not found_any:
        print(f"  └── {Colors.THISTLE}No CORS issues detected on sensitive endpoints{Colors.RESET}")
