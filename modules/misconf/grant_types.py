#!/usr/bin/env python3

from utils.style import Colors, Identify
from utils.output import get_reporter


def check_grant_types(s, realms):
    print(f"{Colors.CYAN} ├ Grant Types & OAuth Flows {Colors.RESET}")
    reporter = get_reporter()
    found_any = False

    for realm in realms:
        realm = realm.rstrip('/')
        try:
            req = s.get(f"{realm}/.well-known/openid-configuration", allow_redirects=False)
            if req.status_code != 200:
                continue
            data = req.json()
        except Exception:
            continue

        grant_types = data.get("grant_types_supported", [])
        response_types = data.get("response_types_supported", [])
        signing_algs = data.get("id_token_signing_alg_values_supported", [])

        # Implicit flow (deprecated, tokens exposed in URL fragment)
        if "implicit" in grant_types:
            print(f"  └── {Identify.behavior}")
            print(f"       Implicit grant type enabled (deprecated — tokens exposed in URL fragment)")
            found_any = True
            if reporter:
                reporter.add("GrantTypes", "medium", "Implicit grant type enabled", realm)

        # Implicit response types (token in URL)
        implicit_rts = [rt for rt in response_types
                        if rt in ("token", "id_token")
                        or (rt not in ("code", "none") and "token" in rt.split())]
        if implicit_rts:
            print(f"  └── {Identify.behavior}")
            print(f"       Implicit response types: {', '.join(implicit_rts)}")
            found_any = True
            if reporter:
                reporter.add("GrantTypes", "medium",
                             f"Implicit response types: {', '.join(implicit_rts)}", realm)

        # ROPC: Resource Owner Password Credentials
        if "password" in grant_types:
            print(f"  └── {Identify.behavior}")
            print(f"       ROPC (Resource Owner Password Credentials) grant enabled")
            print(f"       Allows direct username/password submission — brute-force surface")
            print(f"       {Colors.THISTLE}PoC:{Colors.RESET}")
            print(f"         curl -X POST '{realm}/protocol/openid-connect/token' \\")
            print(f"              -d 'grant_type=password&client_id=CLIENT_ID' \\")
            print(f"              -d 'username=admin&password=admin'")
            found_any = True
            if reporter:
                reporter.add("GrantTypes", "medium", "ROPC grant type enabled", realm)

        # Weak HMAC signing algorithms
        weak_algs = [a for a in signing_algs if a.startswith("HS")]
        strong_algs = [a for a in signing_algs if a.startswith(("RS", "ES", "PS"))]
        if weak_algs:
            print(f"  └── {Identify.behavior}")
            print(f"       Weak HMAC JWT signing algorithm(s): {', '.join(weak_algs)}")
            print(f"       HMAC tokens use a shared secret — if leaked, any party can forge tokens")
            print(f"       {Colors.THISTLE}PoC:{Colors.RESET} Use jwt_tool or python-jwt to forge tokens with the shared secret")
            found_any = True
            if reporter:
                reporter.add("GrantTypes", "medium",
                             f"Weak JWT alg(s): {', '.join(weak_algs)}", realm)

            # Algorithm confusion: both HMAC and asymmetric algs enabled
            if strong_algs:
                print(f"  └── {Identify.behavior}")
                print(f"       Algorithm Confusion possible — HMAC ({', '.join(weak_algs)}) "
                      f"AND asymmetric ({', '.join(strong_algs)}) both supported")
                print(f"       Attack: sign a forged JWT with the server's RSA public key as HMAC secret")
                print(f"       {Colors.THISTLE}PoC:{Colors.RESET} jwt_tool TOKEN -X a -pk server.pub")
                found_any = True
                if reporter:
                    reporter.add("GrantTypes", "high",
                                 "Algorithm confusion attack possible (HMAC + asymmetric)", realm)

        # Info only
        if "urn:ietf:params:oauth:grant-type:device_code" in grant_types:
            print(f"  └── {Colors.THISTLE}[INFO] Device Code grant enabled{Colors.RESET}")
        if any("ciba" in g.lower() for g in grant_types):
            print(f"  └── {Colors.THISTLE}[INFO] CIBA (Client-Initiated Backchannel Auth) enabled{Colors.RESET}")

    if not found_any:
        print(f"  └── {Colors.THISTLE}No risky grant types detected{Colors.RESET}")
