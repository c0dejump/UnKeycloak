#!/usr/bin/env python3

import secrets
from utils.style import Colors, Identify
from utils.output import get_reporter

_ENDPOINTS = [
    "/clients-registrations/default",
    "/clients-registrations/openid-connect",
]


def check_client_registration(s, realms):
    print(f"{Colors.CYAN} ├ Open Client Registration {Colors.RESET}")
    reporter = get_reporter()
    found_any = False

    for realm in realms:
        realm = realm.rstrip('/')

        for ep_suffix in _ENDPOINTS:
            url = f"{realm}{ep_suffix}"
            test_client = {
                "clientId": f"probe-{secrets.token_hex(4)}",
                "enabled": True,
                "publicClient": True,
                "redirectUris": ["http://localhost:9999/*"],
            }
            try:
                req = s.post(url, json=test_client, headers={"Content-Type": "application/json"})

                if req.status_code in (200, 201):
                    print(f"  └── {Identify.confirmed}")
                    print(f"       Open Client Registration (CVE-2018-14655): {url}")
                    print(f"       Anyone can register OAuth clients without authentication")
                    found_any = True
                    if reporter:
                        reporter.add(
                            "ClientRegistration", "high",
                            "Open Client Registration — unauthenticated client creation possible",
                            url,
                            "CVE-2018-14655 / Disable in Realm Settings → Client Registration",
                        )

                    # Clean up test client
                    location = req.headers.get("Location", "")
                    if req.status_code == 201 and location:
                        try:
                            s.delete(location)
                        except Exception:
                            pass

            except Exception:
                pass

    if not found_any:
        print(f"  └── {Colors.THISTLE}Client registration appears restricted{Colors.RESET}")
