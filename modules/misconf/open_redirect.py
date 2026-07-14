#!/usr/bin/env python3

from utils.style import Colors, Identify
from utils.output import get_reporter

_EVIL_URLS = [
    "https://evil.attacker.com",
    "//evil.attacker.com",
    "https://evil.attacker.com%2F@legitimate.com",
    "https://legitimate.com.evil.attacker.com",
]


def check_open_redirect(s, realms, client_ids):
    print(f"{Colors.CYAN} ├ Open Redirect (redirect_uri) {Colors.RESET}")
    reporter = get_reporter()
    found_any = False

    test_clients = client_ids[:2] if client_ids else []

    for realm in realms:
        realm = realm.rstrip('/')

        for client_id in test_clients:
            for evil_url in _EVIL_URLS:
                try:
                    url = (
                        f"{realm}/protocol/openid-connect/auth"
                        f"?client_id={client_id}"
                        f"&response_type=code"
                        f"&redirect_uri={evil_url}"
                        f"&scope=openid"
                    )
                    req = s.get(url, allow_redirects=False)
                    location = req.headers.get("Location", "")

                    if req.status_code in (301, 302) and "evil.attacker.com" in location:
                        print(f"  └── {Identify.confirmed}")
                        print(f"       Open redirect to {evil_url}")
                        print(f"       client_id={client_id} → Location: {location[:100]}")
                        found_any = True
                        if reporter:
                            reporter.add(
                                "OpenRedirect", "high",
                                f"Open redirect via redirect_uri (client: {client_id})",
                                url,
                            )

                except Exception:
                    pass

    if not found_any:
        print(f"  └── {Colors.THISTLE}No open redirect detected{Colors.RESET}")
