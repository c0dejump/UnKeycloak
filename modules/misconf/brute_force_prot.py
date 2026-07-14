#!/usr/bin/env python3

import secrets
from urllib.parse import urlparse
from utils.utils import time
from utils.style import Colors, Identify
from utils.output import get_reporter



def check_brute_force_protection(s, realms):
    print(f"{Colors.CYAN} ├ Brute Force Protection {Colors.RESET}")
    reporter = get_reporter()

    for realm in realms:
        realm_clean = realm.rstrip('/')
        url = f"{realm_clean}/login-actions/authenticate"
        timings = []

        for _ in range(5):
            data = {
                "username": f"probe_{secrets.token_hex(4)}",
                "password": "wrongpassword_probe",
            }
            try:
                start = time.time()
                s.post(url, data=data, allow_redirects=False)
                timings.append(time.time() - start)
                time.sleep(0.2)
            except Exception:
                break

        if len(timings) < 3:
            print(f"  └── {Colors.THISTLE}Could not test brute-force protection (endpoint unreachable){Colors.RESET}")
            continue

        # Detect rate-limiting: significant progressive slowdown
        slowdowns = sum(
            1 for i in range(1, len(timings))
            if timings[i] > timings[i - 1] * 1.5
        )

        if slowdowns == 0:
            parsed = urlparse(realm_clean)
            host = parsed.netloc
            realm_path = parsed.path  # e.g. /auth/realms/master
            print(f"  └── {Identify.behavior}")
            print(f"       No brute-force slowdown detected after 5 failed attempts")
            print(f"       Realm: {realm_clean}")
            print(f"       Times: {', '.join(f'{t:.3f}s' for t in timings)}")
            print(f"       {Colors.THISTLE}PoC (login form):{Colors.RESET}")
            print(f"         hydra -l admin -P /usr/share/wordlists/rockyou.txt {host} \\")
            print(f"               https-post-form '{realm_path}/login-actions/authenticate"
                  ":username=^USER^&password=^PASS^:F=Invalid'")
            print(f"       {Colors.THISTLE}PoC (token endpoint / ROPC):{Colors.RESET}")
            print(f"         hydra -l admin -P /usr/share/wordlists/rockyou.txt {host} \\")
            print(f"               https-post-form '{realm_path}/protocol/openid-connect/token"
                  ":grant_type=password&client_id=admin-cli&username=^USER^&password=^PASS^:F=error'")
            if reporter:
                reporter.add(
                    "BruteForce", "high",
                    "No brute-force protection detected",
                    url,
                    "Enable Brute Force Detection in Realm Settings → Security Defenses",
                )
        else:
            print(f"  └── {Colors.GREEN}[OK]{Colors.RESET} Rate limiting active on {realm_clean} "
                  f"({slowdowns} slowdown(s) detected)")
