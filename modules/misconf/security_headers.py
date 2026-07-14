#!/usr/bin/env python3

from utils.style import Colors, Identify
from utils.output import get_reporter

_REQUIRED_HEADERS = [
    ("Strict-Transport-Security", None),
    ("X-Frame-Options", ("DENY", "SAMEORIGIN")),
    ("X-Content-Type-Options", ("nosniff",)),
    ("Content-Security-Policy", None),
    ("Referrer-Policy", None),
]


def check_security_headers(s, realms):
    print(f"{Colors.CYAN} ├ Security Headers {Colors.RESET}")
    reporter = get_reporter()
    checked = False

    for realm in realms:
        try:
            req = s.get(realm, allow_redirects=True)
            headers = {k.lower(): v for k, v in req.headers.items()}
            checked = True

            for hname, expected_vals in _REQUIRED_HEADERS:
                val = headers.get(hname.lower())
                if not val:
                    print(f"  └── {Identify.behavior}")
                    print(f"       Missing security header: {hname}")
                    if reporter:
                        reporter.add("SecurityHeaders", "low", f"Missing header: {hname}", realm)
                elif expected_vals and not any(e.lower() in val.lower() for e in expected_vals):
                    print(f"  └── {Identify.behavior}")
                    print(f"       Weak {hname}: {val}")
                    if reporter:
                        reporter.add("SecurityHeaders", "low", f"Weak {hname}: {val}", realm)
                else:
                    if __import__("utils.utils", fromlist=["args"]).args.verbose:
                        print(f"  └── {Colors.GREEN}[OK]{Colors.RESET} {hname}: {val[:60]}")

            # Clickjacking via X-Frame-Options absence
            if not headers.get("x-frame-options") and not headers.get("content-security-policy"):
                print(f"  └── {Identify.behavior}")
                print(f"       No clickjacking protection (missing X-Frame-Options and CSP frame-ancestors)")
                if reporter:
                    reporter.add("SecurityHeaders", "medium", "No clickjacking protection", realm)

            break  # check once per target base, not per realm
        except Exception:
            pass

    if not checked:
        print(f"  └── {Colors.THISTLE}Could not retrieve headers{Colors.RESET}")
