#!/usr/bin/env python3

from utils.utils import (
    requests,
    sys,
    time,
    args
)
from utils.style import Colors, Identify
from utils.output import get_reporter


def regsitration_endpoints(s, realms, vci):
    print(f"{Colors.CYAN} ├ Registration Endpoints {Colors.RESET}")
    reporter = get_reporter()
    found_any = False

    base_endpoints = [
        "/login-actions/registration",
        "/protocol/openid-connect/registrations",
        "/clients-registrations/openid-connect",
        "/clients-registrations/default",
        "/account/password",
    ]

    dynamic_endpoints = []
    for dci in vci:
        dynamic_endpoints.append(f"/login-actions/registration?client_id={dci}")
        for r in realms:
            base = r.rstrip('/')
            dynamic_endpoints.append(
                f"/protocol/openid-connect/auth?client_id={dci}&response_type=code"
                f"&redirect_uri={base}/{dci}/&kc_action=register"
            )
            dynamic_endpoints.append(
                f"/protocol/openid-connect/registrations?client_id={dci}&response_type=code"
                f"&redirect_uri={base}/{dci}/"
            )
            dynamic_endpoints.append(
                f"/protocol/openid-connect/auth?action=register&client_id={dci}"
                f"&response_type=code&redirect_uri={base}/{dci}/"
            )

    all_endpoints = base_endpoints + dynamic_endpoints

    for e in all_endpoints:
        for r in realms:
            url_e = f"{r.rstrip('/')}{e}"
            if args.verbose:
                print(f"  {Colors.THISTLE}[TEST] {url_e}{Colors.RESET}")
            try:
                req_register = s.get(url_e, allow_redirects=False)
            except Exception:
                continue

            status = req_register.status_code
            location = req_register.headers.get("Location", "")

            if status == 302 and "registration" in location.lower():
                print(f"  └── {Identify.confirmed}")
                print(f"       [REDIRECT] {status} → {location[:100]}")
                print(f"       {url_e}")
                found_any = True
                if reporter:
                    reporter.add("Registration", "medium", "Registration redirect", url_e)

            elif status == 200 and (
                "register" in req_register.text.lower()
                or "create account" in req_register.text.lower()
            ):
                print(f"  └── {Identify.confirmed}")
                print(f"       [FORM] {status} — Registration form accessible at:")
                print(f"       {url_e}")
                found_any = True
                if reporter:
                    reporter.add("Registration", "medium", "Self-registration form accessible", url_e)

            elif status == 400:
                try:
                    ct = req_register.headers.get("Content-Type", "")
                    if "application/json" in ct:
                        error_msg = req_register.json().get("error_description", "")
                        if "redirect" in error_msg.lower() or "client" in error_msg.lower():
                            print(f"  └── {Identify.behavior}")
                            print(f"       [EXISTS] {status} — endpoint exists but redirect mismatch")
                            print(f"       {url_e} — {error_msg[:60]}")
                            found_any = True
                except Exception:
                    pass

    if not found_any:
        print(f"  └── {Colors.THISTLE}No open registration found{Colors.RESET}")
