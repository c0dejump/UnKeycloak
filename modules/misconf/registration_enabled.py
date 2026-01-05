#!/usr/bin/env python3

from utils.utils import (
    requests,
    sys,
    time,
    args
)
from utils.style import Colors


def regsitration_endpoints(s, realms, vci):
    print(f"{Colors.CYAN} ├ Registration Endpoints {Colors.RESET}")
    endpoints_ = [
    "/login-actions/registration",
    "/protocol/openid-connect/registrations",
    "/clients-registrations/openid-connect",
    "/clients-registrations/default",
    "/account/#/security/signingin",
    "/account/password",
    ]
    for dci in vci:
        endpoints_.append(f"login-actions/registration?client_id={dci}")
        for r in realms:
            endpoints_.append(f"/protocol/openid-connect/auth?client_id={dci}&response_type=code&redirect_uri={r}{dci}/&kc_action=register")
            endpoints_.append(f"/protocol/openid-connect/registrations?client_id={dci}&response_type=code&redirect_uri={r}{dci}/")
            endpoints_.append(f"/protocol/openid-connect/auth?action=register&client_id={dci}&response_type=code&redirect_uri={r}{dci}/")
            endpoints_.append(f"/protocol/openid-connect/registrations?client_id={dci}&response_type=code&redirect_uri={r}{dci}/&nonce={int(time.time())}")
    for e in endpoints_:
        for r in realms:
            url_e = f"{r}{e}"
            print(url_e)
            req_register = s.get(url_e, allow_redirects=False)
            status = req_register.status_code
            location = req_register.headers.get('Location', '')

            if status == 302 and 'registration' in location.lower():
                print(f"{Colors.GREEN}  └── [FOUND] {status} -> {location[:80]}{Colors.RESET}")
            elif status == 200 and ('register' in req_register.text.lower() or 'create account' in req_register.text.lower()):
                print(f"{Colors.GREEN}  └── [FOUND] {status} Registration form{Colors.RESET} {url_e}")
            elif status == 400:
                error_msg = req_register.json().get('error_description', '') if 'application/json' in req_register.headers.get('Content-Type', '') else ''
                if 'redirect' in error_msg.lower() or 'client' in error_msg.lower():
                    print(f"{Colors.YELLOW}  └── [EXISTS] {status} {url_e} - {error_msg[:50]}{Colors.RESET}")