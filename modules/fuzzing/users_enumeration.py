#!/usr/bin/env python3

from utils.utils import (
    requests,
    sys,
    time,
    args
)
from utils.style import Colors
from utils.output import get_reporter

_DEFAULT_USERS = [
    'admin', 'administrator', 'user', 'test', 'guest', 'root',
    'keycloak', 'service', 'api', 'dev', 'demo', 'app',
]

_DUMMY_PASSWORD = "Th!sIsN0tAValidP@ssword_xyz"


def _post_token(s, url, client_id, username, password):
    data = {
        "grant_type": "password",
        "client_id": client_id,
        "username": username,
        "password": password or "",
    }
    try:
        start = time.perf_counter()
        req = s.post(url, data=data, allow_redirects=False)
        elapsed = time.perf_counter() - start
        return req, elapsed
    except Exception:
        return None, 0.0


def _error_desc(req):
    try:
        return req.json().get("error_description", "").lower()
    except Exception:
        return req.text.lower()


def user_enum(s, realms, client_ids):
    print(f"{Colors.CYAN} ├ User Enumeration {Colors.RESET}")
    reporter = get_reporter()
    found_any = False

    test_clients = client_ids[:2] if client_ids else ["account", "admin-cli"]

    for realm in realms:
        realm = realm.rstrip('/')
        token_url = f"{realm}/protocol/openid-connect/token"
        reset_url = f"{realm}/login-actions/reset-credentials"

        # --- Timing baseline: completely bogus username ---
        baseline_times = []
        dummy_user = f"__nonexistent_{int(time.time())}__"
        for cid in test_clients[:1]:
            for _ in range(2):
                _, elapsed = _post_token(s, token_url, cid, dummy_user, _DUMMY_PASSWORD)
                if elapsed > 0:
                    baseline_times.append(elapsed)

        baseline = (sum(baseline_times) / len(baseline_times)) if baseline_times else 0.3

        for cid in test_clients[:1]:
            for user in _DEFAULT_USERS:
                req, elapsed = _post_token(s, token_url, cid, user, _DUMMY_PASSWORD)
                if req is None:
                    continue

                error_desc = _error_desc(req)

                # Keycloak <17 returns different messages for valid vs invalid users
                if "invalid user credentials" in error_desc:
                    print(f"  └── {Colors.GREEN}[ENUM] Valid user (error msg): {user}{Colors.RESET}")
                    found_any = True
                    if reporter:
                        reporter.add("UserEnum", "medium", f"Valid user found: {user}", token_url)

                elif "account is not fully set up" in error_desc:
                    print(f"  └── {Colors.GREEN}[ENUM] Valid user (not fully set up): {user}{Colors.RESET}")
                    found_any = True
                    if reporter:
                        reporter.add("UserEnum", "medium", f"Valid user (setup pending): {user}", token_url)

                elif "account is disabled" in error_desc or "user is disabled" in error_desc:
                    print(f"  └── {Colors.YELLOW}[ENUM] Valid user (disabled): {user}{Colors.RESET}")
                    found_any = True
                    if reporter:
                        reporter.add("UserEnum", "low", f"Valid user (disabled): {user}", token_url)

                elif "account is temporarily locked" in error_desc or "temporarily locked" in error_desc:
                    print(f"  └── {Colors.YELLOW}[ENUM] Valid user (locked): {user}{Colors.RESET}")
                    found_any = True
                    if reporter:
                        reporter.add("UserEnum", "low", f"Valid user (locked): {user}", token_url)

                # Timing anomaly (valid user → bcrypt comparison → slower)
                elif elapsed > baseline * 1.8 and elapsed > 0.15:
                    print(f"  └── {Colors.YELLOW}[ENUM?] Timing anomaly for '{user}' "
                          f"({elapsed:.3f}s vs baseline {baseline:.3f}s){Colors.RESET}")
                    found_any = True

                time.sleep(0.05)

        # --- Reset password endpoint: different behavior for valid vs invalid ---
        for user in _DEFAULT_USERS[:5]:
            try:
                req = s.get(
                    reset_url,
                    params={"client_id": test_clients[0] if test_clients else "account"},
                    allow_redirects=True,
                )
                # Just checking endpoint accessibility here; POST-based enum requires a session
                if req.status_code == 200 and args.verbose:
                    print(f"  └── {Colors.THISTLE}[INFO] Reset-credentials endpoint accessible{Colors.RESET}")
                break
            except Exception:
                pass

    if not found_any:
        print(f"  └── {Colors.THISTLE}No user enumeration evidence found{Colors.RESET}")
