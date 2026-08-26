#!/usr/bin/env python3

import uuid
from urllib.parse import urljoin

from bs4 import BeautifulSoup

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

# --- Registration oracle markers (default English Keycloak messages) ---
_REG_USER_EXISTS = "username already exists"
_REG_EMAIL_EXISTS = "email already exists"
_REG_FORM_MARKERS = ("kc-register-form", "password-confirm", 'name="firstname"')


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


# --------------------------------------------------------------------------- #
# Registration-based enumeration oracle
# --------------------------------------------------------------------------- #
def _parse_forms(html, page_url):
    """Return [{action, inputs:{name:value}, id, text}] for every <form>."""
    out = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return out
    for f in soup.find_all("form"):
        action = f.get("action") or page_url
        inputs = {}
        for inp in f.find_all(["input", "button", "select", "textarea"]):
            name = inp.get("name")
            if name:
                inputs[name] = inp.get("value", "") or ""
        out.append({
            "action": urljoin(page_url, action.replace("&amp;", "&")),
            "inputs": inputs,
            "id": f.get("id", "") or "",
        })
    return out


def _is_registration_page(text):
    low = text.lower()
    return any(m in low for m in _REG_FORM_MARKERS)


def _get_registration_form(s, realm, cid, ru):
    """GET a fresh registration form (fresh session_code) for a given client/redirect."""
    try:
        r = s.get(
            f"{realm}/protocol/openid-connect/registrations",
            params={
                "client_id": cid,
                "response_type": "code",
                "scope": "openid",
                "redirect_uri": ru,
            },
            allow_redirects=True,
        )
    except Exception:
        return None, None
    if r.status_code != 200 or not _is_registration_page(r.text):
        return None, None
    for form in _parse_forms(r.text, r.url):
        if "password-confirm" in form["inputs"] or "kc-register-form" in form["id"]:
            return form, r.url
    return None, None


def _find_registration_entry(s, realm, client_ids):
    """Return the first (cid, redirect_uri) that serves a registration form, else None."""
    base = realm.split("/realms/")[0]
    candidates = [("account", f"{realm}/account/")]
    for cid in (client_ids or [])[:4]:
        if cid == "account":
            continue
        candidates.append((cid, f"{base}/"))
        candidates.append((cid, f"{realm}/account/"))
    for cid, ru in candidates:
        form, page_url = _get_registration_form(s, realm, cid, ru)
        if form:
            return cid, ru
    return None


def _probe_registration_username(s, realm, cid, ru, username):
    """Submit the registration form for `username` with mismatched passwords.

    Mismatched password/password-confirm guarantees validation fails, so NO
    account is ever created; we only read whether Keycloak reports the username
    as already taken. Returns True (exists), False (free), or None (inconclusive).
    """
    form, page_url = _get_registration_form(s, realm, cid, ru)
    if not form:
        return None
    if "username" not in form["inputs"]:
        # registrationEmailAsUsername mode — no bare username field to probe
        return None

    tag = uuid.uuid4().hex[:10]
    data = dict(form["inputs"])
    data.setdefault("firstName", "Test")
    data.setdefault("lastName", "User")
    # unique, non-existent email so an "email exists" error can never confound
    # the username verdict; .invalid is a reserved TLD that never resolves
    data["email"] = f"nx_{tag}@example.invalid"
    data["username"] = username
    # mismatched -> guaranteed failure -> no account creation
    data["password"] = "Aa1!aaaa"
    data["password-confirm"] = "Aa1!bbbb"

    try:
        r = s.post(form["action"], data=data, allow_redirects=True)
    except Exception:
        return None
    return _REG_USER_EXISTS in r.text.lower()


def _registration_user_enum(s, realm, client_ids, candidates, already_found, reporter):
    """Enumerate usernames through the self-registration 'already exists' oracle."""
    entry = _find_registration_entry(s, realm, client_ids)
    if not entry:
        if args.verbose:
            print(f"  └── {Colors.THISTLE}[INFO] No open registration form on "
                  f"{realm} — skipping registration oracle{Colors.RESET}")
        return False

    cid, ru = entry
    print(f"  {Colors.THISTLE}[i] Registration oracle active (client '{cid}') — "
          f"probes never create an account (mismatched password){Colors.RESET}")

    found_any = False
    for user in candidates:
        if user in already_found:
            continue
        exists = _probe_registration_username(s, realm, cid, ru, user)
        if exists is True:
            print(f"  └── {Colors.GREEN}[ENUM] Valid user (registration oracle): {user}{Colors.RESET}")
            already_found.add(user)
            found_any = True
            if reporter:
                reporter.add(
                    "UserEnum", "medium",
                    f"Valid user found: {user}",
                    f"{realm}/login-actions/registration",
                    "confirmed via self-registration 'username already exists' oracle",
                )
        time.sleep(0.05)
    return found_any


def user_enum(s, realms, client_ids):
    print(f"{Colors.CYAN} ├ User Enumeration {Colors.RESET}")
    reporter = get_reporter()
    found_any = False
    found_users = set()

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
                    found_users.add(user)
                    if reporter:
                        reporter.add("UserEnum", "medium", f"Valid user found: {user}", token_url)

                elif "account is not fully set up" in error_desc:
                    print(f"  └── {Colors.GREEN}[ENUM] Valid user (not fully set up): {user}{Colors.RESET}")
                    found_any = True
                    found_users.add(user)
                    if reporter:
                        reporter.add("UserEnum", "medium", f"Valid user (setup pending): {user}", token_url)

                elif "account is disabled" in error_desc or "user is disabled" in error_desc:
                    print(f"  └── {Colors.YELLOW}[ENUM] Valid user (disabled): {user}{Colors.RESET}")
                    found_any = True
                    found_users.add(user)
                    if reporter:
                        reporter.add("UserEnum", "low", f"Valid user (disabled): {user}", token_url)

                elif "account is temporarily locked" in error_desc or "temporarily locked" in error_desc:
                    print(f"  └── {Colors.YELLOW}[ENUM] Valid user (locked): {user}{Colors.RESET}")
                    found_any = True
                    found_users.add(user)
                    if reporter:
                        reporter.add("UserEnum", "low", f"Valid user (locked): {user}", token_url)

                # Timing anomaly (valid user → bcrypt comparison → slower)
                elif elapsed > baseline * 1.8 and elapsed > 0.15:
                    print(f"  └── {Colors.YELLOW}[ENUM?] Timing anomaly for '{user}' "
                          f"({elapsed:.3f}s vs baseline {baseline:.3f}s){Colors.RESET}")
                    found_any = True

                time.sleep(0.05)

        # --- Registration 'already exists' oracle (if self-registration is open) ---
        if _registration_user_enum(s, realm, client_ids, _DEFAULT_USERS, found_users, reporter):
            found_any = True

        # --- Reset password endpoint: accessibility note only ---
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
