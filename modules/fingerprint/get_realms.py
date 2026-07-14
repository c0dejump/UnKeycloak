#!/usr/bin/env python3

from utils.utils import args
from modules.defaultkeycloak import default_realms


def _fetch_realms_from_admin_api(url, s):
    """Try to get the full realm list from the admin API without auth."""
    candidates = [
        f"{url}auth/admin/realms",
        f"{url}admin/realms",
    ]
    for endpoint in candidates:
        try:
            r = s.get(endpoint, allow_redirects=False)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list) and data:
                    names = [entry["realm"] for entry in data if "realm" in entry]
                    if names:
                        return names, endpoint
        except Exception:
            pass
    return [], None


def _probe_realm(url, realm_name, s):
    """Return the full URL for a realm if it exists, else None."""
    for prefix in ("auth/realms/", "realms/"):
        realm_url = f"{url}{prefix}{realm_name}"
        try:
            r = s.get(realm_url, allow_redirects=False)
            if r.status_code == 200:
                return realm_url
            if r.status_code in (301, 302):
                followed = s.get(realm_url, allow_redirects=True)
                if realm_name in followed.url:
                    return realm_url
        except Exception:
            pass
    return None


def get_realms(url, s):
    realms_founded = []
    seen = set()

    # 1. Try admin API first — gives the full authoritative list
    api_names, api_endpoint = _fetch_realms_from_admin_api(url, s)
    if api_names:
        from utils.style import Colors
        print(f"  {Colors.THISTLE}[i] Admin API exposed at {api_endpoint} "
              f"— {len(api_names)} realm(s) retrieved{Colors.RESET}")

    # 2. Build wordlist: API names + defaults + custom
    wordlist = list(api_names)
    for r in default_realms:
        if r not in wordlist:
            wordlist.append(r)
    if args.custom_realms:
        for cr in args.custom_realms:
            if cr not in wordlist:
                wordlist.append(cr)

    # 3. Probe each name
    for name in wordlist:
        if name in seen:
            continue
        seen.add(name)
        found = _probe_realm(url, name, s)
        if found:
            realms_founded.append(found)

    return realms_founded