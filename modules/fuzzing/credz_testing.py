#!/usr/bin/env python3

from utils.utils import (
    requests,
    sys,
    time,
    args
)
from utils.style import Colors
from utils.output import get_reporter
from modules.defaultkeycloak import default_credentials


def _load_credentials():
    if args.wordlist:
        creds = []
        try:
            with open(args.wordlist) as fh:
                for line in fh.read().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        user, _, pwd = line.partition(":")
                        creds.append((user, pwd))
            if creds:
                print(f"  {Colors.THISTLE}[i] Loaded {len(creds)} credentials from {args.wordlist}{Colors.RESET}")
                return creds
        except Exception as e:
            print(f"  {Colors.YELLOW}[!] Could not load wordlist '{args.wordlist}': {e}{Colors.RESET}")
    return default_credentials


def direct_access_grant_bf(s, realms, client_ids, rate_limit=0.1):
    print(f"{Colors.CYAN}   └── Direct Access Grant{Colors.RESET}")
    reporter = get_reporter()

    credentials = _load_credentials()

    results = {
        "dag_enabled": [],
        "credentials": [],
        "user_info": [],
    }

    for realm in realms:
        realm = realm.rstrip('/') + '/'
        url = f"{realm}protocol/openid-connect/token"

        for client_id in client_ids:
            dag_status = None

            for user, password in credentials:
                data = {
                    "grant_type": "password",
                    "client_id": client_id,
                    "username": user,
                    "password": password or "",
                }

                try:
                    start = time.perf_counter()
                    req = s.post(url, data=data, allow_redirects=False, timeout=10)
                    elapsed = time.perf_counter() - start
                except Exception as e:
                    print(f"      {Colors.RED}[ERR] {e}{Colors.RESET}")
                    break

                if req.status_code == 429 or elapsed > 5:
                    print(f"      {Colors.YELLOW}[!] Rate limit/slowdown detected on {client_id}{Colors.RESET}")
                    break

                if req.status_code == 400:
                    try:
                        body = req.json()
                        err = body.get("error", "")
                    except Exception:
                        err = req.text
                    if "unauthorized_client" in err or "invalid_client" in err:
                        dag_status = False
                        break

                if dag_status is None:
                    dag_status = True
                    results["dag_enabled"].append(client_id)
                    print(f"      {Colors.GREEN}[DAG] {client_id}: Direct Access Grant enabled{Colors.RESET}")

                try:
                    resp_json = req.json()
                    error_desc = resp_json.get("error_description", "").lower()
                except Exception:
                    error_desc = req.text.lower()

                if req.status_code == 200:
                    results["credentials"].append({
                        "realm": realm, "client": client_id,
                        "user": user, "pass": password,
                    })
                    print(f"      {Colors.RED}[!!!] Valid credentials: {user}:{password} @ {client_id}{Colors.RESET}")
                    if reporter:
                        reporter.add(
                            "DefaultCredentials", "critical",
                            f"Valid credentials: {user}:{password}",
                            url,
                            f"client_id={client_id} realm={realm}",
                        )

                elif "disabled" in error_desc:
                    results["user_info"].append({"user": user, "status": "disabled"})
                    print(f"      {Colors.YELLOW}[i] {user}: account disabled{Colors.RESET}")

                elif "locked" in error_desc or "temporarily" in error_desc:
                    results["user_info"].append({"user": user, "status": "locked"})
                    print(f"      {Colors.YELLOW}[i] {user}: account locked{Colors.RESET}")

                time.sleep(rate_limit)

            if dag_status is False:
                print(f"      {Colors.THISTLE}[DAG] {client_id}: Disabled (unauthorized_client){Colors.RESET}")

    return results


def bf_credz(url, s, realms, client_ids):
    print(f"{Colors.CYAN} ├ Credentials Analysis {Colors.RESET}")
    rate_limit = getattr(args, "rate_limit", 0.1)
    direct_access_grant_bf(s, realms, client_ids, rate_limit=rate_limit)
