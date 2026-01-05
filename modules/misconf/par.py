#!/usr/bin/env python3

from utils.utils import (
    requests,
    sys,
    time,
    args
)
from utils.style import Colors

def par_misconf(s, realms):
    print(f"{Colors.CYAN} ├ PAR misconfig {Colors.RESET}")
    for r in realms:
        url_par = f"{r}/.well-known/openid-configuration"
        #print(url_par)
        par_req = s.get(url_par, allow_redirects=False)
        if par_req.status_code == 200:
            data = par_req.json()
            par_value = data.get("require_pushed_authorization_requests")
            if par_value == False:
                print(f"  └── require_pushed_authorization_requests: {Colors.RED}False{Colors.RESET}")
                """
                Exploitation :
Si PAR est supporté mais pas requis, tu peux envoyer une auth request classique avec des paramètres malveillants (redirect_uri, scope) sans passer par PAR, contournant potentiellement des validations côté serveur.
                """