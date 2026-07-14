#!/usr/bin/env python3

from utils.utils import (
    requests,
    sys,
    time,
    args
)
from utils.style import Colors
from modules.defaultkeycloak import default_idps


def get_idp(s, realms):
    valid_idps = []
    for r in realms:
        r = r.rstrip('/')
        for didp in default_idps:
            try:
                url_idp = f"{r}/broker/{didp}/endpoint"
                req_idp = s.get(url_idp, allow_redirects=False)
                # A valid IDP returns 400/302/200 — not 404
                if req_idp.status_code != 404:
                    valid_idps.append(didp)
                    if args.verbose:
                        print(f"  └── [{req_idp.status_code}] IDP: {didp}")
            except Exception:
                pass
    return valid_idps
