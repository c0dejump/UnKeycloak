#!/usr/bin/env python3

from utils.utils import (
    requests,
    sys,
    time,
    args
)

from modules.defaultkeycloak import default_idps


def get_idp(s, realms):
    valid_idps = []
    for r in realms:
        for didp in default_idps:
            url_idp = f"{r}/broker/{didp}/endpoint"
            #print(url_idp)
            req_idp = s.get(url_idp, allow_redirects=False)
            if req_idp == 200:
                valid_idps.append(url_idp)
    return valid_idps