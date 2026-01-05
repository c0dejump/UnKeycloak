#!/usr/bin/env python3

from utils.utils import (
    requests,
    sys,
    time,
    args
)

from modules.defaultkeycloak import default_realms

def get_realms(url, s):
    realms_founded = []
    realms_list = default_realms
    if args.custom_realms:
        for cr in args.custom_realms:
            realms_list.append(cr)
    path_check = [
    "auth/realms/",
    "realms/"
    ]
    for rl in realms_list:
        for pc in path_check:
            url_realms = f"{url}{pc}{rl}"
            req_realms = s.get(url_realms, allow_redirects=False)
            if req_realms.status_code in [302, 301]:
                req_realms_redir = s.get(url_realms, allow_redirects=True)
                if rl in req_realms_redir.url:
                    realms_founded.append(url_realms)
            elif req_realms.status_code == 200:
                realms_founded.append(url_realms)
    return realms_founded