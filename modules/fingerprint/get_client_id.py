#!/usr/bin/env python3

from utils.utils import (
    requests,
    sys,
    time,
    args
)
import tldextract
from modules.defaultkeycloak import default_client_ids

def client_id_enum(url, s, realms):
    valid_client_ids = []

    extracted = tldextract.extract(url)
    app_name = extracted.domain

    other_client_id = [f'{app_name}', f"{app_name}-api", f"{app_name}-frontend", f"{app_name}-mobile"]

    invalid_client_id = "/protocol/openid-connect/auth?client_id=plopiplop&redirect_uri=xxx/callback&response_type=code&scope=openid"
    for r in realms:
        invalid_url = f"{r}{invalid_client_id}"
        invalid_req = s.get(invalid_url, allow_redirects=False)

    for dci in default_client_ids:
        for r in realms:
            url_id = f"{r}/protocol/openid-connect/auth?client_id={dci}&redirect_uri={url}/callback&response_type=code&scope=openid"
            req = s.get(url_id, allow_redirects=False)
            if len(req.content) != len(invalid_req.content):
                valid_client_ids.append(dci)
    for ocd in other_client_id:
        for r in realms:
            url_id = f"{r}/protocol/openid-connect/auth?client_id={ocd}&redirect_uri={url}/callback&response_type=code&scope=openid"
            req = s.get(url_id, allow_redirects=False)
            if len(req.content) != len(invalid_req.content):
                valid_client_ids.append(ocd)
    return valid_client_ids