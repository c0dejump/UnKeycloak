#!/usr/bin/env python3

from utils.utils import (
    requests,
    sys,
    time,
    args
)
from utils.style import Colors, Identify
import json as _json


def _analyze_sensitive_response(url_e, req, reporter):
    """Extract notable data from 200 responses on sensitive endpoints."""
    ct = req.headers.get("Content-Type", "")

    # clients-registrations/install/* → may contain client secret or sensitive config
    if "clients-registrations/install" in url_e and "application/json" in ct:
        try:
            data = req.json()
            secret = data.get("secret") or data.get("credentials", {}).get("secret")
            if secret:
                print(f"       {Identify.confirmed}")
                print(f"       Client SECRET exposed: {secret}")
                if reporter:
                    reporter.add("SensitiveEndpoint", "critical",
                                 f"Client secret exposed at {url_e}", url_e, f"secret={secret}")
            else:
                # Show interesting fields
                interesting = {k: v for k, v in data.items()
                               if k in ("clientId", "rootUrl", "redirectUris", "webOrigins",
                                        "publicClient", "bearerOnly", "standardFlowEnabled",
                                        "implicitFlowEnabled", "directAccessGrantsEnabled")}
                if interesting:
                    print(f"       {Colors.THISTLE}Config:{Colors.RESET} "
                          f"{_json.dumps(interesting, separators=(',', ':'))[:200]}")
                    if interesting.get("implicitFlowEnabled"):
                        print(f"       {Identify.behavior}")
                        print(f"       implicitFlowEnabled=true on this client")
                        if reporter:
                            reporter.add("SensitiveEndpoint", "medium",
                                         "Client config: implicit flow enabled", url_e)
                    if interesting.get("directAccessGrantsEnabled"):
                        print(f"       {Colors.YELLOW}[i] directAccessGrantsEnabled=true "
                              f"(ROPC/brute-force surface){Colors.RESET}")
        except Exception:
            pass

    # admin serverinfo → version leak
    elif "serverinfo" in url_e and "application/json" in ct:
        try:
            data = req.json()
            version = data.get("systemInfo", {}).get("version")
            if version:
                print(f"       {Identify.confirmed}")
                print(f"       Serverinfo accessible without auth — version: {version}")
                if reporter:
                    reporter.add("SensitiveEndpoint", "high",
                                 f"Serverinfo exposed (version {version})", url_e)
        except Exception:
            pass

    # admin realms/users → user list
    elif "/admin/" in url_e and ("users" in url_e or "groups" in url_e or "clients" in url_e):
        try:
            data = req.json()
            if isinstance(data, list) and data:
                print(f"       {Identify.confirmed}")
                print(f"       Admin API accessible without auth — {len(data)} item(s) returned")
                if reporter:
                    reporter.add("SensitiveEndpoint", "critical",
                                 f"Admin API accessible without auth", url_e)
        except Exception:
            pass


def sensitive_endpoints(url, s, realms, vci):
    print(f"{Colors.CYAN} ├ (Sensitive) Endpoints {Colors.RESET}")
    endpoints_ = [
        "auth/realms/master/admin/serverinfo",
        "metrics",
        "health",
        "auth/admin/master/console/config",
        "auth/resources/",
        "auth/js/keycloak.js",
        "auth/welcome/",
        "auth/robots.txt",
        "auth/version",
        "auth/admin/realms",
        "q/dev",
        "q/health",
        "q/health/ready",
        "q/health/live",
        "q/metrics",
        "q/info",
        "q/openapi",
        "q/swagger-ui",
        "auth/resources/js/",
        "auth/resources/css/",
        "auth/admin/serverinfo",
        "auth/admin/",
        "auth/admin/master/console/",
        "auth/admin/realms/master",
        "auth/admin/master/console/whoami",
        "realms/master/admin/serverinfo",
        "admin/serverinfo",
        "admin/realms/master",
        "admin/master/console/",
        "health/ready",
        "health/live",
        "health/started",
        "openapi",
        "swagger-ui",
        "q/arc",
        "q/arc/beans",
        "q/arc/observers",
        "q/arc/removed-beans",
        "q/config",
        "q/env",
        "q/config-sources",
    ]
    for r in realms:
        r = r.split("/")[-1]
        realms_list =[
            f"auth/realms/{r}",
            f"auth/realms/{r}/.well-known/openid-configuration",
            f"auth/realms/{r}/.well-known/uma2-configuration",
            f"auth/realms/{r}/protocol/saml/descriptor",
            f"auth/realms/{r}/login-actions/registration",
            f"auth/realms/{r}/login-actions/reset-credentials",
            f"auth/realms/{r}/protocol/openid-connect/registrations",
            f"auth/realms/{r}/clients-registrations/default",
            f"auth/realms/{r}/clients-registrations/openid-connect",
            f"auth/realms/{r}/clients-registrations/saml2-entity-descriptor",
            f"auth/admin/realms/{r}/users",
            f"auth/admin/realms/{r}/clients",
            f"auth/admin/realms/{r}/groups",
            f"auth/admin/realms/{r}/roles",
            f"auth/admin/realms/{r}/events",
            f"auth/realms/{r}/protocol/openid-connect/certs",
            f"auth/realms/{r}/broker",
            f"auth/realms/{r}/account",
            f"auth/realms/{r}/account/credentials",
            f"auth/realms/{r}/account/sessions",
            f"auth/realms/{r}/account/applications",
            f"auth/realms/{r}/account/linked-accounts",
            f"auth/realms/{r}/account/totp",
            f"auth/realms/{r}/account/federated-identity",
            f"auth/realms/{r}/protocol/openid-connect/auth/device",
            f"auth/realms/{r}/protocol/openid-connect/ext/ciba/auth",
            f"auth/realms/{r}/protocol/openid-connect/ext/par/request",
            f"auth/realms/{r}/protocol/openid-connect/logout",
            f"auth/realms/{r}/protocol/openid-connect/revoke",
            f"auth/realms/{r}/protocol/openid-connect/token/introspect",
            f"auth/realms/{r}/protocol/openid-connect/userinfo",
            f"auth/realms/{r}/protocol/docker-v2/auth",
            f"auth/admin/realms/{r}/attack-detection/brute-force/users",
            f"auth/admin/realms/{r}/authentication/flows",
            f"auth/admin/realms/{r}/authentication/authenticator-providers",
            f"auth/admin/realms/{r}/authentication/required-actions",
            f"auth/admin/realms/{r}/client-scopes",
            f"auth/admin/realms/{r}/default-groups",
            f"auth/admin/realms/{r}/identity-provider/instances",
            f"auth/admin/realms/{r}/keys",
            f"auth/admin/realms/{r}/localization",
            f"auth/admin/realms/{r}/client-policies/policies",
            f"auth/admin/realms/{r}/client-policies/profiles",
            f"auth/admin/realms/{r}/components",
            f"auth/admin/realms/{r}/user-storage",
            f"auth/realms/{r}/protocol/openid-connect/3p-cookies/step1.html",
            f"auth/realms/{r}/protocol/openid-connect/3p-cookies/step2.html",
            f"auth/realms/{r}/protocol/openid-connect/login-status-iframe.html",
            f"auth/realms/{r}/protocol/openid-connect/login-status-iframe.html/init",
            f"auth/realms/{r}/authz/protection/resource_set",
            f"auth/realms/{r}/authz/protection/permission",
            f"auth/realms/{r}/authz/protection/uma-policy",
            f"realms/{r}",
            f"realms/{r}/.well-known/openid-configuration",
            f"realms/{r}/.well-known/uma2-configuration",
            f"realms/{r}/protocol/saml/descriptor",
            f"realms/{r}/login-actions/registration",
            f"realms/{r}/login-actions/reset-credentials",
            f"realms/{r}/login-actions/authenticate",
            f"realms/{r}/login-actions/required-action",
            f"realms/{r}/login-actions/first-broker-login",
            f"realms/{r}/login-actions/post-broker-login",
            f"realms/{r}/login-actions/detached-info",
            f"realms/{r}/protocol/openid-connect/registrations",
            f"realms/{r}/clients-registrations/default",
            f"realms/{r}/clients-registrations/openid-connect",
            f"realms/{r}/clients-registrations/saml2-entity-descriptor",
            f"realms/{r}/clients-registrations/install",
            f"admin/realms/{r}/users",
            f"admin/realms/{r}/users/count",
            f"admin/realms/{r}/clients",
            f"admin/realms/{r}/groups",
            f"admin/realms/{r}/groups/count",
            f"admin/realms/{r}/roles",
            f"admin/realms/{r}/events",
            f"admin/realms/{r}/events/config",
            f"admin/realms/{r}/admin-events",
            f"realms/{r}/protocol/openid-connect/certs",
            f"realms/{r}/broker",
            f"realms/{r}/broker/token",
            f"realms/{r}/account",
            f"realms/{r}/account/credentials",
            f"realms/{r}/account/credentials/password",
            f"realms/{r}/account/sessions",
            f"realms/{r}/account/sessions/devices",
            f"realms/{r}/account/applications",
            f"realms/{r}/account/linked-accounts",
            f"realms/{r}/account/totp",
            f"realms/{r}/account/federated-identity",
            f"realms/{r}/account/resource",
            f"realms/{r}/account/resources",
            f"realms/{r}/protocol/openid-connect/auth/device",
            f"realms/{r}/protocol/openid-connect/ext/ciba/auth",
            f"realms/{r}/protocol/openid-connect/ext/par/request",
            f"realms/{r}/protocol/openid-connect/logout",
            f"realms/{r}/protocol/openid-connect/logout/backchannel-logout",
            f"realms/{r}/protocol/openid-connect/revoke",
            f"realms/{r}/protocol/openid-connect/token",
            f"realms/{r}/protocol/openid-connect/token/introspect",
            f"realms/{r}/protocol/openid-connect/userinfo",
            f"realms/{r}/protocol/docker-v2/auth",
            f"admin/realms/{r}/attack-detection/brute-force/users",
            f"admin/realms/{r}/authentication/flows",
            f"admin/realms/{r}/authentication/authenticator-providers",
            f"admin/realms/{r}/authentication/form-providers",
            f"admin/realms/{r}/authentication/form-action-providers",
            f"admin/realms/{r}/authentication/required-actions",
            f"admin/realms/{r}/authentication/config-description",
            f"admin/realms/{r}/authentication/per-client-config-description",
            f"admin/realms/{r}/authentication/unregistered-required-actions",
            f"admin/realms/{r}/client-scopes",
            f"admin/realms/{r}/default-groups",
            f"admin/realms/{r}/default-default-client-scopes",
            f"admin/realms/{r}/default-optional-client-scopes",
            f"admin/realms/{r}/identity-provider/providers",
            f"admin/realms/{r}/identity-provider/instances",
            f"admin/realms/{r}/keys",
            f"admin/realms/{r}/localization",
            f"admin/realms/{r}/client-policies/policies",
            f"admin/realms/{r}/client-policies/profiles",
            f"admin/realms/{r}/components",
            f"admin/realms/{r}/user-storage",
            f"admin/realms/{r}/testLDAPConnection",
            f"admin/realms/{r}/testSMTPConnection",
            f"admin/realms/{r}/clear-realm-cache",
            f"admin/realms/{r}/clear-user-cache",
            f"admin/realms/{r}/clear-keys-cache",
            f"admin/realms/{r}/sessions/count",
            f"admin/realms/{r}/client-session-stats",
            f"realms/{r}/protocol/openid-connect/3p-cookies/step1.html",
            f"realms/{r}/protocol/openid-connect/3p-cookies/step2.html",
            f"realms/{r}/protocol/openid-connect/login-status-iframe.html",
            f"realms/{r}/protocol/openid-connect/login-status-iframe.html/init",
            f"realms/{r}/authz/protection/resource_set",
            f"realms/{r}/authz/protection/permission",
            f"realms/{r}/authz/protection/permission/ticket",
            f"realms/{r}/authz/protection/uma-policy",
            f"realms/{r}/authz/protection/token/introspect",
            f"realms/{r}/protocol/openid-connect/auth?response_type=token",
            f"auth/realms/{r}/protocol/openid-connect/auth?response_type=token",
            f"admin/realms/{r}/clients-initial-access",
            f"admin/realms/{r}/client-registration-policy/providers",
            f"admin/realms/{r}/credential-registrators",
            f"admin/realms/{r}/partial-export",
            f"admin/realms/{r}/partial-import",
            f"admin/realms/{r}/logout-all",
            f"admin/realms/{r}/push-revocation",
            f"admin/realms/{r}/events?type=LOGIN_ERROR",
            f"admin/realms/{r}/admin-events",
        ]
        for rl in realms_list:
            endpoints_.append(rl)
    for v in vci:
        for r in realms:
            r = r.split("/")[-1]
            endpoints_.append(f"realms/{r}/clients-registrations/install/{v}")
    from utils.style import Identify
    from utils.output import get_reporter
    reporter = get_reporter()

    for e in endpoints_:
        url_e = f"{url}{e}"
        try:
            req_s = s.get(url_e, allow_redirects=False)
        except Exception:
            continue
        if req_s.status_code not in [403, 401, 404, 400, 405, 301, 302, 503]:
            print(f"  └── [{req_s.status_code}] {url_e}")
            _analyze_sensitive_response(url_e, req_s, reporter)