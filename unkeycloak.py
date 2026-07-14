#!/usr/bin/env python3

import traceback

from utils.style import Colors
from utils.utils import (
    requests,
    sys,
    time,
    args
)
from utils.output import init_reporter

from modules.fingerprint.get_version import GetVersion
from modules.fingerprint.get_realms import get_realms
from modules.fingerprint.get_client_id import client_id_enum
from modules.fingerprint.get_idps import get_idp

from modules.misconf.registration_enabled import regsitration_endpoints
from modules.misconf.par import par_misconf
from modules.misconf.cors import check_cors
from modules.misconf.grant_types import check_grant_types
from modules.misconf.security_headers import check_security_headers
from modules.misconf.open_redirect import check_open_redirect
from modules.misconf.brute_force_prot import check_brute_force_protection
from modules.misconf.session_security import check_session_security
from modules.misconf.client_registration import check_client_registration
from modules.misconf.scope_enum import check_scopes
from modules.misconf.cve_check import check_cves

from modules.fuzzing.pot_sensitive_endpoints import sensitive_endpoints
from modules.fuzzing.credz_testing import bf_credz
from modules.fuzzing.users_enumeration import user_enum

from static.banner import print_banner


def parse_headers(header_list):
    headers = {}
    for h in header_list:
        if ":" not in h:
            print(f"  {Colors.YELLOW}[!] Invalid header format (expected 'Name: Value'): {h}{Colors.RESET}")
            continue
        name, _, value = h.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def general_informations(realms, version, client_ids, idps):
    print(f"{Colors.CYAN} ├ General Informations {Colors.RESET}")
    print(f"{Colors.BLUE} ⟙{Colors.RESET}")

    print(f"{Colors.SALMON}  ├ Realms:{Colors.RESET}")
    if realms:
        for r in realms:
            print(f"  └── {r}")
    else:
        print(f"  └── {Colors.YELLOW}None found{Colors.RESET}")

    if version:
        print(f"{Colors.SALMON}  ├ Version:{Colors.RESET} {Colors.YELLOW}{version}{Colors.RESET}")
    else:
        print(f"{Colors.SALMON}  ├ Version:{Colors.RESET} {Colors.THISTLE}Unknown{Colors.RESET}")

    print(f"{Colors.SALMON}  ├ Client IDs:{Colors.RESET}")
    if client_ids:
        for v in client_ids:
            print(f"  └── {v}")
    else:
        print(f"  └── {Colors.THISTLE}None found{Colors.RESET}")

    print(f"{Colors.SALMON}  ├ Identity Providers:{Colors.RESET}")
    if idps:
        for i in idps:
            print(f"  └── {i}")
    else:
        print(f"  └── {Colors.THISTLE}None found{Colors.RESET}")

    print(f"{Colors.BLUE} ⟘{Colors.RESET}")


def process_modules(url, s, reporter, show_summary=True):
    try:
        realms = get_realms(url, s)

        # Version: use first realm that returns a result
        version = None
        for r in realms:
            kcv = GetVersion(r, session=s)
            v = kcv.run()
            if v:
                version = v
                break

        client_ids = client_id_enum(url, s, realms)
        idps = get_idp(s, realms)

        reporter.set_info("target", url)
        reporter.set_info("version", version or "")
        reporter.set_info("realms", realms)

        general_informations(realms, version, client_ids, idps)

        # CVE check based on detected version
        check_cves(version, s=s, realms=realms, client_ids=client_ids)

        # Misconfiguration checks
        regsitration_endpoints(s, realms, client_ids)
        par_misconf(s, realms)
        check_client_registration(s, realms)
        check_cors(s, realms)
        check_grant_types(s, realms)
        check_scopes(s, realms, client_ids)
        check_security_headers(s, realms)
        check_open_redirect(s, realms, client_ids)
        check_brute_force_protection(s, realms)
        check_session_security(s, realms, client_ids)

        # Fuzzing
        sensitive_endpoints(url, s, realms, client_ids)

        if not args.no_enum:
            user_enum(s, realms, client_ids)

        if not args.no_brute:
            bf_credz(url, s, realms, client_ids)

        _correlate_findings(reporter)

        if show_summary:
            reporter.print_summary()

        if args.output:
            reporter.save_json(args.output)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        reporter.print_summary()
        sys.exit(0)
    except Exception as e:
        traceback.print_exc()
        print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")


def _correlate_findings(reporter):
    """Detect dangerous combinations across findings and emit correlation alerts."""
    if not reporter or not reporter.findings:
        return

    categories = {}
    for f in reporter.findings:
        cat = f.get("category", "")
        categories.setdefault(cat, []).append(f)

    alerts = []

    # ROPC enabled + No BF protection → brute force viable
    has_ropc = any("ROPC" in f["title"] for f in categories.get("GrantTypes", []))
    has_no_bf = any("brute-force" in f["title"].lower() for f in categories.get("BruteForce", []))
    has_dag = any("dag" in f.get("details", "").lower() for f in categories.get("DefaultCredentials", []))

    if has_ropc and has_no_bf:
        alerts.append((
            "high",
            "Attack chain: ROPC enabled + No BF protection → direct credential brute-force viable on token endpoint",
        ))

    # Implicit flow + CORS → token theft chain
    has_implicit = any("Implicit" in f["title"] for f in categories.get("GrantTypes", []))
    has_cors = bool(categories.get("CORS", []))

    if has_implicit and has_cors:
        alerts.append((
            "high",
            "Attack chain: Implicit flow (tokens in URL) + CORS on userinfo → cross-origin token theft possible",
        ))

    # Algorithm confusion (already flagged in GrantTypes but worth reiterating)
    has_alg_conf = any("Algorithm Confusion" in f["title"] for f in categories.get("GrantTypes", []))
    if has_alg_conf:
        alerts.append((
            "high",
            "Attack chain: Algorithm confusion — obtain server RSA pubkey via /certs, forge JWT with pubkey as HMAC secret",
        ))

    if not alerts:
        return

    print(f"\n{Colors.RED} ├ Attack Chain Correlations {Colors.RESET}")
    for sev, msg in alerts:
        print(f"  └── {Colors.RED}[CHAIN]{Colors.RESET} {msg}")
        reporter.add("AttackChain", sev, msg)


def _patch_session_timeout(s, timeout):
    """Make every request through this session respect the timeout by default."""
    _orig = s.request

    def _request_with_timeout(method, url, **kwargs):
        kwargs.setdefault("timeout", timeout)
        return _orig(method, url, **kwargs)

    s.request = _request_with_timeout


def main() -> None:
    print(print_banner())

    reporter = init_reporter()

    s = requests.Session()
    s.verify = False
    s.max_redirects = 60

    _patch_session_timeout(s, args.timeout)

    if args.custom_header:
        custom_headers = parse_headers(args.custom_header)
        s.headers.update(custom_headers)

    if args.proxy:
        s.proxies = {
            "http": args.proxy,
            "https": args.proxy,
        }
        print(f"  {Colors.THISTLE}[i] Proxy: {args.proxy}{Colors.RESET}")

    if args.url_file:
        with open(args.url_file) as fh:
            urls = [u.strip() for u in fh.read().splitlines() if u.strip() and not u.startswith("#")]
        for url in urls:
            url = url if url.endswith("/") else url + "/"
            process_modules(url, s, reporter, show_summary=False)
    else:
        url = args.url if args.url.endswith("/") else args.url + "/"
        process_modules(url, s, reporter)


if __name__ == "__main__":
    main()
