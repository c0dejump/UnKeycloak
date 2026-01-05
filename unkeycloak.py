#!/usr/bin/env python3

from utils.style import Colors
from utils.utils import (
    requests,
    sys,
    time,
    args
)
from modules.fingerprint.get_version import GetVersion
from modules.fingerprint.get_realms import get_realms
from modules.fingerprint.get_client_id import client_id_enum
from modules.fingerprint.get_idps import get_idp

from modules.misconf.registration_enabled import regsitration_endpoints
from modules.misconf.par import par_misconf

from modules.fuzzing.pot_sensitive_endpoints import sensitive_endpoints
from modules.fuzzing.credz_testing import bf_credz

from static.banner import print_banner
import traceback


def general_informations(realms, version, client_ids, idps):
    print(f"{Colors.CYAN} ├ General informations {Colors.RESET}")

    print(f"{Colors.BLUE} ⟙{Colors.RESET}")

    print(f"{Colors.SALMON}  ├ Realms:{Colors.RESET}")
    if realms:
        for r in realms:
            print(f"  └── {r}")
    #############################
    if version:
        print(f"{Colors.SALMON}  ├ Version:{Colors.RESET} {version}")
    else:
        print("Unknown")
    #############################
    print(f"{Colors.SALMON}  ├ Client ids:{Colors.RESET}")
    if client_ids:
        for v in client_ids:
            print(f"  └── {v}")
    #############################
    print(f"{Colors.SALMON}  ├ Identity Providers:{Colors.RESET}")
    if idps:
        for i in idps:
            print(f"  └── {i}")        

    print(f"{Colors.BLUE} ⟘{Colors.RESET}")


 
def process_modules(url, s):
    try:
        realms = get_realms(url, s)
        #get version
        version = ""
        for r in realms:
            kcv = GetVersion(r)
            version = kcv.run()
        client_ids = client_id_enum(url, s, realms)
        idps = get_idp(s, realms)

        general_informations(realms, version, client_ids, idps)
        regsitration_endpoints(s, realms, client_ids)
        par_misconf(s, realms)
        sensitive_endpoints(url, s, realms, client_ids)
        bf_credz(url, s, realms, client_ids)

    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except Exception as e:
        traceback.print_exc()
        print(f"Error : {e}")

def main() -> None:
    print(print_banner())


    s = requests.Session()
    s.verify = False
    s.max_redirects = 60
    s.timeout = 10

    if args.custom_header:
        try:
            custom_headers = parse_headers(args.custom_header)
            s.headers.update(custom_headers)
        except Exception as e:
            logger.exception(e)
            print(f" Error in custom header format: {e}")
            sys.exit()


    if args.url_file:
        with open(args.url_file) as url_file_handle:
            urls = url_file_handle.read().splitlines()
            for url in urls:
                url = f"{url}/" if url[-1] != "/" else url
                process_modules(url, s)
    else:
        url = f"{args.url}/" if args.url[-1] != "/" else args.url
        process_modules(url, s)


if __name__ == "__main__":
    main()