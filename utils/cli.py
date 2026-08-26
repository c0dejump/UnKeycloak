#!/usr/bin/env python3

from utils.utils import argparse, sys
from utils.style import Colors
from static.banner import print_banner

def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=print_banner())

    group = parser.add_argument_group(f"{Colors.BLUE}> General{Colors.RESET}")
    group.add_argument(
        "-u", "--url",
        dest="url",
        help=f"URL to test {Colors.RED}[required]{Colors.RESET} if no -f/--file provided",
    )
    group.add_argument(
        "-f", "--file",
        dest="url_file",
        help="File of URLs (one per line)",
        required=False,
    )
    group.add_argument(
        "-o", "--output",
        dest="output",
        help="Save results to JSON file",
        required=False,
    )
    group.add_argument(
        "-v", "--verbose",
        dest="verbose",
        action="store_true",
        default=False,
        help="Verbose output",
    )

    group = parser.add_argument_group(f"{Colors.BLUE}> Request Settings{Colors.RESET}")
    group.add_argument(
        "-H", "--header",
        dest="custom_header",
        help="Add a custom HTTP header (format: 'Name: Value')",
        action="append",
        required=False,
    )
    group.add_argument(
        "-r", "--realms",
        dest="custom_realms",
        help="Add custom realm(s) to test",
        action="append",
        required=False,
    )
    group.add_argument(
        "-x", "--proxy",
        dest="proxy",
        help="Proxy URL (e.g. http://127.0.0.1:8080)",
        required=False,
    )
    group.add_argument(
        "-t", "--timeout",
        dest="timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )

    group = parser.add_argument_group(f"{Colors.BLUE}> Modules{Colors.RESET}")
    group.add_argument(
        "--no-brute",
        dest="no_brute",
        action="store_true",
        default=False,
        help="Skip credential brute-force",
    )
    group.add_argument(
        "--no-enum",
        dest="no_enum",
        action="store_true",
        default=False,
        help="Skip user enumeration",
    )
    group.add_argument(
        "-w", "--wordlist",
        dest="wordlist",
        help="Custom credential wordlist (user:pass per line)",
        required=False,
    )
    group.add_argument(
        "--rate-limit",
        dest="rate_limit",
        type=float,
        default=0.1,
        help="Delay between brute-force requests in seconds (default: 0.1)",
    )

    group = parser.add_argument_group(
        f"{Colors.BLUE}> CVE-2026-18963 (reset-credentials bypass){Colors.RESET}"
    )
    group.add_argument(
        "--reset-user",
        dest="reset_users",
        action="append",
        required=False,
        help="Username(s) to actively test for the unauth reset-credentials bypass "
             "(repeatable). Enumerated valid users are also tested automatically.",
    )
    group.add_argument(
        "--no-reset-test",
        dest="no_reset_test",
        action="store_true",
        default=False,
        help="Skip the active CVE-2026-18963 reset-credentials bypass test (it sends a "
             "password-reset email to each tested user)",
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if not args.url and not args.url_file:
        parser.error("Either -u/--url or -f/--file must be provided.")

    return args
