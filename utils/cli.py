#!/usr/bin/env python3

from utils.utils import argparse, sys, random
from utils.style import Colors
from static.banner import print_banner

def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=print_banner())

    group = parser.add_argument_group(f"{Colors.BLUE}> General{Colors.RESET}")
    group.add_argument(
        "-u",
        "--url",
        dest="url",
        help=f"URL to test {Colors.RED}[required]{Colors.RESET} if no -f/--file provided",
    )
    group.add_argument(
        "-f",
        "--file",
        dest="url_file",
        help="File of URLs",
        required=False,
    )

    group = parser.add_argument_group(f"{Colors.BLUE}> Request Settings{Colors.RESET}")
    group.add_argument(
        "-H",
        "--header",
        dest="custom_header",
        help="Add a custom HTTP Header",
        action="append",
        required=False,
    )
    group.add_argument(
        "-r",
        "--realms",
        dest="custom_realms",
        help="Add a custom realms in url",
        action="append",
        required=False,
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # Validate that either URL or file is provided
    if not args.url and not args.url_file:
        parser.error("Either -u/--url or -f/--file must be provided.")

    return args
