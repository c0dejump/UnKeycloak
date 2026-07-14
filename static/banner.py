#!/usr/bin/env python3
from utils.style import Colors

def print_banner():
    banner = f"""
{Colors.CYAN}
  _   _       _  _  __                _            _
 | | | |_ __ | || |/ / ___  _   _  __| | ___  __ _| | __
 | | | | '_ \\| || ' / / _ \\| | | |/ _` |/ _ \\/ _` | |/ /
 | |_| | | | | || . \\  __/ |_| | (_| | (_) | (_| |   <
  \\___/|_| |_|_||_|\\_\\___\\__, |\\__,_|\\___/ \\__,_|_|\\_\\
                          |___/
{Colors.RESET}
{Colors.SALMON}  Keycloak Security Auditor{Colors.RESET}  {Colors.THISTLE}~ by c0dejump ~{Colors.RESET}
  {Colors.YELLOW}[!] For authorized pentesting only{Colors.RESET}
"""
    return banner
