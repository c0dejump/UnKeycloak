#!/usr/bin/env python3

import json
from datetime import datetime
from utils.style import Colors

_reporter = None


class Reporter:
    def __init__(self):
        self.findings = []
        self.target_info = {}
        self.start_time = datetime.now()

    def add(self, category: str, severity: str, title: str, url: str = "", details: str = ""):
        self.findings.append({
            "category": category,
            "severity": severity,
            "title": title,
            "url": url,
            "details": details,
            "timestamp": datetime.now().isoformat(),
        })

    def set_info(self, key: str, value):
        self.target_info[key] = value

    def print_summary(self):
        elapsed = (datetime.now() - self.start_time).total_seconds()
        sev_colors = {
            "critical": Colors.RED,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.BLUE,
            "info": Colors.THISTLE,
        }

        print(f"\n{Colors.CYAN} ├ Scan Summary {Colors.RESET}")
        print(f"{Colors.BLUE} ⟙{Colors.RESET}")
        print(f"  Duration : {elapsed:.1f}s")
        print(f"  Findings : {len(self.findings)}")

        if self.findings:
            counts = {}
            for f in self.findings:
                s = f.get("severity", "info")
                counts[s] = counts.get(s, 0) + 1
            for sev in ["critical", "high", "medium", "low", "info"]:
                if counts.get(sev):
                    color = sev_colors.get(sev, Colors.RESET)
                    print(f"  {color}[{sev.upper():8}]{Colors.RESET} {counts[sev]}")

            print(f"\n{Colors.SALMON}  Findings detail:{Colors.RESET}")
            for f in self.findings:
                color = sev_colors.get(f.get("severity", "info"), Colors.RESET)
                print(f"  {color}[{f['severity'].upper():8}]{Colors.RESET} [{f['category']}] {f['title']}")
                if f.get("url"):
                    print(f"             └── {f['url']}")
        else:
            print(f"  {Colors.GREEN}No issues flagged.{Colors.RESET}")

        print(f"{Colors.BLUE} ⟘{Colors.RESET}")

    def save_json(self, filepath: str):
        elapsed = (datetime.now() - self.start_time).total_seconds()
        data = {
            "scan_info": {
                "target": self.target_info.get("target", ""),
                "scan_date": self.start_time.isoformat(),
                "duration_seconds": round(elapsed, 2),
                "version": self.target_info.get("version", "unknown"),
                "realms": self.target_info.get("realms", []),
            },
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f["severity"] == "critical"),
                "high": sum(1 for f in self.findings if f["severity"] == "high"),
                "medium": sum(1 for f in self.findings if f["severity"] == "medium"),
                "low": sum(1 for f in self.findings if f["severity"] == "low"),
                "info": sum(1 for f in self.findings if f["severity"] == "info"),
            },
            "findings": self.findings,
        }
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        print(f"\n{Colors.GREEN}  [+] Results saved to {filepath}{Colors.RESET}")


def init_reporter() -> Reporter:
    global _reporter
    _reporter = Reporter()
    return _reporter


def get_reporter():
    return _reporter
