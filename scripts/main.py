#!/usr/bin/env python3
import os
import subprocess
import sys
from datetime import datetime, timezone

from fetch_cves import fetch_cves
from format_issue import format_issue


def create_github_issue(title: str, body: str, repo: str) -> None:
    result = subprocess.run(
        ["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body, "--label", "cve-report"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # Label may not exist yet — retry without label
        result = subprocess.run(
            ["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body],
            capture_output=True,
            text=True,
        )
    if result.returncode != 0:
        print(f"Error creating issue:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    print(f"Issue created: {result.stdout.strip()}")


def main() -> None:
    repo = os.environ.get("GITHUB_REPO", "wj-tech/daily-cves")
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    print(f"Fetching CVEs for {date}...")
    cves = fetch_cves(days_back=1)
    print(f"Found {len(cves)} CVEs with CVSS >= 7.0")

    title, body = format_issue(cves, date)
    print(f"Creating GitHub issue: {title}")
    create_github_issue(title, body, repo)


if __name__ == "__main__":
    main()
