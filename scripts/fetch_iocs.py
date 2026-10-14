#!/usr/bin/env python3
"""
ThreatFox Daily IOC Ingestion for Threat Hunting
Fetches daily indicators from abuse.ch ThreatFox filtered by specific tags:
- clickfix
- etherhiding
- c2 (or threat_type == botnet_cc)
- stealer

Saves output to:
- ../iocs/<YYYY-MM-DD>.csv
- ../iocs/<YYYY-MM-DD>.json

Automated Git Integration:
- Automatically stages and commits new CSV feeds.
- Pushes to the configured remote repository ('origin').
"""

import os
import sys
import json
import csv
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timedelta

# Configuration
API_URL = "https://threatfox-api.abuse.ch/api/v1/"
AUTH_KEY = os.environ.get("THREATFOX_AUTH_KEY", "9fd58d153e02f42d5ed3bd08544ea72c47b4ba33d0359a0c")
TARGET_TAGS = {"clickfix", "etherhiding", "c2", "stealer"}

# Organized directory paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
IOCS_DIR = os.path.join(BASE_DIR, "iocs")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

os.makedirs(IOCS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOGS_DIR, "fetch.log")
STATE_FILE = os.path.join(LOGS_DIR, "last_run.json")

def log(msg: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"Failed writing log: {e}", file=sys.stderr)

def fetch_daily_iocs(days: int = 1) -> list:
    payload = json.dumps({"query": "get_iocs", "days": days}).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Auth-Key": AUTH_KEY,
            "Content-Type": "application/json",
            "User-Agent": "ThreatHunting-DailyFetcher/1.0"
        }
    )

    log(f"Querying ThreatFox API for past {days} day(s)...")
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        log(f"HTTP error during fetch: {e}")
        raise

    status = data.get("query_status")
    if status != "ok":
        log(f"API returned non-ok status: {status}")
        return []

    return data.get("data", [])

def filter_iocs(raw_iocs: list) -> list:
    matched = []
    for item in raw_iocs:
        raw_tags = item.get("tags") or []
        normalized_tags = {t.strip().lower() for t in raw_tags if t}
        threat_type = (item.get("threat_type") or "").strip().lower()

        matched_tags = normalized_tags.intersection(TARGET_TAGS)
        
        # Threat type botnet_cc corresponds to C2
        if "c2" in TARGET_TAGS and threat_type == "botnet_cc":
            matched_tags.add("c2 (threat_type)")

        if matched_tags:
            item_copy = dict(item)
            item_copy["matched_criteria"] = sorted(list(matched_tags))
            matched.append(item_copy)

    return matched

def save_results(matched_iocs: list, date_str: str):
    json_path = os.path.join(IOCS_DIR, f"{date_str}.json")
    csv_path = os.path.join(IOCS_DIR, f"{date_str}.csv")
    latest_json = os.path.join(IOCS_DIR, "latest.json")
    latest_csv = os.path.join(IOCS_DIR, "latest.csv")

    # 1. Save JSON for date
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(matched_iocs, f, indent=2)

    # 2. Save CSV for date
    csv_columns = [
        "id", "ioc", "ioc_type", "threat_type", "malware_printable",
        "confidence_level", "first_seen", "matched_criteria", "tags",
        "reporter", "malware_malpedia", "reference"
    ]

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns, extrasaction="ignore")
        writer.writeheader()
        for item in matched_iocs:
            row = dict(item)
            row["tags"] = ", ".join(item.get("tags") or [])
            row["matched_criteria"] = ", ".join(item.get("matched_criteria") or [])
            writer.writerow(row)

    # 3. Update 'latest' references
    with open(latest_json, "w", encoding="utf-8") as f:
        json.dump(matched_iocs, f, indent=2)

    with open(latest_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns, extrasaction="ignore")
        writer.writeheader()
        for item in matched_iocs:
            row = dict(item)
            row["tags"] = ", ".join(item.get("tags") or [])
            row["matched_criteria"] = ", ".join(item.get("matched_criteria") or [])
            writer.writerow(row)

    log(f"Successfully saved {len(matched_iocs)} filtered IOCs:")
    log(f"  -> JSON: {json_path}")
    log(f"  -> CSV:  {csv_path}")

def git_commit_and_push(date_str: str):
    """Stages only CSV files, commits, and pushes to remote repository."""
    try:
        # Check if inside a git repository
        check_repo = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=BASE_DIR, capture_output=True, text=True
        )
        if check_repo.returncode != 0:
            log("Git: Not a git repository. Skipping git push.")
            return

        # Stage only CSV files in iocs/
        subprocess.run(["git", "add", "iocs/*.csv"], cwd=BASE_DIR, check=True)

        # Check if there are changes staged
        diff_res = subprocess.run(["git", "diff", "--staged", "--quiet"], cwd=BASE_DIR)
        if diff_res.returncode == 0:
            log("Git: No CSV changes detected to commit.")
            return

        # Commit changes
        commit_msg = f"Update ThreatFox IOCs: {date_str}"
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=BASE_DIR, check=True)
        log(f"Git: Committed CSV updates ({commit_msg})")

        # Check if remote 'origin' is configured
        remotes = subprocess.run(["git", "remote"], cwd=BASE_DIR, capture_output=True, text=True).stdout.split()
        if "origin" not in remotes:
            log("Git: Remote 'origin' not configured yet. Changes committed locally.")
            return

        # Get current branch
        branch_res = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=BASE_DIR, capture_output=True, text=True
        )
        branch = branch_res.stdout.strip() or "main"

        # Push to remote
        log(f"Git: Pushing CSV files to origin/{branch}...")
        push_res = subprocess.run(
            ["git", "push", "origin", branch],
            cwd=BASE_DIR, capture_output=True, text=True
        )
        if push_res.returncode == 0:
            log(f"Git: Successfully pushed to origin/{branch}")
        else:
            log(f"Git: Push failed. Output: {push_res.stderr.strip() or push_res.stdout.strip()}")

    except Exception as e:
        log(f"Git automation error: {e}")

def get_last_run_time():
    """
    Reads timestamp of the last successful run from state file,
    falling back to git commit log or file modification date.
    """
    # 1. State file check
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                ts_str = data.get("last_run_timestamp")
                if ts_str:
                    return datetime.fromisoformat(ts_str)
        except Exception as e:
            log(f"Notice: Failed reading state file {STATE_FILE}: {e}")

    # 2. Git commit history fallback
    try:
        res = subprocess.run(
            ["git", "log", "-1", "--format=%cI"],
            cwd=BASE_DIR, capture_output=True, text=True
        )
        if res.returncode == 0 and res.stdout.strip():
            return datetime.fromisoformat(res.stdout.strip())
    except Exception:
        pass

    # 3. Latest CSV file mtime fallback
    latest_csv = os.path.join(IOCS_DIR, "latest.csv")
    if os.path.exists(latest_csv):
        return datetime.fromtimestamp(os.path.getmtime(latest_csv)).astimezone()

    return None

def update_last_run(iocs_count: int, status: str = "success"):
    """Records the execution result and timestamp into STATE_FILE."""
    now_iso = datetime.now().astimezone().isoformat()
    data = {
        "last_run_timestamp": now_iso,
        "status": status,
        "iocs_count": iocs_count,
        "date": datetime.now().strftime("%Y-%m-%d")
    }
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        log(f"Warning: Failed updating {STATE_FILE}: {e}")

def should_run(force: bool = False):
    """
    Evaluates whether ingestion should run based on the daily 6:00 PM (18:00) schedule:
    - If current time < 18:00 (before 6 PM): checks if it ran for yesterday's 6 PM cycle.
      If it did not run after yesterday 18:00, it runs and pushes immediately.
    - If current time >= 18:00 (6 PM or later): checks if it ran for today's 6 PM cycle.
      If it did not run after today 18:00, it runs and pushes.
    - If already run for the expected cycle, skips gracefully.
    """
    if force:
        return True, "Forced execution flag passed (--force)."

    now = datetime.now().astimezone()

    # Determine cutoff milestone (the most recent 6:00 PM that should have executed)
    if now.hour >= 18:
        # Today at or past 18:00 -> cutoff is today at 18:00
        cutoff = now.replace(hour=18, minute=0, second=0, microsecond=0)
        milestone = "today's 6:00 PM milestone"
    else:
        # Current time is not yet 6:00 PM today -> cutoff is yesterday at 18:00
        cutoff = (now - timedelta(days=1)).replace(hour=18, minute=0, second=0, microsecond=0)
        milestone = "yesterday's 6:00 PM milestone"

    last_run = get_last_run_time()
    if last_run is None:
        return True, "No record of previous run found. Ingestion required."

    # Normalize timezone for comparison
    if last_run.tzinfo is None:
        last_run = last_run.replace(tzinfo=now.tzinfo)

    if last_run < cutoff:
        return True, (
            f"Last run was {last_run.strftime('%Y-%m-%d %H:%M:%S')}, which is before "
            f"{milestone} ({cutoff.strftime('%Y-%m-%d %H:%M:%S')}). Need to catch up and push."
        )
    else:
        return False, (
            f"Already ran at {last_run.strftime('%Y-%m-%d %H:%M:%S')} (after "
            f"{milestone} at {cutoff.strftime('%Y-%m-%d %H:%M:%S')}). Skipping."
        )

def main():
    force = "--force" in sys.argv
    run_needed, reason = should_run(force=force)

    log(f"Schedule check: {reason}")
    if not run_needed:
        log("Execution skipped: condition for scheduled run is satisfied.")
        return

    date_str = datetime.now().strftime("%Y-%m-%d")
    log("=== Starting ThreatFox Daily Ingestion ===")
    try:
        raw_iocs = fetch_daily_iocs(days=1)
        log(f"Fetched {len(raw_iocs)} total raw IOCs from ThreatFox.")

        matched = filter_iocs(raw_iocs)
        log(f"Filtered {len(matched)} IOCs matching target tags ({', '.join(sorted(TARGET_TAGS))}).")

        save_results(matched, date_str)
        git_commit_and_push(date_str)
        update_last_run(len(matched), status="success")
        log("=== Ingestion Complete ===")
    except Exception as e:
        log(f"ERROR: Execution failed: {e}")
        update_last_run(0, status=f"failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
