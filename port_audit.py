"""Compare a declared port plan with what is actually listening on this machine. Read-only.

    python port_audit.py --plan ports.example.json
    python port_audit.py --plan ports.example.json --json

Each planned port is reported as OK (listening), DOWN (planned but nothing listens) or
CONFLICT (listening, but the process name does not match the plan). Any listener inside
the managed range that is not in the plan is reported as UNPLANNED.
Exit code is 1 when anything is DOWN, CONFLICT or UNPLANNED, so it can run as a scheduled check.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
from pathlib import Path
import re
import subprocess
import sys

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
NETSTAT_LINE = re.compile(r"^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)", re.I)
SS_LINE = re.compile(r"^LISTEN\s+\d+\s+\d+\s+(\S+):(\d+)\s+\S+(?:\s+users:\(\(\"([^\"]+)\",pid=(\d+))?")


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=60,
                              creationflags=NO_WINDOW).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def parse_netstat(text: str) -> dict[int, dict]:
    """Parse `netstat -ano -p TCP` output (Windows) into port -> {pid, address}."""
    found: dict[int, dict] = {}
    for line in text.splitlines():
        m = NETSTAT_LINE.match(line)
        if m:
            found.setdefault(int(m.group(2)), {"pid": int(m.group(3)), "address": m.group(1), "process": None})
    return found


def parse_ss(text: str) -> dict[int, dict]:
    """Parse `ss -ltnpH` output (Linux) into port -> {pid, address, process}."""
    found: dict[int, dict] = {}
    for line in text.splitlines():
        m = SS_LINE.match(line.strip())
        if m:
            pid = int(m.group(4)) if m.group(4) else None
            found.setdefault(int(m.group(2)), {"pid": pid, "address": m.group(1), "process": m.group(3)})
    return found


def parse_tasklist(text: str) -> dict[int, str]:
    """Parse `tasklist /FO CSV /NH` into pid -> image name."""
    names = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 2 and row[1].isdigit():
            names[int(row[1])] = row[0]
    return names


def listeners() -> dict[int, dict]:
    if sys.platform == "win32":
        found = parse_netstat(_run(["netstat", "-ano", "-p", "TCP"]))
        names = parse_tasklist(_run(["tasklist", "/FO", "CSV", "/NH"]))
        for row in found.values():
            row["process"] = names.get(row["pid"])
        return found
    return parse_ss(_run(["ss", "-ltnpH"]))


def audit(plan: dict, live: dict[int, dict]) -> list[dict]:
    low, high = plan.get("range", [0, 65535])
    planned = {int(p): row for p, row in plan.get("ports", {}).items()}
    rows = []
    for port in sorted(planned):
        want = planned[port]
        got = live.get(port)
        if not got:
            status = "DOWN"
        elif want.get("process") and got.get("process") and want["process"].lower() != got["process"].lower():
            status = "CONFLICT"
        else:
            status = "OK"
        rows.append({"port": port, "status": status, "name": want.get("name", ""),
                     "expected": want.get("process"), "pid": got and got["pid"], "process": got and got["process"]})
    for port in sorted(live):
        if low <= port <= high and port not in planned:
            got = live[port]
            rows.append({"port": port, "status": "UNPLANNED", "name": "", "expected": None,
                         "pid": got["pid"], "process": got["process"]})
    return rows


def render(rows: list[dict]) -> str:
    out = [f"{'PORT':>6}  {'STATUS':<9}  {'NAME':<16}  {'PID':>7}  PROCESS"]
    for r in rows:
        out.append(f"{r['port']:>6}  {r['status']:<9}  {r['name']:<16}  {r['pid'] or '-':>7}  {r['process'] or '-'}")
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    out.append("summary: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--plan", required=True, help="JSON port plan")
    ap.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = ap.parse_args(argv)
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    rows = audit(plan, listeners())
    print(json.dumps(rows, indent=1) if args.json else render(rows))
    return 1 if any(r["status"] != "OK" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
