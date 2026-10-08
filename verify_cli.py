"""Reproduce end-to-end CLI checks without storing wealth or difference values."""
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    environment = {**os.environ, "PYTHONUTF8": "1"}
    checks = []
    cases = [(7, 4, "Alice 更富有"), (4, 7, "Bob 更富有"), (5, 5, "双方财富相等")]
    for alice, bob, label in cases:
        process = subprocess.run(
            [sys.executable, "main.py", "--alice", str(alice), "--bob", str(bob),
             "--domain", "10", "--scheme", "both"],
            capture_output=True, text=True, encoding="utf-8", env=environment)
        checks.append({"expected": label,
                       "success": process.returncode == 0 and process.stdout.strip().splitlines()
                       == ["original: " + label, "ot: " + label]})
    process = subprocess.run(
        [sys.executable, "main.py", "--alice", "7", "--bob", "4", "--scheme", "ot", "--metrics"],
        capture_output=True, text=True, encoding="utf-8", env=environment)
    lines = process.stdout.strip().splitlines()
    metrics_ok = False
    if process.returncode == 0 and len(lines) == 2:
        try:
            metrics = json.loads(lines[1])
            metrics_ok = (lines[0] == "ot: Alice 更富有" and metrics["scheme"] == "ot"
                          and metrics["messages"] == 4 and metrics["bytes"] > 0)
        except (ValueError, KeyError):
            pass
    checks.append({"expected": "OT public metrics", "success": metrics_ok})
    process = subprocess.run(
        [sys.executable, "main.py", "--alice", "0", "--bob", "4"],
        capture_output=True, text=True, encoding="utf-8", env=environment)
    checks.append({"expected": "reject out-of-domain input",
                   "success": process.returncode != 0 and "wealth must be" in process.stderr})
    out = Path("results")
    out.mkdir(exist_ok=True)
    (out / "cli_checks.json").write_text(json.dumps(checks, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"checks": len(checks), "passed": sum(c["success"] for c in checks)}))
    if not all(c["success"] for c in checks):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
