"""Collect Android tests; execute the host-only procedural macro test on Linux."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

source, destination = map(Path, sys.argv[1:])
events = [json.loads(line) for line in source.read_text().splitlines()]
errors = [event["message"] for event in events if event.get("reason") == "compiler-message" and event["message"]["level"] == "error"]
if errors:
    for error in errors:
        print(error.get("rendered", error["message"]), file=sys.stderr)
    raise SystemExit("Android test compilation failed; see diagnostics above")
destination.mkdir(parents=True, exist_ok=True)
entries, host_tests = [], []
for event in events:
    if event.get("reason") != "compiler-artifact" or not event.get("profile", {}).get("test") or not event.get("executable"):
        continue
    binary = Path(event["executable"])
    data = binary.read_bytes()
    if data[:4] != b"\x7fELF":
        raise SystemExit("Test target is not an ELF executable")
    entry = {"file": binary.name, "sha256": hashlib.sha256(data).hexdigest(), "target": event["target"]["name"]}
    machine = int.from_bytes(data[18:20], "little")
    if machine == 62 and "proc-macro" in event["target"]["kind"]:
        subprocess.run([str(binary)], check=True)
        host_tests.append(entry)
    elif machine == 183:
        shutil.copy2(binary, destination / binary.name)
        entries.append(entry)
    else:
        raise SystemExit("Unexpected architecture in workspace tests")
if not entries:
    raise SystemExit("No Android test executables were produced")
(destination / "manifest.json").write_text(json.dumps(entries, indent=2) + "\n")
(destination / "host-tests.json").write_text(json.dumps(host_tests, indent=2) + "\n")
