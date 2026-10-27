"""Collect only executable Android workspace test targets, with a private-data-free manifest."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
source, destination = map(Path, sys.argv[1:])
destination.mkdir(parents=True, exist_ok=True)
entries = []
for line in source.read_text().splitlines():
    event = json.loads(line)
    if event.get("reason") != "compiler-artifact" or not event.get("profile", {}).get("test") or not event.get("executable"):
        continue
    binary = Path(event["executable"])
    target = destination / binary.name
    shutil.copy2(binary, target)
    entries.append({"file": binary.name, "sha256": hashlib.sha256(target.read_bytes()).hexdigest(), "target": event["target"]["name"]})
if not entries:
    raise SystemExit("No Android test executables were produced")
(destination / "manifest.json").write_text(json.dumps(entries, indent=2) + "\n")
