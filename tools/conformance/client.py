#!/usr/bin/env python3
"""Original HTTP/disk adapter for the official TUF CLI protocol.

Only I/O lives here: parsing, signature checks, role progression, delegations,
rollback and byte verification are executed by the MoonBit bridge.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / "_build/js/release/build/tools/bridge/bridge.js"


def atomic_write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".temporary")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def fetch(base, name, maximum):
    # The MoonBit core validates paths; quote per segment, preserving only '/'.
    url = base.rstrip("/") + "/" + urllib.parse.quote(name, safe="" if name.endswith(".json") else "/")
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            data = response.read(maximum + 1)
            if len(data) > maximum:
                return {"status": "failed"}
            return {"status": "present", "raw": data.hex()}
    except urllib.error.HTTPError as error:
        return {"status": "absent" if error.code in (403, 404) else "failed"}
    except (OSError, ValueError):
        return {"status": "failed"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata-dir", required=True, type=Path)
    parser.add_argument("--metadata-url", default="")
    parser.add_argument("--target-name", action="append", default=[])
    parser.add_argument("--target-base-url", default="")
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("command", choices=["init", "refresh", "download"])
    parser.add_argument("trusted_root", nargs="?", type=Path)
    args = parser.parse_args()
    store = args.metadata_dir
    store.mkdir(parents=True, exist_ok=True)
    if args.command == "init":
        atomic_write(store / "root.json", args.trusted_root.read_bytes())
        return 0
    state_path = store / "moontuf-state.bin"
    state = state_path.read_bytes() if state_path.exists() else b""
    root = bytes.fromhex(json.loads(state)["root"]) if state else (store / "root.json").read_bytes()
    request = {"root": root.hex(), "state": state.hex(),
               "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if args.command == "download":
        request["targets"] = args.target_name
    process = subprocess.Popen(["node", str(BRIDGE)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               text=True, encoding="utf-8")
    process.stdin.write(json.dumps(request) + "\n")
    process.stdin.flush()
    result = None
    for line in process.stdout:
        event = json.loads(line)
        if "fetch" in event:
            name, maximum = event["name"], min(int(event["maximum"]), 64 * 1024 * 1024)
            if event["fetch"] == "cached":
                path = args.target_dir / name
                data = path.read_bytes() if path.is_file() and path.stat().st_size <= maximum else None
                response = {"status": "present", "raw": data.hex()} if data is not None else {"status": "absent"}
            else:
                base = args.metadata_url if event["fetch"] == "metadata" else args.target_base_url
                response = fetch(base, name, maximum)
            process.stdin.write(json.dumps(response) + "\n")
            process.stdin.flush()
        elif event.get("store") == "target":
            atomic_write(args.target_dir / event["name"], bytes.fromhex(event["raw"]))
            process.stdin.write("{}\n")
            process.stdin.flush()
        else:
            result = event
    process.wait(timeout=10)
    if result is None:
        raise RuntimeError("MoonBit bridge did not return a result")
    if result.get("state"):
        state = bytes.fromhex(result["state"])
        decoded = json.loads(state)
        # A single atomic state file is authoritative. Standard role filenames
        # are projections for the conformance harness, never alternate anchors.
        atomic_write(state_path, state)
        for role in ("root", "timestamp", "snapshot", "targets"):
            file = store / (role + ".json")
            if decoded.get(role):
                atomic_write(file, bytes.fromhex(decoded[role]))
            elif role in ("timestamp", "snapshot") and not decoded.get("timestampBaseline") and not decoded.get("previousSnapshot"):
                file.unlink(missing_ok=True)
    if not result.get("ok"):
        print(result.get("error", "verification failed"), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
