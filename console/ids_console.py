#!/usr/bin/env python3
# =============================================================================
# File        : ids_console.py
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# Course      : 21ECC402P - Computer Communication and Network Security
# =============================================================================
# Description
# -----------
# Operator console for EVALUATING the cross-layer IDS. A small web dashboard,
# served from the Python standard library (no Flask), that launches a fixed
# catalogue of attacks and network-analysis tools against the operator's own
# robot, shows the exact command line for each, streams its output, and
# displays the live detector verdict. It is the "attacker + analyst" station;
# run it on a second laptop while Gazebo/RViz2 run on the robot laptop.
#
# Design / safety
#   - ID-BASED ONLY. The browser sends an attack *id*; the server looks the
#     command up in attacks.json and runs that. Arbitrary text from the browser
#     is never executed, so the console is a controlled test bench, not a shell.
#   - Every catalogue command targets the operator's own robot on an isolated
#     ROS_DOMAIN_ID. Intended for a closed lab network only.
#   - Each entry declares the detector layer expected to catch it, so the
#     console doubles as the cross-layer evaluation scoreboard.
#
# Live verdict
#   Background `ros2 topic echo` readers tail the detector's String topics
#   (default /physguard/status and /track/state) so the dashboard shows CLEAR /
#   INTRUSION / RECOVERING without embedding rclpy in the web process.
#
# Usage
#   python3 ids_console.py                 # serve on 0.0.0.0:8088
#   python3 ids_console.py --dry-run       # show commands, run nothing
#   python3 ids_console.py --port 9000 --status-topic /physguard/status
#   Then open http://<this-laptop-ip>:8088 from any browser on the lab network.
#
# Source the ROS 2 environment in the SAME shell before launching, so the
# console inherits ROS_DOMAIN_ID and the DDS profile:
#   source /opt/ros/humble/setup.bash
#   source ~/physguard_ws/install/setup.bash
#   source ~/physguard_ws/ids_env.sh
# =============================================================================

import argparse
import json
import os
import shlex
import signal
import subprocess
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = {
    "procs": {},        # pid -> {id, label, cmd, cat, started, rc}
    "logs": deque(maxlen=400),
    "verdict": {"status": "unknown", "track": "unknown", "xte": None, "ts": 0.0},
}
LOCK = threading.Lock()
ARGS = None
CATALOG = {}


# ---------------------------------------------------------------------------
# catalogue
# ---------------------------------------------------------------------------
def load_catalog():
    with open(os.path.join(HERE, "attacks.json")) as f:
        cat = json.load(f)
    cfg = cat.get("config", {})
    # Substitute ONLY our known {placeholders} by explicit replace. Do not use
    # str.format(): the ROS message payloads contain their own literal braces
    # (e.g. "{linear: {x: 2.5}}") which format() would try to parse as fields.
    for item in cat["attacks"] + cat["tools"]:
        resolved = item["cmd"]
        for k, v in cfg.items():
            resolved = resolved.replace("{" + k + "}", str(v))
        item["cmd_resolved"] = resolved
    cat["by_id"] = {i["id"]: i for i in cat["attacks"] + cat["tools"]}
    return cat


def log(line):
    with LOCK:
        STATE["logs"].append(f"{time.strftime('%H:%M:%S')}  {line}")


# ---------------------------------------------------------------------------
# process management
# ---------------------------------------------------------------------------
def reap(pid, item):
    p = STATE["procs"][pid]["popen"]
    for raw in iter(p.stdout.readline, ""):
        log(f"[{item['id']}] {raw.rstrip()}")
    p.wait()
    with LOCK:
        if pid in STATE["procs"]:
            STATE["procs"][pid]["rc"] = p.returncode
    log(f"[{item['id']}] exited rc={p.returncode}")


def run_attack(item):
    cmd = item["cmd_resolved"]
    if ARGS.dry_run:
        log(f"DRY-RUN {item['id']}: {cmd}")
        return {"ok": True, "dry_run": True, "cmd": cmd}
    try:
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, bufsize=1,
                             preexec_fn=os.setsid)
    except Exception as e:                       # noqa: BLE001
        log(f"FAILED to start {item['id']}: {e}")
        return {"ok": False, "error": str(e)}
    rec = {"id": item["id"], "label": item["label"], "cmd": cmd,
           "cat": item.get("cat", "Tool"), "started": time.time(),
           "rc": None, "popen": p}
    with LOCK:
        STATE["procs"][p.pid] = rec
    log(f"START {item['id']} (pid {p.pid}): {cmd}")
    threading.Thread(target=reap, args=(p.pid, item), daemon=True).start()
    return {"ok": True, "pid": p.pid, "cmd": cmd}


def stop_proc(pid):
    rec = STATE["procs"].get(pid)
    if not rec or not rec.get("popen"):
        return {"ok": False}
    try:
        os.killpg(os.getpgid(pid), signal.SIGINT)
        time.sleep(0.3)
        if rec["popen"].poll() is None:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
    except ProcessLookupError:
        pass
    log(f"STOP pid {pid} ({rec['id']})")
    return {"ok": True}


def stop_all():
    for pid in list(STATE["procs"].keys()):
        if STATE["procs"][pid].get("rc") is None:
            stop_proc(pid)
    return {"ok": True}


# ---------------------------------------------------------------------------
# live detector verdict via `ros2 topic echo`
# ---------------------------------------------------------------------------
def tail_topic(topic, key, msgtype="std_msgs/msg/String", numeric=False):
    if ARGS.dry_run:
        return
    cmd = ["ros2", "topic", "echo", "--field", "data", topic, msgtype]
    while True:
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, bufsize=1)
            for raw in iter(p.stdout.readline, ""):
                v = raw.strip().strip('"').strip("'")
                if v and v not in ("---",):
                    with LOCK:
                        STATE["verdict"][key] = round(float(v), 3) if numeric else v
                        STATE["verdict"]["ts"] = time.time()
        except Exception:                        # noqa: BLE001
            pass
        time.sleep(2.0)


# ---------------------------------------------------------------------------
# http
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):                   # quiet
        pass

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if self.path == "/api/catalog":
            pub = {"config": CATALOG["config"],
                   "attacks": [_pub(i) for i in CATALOG["attacks"]],
                   "tools": [_pub(i) for i in CATALOG["tools"]],
                   "dry_run": ARGS.dry_run}
            return self._send(200, json.dumps(pub))
        if self.path == "/api/state":
            with LOCK:
                procs = [{"pid": pid, "id": r["id"], "label": r["label"],
                          "cat": r["cat"], "cmd": r["cmd"],
                          "running": r["rc"] is None,
                          "secs": round(time.time() - r["started"])}
                         for pid, r in STATE["procs"].items()]
                out = {"procs": procs, "logs": list(STATE["logs"])[-120:],
                       "verdict": STATE["verdict"]}
            return self._send(200, json.dumps(out))
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/api/run":
            item = CATALOG["by_id"].get(body.get("id"))
            if not item:
                return self._send(404, json.dumps({"ok": False, "error": "unknown id"}))
            return self._send(200, json.dumps(run_attack(item)))
        if self.path == "/api/stop":
            return self._send(200, json.dumps(stop_proc(int(body["pid"]))))
        if self.path == "/api/stop_all":
            return self._send(200, json.dumps(stop_all()))
        return self._send(404, json.dumps({"error": "not found"}))


def _pub(i):
    return {k: i.get(k) for k in ("id", "cat", "label", "layer", "persistent",
                                  "needs", "danger", "runs_on", "desc", "cmd_resolved")}


def main():
    global ARGS, CATALOG
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--dry-run", action="store_true",
                    help="show commands, launch nothing (safe preview)")
    ap.add_argument("--status-topic", default="/physguard/status")
    ap.add_argument("--track-topic", default="/track/state")
    ap.add_argument("--xte-topic", default="/track/xte")
    ARGS = ap.parse_args()
    CATALOG = load_catalog()

    threading.Thread(target=tail_topic, args=(ARGS.status_topic, "status"),
                     daemon=True).start()
    threading.Thread(target=tail_topic, args=(ARGS.track_topic, "track"),
                     daemon=True).start()
    threading.Thread(target=tail_topic,
                     args=(ARGS.xte_topic, "xte", "std_msgs/msg/Float32", True),
                     daemon=True).start()

    mode = "DRY-RUN (nothing launches)" if ARGS.dry_run else "LIVE"
    print(f"[console] {mode}  catalogue: {len(CATALOG['attacks'])} attacks, "
          f"{len(CATALOG['tools'])} tools")
    print(f"[console] open http://<this-laptop-ip>:{ARGS.port}  (Ctrl+C to stop)")
    srv = ThreadingHTTPServer((ARGS.host, ARGS.port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[console] stopping all launched processes...")
        stop_all()


if __name__ == "__main__":
    main()
