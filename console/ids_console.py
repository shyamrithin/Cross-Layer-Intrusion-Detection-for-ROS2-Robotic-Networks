#!/usr/bin/env python3
# =============================================================================
# File        : ids_console.py
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# Course      : 21ECC402P - Computer Communication and Network Security
# Version     : 2.0
# =============================================================================
# Description
# -----------
# Back end of the IDS Monitor: an analyst workstation for evaluating the
# cross-layer IDS. Python standard library only (no Flask, no build step).
#
# What it does
#   * Launches a fixed catalogue of attacks and tools (attacks.json) by ID.
#     The browser never sends a command line, only an ID, so this is a
#     controlled test bench and not a remote shell.
#   * Follows the detector and the bench through `ros2 topic echo` readers
#     (no rclpy inside the web process):
#         /physguard/telemetry  full detector state (JSON, 20 Hz)
#         /track/xte            cross-track error from the TRUE pose (Gazebo)
#         /sim/odom_error       wheel-odometry drift (Gazebo bench)
#         /attack/mode          attacker mode, for episode bookkeeping
#   * Keeps a time-series history (10 min at 20 Hz) that the UI streams
#     incrementally for its live charts.
#   * Runs the tshark wire collector on demand and turns its per-second output
#     into DDS traffic series (packets, user data, endpoint announcements).
#   * Builds a structured event log (detector alarms, blocks, releases,
#     publisher changes, wire alerts, attacker launches) from state edges.
#   * Scores every attack episode: detection latency, layer, blocked or not,
#     peak deviation from the track, recovery time. This is the safety-on vs
#     safety-off table.
#   * Detector controls: safety filter, network layer, physics layer, set
#     through `ros2 param set /physguard ...` (fixed whitelist of names).
#   * Recording: every sample to logs/session_<time>.csv while recording is on;
#     the in-memory history and the episode table export as CSV at any time.
#
# Modes
#   python3 ids_console.py              live (needs the ROS 2 env sourced)
#   python3 ids_console.py --dry-run    show commands, launch nothing
#   python3 ids_console.py --demo       synthetic detector + traffic feed, for
#                                       previewing the UI without ROS or Gazebo
#
# HTTP API
#   GET  /                       the UI
#   GET  /api/catalog            attack/tool catalogue
#   GET  /api/state?s=&w=&e=     incremental: samples after s, wire after w,
#                                events after seq e, plus current state
#   GET  /api/export.csv         sample history as CSV
#   GET  /api/episodes.csv       episode table as CSV
#   POST /api/run {id}           launch catalogue entry
#   POST /api/stop {pid}         stop one process      POST /api/stop_all
#   POST /api/param {name,value} safety_enabled | net_enabled | phy_enabled
#   POST /api/capture {on}       start/stop the wire collector
#   POST /api/record {on}        start/stop CSV recording
#   POST /api/clear              clear charts, events and episodes
#
# Source the ROS 2 environment in the SAME shell before launching (the `ids
# console` helper does this), so the console shares ROS_DOMAIN_ID and the
# DDS profile with the bench.
# =============================================================================

import argparse
import csv
import io
import json
import math
import os
import random
import re
import signal
import subprocess
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(HERE, "logs")
LOCK = threading.RLock()
ARGS = None
CATALOG = {}

PARAMS = ("safety_enabled", "net_enabled", "phy_enabled")
SAMPLE_COLS = ["ts", "r", "eps", "S", "tau", "wv", "ww", "av", "aw", "mv", "mw",
               "alarm", "net", "phy", "safe", "eng", "cal", "xte", "derr", "atk"]
WIRE_RE = re.compile(r"pkts/s=\s*([\d.]+)\s+disc/s=\s*([\d.]+)\s+sedp/s=\s*([\d.]+)\s+"
                     r"data/s=\s*([\d.]+)\s+part=\s*(\d+)\s+writers=(\d+)")
WIRE_EVT_RE = re.compile(r"^\s*(!!|ok)?\s*((?:ALERT|CLEARED|NEW|PARTICIPANT|TARGET)_[A-Z_]+)\s*(.*)$")
NOISE_RE = re.compile(r"^(publishing #\d+|publisher: beginning loop)")


class Store:
    """All shared state. Guarded by LOCK."""

    def __init__(self):
        self.samples = deque(maxlen=12000)     # 10 min at 20 Hz
        self.wire = deque(maxlen=1200)         # 20 min at 1 Hz
        self.events = deque(maxlen=3000)
        self.seq = 0
        self.procs = {}                        # pid -> record
        self.tele = {}
        self.tele_ts = 0.0
        self.xte = None
        self.derr = None
        self.mode = "none"
        self.episodes = []
        self.ep = None                         # open episode
        self.prev = {}                         # previous telemetry, for edges
        self.rec_fh = None
        self.rec_w = None
        self.rec_path = None
        self.capture_pid = None
        self.demo_procs = 0


S = Store()


# ---------------------------------------------------------------------------
# events
# ---------------------------------------------------------------------------
def event(src, msg, sev="info", layer="", detail=""):
    """sev: info | ok | warn | alert | sys"""
    with LOCK:
        S.seq += 1
        S.events.append({"seq": S.seq, "ts": time.time(), "src": src, "layer": layer,
                         "sev": sev, "msg": msg, "detail": detail})


# ---------------------------------------------------------------------------
# catalogue
# ---------------------------------------------------------------------------
def load_catalog():
    with open(os.path.join(HERE, "attacks.json")) as f:
        cat = json.load(f)
    cfg = cat.setdefault("config", {})
    cfg.setdefault("wire_py", find_wire_collector())
    # Only our known {placeholders}, by explicit replace: ROS message payloads
    # contain literal braces that str.format() would try to parse.
    for item in cat["attacks"] + cat["tools"]:
        resolved = item["cmd"]
        for k, v in cfg.items():
            resolved = resolved.replace("{" + k + "}", str(v))
        item["cmd_resolved"] = resolved
    cat["by_id"] = {i["id"]: i for i in cat["attacks"] + cat["tools"]}
    return cat


def find_wire_collector():
    for p in (os.path.join(HERE, "..", "src", "physguard", "tools", "wire_collector.py"),
              os.path.expanduser("~/physguard_ws/install/physguard/share/physguard/tools/wire_collector.py"),
              os.path.expanduser("~/physguard_ws/src/physguard/tools/wire_collector.py")):
        if os.path.isfile(p):
            return os.path.abspath(p)
    return "wire_collector.py"


def pub_item(i):
    return {k: i.get(k) for k in ("id", "cat", "label", "layer", "persistent", "needs",
                                  "danger", "runs_on", "desc", "method", "cmd_resolved",
                                  "target")}


# ---------------------------------------------------------------------------
# processes
# ---------------------------------------------------------------------------
def attack_running():
    return any(r["rc"] is None and r["cat"] != "Tool" for r in S.procs.values())


def handle_wire_line(line):
    m = WIRE_RE.search(line)
    if m:
        pk, disc, sedp, data, part, writers = m.groups()
        flags = line[m.end():].strip()
        with LOCK:
            S.wire.append({"ts": time.time(), "pkts": float(pk), "disc": float(disc),
                           "sedp": float(sedp), "data": float(data), "part": int(part),
                           "writers": int(writers), "alert": 1 if "[" in flags else 0})
        return True
    m = WIRE_EVT_RE.match(line)
    if m:
        kind, rest = m.group(2), m.group(3).strip()
        sev = "alert" if kind.startswith("ALERT") else ("ok" if kind.startswith("CLEARED") else "info")
        event("wire", f"{kind} {rest}".strip(), sev, "NET" if sev == "alert" else "")
        return True
    return False


def reap(pid, item):
    rec = S.procs[pid]
    p = rec["popen"]
    budget, window = 0, time.time()
    for raw in iter(p.stdout.readline, ""):
        line = raw.rstrip()
        if not line or NOISE_RE.match(line):
            continue
        if item["id"] == "t_capture" and handle_wire_line(line):
            continue
        now = time.time()                       # rate-limit chatty tools
        if now - window > 1.0:
            budget, window = 0, now
        budget += 1
        if budget <= 4:
            event(item["id"], line, "sys")
    p.wait()
    with LOCK:
        rec["rc"] = p.returncode
        if S.capture_pid == pid:
            S.capture_pid = None
    event("launcher", f"{item['label']} exited (rc={p.returncode})",
          "warn" if p.returncode not in (0, -2, -15, 130) else "sys")


def run_item(item):
    cmd = item["cmd_resolved"]
    cat = item.get("cat", "Tool")
    if ARGS.dry_run:
        event("launcher", f"DRY-RUN {item['label']}: {cmd}", "sys")
        return {"ok": True, "dry_run": True, "cmd": cmd}
    if ARGS.demo:
        with LOCK:
            S.demo_procs += 1
            pid = 900000 + S.demo_procs
            S.procs[pid] = {"id": item["id"], "label": item["label"], "cmd": cmd, "cat": cat,
                            "layer": item.get("layer", "none"), "started": time.time(),
                            "rc": None, "popen": None}
            if item["id"] == "t_capture":
                S.capture_pid = pid
        event("launcher", f"START {item['label']}", "info",
              detail=f"pid {pid} (demo)\n{cmd}")
        return {"ok": True, "pid": pid, "cmd": cmd}
    try:
        env = dict(os.environ, PYTHONUNBUFFERED="1")
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1, preexec_fn=os.setsid, cwd=HERE, env=env)
    except Exception as e:                       # noqa: BLE001
        event("launcher", f"FAILED to start {item['label']}: {e}", "warn")
        return {"ok": False, "error": str(e)}
    with LOCK:
        S.procs[p.pid] = {"id": item["id"], "label": item["label"], "cmd": cmd, "cat": cat,
                          "layer": item.get("layer", "none"), "started": time.time(),
                          "rc": None, "popen": p}
        if item["id"] == "t_capture":
            S.capture_pid = p.pid
    event("launcher", f"START {item['label']}", "info", detail=f"pid {p.pid}\n{cmd}")
    threading.Thread(target=reap, args=(p.pid, item), daemon=True).start()
    return {"ok": True, "pid": p.pid, "cmd": cmd}


def stop_proc(pid):
    rec = S.procs.get(pid)
    if not rec or rec["rc"] is not None:
        return {"ok": False}
    if rec["popen"] is None:                     # demo process
        with LOCK:
            rec["rc"] = 0
            if S.capture_pid == pid:
                S.capture_pid = None
        event("launcher", f"STOP {rec['label']}", "sys")
        return {"ok": True}
    try:
        os.killpg(os.getpgid(pid), signal.SIGINT)
        time.sleep(0.3)
        if rec["popen"].poll() is None:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
    except ProcessLookupError:
        pass
    event("launcher", f"STOP {rec['label']}", "sys")
    return {"ok": True}


def stop_all(include_tools=True):
    for pid, rec in list(S.procs.items()):
        if rec["rc"] is None and (include_tools or rec["cat"] != "Tool"):
            stop_proc(pid)
    return {"ok": True}


# ---------------------------------------------------------------------------
# detector controls
# ---------------------------------------------------------------------------
def set_param(name, value):
    if name not in PARAMS:
        return {"ok": False, "error": "unknown parameter"}
    val = "true" if value else "false"
    if ARGS.demo:
        DEMO[name] = bool(value)
        return {"ok": True}
    if ARGS.dry_run:
        event("control", f"DRY-RUN ros2 param set /physguard {name} {val}", "sys")
        return {"ok": True}

    def work():
        try:
            out = subprocess.run(["ros2", "param", "set", "/physguard", name, val],
                                 capture_output=True, text=True, timeout=15)
            txt = (out.stdout + out.stderr).strip()
            if out.returncode != 0 or "failed" in txt.lower():
                event("control", f"could not set {name}={val}: {txt}", "warn")
        except Exception as e:                   # noqa: BLE001
            event("control", f"could not set {name}={val}: {e}", "warn")
    threading.Thread(target=work, daemon=True).start()
    event("control", f"requested {name} = {val}", "sys",
          detail=f"ros2 param set /physguard {name} {val}")
    return {"ok": True}


def set_capture(on):
    with LOCK:
        running = S.capture_pid is not None
    if on and not running:
        item = CATALOG["by_id"].get("t_capture")
        if not item:
            return {"ok": False, "error": "t_capture missing from attacks.json"}
        return run_item(item)
    if not on and running:
        return stop_proc(S.capture_pid)
    return {"ok": True}


def set_record(on):
    with LOCK:
        if on and S.rec_fh is None:
            os.makedirs(LOG_DIR, exist_ok=True)
            S.rec_path = os.path.join(LOG_DIR, time.strftime("session_%Y%m%d_%H%M%S.csv"))
            S.rec_fh = open(S.rec_path, "w", newline="")
            S.rec_w = csv.writer(S.rec_fh)
            S.rec_w.writerow(SAMPLE_COLS + ["mode"])
            path = S.rec_path
        elif not on and S.rec_fh is not None:
            S.rec_fh.close()
            path, S.rec_fh, S.rec_w = S.rec_path, None, None
        else:
            return {"ok": True}
    event("recorder", ("recording to " if on else "recording saved: ") + path,
          "ok" if not on else "info")
    return {"ok": True, "path": path}


# ---------------------------------------------------------------------------
# sample pipeline: one call per telemetry message
# ---------------------------------------------------------------------------
def ingest(t):
    now = time.time()
    with LOCK:
        S.tele, S.tele_ts = t, now
        atk = S.mode not in ("none", "") or attack_running()
        smp = {
            "ts": round(now, 3),
            "r": t.get("residual", 0.0), "eps": t.get("eps", 0.0),
            "S": t.get("cusum", 0.0), "tau": t.get("cusum_tau", 3.0),
            "wv": (t.get("wire") or [0, 0])[0], "ww": (t.get("wire") or [0, 0])[1],
            "av": (t.get("auth") or [0, 0])[0], "aw": (t.get("auth") or [0, 0])[1],
            "mv": (t.get("meas") or [0, 0])[0], "mw": (t.get("meas") or [0, 0])[1],
            "alarm": int(bool(t.get("alarm"))), "net": int(bool(t.get("net_fired"))),
            "phy": int(bool(t.get("phy_fired"))), "safe": int(t.get("safety_enabled", True)),
            "eng": int(bool(t.get("safety_engaged"))), "cal": int(bool(t.get("calibrating"))),
            "xte": S.xte, "derr": S.derr, "atk": int(atk),
        }
        for k in ("wv", "ww", "av", "aw", "mv", "mw"):     # NaN/inf attacks
            if not isinstance(smp[k], (int, float)) or not math.isfinite(smp[k]):
                smp[k] = None
        S.samples.append(smp)
        if S.rec_w:
            S.rec_w.writerow([smp[c] if smp[c] is not None else "" for c in SAMPLE_COLS]
                             + [S.mode])
        prev = S.prev
        S.prev = dict(t)
    edges(prev, t, smp)
    episodes(smp, t)


def layers_of(t):
    return "+".join(x for x, k in (("NET", "net_fired"), ("PHY", "phy_fired")) if t.get(k))


def edges(prev, t, smp):
    if not prev:
        event("detector", "telemetry stream connected", "sys")
        return
    for k, label in (("safety_enabled", "Safety filter"), ("net_enabled", "Network layer"),
                     ("phy_enabled", "Physics layer")):
        if k in prev and prev.get(k) != t.get(k):
            event("control", f"{label} {'enabled' if t.get(k) else 'disabled'}",
                  "ok" if t.get(k) else "warn")
    if prev.get("calibrating") and not t.get("calibrating"):
        event("detector", f"IDS armed, threshold ε = {t.get('eps', 0):.4f}", "ok",
              detail="threshold learned from benign data: mean + 3σ of the residual")
    if t.get("alarm") and not prev.get("alarm"):
        why = "; ".join(t.get("reasons") or []) or "[LATCH] latched"
        lay = layers_of(t)
        event("detector", f"INTRUSION {why}", "alert", lay,
              detail="\n".join(t.get("reasons") or []))
        if t.get("safety_enabled"):
            event("safety", "BLOCKED — forwarding the authorized command", "alert", lay)
        else:
            event("safety", "NOT BLOCKED — safety filter is off, wire reaches the motors",
                  "warn", lay)
    if prev.get("alarm") and not t.get("alarm"):
        event("detector", "wire consistent again, safety filter released", "ok")
    a, b = set(prev.get("publishers") or []), set(t.get("publishers") or [])
    allow = set(t.get("allowlist") or [])
    for n in sorted(b - a):
        if n in allow:
            event("graph", f"publisher joined /cmd_vel_raw: {n} (allowlisted)", "info")
        else:
            event("graph", f"ROGUE publisher on /cmd_vel_raw: {n}", "warn", "NET")
    for n in sorted(a - b):
        event("graph", f"publisher left /cmd_vel_raw: {n}", "sys")


def ep_label():
    names = [r["label"] for r in S.procs.values() if r["rc"] is None and r["cat"] != "Tool"]
    if S.mode not in ("none", ""):
        names.insert(0, f"injector: {S.mode}")
    return ", ".join(names) or "attack"


def episodes(smp, t):
    with LOCK:
        ep = S.ep
        if smp["atk"] and ep is None and not smp["cal"]:
            S.ep = ep = {"n": len(S.episodes) + 1, "attack": ep_label(), "t0": smp["ts"],
                         "safety": bool(smp["safe"]), "t_det": None, "layer": "",
                         "t_end": None, "peak": 0.0, "back": None, "blocked": None}
        if ep is None:
            return
        if smp["xte"] is not None:
            ep["peak"] = max(ep["peak"], abs(smp["xte"]))
        if smp["alarm"] and ep["t_det"] is None:
            ep["t_det"] = smp["ts"]
            ep["layer"] = layers_of(t)
            ep["blocked"] = bool(smp["safe"])
        if not smp["atk"] and ep["t_end"] is None:
            ep["t_end"] = smp["ts"]
        done = False
        if ep["t_end"] is not None:
            ok = not smp["alarm"] and (smp["xte"] is None or abs(smp["xte"]) < 0.05)
            if ok:
                ep["back"] = ep["back"] or smp["ts"]
                done = smp["ts"] - ep["back"] >= 1.0
            else:
                ep["back"] = None
            done = done or smp["ts"] - ep["t_end"] > 30.0
        if done:
            row = {"n": ep["n"], "attack": ep["attack"], "safety": ep["safety"],
                   "detected": ep["t_det"] is not None,
                   "latency": round(ep["t_det"] - ep["t0"], 2) if ep["t_det"] else None,
                   "layer": ep["layer"], "blocked": ep["blocked"],
                   "peak": round(ep["peak"], 3),
                   "recovery": round(ep["back"] - ep["t_end"], 2) if ep["back"] else None,
                   "t0": ep["t0"]}
            S.episodes.append(row)
            S.ep = None
    if done:
        lat = f"{row['latency']:.2f} s" if row["detected"] else "MISSED"
        event("scorer", f"episode #{row['n']} {row['attack']}: detection {lat}, peak "
              f"deviation {row['peak']:.3f} m, safety {'on' if row['safety'] else 'off'}",
              "ok" if row["detected"] else "warn")


# ---------------------------------------------------------------------------
# ROS readers (live mode)
# ---------------------------------------------------------------------------
def echo_lines(topic, msgtype):
    cmd = ["ros2", "topic", "echo", "--field", "data", topic, msgtype]
    while True:
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 text=True, bufsize=1)
            for raw in iter(p.stdout.readline, ""):
                line = raw.strip()
                if line and line != "---":
                    yield line
        except Exception:                        # noqa: BLE001
            pass
        time.sleep(2.0)


def tail_telemetry(topic):
    for line in echo_lines(topic, "std_msgs/msg/String"):
        i, j = line.find("{"), line.rfind("}")
        if i < 0 or j <= i:
            continue
        frag = line[i:j + 1]
        for cand in (frag, frag.replace("''", "'"), frag.replace('\\"', '"')):
            try:
                obj = json.loads(cand)
            except Exception:                    # noqa: BLE001
                continue
            ingest(obj)
            break


def tail_float(topic, attr):
    for line in echo_lines(topic, "std_msgs/msg/Float32"):
        try:
            with LOCK:
                setattr(S, attr, round(float(line), 4))
        except ValueError:
            pass


def tail_mode(topic):
    for line in echo_lines(topic, "std_msgs/msg/String"):
        v = line.strip("'\"")
        with LOCK:
            old, S.mode = S.mode, v
        if v != old:
            event("attacker", f"injector mode: {old} → {v}",
                  "warn" if v != "none" else "info")


# ---------------------------------------------------------------------------
# demo feed: a believable detector + bench, driven by the UI's own controls
# ---------------------------------------------------------------------------
DEMO = {"safety_enabled": True, "net_enabled": True, "phy_enabled": True}


def demo_loop():
    """Synthetic telemetry at 20 Hz and wire metrics at 1 Hz. Launching a
    physics-layer attack raises the residual and CUSUM; a network-layer attack
    adds a rogue publisher and DDS churn. With the safety filter off, the
    robot leaves the track. Only for previewing the UI."""
    t0 = time.time()
    eps, S_, xte, drift, latch, quiet = 0.019, 0.0, 0.0, 0.0, False, 0.0
    disc_t = 0.0
    while True:
        time.sleep(0.05)
        now = time.time()
        t = now - t0
        cal = t < 8.0
        with LOCK:
            live = [r for r in S.procs.values() if r["rc"] is None and r["cat"] != "Tool"]
        phy_atk = any(r["layer"] == "physics" for r in live)
        net_atk = any(r["layer"] == "network" for r in live)
        av = 0.35
        aw = 0.0 if math.sin(t * 0.2) > 0 else 0.175
        wv, ww = av, aw
        if phy_atk:
            wv, ww = av + 0.05, aw + 0.9
        mv = wv + random.gauss(0, 0.004)
        mw = ww + random.gauss(0, 0.006)
        r = abs(random.gauss(0.006, 0.003)) + (0.06 + random.gauss(0, 0.01) if phy_atk else 0)
        S_ = min(6.0, max(0.0, S_ + (r - eps) * 8.0))
        net_f = net_atk and DEMO["net_enabled"]
        phy_f = (r > eps or S_ > 3.0) and DEMO["phy_enabled"] and not cal and phy_atk
        fired = net_f or phy_f
        if fired:
            latch, quiet = True, 0.0
        elif latch:
            quiet += 0.05
            if quiet >= 3.0:
                latch = False
        blocked = latch and DEMO["safety_enabled"]
        target = 0.0 if (blocked or not phy_atk) else 1.8
        xte += (target - xte) * (0.02 if target else 0.05) + random.gauss(0, 0.002)
        drift = min(0.04, drift + abs(random.gauss(0, 0.0002)))
        pubs = ["/pure_pursuit"] + (["/attack_injector"] if live else [])
        reasons = []
        if net_f:
            reasons.append("[NET] unauthorized publisher: /attack_injector")
        if phy_f:
            reasons.append(f"[PHY] CUSUM {S_:.2f} over limit")
        with LOCK:
            S.xte, S.derr = round(xte, 4), round(drift, 4)
        ingest({"t": round(t, 2), "armed": not cal, "calibrating": cal,
                "calib_remaining": round(max(0, 8 - t), 1), "eps": eps, "residual": round(r, 5),
                "cusum": round(S_, 4), "cusum_tau": 3.0, "cusum_clip": 6.0,
                "net_enabled": DEMO["net_enabled"], "phy_enabled": DEMO["phy_enabled"],
                "net_fired": net_f, "phy_fired": phy_f, "fused": fired, "alarm": latch,
                "safety_enabled": DEMO["safety_enabled"], "safety_engaged": latch,
                "safety_quiet": round(quiet, 2), "release_s": 3.0,
                "churn": 8.0 if net_atk else 0.0, "churn_thresh": 5.0,
                "publishers": pubs, "allowlist": ["/pure_pursuit", "/patrol_controller"],
                "wire": [wv, ww], "auth": [av, aw], "meas": [mv, mw], "reasons": reasons})
        with LOCK:
            capturing = S.capture_pid is not None
        if capturing and now - disc_t >= 1.0:
            disc_t = now
            base = 140 + random.gauss(0, 6)
            handle_wire_line(
                f"pkts/s={base + (420 if net_atk else 0) + (80 if phy_atk else 0):6.1f}  "
                f"disc/s={2 + random.random():5.1f}  sedp/s={(60 if net_atk else 0.4):5.1f}  "
                f"data/s={60 + (100 if live else 0):5.1f}  part= 9  writers={2 if live else 1}"
                + ("  [ENDPOINT_CHURN]" if net_atk else ""))


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def state_payload(q):
    s_after = float(q.get("s", ["0"])[0] or 0)
    w_after = float(q.get("w", ["0"])[0] or 0)
    e_after = int(q.get("e", ["0"])[0] or 0)
    now = time.time()
    with LOCK:
        if s_after <= 0:
            s_after = now - 120.0
        if w_after <= 0:
            w_after = now - 600.0
        samples = [x for x in S.samples if x["ts"] > s_after][-3000:]
        wire = [x for x in S.wire if x["ts"] > w_after]
        events = [x for x in S.events if x["seq"] > e_after][-500:]
        procs = [{"pid": pid, "id": r["id"], "label": r["label"], "cat": r["cat"],
                  "layer": r["layer"], "cmd": r["cmd"], "running": r["rc"] is None,
                  "secs": round(now - r["started"])}
                 for pid, r in S.procs.items() if r["rc"] is None]
        return {"now": now, "samples": samples, "wire": wire, "events": events,
                "procs": procs, "tele": S.tele, "tele_age": round(now - S.tele_ts, 2)
                if S.tele_ts else None, "xte": S.xte, "derr": S.derr, "mode": S.mode,
                "episodes": S.episodes[-50:], "open_episode": bool(S.ep),
                "recording": S.rec_path if S.rec_fh else None,
                "capturing": S.capture_pid is not None,
                "flags": {"dry_run": ARGS.dry_run, "demo": ARGS.demo}}


def csv_text(rows, cols):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow(["" if r.get(c) is None else r.get(c) for c in cols])
    return buf.getvalue()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):                   # quiet
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if u.path == "/app.js":
            with open(os.path.join(HERE, "app.js"), "rb") as f:
                return self._send(200, f.read(), "application/javascript; charset=utf-8")
        if u.path == "/api/catalog":
            pub = {"config": {k: v for k, v in CATALOG["config"].items()},
                   "attacks": [pub_item(i) for i in CATALOG["attacks"]],
                   "tools": [pub_item(i) for i in CATALOG["tools"]],
                   "flags": {"dry_run": ARGS.dry_run, "demo": ARGS.demo}}
            return self._send(200, json.dumps(pub))
        if u.path == "/api/state":
            return self._send(200, json.dumps(state_payload(q)))
        if u.path == "/api/export.csv":
            with LOCK:
                rows = list(S.samples)
            name = time.strftime("ids_samples_%Y%m%d_%H%M%S.csv")
            return self._send(200, csv_text(rows, SAMPLE_COLS), "text/csv",
                              {"Content-Disposition": f'attachment; filename="{name}"'})
        if u.path == "/api/episodes.csv":
            with LOCK:
                rows = list(S.episodes)
            cols = ["n", "attack", "safety", "detected", "latency", "layer", "blocked",
                    "peak", "recovery", "t0"]
            name = time.strftime("ids_episodes_%Y%m%d_%H%M%S.csv")
            return self._send(200, csv_text(rows, cols), "text/csv",
                              {"Content-Disposition": f'attachment; filename="{name}"'})
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, json.dumps({"ok": False, "error": "bad json"}))
        p = urlparse(self.path).path
        if p == "/api/run":
            item = CATALOG["by_id"].get(body.get("id"))
            if not item:
                return self._send(404, json.dumps({"ok": False, "error": "unknown id"}))
            return self._send(200, json.dumps(run_item(item)))
        if p == "/api/stop":
            return self._send(200, json.dumps(stop_proc(int(body.get("pid", 0)))))
        if p == "/api/stop_all":
            return self._send(200, json.dumps(stop_all(bool(body.get("tools", True)))))
        if p == "/api/param":
            return self._send(200, json.dumps(set_param(body.get("name"), bool(body.get("value")))))
        if p == "/api/capture":
            return self._send(200, json.dumps(set_capture(bool(body.get("on")))))
        if p == "/api/record":
            return self._send(200, json.dumps(set_record(bool(body.get("on")))))
        if p == "/api/clear":
            with LOCK:
                S.samples.clear()
                S.wire.clear()
                S.events.clear()
                S.episodes.clear()
                S.ep = None
            event("console", "cleared charts, events and episodes", "sys")
            return self._send(200, json.dumps({"ok": True}))
        return self._send(404, json.dumps({"error": "not found"}))


def main():
    global ARGS, CATALOG
    ap = argparse.ArgumentParser(description="Cross-Layer IDS Monitor back end")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--dry-run", action="store_true", help="show commands, launch nothing")
    ap.add_argument("--demo", action="store_true",
                    help="synthetic detector/traffic feed for previewing the UI (no ROS)")
    ap.add_argument("--tele-topic", default="/physguard/telemetry")
    ap.add_argument("--xte-topic", default="/track/xte")
    ap.add_argument("--drift-topic", default="/sim/odom_error")
    ap.add_argument("--mode-topic", default="/attack/mode")
    ARGS = ap.parse_args()
    CATALOG = load_catalog()

    if ARGS.demo:
        threading.Thread(target=demo_loop, daemon=True).start()
    elif not ARGS.dry_run:
        for target, args in ((tail_telemetry, (ARGS.tele_topic,)),
                             (tail_float, (ARGS.xte_topic, "xte")),
                             (tail_float, (ARGS.drift_topic, "derr")),
                             (tail_mode, (ARGS.mode_topic,))):
            threading.Thread(target=target, args=args, daemon=True).start()
    event("console", "IDS Monitor started"
          + (" (DEMO feed)" if ARGS.demo else " (DRY-RUN)" if ARGS.dry_run else ""), "sys")

    mode = "DEMO (synthetic feed)" if ARGS.demo else ("DRY-RUN" if ARGS.dry_run else "LIVE")
    print(f"[console] {mode}  catalogue: {len(CATALOG['attacks'])} attacks, "
          f"{len(CATALOG['tools'])} tools")
    print(f"[console] open http://localhost:{ARGS.port}  (Ctrl+C to stop)")
    srv = ThreadingHTTPServer((ARGS.host, ARGS.port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[console] stopping launched processes...")
        stop_all()
        set_record(False)


if __name__ == "__main__":
    main()
