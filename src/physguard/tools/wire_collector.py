#!/usr/bin/env python3
# =============================================================================
# File        : wire_collector.py
# Package     : physguard (tools)
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# Course      : 21ECC402P - Computer Communication and Network Security
# Version     : 0.2  (fixes from first live run)
# =============================================================================
# Description
# -----------
# Wire-level network sensor for the IDS. Runs tshark (Wireshark's command-line
# engine) with its built-in RTPS dissector, and turns raw DDS packets into
# per-second network metrics and security events. This is the packet-level half
# of the network layer: it reports what is actually on the wire, independently
# of what the ROS 2 graph API claims.
#
# Metrics per window (default 1 s):
#   pkts, bytes          total RTPS traffic in the domain's port range
#   disc                 packets to the SPDP discovery multicast port
#   sedp                 endpoint announcements, DATA(w) / DATA(r), incl. disposals
#   data                 user-data DATA submessages
#   target_data          user data on the target topic (only when Wireshark
#                        annotates DATA with its topic name)
#   participants         DDS participants active in the last N seconds
#   target_writers       participants announcing a WRITER on the target topic
#
# Events (edge-triggered: raised once on onset, cleared once on recovery)
#   NEW_PARTICIPANT / PARTICIPANT_LEFT
#   NEW_TARGET_WRITER / TARGET_WRITER_GONE / TARGET_WRITER_STALE
#   ALERT_MULTI_WRITER       / CLEARED_MULTI_WRITER
#   ALERT_DISCOVERY_FLOOD    / CLEARED_DISCOVERY_FLOOD
#   ALERT_ENDPOINT_CHURN     / CLEARED_ENDPOINT_CHURN
#
# Flood logic, designed to avoid false alarms on normal node start-up:
#   discovery flood  -> >= flood_new NEW participants in one window, or the
#                       discovery rate above flood_thresh for `sustain` windows
#   endpoint churn   -> endpoint announcements above churn_thresh for
#                       `sustain` windows (matches the attack_injector 'flood'
#                       mode, which churns publishers, not participants)
#
# Changes in 0.2
#   - DATA counting handles Wireshark's "DATA -> topic" annotation
#   - a departing participant is logged once, and its writers are removed
#   - writers whose participant goes silent are expired (DATA(w[UD]) carries
#     no topic name, so it cannot be matched by topic alone)
#   - start-up discovery bursts no longer raise a flood alert
#   - alerts are edge-triggered instead of repeating every window
#
# DDS port mapping (RTPS spec): base = 7400 + 250 * domain_id. Domain 42 uses
# 17900-18149; the SPDP multicast port is the base itself.
#
# Modes
#   live  : python3 wire_collector.py --domain 42 --iface any
#   pcap  : python3 wire_collector.py --domain 42 --pcap capture.pcapng
#   stdin : tshark field lines piped in (used for testing)
#
# Sinks: console (always), CSV (default on), InfluxDB (only if INFLUX_URL,
# INFLUX_TOKEN and INFLUX_ORG are set; bucket from INFLUX_BUCKET, default "ids").
#
# Notes
#   - Start the collector BEFORE the ROS 2 nodes. SEDP writer announcements are
#     sent at match time; a collector started later will not learn them.
#   - Fast DDS shared memory must be disabled (fastdds_udp_only.xml).
#   - Capture only on networks you control.
# =============================================================================

import argparse
import csv
import os
import queue
import subprocess
import sys
import threading
import time
from collections import defaultdict

PB, DG = 7400, 250   # RTPS port base and domain gain

CANDIDATES = {
    "guid":  ["rtps.guidPrefix.src", "rtps.guidPrefix"],
    "topic": ["rtps.param.topicName"],
    "info":  ["_ws.col.info", "_ws.col.Info"],
}
BASE_FIELDS = ["frame.time_epoch", "ip.src", "ip.dst",
               "udp.srcport", "udp.dstport", "frame.len"]


# ---------------------------------------------------------------------------
# tshark plumbing
# ---------------------------------------------------------------------------
def resolve_fields(tshark):
    """Pick field names that exist in the installed tshark."""
    try:
        out = subprocess.run([tshark, "-G", "fields"], capture_output=True,
                             text=True, timeout=120).stdout
    except Exception as e:
        sys.exit(f"[wire] cannot query tshark fields: {e}")
    avail = {ln.split("\t")[2] for ln in out.splitlines()
             if ln.startswith("F\t") and ln.count("\t") >= 2}
    chosen = {k: next((c for c in v if c in avail), None) for k, v in CANDIDATES.items()}
    if chosen["info"] is None:
        chosen["info"] = "_ws.col.Info"
    return chosen


def tshark_cmd(args, extra, lo, hi):
    cmd = [args.tshark, "-l", "-n", "-Q"]
    if args.pcap:
        cmd += ["-r", args.pcap]
    else:
        cmd += ["-i", args.iface, "-f", f"udp portrange {lo}-{hi}"]
    cmd += ["-Y", f"rtps && udp.dstport >= {lo} && udp.dstport <= {hi}",
            "-T", "fields", "-E", "separator=/t",
            "-E", "occurrence=a", "-E", "aggregator=,"]
    for f in BASE_FIELDS + extra:
        cmd += ["-e", f]
    return cmd


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------
class WireState:
    def __init__(self, a, disc_port):
        self.a = a
        self.disc_port = disc_port
        self.target = a.topic
        self.last_seen = {}        # guid -> (t, ip)
        self.known = set()
        self.departed = set()
        self.target_writers = {}   # guid -> ip
        self.peak_disc = 0.0
        self.flood_streak = 0
        self.churn_streak = 0
        self.active = {"MULTI_WRITER": False, "DISCOVERY_FLOOD": False,
                       "ENDPOINT_CHURN": False}
        self._new_window()

    def _new_window(self):
        self.pkts = self.bytes = self.disc = self.sedp = 0
        self.user = self.target_user = self.new_parts = 0
        self.by_ip = defaultdict(int)
        self.events = []

    def _drop_writer(self, g, ip, why):
        if self.target_writers.pop(g, None) is not None:
            self.events.append((why, g, ip))

    def ingest(self, r, t):
        self.pkts += 1
        self.bytes += r["len"]
        self.by_ip[r["src"]] += 1
        if r["dport"] == self.disc_port:
            self.disc += 1

        info = r["info"]
        for s in (x.strip() for x in info.split(",")):
            if s.startswith("DATA("):
                if s.startswith("DATA(w") or s.startswith("DATA(r"):
                    self.sedp += 1
            elif s.startswith("DATA"):          # "DATA" or "DATA -> topic"
                self.user += 1
                if self.target in s:
                    self.target_user += 1

        g = r["guid"]
        if not g:
            return

        if "DATA(p[UD])" in info:                  # participant leaving
            if g not in self.departed:
                self.departed.add(g)
                self.last_seen.pop(g, None)
                self.events.append(("PARTICIPANT_LEFT", g, r["src"]))
                self._drop_writer(g, r["src"], "TARGET_WRITER_GONE")
            return
        if g in self.departed:                     # trailing duplicates
            return

        if g not in self.known:
            self.known.add(g)
            self.new_parts += 1
            self.events.append(("NEW_PARTICIPANT", g, r["src"]))
        self.last_seen[g] = (t, r["src"])

        if r["topic"] and self.target in r["topic"]:
            if "DATA(w[UD])" in info:
                self._drop_writer(g, r["src"], "TARGET_WRITER_GONE")
            elif "DATA(w)" in info and g not in self.target_writers:
                self.target_writers[g] = r["src"]
                self.events.append(("NEW_TARGET_WRITER", g, r["src"]))

    @staticmethod
    def _coalesce(events, limit=5):
        by_kind = defaultdict(list)
        for e in events:
            by_kind[e[0]].append(e)
        out = []
        for kind, evs in by_kind.items():
            if len(evs) > limit:
                ips = sorted({e[2] for e in evs if e[2]})
                out.append((kind, f"x{len(evs)}", "from " + ",".join(ips)))
            else:
                out.extend(evs)
        return out

    def _edge(self, events, name, cond, detail):
        if cond and not self.active[name]:
            self.active[name] = True
            events.append(("ALERT_" + name, detail, ""))
        elif not cond and self.active[name]:
            self.active[name] = False
            events.append(("CLEARED_" + name, "", ""))

    def flush(self, now, win):
        a = self.a
        # expire writers whose participant has gone silent
        for g, ip in list(self.target_writers.items()):
            seen = self.last_seen.get(g)
            if seen is None or now - seen[0] > a.active_window:
                self._drop_writer(g, ip, "TARGET_WRITER_STALE")

        active = sum(1 for (ts, _) in self.last_seen.values()
                     if now - ts <= a.active_window)
        disc_rate, sedp_rate = self.disc / win, self.sedp / win
        self.peak_disc = max(self.peak_disc, disc_rate)
        self.flood_streak = self.flood_streak + 1 if disc_rate > a.flood_thresh else 0
        self.churn_streak = self.churn_streak + 1 if sedp_rate > a.churn_thresh else 0

        m = {
            "t": now,
            "pkts_s": self.pkts / win,
            "kbytes_s": self.bytes / win / 1024.0,
            "disc_s": disc_rate,
            "sedp_s": sedp_rate,
            "user_s": self.user / win,
            "target_s": self.target_user / win,
            "participants": active,
            "new_participants": self.new_parts,
            "target_writers": len(self.target_writers),
            "top_src": max(self.by_ip, key=self.by_ip.get) if self.by_ip else "",
        }

        events = self._coalesce(self.events)
        nw = len(self.target_writers)
        self._edge(events, "MULTI_WRITER", nw > a.expected_writers,
                   f"{nw} writers: " + ",".join(sorted(set(self.target_writers.values()))))
        self._edge(events, "DISCOVERY_FLOOD",
                   self.new_parts >= a.flood_new or self.flood_streak >= a.sustain,
                   f"{self.new_parts} new participants, {disc_rate:.0f} disc/s")
        self._edge(events, "ENDPOINT_CHURN", self.churn_streak >= a.sustain,
                   f"{sedp_rate:.0f} endpoint announcements/s")
        for k, v in self.active.items():
            m["alert_" + k.lower()] = int(v)

        self._new_window()
        return m, events


# ---------------------------------------------------------------------------
# sinks
# ---------------------------------------------------------------------------
NUMERIC = ["pkts_s", "kbytes_s", "disc_s", "sedp_s", "user_s", "target_s",
           "participants", "new_participants", "target_writers",
           "alert_multi_writer", "alert_discovery_flood", "alert_endpoint_churn"]


def make_influx():
    url = os.environ.get("INFLUX_URL")
    if not url:
        return None
    try:
        from influxdb_client import InfluxDBClient, Point, WritePrecision
        from influxdb_client.client.write_api import SYNCHRONOUS
    except ImportError:
        print("[wire] influxdb-client not installed, Influx sink disabled")
        return None
    client = InfluxDBClient(url=url, token=os.environ.get("INFLUX_TOKEN", ""),
                            org=os.environ.get("INFLUX_ORG", ""))
    api = client.write_api(write_options=SYNCHRONOUS)
    bucket = os.environ.get("INFLUX_BUCKET", "ids")

    def write(m, events):
        ts = int(m["t"] * 1e9)
        p = Point("wire").tag("source", "tshark").time(ts, WritePrecision.NS)
        for k in NUMERIC:
            p = p.field(k, float(m[k]))
        pts = [p]
        for (kind, x, y) in events:
            pts.append(Point("wire_event").tag("source", "tshark").tag("type", kind)
                       .field("detail", f"{x} {y}".strip())
                       .time(ts, WritePrecision.NS))
        try:
            api.write(bucket=bucket, record=pts)
        except Exception as e:
            print(f"[wire] influx write failed: {e}")
    print(f"[wire] InfluxDB sink -> {url} bucket={bucket}")
    return write


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="tshark RTPS wire collector")
    ap.add_argument("--domain", type=int, default=int(os.environ.get("ROS_DOMAIN_ID", "0")))
    ap.add_argument("--iface", default="any")
    ap.add_argument("--pcap", default=None)
    ap.add_argument("--stdin", action="store_true")
    ap.add_argument("--tshark", default="tshark")
    ap.add_argument("--topic", default="rt/cmd_vel", help="ROS 2 topics are prefixed rt/")
    ap.add_argument("--window", type=float, default=1.0)
    ap.add_argument("--active-window", type=float, default=10.0)
    ap.add_argument("--expected-writers", type=int, default=1)
    ap.add_argument("--flood-new", type=int, default=5,
                    help="new participants in one window that count as a flood")
    ap.add_argument("--flood-thresh", type=float, default=20.0,
                    help="discovery packets/s; must persist for --sustain windows")
    ap.add_argument("--churn-thresh", type=float, default=30.0,
                    help="endpoint announcements/s; must persist for --sustain windows")
    ap.add_argument("--sustain", type=int, default=3)
    ap.add_argument("--csv", default=f"wire_metrics_{int(time.time())}.csv")
    ap.add_argument("--no-csv", action="store_true")
    args = ap.parse_args()

    lo = PB + DG * args.domain
    hi = lo + DG - 1

    if args.stdin:
        proc, stream = None, sys.stdin
    else:
        f = resolve_fields(args.tshark)
        for k, v in f.items():
            print(f"[wire] field {k:6s} -> {v or 'UNAVAILABLE (feature disabled)'}")
        extra = [f["guid"] or "frame.number", f["topic"] or "frame.number", f["info"]]
        cmd = tshark_cmd(args, extra, lo, hi)
        print("[wire] " + " ".join(cmd))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1)
        stream = proc.stdout

    print(f"[wire] domain {args.domain}: ports {lo}-{hi}, discovery port {lo}, "
          f"target topic '{args.topic}'")

    idx = {n: i for i, n in enumerate(BASE_FIELDS + ["guid", "topic", "info"])}
    state = WireState(args, lo)
    influx = make_influx()

    writer, fh = None, None
    if not args.no_csv:
        fh = open(args.csv, "w", newline="")
        writer = csv.writer(fh)
        writer.writerow(["t"] + NUMERIC + ["top_src", "events"])
        print(f"[wire] CSV -> {args.csv}")

    def first(v):
        return v.split(",")[0] if v else ""

    def parse(line):
        p = line.rstrip("\n").split("\t")
        p += [""] * (len(idx) - len(p))
        try:
            return {
                "t": float(first(p[idx["frame.time_epoch"]])),
                "src": first(p[idx["ip.src"]]),
                "dport": int(first(p[idx["udp.dstport"]])),
                "len": int(first(p[idx["frame.len"]])),
                "guid": first(p[idx["guid"]]),
                "topic": p[idx["topic"]],
                "info": p[idx["info"]],
            }
        except (ValueError, IndexError):
            return None

    def emit(m, events):
        stamp = time.strftime("%H:%M:%S", time.localtime(m["t"]))
        flags = [k for k in ("multi_writer", "discovery_flood", "endpoint_churn")
                 if m["alert_" + k]]
        print(f"{stamp}  pkts/s={m['pkts_s']:6.1f}  disc/s={m['disc_s']:5.1f}  "
              f"sedp/s={m['sedp_s']:5.1f}  data/s={m['user_s']:5.1f}  "
              f"part={m['participants']:2d}  writers={m['target_writers']}"
              + (f"  [{' '.join(flags).upper()}]" if flags else ""))
        for (kind, x, y) in events:
            mark = "!!" if kind.startswith("ALERT") else ("ok" if kind.startswith("CLEARED") else "  ")
            print(f"   {mark} {kind:24s} {x} {y}")
        if writer:
            writer.writerow([f"{m['t']:.3f}"] + [f"{m[k]:.3f}" if isinstance(m[k], float)
                                                  else m[k] for k in NUMERIC]
                            + [m["top_src"],
                               " | ".join(f"{k} {x} {y}".strip() for k, x, y in events)])
            fh.flush()
        if influx:
            influx(m, events)

    q = queue.Queue()

    def reader():
        for line in stream:
            q.put(line)
        q.put(None)
    threading.Thread(target=reader, daemon=True).start()

    packet_clock = bool(args.pcap or args.stdin)
    win, next_flush = args.window, None
    try:
        while True:
            try:
                line = q.get(timeout=0.2)
            except queue.Empty:
                line = ""
            if line is None:
                break
            now = time.time()
            if line:
                r = parse(line)
                if r is None:
                    continue
                t = r["t"] if packet_clock else now
                if next_flush is None:
                    next_flush = t + win
                if t - next_flush > 60 * win:
                    next_flush = t
                while t >= next_flush:
                    emit(*state.flush(next_flush, win))
                    next_flush += win
                state.ingest(r, t)
            elif not packet_clock:
                if next_flush is None:
                    next_flush = now + win
                while now >= next_flush:
                    emit(*state.flush(next_flush, win))
                    next_flush += win
    except KeyboardInterrupt:
        pass
    finally:
        if next_flush is not None:
            emit(*state.flush(next_flush, win))
        if proc:
            proc.terminate()
        if fh:
            fh.close()
        print(f"\n[wire] summary: {len(state.known)} participants seen, "
              f"peak discovery {state.peak_disc:.1f}/s, "
              f"writers on {args.topic} at exit: "
              f"{', '.join(state.target_writers.values()) or 'none'}")


if __name__ == "__main__":
    main()
