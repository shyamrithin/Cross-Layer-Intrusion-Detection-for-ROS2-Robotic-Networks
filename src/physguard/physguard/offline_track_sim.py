#!/usr/bin/env python3
# =============================================================================
# File        : offline_track_sim.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# =============================================================================
# Description
# -----------
# ROS-free closed-loop simulation of the full track demo: oval track, pure
# pursuit controller, differential-drive plant with acceleration limits and
# odometry noise, an attacker interleaving commands on the wire, the
# cross-layer detector with auto-calibration, and the inline safety filter.
#
# It reproduces, without Gazebo or ROS, exactly the behaviour shown in the live
# demo, and generates the Review 2 figures:
#
#   fig5_track_attack.png  trajectory of three runs on the track
#                          (a) no IDS, (b) IDS detects but safety filter off,
#                          (c) IDS + safety filter; plus cross-track error and
#                          detector state over time
#   track_metrics.txt      false alarms, detection latency, peak deviation,
#                          recovery time
#
# The attacker eavesdrops on the authorized command stream (DDS has no
# encryption by default) and re-publishes it with an added bias, interleaved
# with the legitimate publisher at the same rate.
#
# Usage: python3 offline_track_sim.py [--outdir figs]
# =============================================================================

import argparse
import math
import os
import random
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

try:
    from physguard.detector_core import IDSDetector, DetectorConfig, SafetyLatch
    from physguard.track import OvalTrack, PurePursuit
except ImportError:
    from detector_core import IDSDetector, DetectorConfig, SafetyLatch
    from track import OvalTrack, PurePursuit

DT = 0.05


def attack_cmd(mode, auth_v, auth_w, k, t):
    if mode == "inject":
        return auth_v + 1.4 + 2.2 * k, auth_w + 1.6 * k * math.sin(7 * t)
    if mode == "stealth":
        return auth_v + 0.10 * k, auth_w + 0.14 * k * math.sin(0.9 * t)
    if mode == "hijack":                 # drives the robot off the track, feasible
        return min(auth_v + 0.10, 0.6), auth_w - 0.70
    return auth_v, auth_w


def run(ids_on, safety_on, mode, t_attack=(40.0, 52.0), T=95.0, k=0.6,
        calibrate_s=20.0, seed=1):
    random.seed(seed)
    track = OvalTrack()
    pp = PurePursuit(track)
    det = IDSDetector(DetectorConfig(cusum_clip=6.0))
    det.net_enabled = ids_on
    latch = SafetyLatch()
    x = y = th = 0.0
    v = w = 0.0
    calib, eps = [], None
    log = []
    for n in range(int(T / DT)):
        t = n * DT
        auth_v, auth_w, e = pp.step(x, y, th, DT)
        attacking = mode != "none" and t_attack[0] <= t < t_attack[1]
        wire_v, wire_w = auth_v, auth_w
        pubs = ("/pure_pursuit",)
        if attacking:
            pubs = ("/pure_pursuit", "/attack_injector") if mode != "hijack" \
                else ("/pure_pursuit", "/pure_pursuit")          # spoofed node name
            if n % 3 != 0:                                        # attacker publishes 2x faster
                wire_v, wire_w = attack_cmd(mode, auth_v, auth_w, k, t)

        meas_v = v + 0.01 * random.gauss(0, 1)
        meas_w = w + 0.02 * random.gauss(0, 1)
        calibrating = t < calibrate_s
        det.phy_enabled = ids_on and not calibrating
        st = det.update(wire_v, wire_w, auth_v, auth_w, meas_v, meas_w, DT, pubs, 2)
        if calibrating:
            calib.append(st.residual)
        elif eps is None:
            tail = calib[int(len(calib) * 0.3):]
            eps = max(statistics.mean(tail) + 3 * statistics.pstdev(tail), 0.01)
            det.cfg.residual_eps = eps
            det.s.cusum = 0.0
        alarm = False
        if ids_on and not calibrating:
            alarm = latch.update(det, st, wire_v, wire_w, auth_v, auth_w, DT)

        if safety_on and alarm:
            cv, cw = auth_v, auth_w
        else:
            cv = wire_v if math.isfinite(wire_v) else 0.0
            cw = wire_w if math.isfinite(wire_w) else 0.0
        v += max(-1.6 * DT, min(1.6 * DT, cv - v))
        w += max(-4.0 * DT, min(4.0 * DT, cw - w))
        x += v * math.cos(th) * DT
        y += v * math.sin(th) * DT
        th += w * DT
        log.append(dict(t=t, x=x, y=y, e=e, alarm=alarm, attacking=attacking,
                        cusum=st.cusum, res=st.residual))
    return log, eps, track


def metrics(log, t_attack, tol=0.15, rec_tol=0.05):
    post = [r for r in log if r["t"] >= 20.0]
    benign = [r for r in post if r["t"] < t_attack[0]]
    false_alarm_s = sum(DT for r in benign if r["alarm"])
    det_t = next((r["t"] for r in post if r["alarm"] and r["t"] >= t_attack[0]), None)
    peak = max(abs(r["e"]) for r in post)
    rec = None
    after = [r for r in post if r["t"] >= t_attack[0]]
    left = next((r["t"] for r in after if abs(r["e"]) > tol), None)
    if left is not None:
        streak = 0.0
        for r in after:
            if r["t"] <= left:
                continue
            streak = streak + DT if abs(r["e"]) < rec_tol else 0.0
            if streak >= 1.0:
                rec = r["t"] - 1.0
                break
    return dict(false_alarm_s=false_alarm_s,
                detect_latency=None if det_t is None else det_t - t_attack[0],
                peak_dev=peak, left_band=left, recovered=rec)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="figs")
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    TA = (40.0, 52.0)

    runs = [("(a) No IDS", False, False, "hijack"),
            ("(b) IDS, safety filter off", True, False, "hijack"),
            ("(c) IDS + safety filter", True, True, "hijack")]
    results = []
    for name, ids, saf, mode in runs:
        log, eps, track = run(ids, saf, mode, TA)
        results.append((name, log, eps, metrics(log, TA)))

    # benign false-alarm check, 10 seeds, 120 s each
    fa = []
    for s in range(10):
        log, eps, _ = run(True, True, "none", TA, T=120.0, seed=100 + s)
        fa.append(sum(DT for r in log if r["alarm"] and r["t"] >= 20.0))
    # per-attack detection latency with IDS on
    lat = {}
    for mode in ("inject", "stealth", "hijack"):
        log, eps, _ = run(True, True, mode, TA, seed=7)
        lat[mode] = metrics(log, TA)["detect_latency"]

    # ---------------- figure ----------------
    C_OK, C_ATK, C_TRK = "#2e9e6b", "#d4453c", "#9aa3ad"
    fig = plt.figure(figsize=(13, 8.2))
    gs = fig.add_gridspec(3, 3, height_ratios=[2.2, 1, 1], hspace=0.45, wspace=0.18)
    tx = [p[0] for p in track.pts] + [track.pts[0][0]]
    ty = [p[1] for p in track.pts] + [track.pts[0][1]]
    for c, (name, log, eps, m) in enumerate(results):
        ax = fig.add_subplot(gs[0, c])
        ax.plot(tx, ty, color=C_TRK, lw=14, alpha=0.35, solid_capstyle="round")
        ax.plot(tx, ty, color=C_TRK, lw=1, ls="--")
        seg_x, seg_y, col = [], [], None
        for r in log:
            cc = C_ATK if (r["attacking"] or r["alarm"]) else C_OK
            if cc != col and seg_x:
                ax.plot(seg_x, seg_y, color=col, lw=1.8)
                seg_x, seg_y = seg_x[-1:], seg_y[-1:]
            col = cc
            seg_x.append(r["x"]); seg_y.append(r["y"])
        ax.plot(seg_x, seg_y, color=col, lw=1.8)
        ax.set_title(name, fontsize=11)
        ax.set_aspect("equal"); ax.set_xticks([]); ax.set_yticks([])
        ax.set_xlim(-5.6, 5.6); ax.set_ylim(-2.2, 6.2)
        txt = f"peak deviation {m['peak_dev']:.2f} m"
        if m["detect_latency"] is not None:
            txt += f"\ndetected +{m['detect_latency']:.2f} s"
        if m["recovered"] is not None:
            txt += f"\nback on track {m['recovered'] - TA[0]:.1f} s after attack"
        ax.text(0, 2.0, txt, ha="center", va="center", fontsize=9)

    axe = fig.add_subplot(gs[1, :])
    for (name, log, eps, m), col in zip(results, ["#888888", "#e08a1e", C_OK]):
        axe.plot([r["t"] for r in log], [abs(r["e"]) for r in log], color=col, lw=1.6,
                 label=name)
    axe.axvspan(*TA, color=C_ATK, alpha=0.10)
    axe.axhline(0.15, color=C_ATK, ls="--", lw=1)
    axe.set_ylabel("|cross-track\nerror| (m)"); axe.legend(fontsize=8, frameon=False, ncol=3)
    axe.text(TA[0] + 0.3, axe.get_ylim()[1] * 0.85, "attack window", color=C_ATK, fontsize=8)

    axc = fig.add_subplot(gs[2, :], sharex=axe)
    log_c = results[2][1]
    axc.plot([r["t"] for r in log_c], [r["cusum"] for r in log_c], color="#7c5cd6", lw=1.6,
             label="CUSUM $S_k$ (run c)")
    axc.fill_between([r["t"] for r in log_c], 0, [6 * r["alarm"] for r in log_c],
                     color=C_ATK, alpha=0.15, step="mid", label="alarm")
    axc.axvspan(0, 20, color="#9aa3ad", alpha=0.15)
    axc.text(1, 4.8, "auto-calibration (benign)", fontsize=8, color="#555")
    axc.axhline(3.0, color=C_ATK, ls="--", lw=1)
    axc.set_xlabel("time (s)"); axc.set_ylabel("detector")
    axc.legend(fontsize=8, frameon=False, loc="upper right")
    fig.suptitle("Robot on the oval track under a node-name-spoofing hijack attack", fontsize=12)
    out = os.path.join(a.outdir, "fig5_track_attack.png")
    fig.savefig(out, dpi=160, bbox_inches="tight")

    lines = [f"auto-calibrated eps (run c): {results[2][2]:.4f}",
             f"false alarms, 10 benign runs x 100 s post-calibration: "
             f"{sum(1 for f in fa if f > 0)}/10 runs, total {sum(fa):.2f} s"]
    for name, log, eps, m in results:
        lines.append(f"{name}: peak {m['peak_dev']:.3f} m, detect {m['detect_latency']}, "
                     f"left band {m['left_band']}, recovered {m['recovered']}")
    for mode, l in lat.items():
        lines.append(f"detection latency [{mode}]: {l}")
    open(os.path.join(a.outdir, "track_metrics.txt"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print("figure:", out)


if __name__ == "__main__":
    main()
