#!/usr/bin/env python3
# =============================================================================
# File        : evaluate_offline.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S
# =============================================================================
# Description
# -----------
# Offline evaluation harness for the IDS detector core. Runs entirely
# without ROS so results can be regenerated on any machine, and produces the
# four figures used in Review 1:
#
#   fig1_calibration.png  - benign residual distribution and the mu+3sigma
#                           threshold derived from it (threshold is CALIBRATED,
#                           not hand-picked)
#   fig2_timeseries.png   - residual and CUSUM through a benign -> attack ->
#                           benign session, with the detection instant marked
#   fig3_latency.png      - detection latency vs attack magnitude, showing the
#                           stealth floor below which the attack is undetectable
#   fig4_ablation.png     - per-layer coverage: which layer catches which attack
#
# The ablation figure is the core scientific claim: the network layer and the
# physics layer catch DIFFERENT attacks, so fusion strictly dominates either
# layer alone.
#
# Usage: python3 evaluate_offline.py [--outdir figs]
# =============================================================================

import argparse
import os
import random
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from detector_core import IDSDetector, DetectorConfig

DT = 0.05
C_NET, C_PHY, C_FUS = "#2196c4", "#e08a1e", "#7c5cd6"
C_OK, C_BAD = "#2e9e6b", "#d4453c"


def _plant(meas_v, wire_v, noise=0.01):
    """First-order drive response plus odometry noise."""
    return meas_v + 0.3 * (wire_v - meas_v) + noise * random.gauss(0, 1)


def calibrate(n=4000, seed=0):
    """Estimate the residual threshold from BENIGN data only."""
    random.seed(seed)
    d = IDSDetector(DetectorConfig(residual_eps=1e9))
    meas_v, res = 0.4, []
    for i in range(n):
        auth_v = 0.4 + 0.01 * random.gauss(0, 1)
        meas_v = _plant(meas_v, auth_v)
        st = d.update(auth_v, 0.0, auth_v, 0.0, meas_v, 0.0, DT,
                      ("/patrol_controller",), 2)
        if i > 400:
            res.append(st.residual)
    mu, sd = statistics.mean(res), statistics.pstdev(res)
    return mu, sd, mu + 3 * sd, res


def run_session(eps, tau, bias, seed, n=1200, atk_start=None, atk_end=None,
                pubs_during_attack=("/patrol_controller",)):
    """Run one session; returns time series and first detection time."""
    random.seed(seed)
    d = IDSDetector(DetectorConfig(residual_eps=eps, cusum_tau=tau))
    meas_v, fired = 0.4, None
    T, R, S, F = [], [], [], []
    for i in range(n):
        t = i * DT
        attacking = (atk_start is None) or (atk_start <= t < (atk_end or 1e9))
        auth_v = 0.4
        wire_v = auth_v + (bias if attacking else 0.0)
        pubs = pubs_during_attack if attacking else ("/patrol_controller",)
        meas_v = _plant(meas_v, wire_v)
        st = d.update(wire_v, 0.0, auth_v, 0.0, meas_v, 0.0, DT, pubs, 2)
        if st.fused and fired is None and attacking:
            fired = t
        T.append(t); R.append(st.residual); S.append(st.cusum); F.append(st.fused)
    return dict(t=T, res=R, cusum=S, fired=F, detect_t=fired)


def fig_calibration(mu, sd, eps, res, outdir):
    fig, ax = plt.subplots(figsize=(6.2, 3.4))
    ax.hist(res, bins=60, color=C_PHY, alpha=.75, edgecolor="none")
    ax.axvline(eps, color=C_BAD, ls="--", lw=2,
               label=f"threshold $\\varepsilon=\\mu+3\\sigma$ = {eps:.3f}")
    ax.axvline(mu, color="#555", ls=":", lw=1.5, label=f"benign mean = {mu:.3f}")
    ax.set_xlabel("consistency residual (benign operation)")
    ax.set_ylabel("samples")
    ax.set_title("Threshold calibrated from benign data only\n(no attack data used)",
                 fontsize=10)
    ax.legend(fontsize=8, frameon=False)
    fig.tight_layout(); fig.savefig(f"{outdir}/fig1_calibration.png", dpi=170)
    plt.close(fig)


def fig_timeseries(eps, tau, outdir):
    s = run_session(eps, tau, bias=0.10, seed=7, n=1200,
                    atk_start=20.0, atk_end=45.0)
    fig, ax = plt.subplots(2, 1, figsize=(7.4, 4.6), sharex=True)
    for a in ax:
        a.axvspan(20, 45, color=C_BAD, alpha=.10)
    ax[0].plot(s["t"], s["res"], color=C_PHY, lw=1.6)
    ax[0].axhline(eps, color=C_BAD, ls="--", lw=1.2, label=f"$\\varepsilon$={eps:.3f}")
    ax[0].set_ylabel("residual"); ax[0].legend(fontsize=8, frameon=False, loc="upper left")
    ax[0].set_title("Stealthy injection (+0.10 m/s) inside the feasible envelope",
                    fontsize=10)
    ax[1].plot(s["t"], s["cusum"], color=C_FUS, lw=1.6)
    ax[1].axhline(tau, color=C_BAD, ls="--", lw=1.2, label=f"$\\tau$={tau}")
    if s["detect_t"]:
        for a in ax:
            a.axvline(s["detect_t"], color=C_OK, lw=2)
        ax[1].annotate(f"detected  +{s['detect_t']-20:.2f}s",
                       xy=(s["detect_t"], tau), xytext=(s["detect_t"] + 3, tau * 1.9),
                       color=C_OK, fontsize=9,
                       arrowprops=dict(arrowstyle="->", color=C_OK))
    ax[1].set_ylabel("CUSUM $S_k$"); ax[1].set_xlabel("time (s)")
    ax[1].legend(fontsize=8, frameon=False, loc="upper left")
    ax[0].text(21, max(s["res"]) * .92, "attack window", color=C_BAD, fontsize=8)
    fig.tight_layout(); fig.savefig(f"{outdir}/fig2_timeseries.png", dpi=170)
    plt.close(fig)
    return s["detect_t"]


def fig_latency(eps, tau, outdir):
    biases = [0.02, 0.03, 0.05, 0.08, 0.12, 0.20, 0.30, 0.50]
    lat = []
    for b in biases:
        runs = [run_session(eps, tau, b, seed=s, n=1600)["detect_t"]
                for s in range(5)]
        ok = [r for r in runs if r is not None]
        lat.append(statistics.mean(ok) if ok else None)
    fig, ax = plt.subplots(figsize=(6.2, 3.6))
    xs = [b for b, l in zip(biases, lat) if l is not None]
    ys = [l for l in lat if l is not None]
    ax.plot(xs, ys, "o-", color=C_PHY, lw=2, ms=6)
    miss = [b for b, l in zip(biases, lat) if l is None]
    for b in miss:
        ax.axvspan(0, max(miss) * 1.15, color=C_BAD, alpha=.08)
    if miss:
        ax.text(max(miss) * .55, max(ys) * .75,
                "undetectable\n(stealth floor)", color=C_BAD, fontsize=9, ha="center")
    ax.set_xlabel("injected velocity bias (m/s)")
    ax.set_ylabel("detection latency (s)")
    ax.set_title("Detection latency vs attack magnitude\nstealthier attack = slower detection, less damage",
                 fontsize=10)
    ax.grid(alpha=.25)
    fig.tight_layout(); fig.savefig(f"{outdir}/fig3_latency.png", dpi=170)
    plt.close(fig)
    return list(zip(biases, lat))


def fig_ablation(eps, tau, outdir):
    """Which layer catches which attack. This is the core claim."""
    scenarios = {
        "Garbage\nvalues":      dict(bias=9e9, pubs=("/patrol_controller", "/evil")),
        "Command\ninjection":   dict(bias=2.0, pubs=("/patrol_controller", "/evil")),
        "Discovery\nflood":     dict(bias=0.0, pubs=("/patrol_controller",), disc=200),
        "Stealthy\ndrift":      dict(bias=0.10, pubs=("/patrol_controller", "/evil")),
        "Compromised\nnode":    dict(bias=0.12, pubs=("/patrol_controller",)),
    }
    results = {}
    for name, sc in scenarios.items():
        row = []
        for net_on, phy_on in [(True, False), (False, True), (True, True)]:
            random.seed(3)
            d = IDSDetector(DetectorConfig(residual_eps=eps, cusum_tau=tau),
                                  net_enabled=net_on, phy_enabled=phy_on)
            meas_v, hit = 0.4, 0
            for i in range(1400):
                wire_v = 0.4 + sc["bias"]
                if sc["bias"] > 1e8:
                    wire_v = float("nan")
                meas_v = _plant(meas_v, 0.4 + min(sc["bias"], 1.0))
                st = d.update(wire_v, 0.0, 0.4, 0.0, meas_v, 0.0, DT,
                              sc["pubs"], sc.get("disc", 2))
                if st.fused:
                    hit = 1; break
            row.append(hit)
        results[name] = row

    labels = list(results.keys())
    M = np.array([results[k] for k in labels]).T  # 3 x N
    fig, ax = plt.subplots(figsize=(7.6, 3.2))
    ax.imshow(M, cmap=matplotlib.colors.ListedColormap(["#f2dede", "#cfe9dc"]),
              aspect="auto", vmin=0, vmax=1)
    rows = ["Network only", "Physics only", "Fused"]
    for i in range(M.shape[0]):
        for j in range(M.shape[1]):
            ax.text(j, i, "detected" if M[i, j] else "MISSED",
                    ha="center", va="center", fontsize=9,
                    color=C_OK if M[i, j] else C_BAD,
                    fontweight="bold" if not M[i, j] else "normal")
    ax.set_xticks(range(len(labels))); ax.set_xticklabels(labels, fontsize=9)
    ax.set_yticks(range(3)); ax.set_yticklabels(rows, fontsize=9)
    ax.set_title("Layer ablation: each layer covers the other's blind spot",
                 fontsize=11, pad=10)
    ax.set_xticks(np.arange(-.5, len(labels), 1), minor=True)
    ax.set_yticks(np.arange(-.5, 3, 1), minor=True)
    ax.grid(which="minor", color="white", lw=2)
    ax.tick_params(which="minor", length=0)
    fig.tight_layout(); fig.savefig(f"{outdir}/fig4_ablation.png", dpi=170)
    plt.close(fig)
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="figs")
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)

    mu, sd, eps, res = calibrate()
    tau = 3.0
    print(f"[calibration] benign mean={mu:.4f} sd={sd:.4f} -> eps={eps:.4f}")

    fig_calibration(mu, sd, eps, res, a.outdir)
    dt_det = fig_timeseries(eps, tau, a.outdir)
    lat = fig_latency(eps, tau, a.outdir)
    abl = fig_ablation(eps, tau, a.outdir)

    # false alarm check
    fa = sum(1 for s in range(10)
             if run_session(eps, tau, 0.0, seed=100 + s, n=1200)["detect_t"] is not None)
    print(f"[false alarms] {fa}/10 benign 60s sessions raised an alarm")
    print(f"[detection] stealth +0.10 m/s detected {dt_det-20:.2f}s after onset")
    print("[latency]", [(b, None if l is None else round(l, 2)) for b, l in lat])
    print("[ablation] net-only / phys-only / fused:")
    for k, v in abl.items():
        print("   %-22s %s" % (k.replace("\n", " "), v))
    print(f"figures written to {a.outdir}/")


if __name__ == "__main__":
    main()
