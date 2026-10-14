#!/usr/bin/env python3
# =============================================================================
# File        : detector_core.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S
# =============================================================================
# Description
# -----------
# Pure-Python core of the IDS cross-layer detector. Deliberately has NO
# ROS dependency so that it can be (a) unit tested on any machine, (b) re-run
# offline over recorded CSV/rosbag data for the paper's evaluation tables, and
# (c) wrapped by the ROS 2 node in physguard_detector.py.
#
# The detector fuses two independent layers:
#
#   NETWORK LAYER  - identity and rate evidence taken from the ROS 2 graph:
#                    how many nodes publish the command topic, whether each is
#                    on the allowlist, and how fast the publisher set churns.
#                    Catches rogue publishers and discovery-flood DoS.
#
#   PHYSICS LAYER  - two checks on the physical process:
#                    (1) FEASIBILITY - is the wire command finite and inside the
#                        robot's kinematic/acceleration envelope?
#                    (2) CONSISTENCY - does the robot's MEASURED motion match
#                        what the AUTHORIZED command stream predicts? An
#                        injected command moves the robot in a way the
#                        authorized stream cannot explain, so the residual grows
#                        even when each individual packet looks legal.
#                    A CUSUM statistic accumulates residual excess so small,
#                    persistent (stealthy) attacks are caught over time.
#
# Fusion is an OR over enabled layers. Each layer can be disabled independently
# at runtime, which is exactly the ablation reported in the paper.
#
# Threat-model note: the consistency residual assumes wheel odometry is not
# itself forged. Sensor-level spoofing is out of scope and stated as such.
# =============================================================================

from dataclasses import dataclass, field
import math


@dataclass
class DetectorConfig:
    """Tunable detector parameters. Calibrate on benign data only."""
    v_max: float = 1.20          # m/s   max feasible linear velocity
    w_max: float = 2.50          # rad/s max feasible angular velocity
    a_max: float = 1.60          # m/s^2 max linear acceleration
    alpha_max: float = 4.00      # rad/s^2 max angular acceleration
    accel_slack: float = 4.0     # tolerance multiplier on accel feasibility
    residual_eps: float = 0.35   # residual threshold (CUSUM drift term)
    cusum_tau: float = 3.00      # CUSUM alarm limit
    cusum_clip: float = 25.0     # keep the statistic bounded
    ema_beta: float = 0.80       # residual smoothing
    discovery_max: float = 40.0  # publisher-churn events/s treated as flood
    tau_v: float = 0.25          # s     drive lag, linear (identify on robot)
    tau_w: float = 0.18          # s     drive lag, angular
    allowlist: tuple = ("/pure_pursuit", "/patrol_controller", "/safety_filter",
                        "/nav2_controller", "/teleop")


@dataclass
class DetectorState:
    residual: float = 0.0
    cusum: float = 0.0
    pred_v: float = 0.0
    pred_w: float = 0.0
    net_fired: bool = False
    phy_fired: bool = False
    fused: bool = False
    reasons: list = field(default_factory=list)


class IDSDetector:
    """Cross-layer detector. Call update() once per control period."""

    def __init__(self, cfg: DetectorConfig = None,
                 net_enabled: bool = True, phy_enabled: bool = True):
        self.cfg = cfg or DetectorConfig()
        self.net_enabled = net_enabled
        self.phy_enabled = phy_enabled
        self.s = DetectorState()

    # ---------------- network layer ----------------
    def _network_layer(self, publisher_names, discovery_rate):
        """Identity + rate evidence from the ROS 2 graph."""
        reasons = []
        unauthorized = [n for n in publisher_names
                        if n not in self.cfg.allowlist]
        if unauthorized:
            reasons.append("unauthorized publisher: " + ",".join(unauthorized))
        if discovery_rate > self.cfg.discovery_max:
            reasons.append(f"discovery flood {discovery_rate:.0f}/s")
        return (len(reasons) > 0), reasons

    # ---------------- physics layer ----------------
    def _physics_layer(self, wire_v, wire_w, auth_v, auth_w,
                       meas_v, meas_w, dt):
        reasons = []

        # (1) feasibility of the command actually on the wire
        if not (math.isfinite(wire_v) and math.isfinite(wire_w)):
            reasons.append("non-finite command")
        else:
            if abs(wire_v) > self.cfg.v_max:
                reasons.append(f"|v|={abs(wire_v):.2f} exceeds v_max")
            if abs(wire_w) > self.cfg.w_max:
                reasons.append(f"|w|={abs(wire_w):.2f} exceeds w_max")
            dv_lim = self.cfg.a_max * dt * self.cfg.accel_slack
            dw_lim = self.cfg.alpha_max * dt * self.cfg.accel_slack
            if abs(wire_v - meas_v) > dv_lim:
                reasons.append("linear accel infeasible")
            if abs(wire_w - meas_w) > dw_lim:
                reasons.append("angular accel infeasible")

        # (2) consistency: measured motion vs authorized-command prediction.
        # First-order lag model of the drive, identified from benign data.
        tau_v, tau_w = self.cfg.tau_v, self.cfg.tau_w
        kv = min(1.0, dt / tau_v)
        kw = min(1.0, dt / tau_w)
        self.s.pred_v += kv * (auth_v - self.s.pred_v)
        self.s.pred_w += kw * (auth_w - self.s.pred_w)

        inst = math.hypot(meas_v - self.s.pred_v,
                          0.5 * (meas_w - self.s.pred_w))
        b = self.cfg.ema_beta
        self.s.residual = b * self.s.residual + (1.0 - b) * inst

        # CUSUM accumulates persistent excess -> catches stealthy drift
        self.s.cusum = max(0.0, self.s.cusum +
                           (self.s.residual - self.cfg.residual_eps))
        self.s.cusum = min(self.s.cusum, self.cfg.cusum_clip)
        if self.s.cusum > self.cfg.cusum_tau:
            reasons.append(f"CUSUM {self.s.cusum:.2f} over limit")

        return (len(reasons) > 0), reasons

    # ---------------- fusion ----------------
    def update(self, wire_v, wire_w, auth_v, auth_w, meas_v, meas_w,
               dt, publisher_names=(), discovery_rate=0.0):
        """Run both layers and fuse. Returns the updated DetectorState."""
        reasons = []

        net_fire, net_r = self._network_layer(publisher_names, discovery_rate)
        phy_fire, phy_r = self._physics_layer(wire_v, wire_w, auth_v, auth_w,
                                              meas_v, meas_w, dt)

        self.s.net_fired = bool(net_fire and self.net_enabled)
        self.s.phy_fired = bool(phy_fire and self.phy_enabled)
        if self.s.net_fired:
            reasons += ["[NET] " + r for r in net_r]
        if self.s.phy_fired:
            reasons += ["[PHY] " + r for r in phy_r]

        self.s.fused = self.s.net_fired or self.s.phy_fired
        self.s.reasons = reasons
        return self.s

    def reset(self):
        self.s = DetectorState()



class SafetyLatch:
    """
    Latched alarm + safety filter decision.

    Once the fused detector fires, the latch engages and the robot is driven
    only by the authorized command stream. While engaged, the plant no longer
    sees the wire, so the physics residual carries no information about the
    attack; the latch therefore does not release on the residual. It releases
    only when the wire has agreed with the authorized stream for `release_s`
    seconds and the network layer is quiet. On release the CUSUM is reset.
    """

    def __init__(self, release_s=3.0, dv_tol=0.02, dw_tol=0.05):
        self.release_s, self.dv_tol, self.dw_tol = release_s, dv_tol, dw_tol
        self.engaged = False
        self.quiet = 0.0
        self.events = []          # ("ENGAGED" | "RELEASED", reasons)

    def update(self, det, st, wire_v, wire_w, auth_v, auth_w, dt):
        self.events = []
        if st.fused and not self.engaged:
            self.engaged = True
            self.quiet = 0.0
            self.events.append(("ENGAGED", list(st.reasons)))
        if self.engaged:
            agree = (math.isfinite(wire_v) and math.isfinite(wire_w)
                     and abs(wire_v - auth_v) < self.dv_tol
                     and abs(wire_w - auth_w) < self.dw_tol)
            self.quiet = self.quiet + dt if (agree and not st.net_fired) else 0.0
            if self.quiet >= self.release_s:
                self.engaged = False
                det.s.cusum = 0.0
                self.events.append(("RELEASED", []))
        return self.engaged


if __name__ == "__main__":
    # smoke test: benign -> injection -> stealth
    d = IDSDetector()
    dt = 0.05
    print("benign:")
    for _ in range(40):
        st = d.update(0.4, 0.1, 0.4, 0.1, 0.4, 0.1, dt, ("/patrol_controller",), 2)
    print("  residual=%.3f cusum=%.3f fused=%s" % (st.residual, st.cusum, st.fused))

    print("injection (wire 3.0 m/s):")
    st = d.update(3.0, 0.1, 0.4, 0.1, 0.4, 0.1, dt, ("/patrol_controller", "/evil"), 2)
    print("  fused=%s reasons=%s" % (st.fused, st.reasons))


