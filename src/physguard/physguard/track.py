#!/usr/bin/env python3
# =============================================================================
# File        : track.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# =============================================================================
# Description
# -----------
# ROS-free track geometry and path-tracking controller, shared by the
# pure_pursuit node, the track_viz node, the Gazebo world generator and the
# offline track simulation. Keeping it ROS-free means the same code is unit
# tested offline and run live.
#
# OvalTrack
#   Stadium-shaped track: two straights joined by two semicircles. The robot
#   starts at the world origin facing +x, in the middle of the bottom straight,
#   so the odometry frame and the world frame coincide in both Gazebo and the
#   built-in simulator.
#       bottom straight : y = 0,     x from -L/2 to +L/2   (driven in +x)
#       right arc       : centre (+L/2, R)
#       top straight    : y = 2R,    x from +L/2 to -L/2
#       left arc        : centre (-L/2, R)
#   Driving direction is counter-clockwise.
#
# PurePursuit
#   Classic pure pursuit on the dense centreline. Closed loop on the measured
#   pose, so after an attack is blocked the robot actively returns to the
#   track. Lookahead grows with cross-track error for a smooth return, speed is
#   ramped to respect acceleration limits, and a turn-in-place branch handles
#   the robot ending up facing the wrong way.
# =============================================================================

import math


def wrap(a):
    return math.atan2(math.sin(a), math.cos(a))


class OvalTrack:
    def __init__(self, straight=6.0, radius=2.0, width=0.8, spacing=0.02):
        self.L, self.R, self.width, self.spacing = straight, radius, width, spacing
        L, R = straight, radius
        pts = []
        n = int(round(L / spacing))
        m = int(round(math.pi * R / spacing))
        for i in range(n):                                   # bottom straight
            pts.append((-L / 2 + i * spacing, 0.0))
        for i in range(m):                                   # right arc
            a = -math.pi / 2 + math.pi * i / m
            pts.append((L / 2 + R * math.cos(a), R + R * math.sin(a)))
        for i in range(n):                                   # top straight
            pts.append((L / 2 - i * spacing, 2 * R))
        for i in range(m):                                   # left arc
            a = math.pi / 2 + math.pi * i / m
            pts.append((-L / 2 + R * math.cos(a), R + R * math.sin(a)))
        self.pts = pts
        self.N = len(pts)
        self.length = 2 * L + 2 * math.pi * R

    def nearest(self, x, y, hint=None, window=150):
        """Index of the nearest centreline point, searched near `hint` first."""
        def d2(i):
            px, py = self.pts[i]
            return (px - x) ** 2 + (py - y) ** 2
        if hint is not None:
            idx = [(hint + k) % self.N for k in range(-window, window + 1)]
            best = min(idx, key=d2)
            if d2(best) < 1.0:
                return best
        return min(range(self.N), key=d2)

    def cross_track(self, x, y, hint=None):
        """(index, signed lateral error). Positive = left of the driving direction."""
        i = self.nearest(x, y, hint)
        px, py = self.pts[i]
        qx, qy = self.pts[(i + 1) % self.N]
        tx, ty = qx - px, qy - py
        n = math.hypot(tx, ty) or 1.0
        e = (tx * (y - py) - ty * (x - px)) / n
        return i, e

    def offset_line(self, d, step=5):
        """Centreline offset laterally by d (left positive), for tolerance bands."""
        out = []
        for i in range(0, self.N, step):
            px, py = self.pts[i]
            qx, qy = self.pts[(i + 1) % self.N]
            tx, ty = qx - px, qy - py
            n = math.hypot(tx, ty) or 1.0
            out.append((px - ty / n * d, py + tx / n * d))
        out.append(out[0])
        return out


class PurePursuit:
    def __init__(self, track, lookahead=0.6, v_ref=0.35, w_max=1.5, a_max=0.5):
        self.t = track
        self.Ld, self.v_ref, self.w_max, self.a_max = lookahead, v_ref, w_max, a_max
        self.v = 0.0
        self.hint = None

    def step(self, x, y, th, dt):
        i, e = self.t.cross_track(x, y, self.hint)
        self.hint = i
        Ld = max(self.Ld, 1.2 * abs(e))
        j = (i + int(Ld / self.t.spacing)) % self.t.N
        gx, gy = self.t.pts[j]
        alpha = wrap(math.atan2(gy - y, gx - x) - th)

        if abs(alpha) > math.pi / 2:                  # facing the wrong way
            v_target = 0.08
            w = math.copysign(self.w_max * 0.6, alpha)
        else:
            v_target = self.v_ref
            w = 2.0 * max(self.v, 0.05) * math.sin(alpha) / Ld
        dv = max(-self.a_max * dt, min(self.a_max * dt, v_target - self.v))
        self.v += dv
        w = max(-self.w_max, min(self.w_max, w))
        return self.v, w, e
