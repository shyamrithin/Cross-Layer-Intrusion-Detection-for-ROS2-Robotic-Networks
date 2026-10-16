#!/usr/bin/env python3
# =============================================================================
# File        : track_viz.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# =============================================================================
# Description
# -----------
# RViz2 visualisation and recovery metrics for the track demo.
#
# Publishes (frame: odom)
#   /track/reference  nav_msgs/Path       the oval centreline
#   /track/markers    MarkerArray         track surface, tolerance band, robot
#                                         body and heading, coloured trail,
#                                         event pins (attack, detected, recovered)
#   /track/xte        Float32             signed cross-track error (m)
#   /track/state      String              NOMINAL | UNDER_ATTACK | RECOVERING
#
# Trail colours: green nominal, red while the IDS alarm is raised, amber while
# returning to the track after the alarm clears.
#
# Episode metrics, printed when an episode closes:
#   detection latency  attack start (/attack/mode) -> alarm
#   peak deviation     max |cross-track error| during the episode
#   recovery time      attack end -> robot back within recover_tol for 1 s
# /attack/mode is ground-truth instrumentation from the attack injector, used
# only for these metrics, never by the detector.
# =============================================================================
import math
import time
from collections import deque

import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, DurabilityPolicy
from geometry_msgs.msg import PoseStamped, Point
from nav_msgs.msg import Odometry, Path
from std_msgs.msg import Bool, Float32, String, ColorRGBA
from visualization_msgs.msg import Marker, MarkerArray

from physguard.track import OvalTrack

GREEN = (0.18, 0.80, 0.45)
RED = (0.94, 0.25, 0.20)
AMBER = (1.00, 0.68, 0.10)
GREY = (0.55, 0.58, 0.62)


def yaw_of(q):
    return math.atan2(2.0 * (q.w * q.z + q.x * q.y), 1.0 - 2.0 * (q.y * q.y + q.z * q.z))


def rgba(c, a=1.0):
    return ColorRGBA(r=float(c[0]), g=float(c[1]), b=float(c[2]), a=float(a))


class TrackViz(Node):
    def __init__(self):
        super().__init__('track_viz')
        for k, v in [('straight', 6.0), ('radius', 2.0), ('tolerance', 0.15),
                     ('recover_tol', 0.05), ('trail_len', 4000)]:
            self.declare_parameter(k, v)
        g = lambda n: self.get_parameter(n).value
        self.track = OvalTrack(straight=g('straight'), radius=g('radius'))
        self.tol, self.rtol = float(g('tolerance')), float(g('recover_tol'))

        latched = QoSProfile(depth=1, durability=DurabilityPolicy.TRANSIENT_LOCAL)
        self.p_path = self.create_publisher(Path, 'track/reference', latched)
        self.p_mrk = self.create_publisher(MarkerArray, 'track/markers', 10)
        self.p_xte = self.create_publisher(Float32, 'track/xte', 10)
        self.p_state = self.create_publisher(String, 'track/state', 10)

        self.create_subscription(Odometry, 'odom', self.on_odom, 10)
        self.create_subscription(Bool, 'physguard/alert', self.on_alert, 10)
        self.create_subscription(String, 'attack/mode', self.on_mode, 10)

        self.pose = None
        self.hint = None
        self.xte = 0.0
        self.alarm = False
        self.alarm_t = 0.0
        self.mode = 'none'
        self.trail = deque(maxlen=int(g('trail_len')))
        self.pins = []
        self.ep = None
        self.inside_since = None
        self.state = 'NOMINAL'

        self.create_timer(0.1, self.tick)
        self.create_timer(2.0, self.publish_static)
        self.publish_static()
        self.get_logger().info('track_viz up')

    # ---------------- inputs ----------------
    def on_odom(self, m):
        p = m.pose.pose
        self.pose = (p.position.x, p.position.y, yaw_of(p.orientation))
        self.hint, self.xte = self.track.cross_track(p.position.x, p.position.y, self.hint)

    def on_alert(self, m):
        now = time.time()
        if m.data and not self.alarm:
            self.alarm_t = now
            if self.ep is not None and self.ep['t_detect'] is None:
                self.ep['t_detect'] = now
                lat = now - self.ep['t_attack']
                self.pin(RED, f'DETECTED\n+{lat:.2f}s')
                self.get_logger().warn(f'alarm raised {lat:.2f} s after attack start')
            elif self.ep is None:
                self.pin(RED, 'ALARM')
        self.alarm = m.data

    def on_mode(self, m):
        now = time.time()
        if m.data != self.mode:
            if m.data != 'none' and self.ep is None:
                self.ep = dict(mode=m.data, t_attack=now, t_detect=None,
                               t_end=None, peak=0.0)
                self.pin(AMBER, f'ATTACK\n{m.data}')
                if self.alarm and now - self.alarm_t < 2.0:   # alarm beat this message
                    self.ep['t_detect'] = self.alarm_t
                    self.pin(RED, 'DETECTED\n+0.00s')
            elif m.data == 'none' and self.ep is not None:
                self.ep['t_end'] = now
            self.mode = m.data

    # ---------------- logic ----------------
    def outward(self, x, y):
        """Unit normal pointing to the OUTSIDE of the track at (x, y).
        The track is driven counter-clockwise, so the left normal points
        inward and the outward normal is its negative."""
        i, _ = self.track.cross_track(x, y, self.hint)
        px, py = self.track.pts[i]
        qx, qy = self.track.pts[(i + 1) % self.track.N]
        tx, ty = qx - px, qy - py
        n = math.hypot(tx, ty) or 1.0
        return ty / n, -tx / n

    def pin(self, color, text):
        """Drop an event pin at the robot. The label is placed outside the
        track, stacked away from earlier pins at the same spot so that
        back-to-back events (attack, then detection 0.01 s later) stay
        readable."""
        if self.pose is None:
            return
        x, y = self.pose[0], self.pose[1]
        ox, oy = self.outward(x, y)
        near = sum(1 for p in self.pins if math.hypot(p[0] - x, p[1] - y) < 0.8)
        d = 0.6 + 0.42 * near
        self.pins.append((x, y, color, text, x + ox * d, y + oy * d))

    def tick(self):
        if self.pose is None:
            return
        now = time.time()
        x, y, th = self.pose
        e = self.xte
        self.p_xte.publish(Float32(data=float(e)))

        if self.ep is not None:
            self.ep['peak'] = max(self.ep['peak'], abs(e))
            if self.ep['t_end'] is not None and not self.alarm:
                self.inside_since = (self.inside_since or now) if abs(e) < self.rtol else None
                if self.inside_since and now - self.inside_since >= 1.0:
                    rec = self.inside_since - self.ep['t_end']
                    lat = max(0.0, self.ep['t_detect'] - self.ep['t_attack']) if self.ep['t_detect'] else None
                    self.pin(GREEN, 'RECOVERED')
                    self.get_logger().info(
                        f"episode [{self.ep['mode']}] detection "
                        f"{'%.2f s' % lat if lat is not None else 'MISSED'}, "
                        f"peak deviation {self.ep['peak']:.3f} m, "
                        f"back on track {max(rec, 0.0):.2f} s after attack ended")
                    self.ep, self.inside_since = None, None

        if self.alarm:
            self.state = 'UNDER_ATTACK'
        elif self.ep is not None or (abs(e) > self.rtol and self.state != 'NOMINAL'):
            self.state = 'RECOVERING'
        else:
            self.state = 'NOMINAL'
        self.p_state.publish(String(data=self.state))
        col = {'UNDER_ATTACK': RED, 'RECOVERING': AMBER}.get(self.state, GREEN)
        if not self.trail or math.hypot(x - self.trail[-1][0], y - self.trail[-1][1]) > 0.02:
            self.trail.append((x, y, col))
        self.publish_dynamic(x, y, th, e, col)

    # ---------------- markers ----------------
    def base(self, ns, mid, mtype):
        m = Marker()
        m.header.frame_id = 'odom'
        m.header.stamp = self.get_clock().now().to_msg()
        m.ns, m.id, m.type, m.action = ns, mid, mtype, Marker.ADD
        m.pose.orientation.w = 1.0
        return m

    def publish_static(self):
        path = Path()
        path.header.frame_id = 'odom'
        path.header.stamp = self.get_clock().now().to_msg()
        for i in range(0, self.track.N, 5):
            ps = PoseStamped()
            ps.header = path.header
            ps.pose.position.x, ps.pose.position.y = self.track.pts[i]
            ps.pose.orientation.w = 1.0
            path.poses.append(ps)
        self.p_path.publish(path)

    def publish_dynamic(self, x, y, th, e, col):
        arr = MarkerArray()

        surf = self.base('track', 0, Marker.LINE_STRIP)
        surf.scale.x = self.track.width
        surf.color = rgba((0.28, 0.30, 0.33), 0.55)
        surf.pose.position.z = -0.01
        surf.points = [Point(x=px, y=py, z=0.0) for px, py in self.track.pts[::10]]
        surf.points.append(surf.points[0])
        arr.markers.append(surf)

        out = abs(e) > self.tol
        for k, d in enumerate((self.tol, -self.tol)):
            b = self.base('band', k, Marker.LINE_STRIP)
            b.scale.x = 0.015
            b.color = rgba(RED if out else GREY, 0.9)
            b.points = [Point(x=px, y=py, z=0.005) for px, py in self.track.offset_line(d)]
            arr.markers.append(b)

        tr = self.base('trail', 0, Marker.LINE_STRIP)
        tr.scale.x = 0.04
        tr.points = [Point(x=px, y=py, z=0.02) for px, py, _ in self.trail]
        tr.colors = [rgba(c) for _, _, c in self.trail]
        if len(tr.points) >= 2:
            arr.markers.append(tr)

        body = self.base('robot', 0, Marker.CUBE)
        body.pose.position.x, body.pose.position.y, body.pose.position.z = x, y, 0.06
        body.pose.orientation.z, body.pose.orientation.w = math.sin(th / 2), math.cos(th / 2)
        body.scale.x, body.scale.y, body.scale.z = 0.30, 0.22, 0.08
        body.color = rgba(col)
        arr.markers.append(body)

        head = self.base('robot', 1, Marker.ARROW)
        head.pose = body.pose
        head.scale.x, head.scale.y, head.scale.z = 0.35, 0.05, 0.05
        head.color = rgba((1.0, 1.0, 1.0))
        arr.markers.append(head)

        # Robot readout, placed just inside the track so it never collides
        # with the event pins (which sit outside). RViz2 renders spaces in
        # TEXT_VIEW_FACING very wide, so labels use line breaks, not spaces.
        ox, oy = self.outward(x, y)
        info = self.base('robot', 2, Marker.TEXT_VIEW_FACING)
        info.pose.position.x = x - ox * 0.75
        info.pose.position.y = y - oy * 0.75
        info.pose.position.z = 0.45
        info.scale.z = 0.19
        info.color = rgba(col)
        info.text = f'{self.state}\nxte={e:+.2f}m'
        arr.markers.append(info)

        pins = self.pins[-12:]
        lead = self.base('pins', 999, Marker.LINE_LIST)
        lead.scale.x = 0.012
        for k, (px, py, c, text, lx, ly) in enumerate(pins):
            s = self.base('pins', 2 * k, Marker.SPHERE)
            s.pose.position.x, s.pose.position.y, s.pose.position.z = px, py, 0.1
            s.scale.x = s.scale.y = s.scale.z = 0.14
            s.color = rgba(c)
            arr.markers.append(s)
            t = self.base('pins', 2 * k + 1, Marker.TEXT_VIEW_FACING)
            t.pose.position.x, t.pose.position.y, t.pose.position.z = lx, ly, 0.3
            t.scale.z = 0.17
            t.color = rgba(c)
            t.text = text
            arr.markers.append(t)
            lead.points += [Point(x=px, y=py, z=0.1), Point(x=lx, y=ly, z=0.1)]
            lead.colors += [rgba(c, 0.6), rgba(c, 0.6)]
        if lead.points:
            arr.markers.append(lead)
        self.p_mrk.publish(arr)


def main():
    rclpy.init()
    n = TrackViz()
    try:
        rclpy.spin(n)
    except KeyboardInterrupt:
        pass
    finally:
        n.destroy_node()
        rclpy.try_shutdown()


if __name__ == '__main__':
    main()
