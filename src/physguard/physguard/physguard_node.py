#!/usr/bin/env python3
# =============================================================================
# File        : physguard_node.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# Version     : 0.3  (auto-calibration, latched safety filter)
# =============================================================================
# Description
# -----------
# ROS 2 wrapper around detector_core: the cross-layer detector plus the inline
# safety filter.
#
# Inputs :  /cmd_vel_raw    the wire (legitimate controller + any attacker)
#           /cmd_vel_auth   authorized reference stream
#           /odom           measured motion (Gazebo, fake_robot or hardware)
# Outputs:  /cmd_vel                  forwarded command (authorized one while
#                                     the safety latch is engaged)
#           /physguard/residual       Float32  consistency residual
#           /physguard/cusum          Float32  CUSUM statistic
#           /physguard/alert          Bool     latched alarm
#           /physguard/status         String   human-readable reasons
#           /physguard/markers        MarkerArray, text above the robot
#           ~/physguard_session_<t>.csv        per-step log for evaluation
#
# Auto-calibration (auto_calibrate_s > 0)
#   For the first N seconds the physics layer only observes. The threshold is
#   then set to mean + 3 sigma of the benign residual. This is the
#   attack-data-free calibration from the paper, and it adapts the detector to
#   whichever plant is running (Gazebo, the built-in simulator, or hardware).
#
# Network layer
#   Reads the live ROS 2 graph: node names publishing /cmd_vel_raw are checked
#   against an allowlist, and publisher-set churn is rate-limited. A node that
#   spoofs an allowlisted name passes this check by design; that case is left
#   to the physics layer and to the wire collector (two writers on the wire).
#
# Runtime parameters (ros2 param set /physguard <name> <value>):
#   net_enabled, phy_enabled, safety_enabled  -> live ablation
#   residual_eps, cusum_tau                    -> thresholds
# =============================================================================
import csv
import math
import os
import statistics
import time

import rclpy
from rclpy.node import Node
from rclpy.parameter import Parameter
from geometry_msgs.msg import Twist
from nav_msgs.msg import Odometry
from std_msgs.msg import Float32, Bool, String
from visualization_msgs.msg import Marker, MarkerArray
from builtin_interfaces.msg import Time

from physguard.detector_core import IDSDetector, DetectorConfig, SafetyLatch


class IDSNode(Node):
    def __init__(self):
        super().__init__('physguard')
        for k, v in [('net_enabled', True), ('phy_enabled', True),
                     ('safety_enabled', True), ('residual_eps', 0.024),
                     ('cusum_tau', 3.0), ('cusum_clip', 6.0),
                     ('tau_v', 0.25), ('tau_w', 0.18),
                     ('auto_calibrate_s', 20.0), ('eps_floor', 0.01),
                     ('release_s', 3.0), ('churn_thresh', 5.0),
                     ('allowlist', ['/pure_pursuit', '/patrol_controller']),
                     ('log_csv', True)]:
            self.declare_parameter(k, v)
        g = lambda n: self.get_parameter(n).value

        cfg = DetectorConfig(residual_eps=float(g('residual_eps')),
                             cusum_tau=float(g('cusum_tau')),
                             cusum_clip=float(g('cusum_clip')),
                             tau_v=float(g('tau_v')), tau_w=float(g('tau_w')),
                             discovery_max=float(g('churn_thresh')),
                             allowlist=tuple(g('allowlist')))
        self.det = IDSDetector(cfg)
        self.latch = SafetyLatch(release_s=float(g('release_s')))

        self.wire_v = self.wire_w = 0.0
        self.auth_v = self.auth_w = 0.0
        self.meas_v = self.meas_w = 0.0
        self.prev_pubs = None
        self.churn = []
        self.t0 = time.time()
        self.calib_s = float(g('auto_calibrate_s'))
        self.calib = []
        self.calibrated = self.calib_s <= 0.0

        self.create_subscription(Twist, 'cmd_vel_raw', self.on_wire, 10)
        self.create_subscription(Twist, 'cmd_vel_auth', self.on_auth, 10)
        self.create_subscription(Odometry, 'odom', self.on_odom, 10)

        self.cmd_pub = self.create_publisher(Twist, 'cmd_vel', 10)
        self.p_res = self.create_publisher(Float32, 'physguard/residual', 10)
        self.p_cus = self.create_publisher(Float32, 'physguard/cusum', 10)
        self.p_alt = self.create_publisher(Bool, 'physguard/alert', 10)
        self.p_sts = self.create_publisher(String, 'physguard/status', 10)
        self.p_mrk = self.create_publisher(MarkerArray, 'physguard/markers', 10)

        self.csv = None
        if g('log_csv'):
            path = os.path.expanduser(f'~/physguard_session_{int(self.t0)}.csv')
            self.csv = open(path, 'w', newline='')
            self.w = csv.writer(self.csv)
            self.w.writerow(['t', 'wire_v', 'wire_w', 'auth_v', 'auth_w', 'meas_v',
                             'meas_w', 'residual', 'cusum', 'eps', 'net', 'phy',
                             'alarm', 'calibrating', 'reasons'])
            self.get_logger().info(f'logging session to {path}')

        self.create_timer(0.05, self.step)
        if self.calibrated:
            self.get_logger().info('detector up, threshold %.4f' % cfg.residual_eps)
        else:
            self.get_logger().info(f'detector up, learning normal behaviour for '
                                   f'{self.calib_s:.0f} s (no attacks please)')

    def on_wire(self, m): self.wire_v, self.wire_w = m.linear.x, m.angular.z
    def on_auth(self, m): self.auth_v, self.auth_w = m.linear.x, m.angular.z

    def on_odom(self, m):
        self.meas_v = m.twist.twist.linear.x
        self.meas_w = m.twist.twist.angular.z

    def graph_publishers(self):
        try:
            names = {'/' + i.node_name.lstrip('/')
                     for i in self.get_publishers_info_by_topic('cmd_vel_raw')}
        except Exception:
            names = set()
        now = time.time()
        if self.prev_pubs is not None and names != self.prev_pubs:
            self.churn.append(now)
        self.prev_pubs = names
        self.churn = [t for t in self.churn if now - t < 1.0]
        return names, float(len(self.churn))

    def finish_calibration(self):
        tail = self.calib[int(len(self.calib) * 0.3):] or [0.0]
        eps = max(statistics.mean(tail) + 3 * statistics.pstdev(tail),
                  float(self.get_parameter('eps_floor').value))
        self.set_parameters([Parameter('residual_eps', value=float(eps))])
        self.det.s.cusum = 0.0
        self.calibrated = True
        self.get_logger().info(f'calibration done: residual mean '
                               f'{statistics.mean(tail):.4f}, threshold eps = {eps:.4f}. '
                               f'IDS armed.')

    def step(self):
        g = lambda n: self.get_parameter(n).value
        t = time.time() - self.t0
        if not self.calibrated and t >= self.calib_s:
            self.finish_calibration()
        calibrating = not self.calibrated

        self.det.net_enabled = bool(g('net_enabled'))
        self.det.phy_enabled = bool(g('phy_enabled')) and not calibrating
        self.det.cfg.residual_eps = float(g('residual_eps'))
        self.det.cfg.cusum_tau = float(g('cusum_tau'))

        pubs, churn = self.graph_publishers()
        st = self.det.update(self.wire_v, self.wire_w, self.auth_v, self.auth_w,
                             self.meas_v, self.meas_w, 0.05, tuple(pubs), churn)
        if calibrating:
            self.calib.append(st.residual)
            alarm = False
        else:
            alarm = self.latch.update(self.det, st, self.wire_v, self.wire_w,
                                      self.auth_v, self.auth_w, 0.05)
            for kind, reasons in self.latch.events:
                if kind == 'ENGAGED':
                    action = ('  -> BLOCKED, forwarding authorized command'
                              if g('safety_enabled') else
                              '  -> NOT BLOCKED, safety filter is off')
                    self.get_logger().warn('INTRUSION: ' + '; '.join(reasons) + action)
                else:
                    self.get_logger().info('wire consistent again, safety filter released')

        out = Twist()
        if alarm and bool(g('safety_enabled')):
            out.linear.x, out.angular.z = self.auth_v, self.auth_w
        else:
            out.linear.x = self.wire_v if math.isfinite(self.wire_v) else 0.0
            out.angular.z = self.wire_w if math.isfinite(self.wire_w) else 0.0
        self.cmd_pub.publish(out)

        self.p_res.publish(Float32(data=float(st.residual)))
        self.p_cus.publish(Float32(data=float(st.cusum)))
        self.p_alt.publish(Bool(data=bool(alarm)))
        if calibrating:
            txt = f'CALIBRATING {max(0.0, self.calib_s - t):.0f}s'
        elif alarm:
            txt = 'INTRUSION: ' + ('; '.join(st.reasons) or 'latched')
            if not g('safety_enabled'):
                txt += '  [safety OFF]'
        else:
            txt = 'CLEAR'
        self.p_sts.publish(String(data=txt))

        # Short label for the RViz marker (full reasons stay on /physguard/status
        # and in the log). RViz2 draws spaces very wide, so use line breaks.
        if calibrating:
            label = f'CALIBRATING\n{max(0.0, self.calib_s - t):.0f}s'
        elif alarm:
            layers = ('[NET]' if st.net_fired else '') + ('[PHY]' if st.phy_fired else '')
            label = 'INTRUSION\n' + (layers or '[LATCHED]')
            label += '\nBLOCKED' if g('safety_enabled') else '\nNOT_BLOCKED'
        else:
            label = 'CLEAR'
        self.publish_markers(alarm, calibrating, label)

        if self.csv:
            self.w.writerow([f'{t:.3f}', f'{self.wire_v:.4f}', f'{self.wire_w:.4f}',
                             f'{self.auth_v:.4f}', f'{self.auth_w:.4f}',
                             f'{self.meas_v:.4f}', f'{self.meas_w:.4f}',
                             f'{st.residual:.5f}', f'{st.cusum:.4f}',
                             f'{self.det.cfg.residual_eps:.5f}',
                             int(st.net_fired), int(st.phy_fired), int(alarm),
                             int(calibrating), ' | '.join(st.reasons)])

    def publish_markers(self, alarm, calibrating, txt):
        m = Marker()
        m.header.frame_id = 'base_link'
        # Zero stamp = "use the latest available transform". Stamping with
        # now() made RViz wait on a base_link transform newer than the last
        # one the simulator had published, so the marker was held back.
        m.header.stamp = Time()
        m.frame_locked = True
        m.ns, m.id = 'physguard', 0
        m.type, m.action = Marker.TEXT_VIEW_FACING, Marker.ADD
        m.pose.position.z = 0.7
        m.pose.orientation.w = 1.0
        m.scale.z = 0.22
        m.color.a = 1.0
        if calibrating:
            m.color.r, m.color.g, m.color.b = 0.6, 0.65, 0.7
        elif alarm:
            m.color.r, m.color.g, m.color.b = 0.94, 0.28, 0.24
        else:
            m.color.r, m.color.g, m.color.b = 0.20, 0.84, 0.60
        m.text = txt[:70]
        arr = MarkerArray()
        arr.markers.append(m)
        self.p_mrk.publish(arr)

    def destroy_node(self):
        if self.csv:
            self.csv.close()
        super().destroy_node()


def main():
    rclpy.init()
    n = IDSNode()
    try:
        rclpy.spin(n)
    except KeyboardInterrupt:
        pass
    finally:
        n.destroy_node()
        rclpy.try_shutdown()


if __name__ == '__main__':
    main()
