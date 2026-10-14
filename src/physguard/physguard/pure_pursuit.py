#!/usr/bin/env python3
# =============================================================================
# File        : pure_pursuit.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# =============================================================================
# Description
# -----------
# The LEGITIMATE controller for the track demo. Follows the oval track with
# pure pursuit, closed loop on /odom, so the robot returns to the track by
# itself once an attack is blocked.
#
# Publishes the same command on two topics:
#   /cmd_vel_auth  authorized reference stream, read by the detector
#   /cmd_vel_raw   the wire; an attacker can also publish here
# and the cross-track error on /track/xte_ctrl for plotting.
#
# Waits for the first /odom message before moving, so it works unchanged with
# Gazebo, the built-in simulator, or the real robot.
# =============================================================================
import math

import rclpy
from rclpy.node import Node
from geometry_msgs.msg import Twist
from nav_msgs.msg import Odometry
from std_msgs.msg import Float32

from physguard.track import OvalTrack, PurePursuit


def yaw_of(q):
    return math.atan2(2.0 * (q.w * q.z + q.x * q.y), 1.0 - 2.0 * (q.y * q.y + q.z * q.z))


class PurePursuitNode(Node):
    def __init__(self):
        super().__init__('pure_pursuit')
        for k, v in [('straight', 6.0), ('radius', 2.0), ('speed', 0.35),
                     ('lookahead', 0.6), ('rate', 20.0)]:
            self.declare_parameter(k, v)
        g = lambda n: self.get_parameter(n).value
        self.track = OvalTrack(straight=g('straight'), radius=g('radius'))
        self.pp = PurePursuit(self.track, lookahead=g('lookahead'), v_ref=g('speed'))
        self.pose = None
        self.dt = 1.0 / g('rate')
        self.create_subscription(Odometry, 'odom', self.on_odom, 10)
        self.auth = self.create_publisher(Twist, 'cmd_vel_auth', 10)
        self.wire = self.create_publisher(Twist, 'cmd_vel_raw', 10)
        self.xte = self.create_publisher(Float32, 'track/xte_ctrl', 10)
        self.create_timer(self.dt, self.step)
        self.get_logger().info('pure_pursuit up, waiting for /odom')

    def on_odom(self, m):
        p = m.pose.pose
        if self.pose is None:
            self.get_logger().info('odometry received, driving the track')
        self.pose = (p.position.x, p.position.y, yaw_of(p.orientation))

    def step(self):
        if self.pose is None:
            return
        v, w, e = self.pp.step(*self.pose, self.dt)
        m = Twist()
        m.linear.x, m.angular.z = float(v), float(w)
        self.auth.publish(m)
        self.wire.publish(m)
        self.xte.publish(Float32(data=float(e)))


def main():
    rclpy.init()
    n = PurePursuitNode()
    try:
        rclpy.spin(n)
    except KeyboardInterrupt:
        pass
    finally:
        n.destroy_node()
        rclpy.try_shutdown()


if __name__ == '__main__':
    main()
