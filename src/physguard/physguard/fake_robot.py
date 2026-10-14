#!/usr/bin/env python3
# =============================================================================
# File        : fake_robot.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S
# =============================================================================
# Description
# -----------
# Dependency-free differential-drive simulator. Subscribes /cmd_vel, integrates
# a first-order drive model with acceleration limits, and publishes /odom plus
# the odom->base_link TF so RViz2 can render the robot without Gazebo.
#
# Purpose: this is the GUARANTEED-WORKING demo path. If Gazebo fails to launch,
# every other node in the stack behaves identically against this simulator, so
# the demonstration still runs. Swap it for Gazebo or real hardware by simply
# not launching it - nothing else in the stack changes.
# =============================================================================
import math
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import Twist, TransformStamped
from nav_msgs.msg import Odometry
from tf2_ros import TransformBroadcaster


class FakeRobot(Node):
    def __init__(self):
        super().__init__('fake_robot')
        self.declare_parameter('a_max', 1.6)
        self.declare_parameter('alpha_max', 4.0)
        self.declare_parameter('odom_noise', 0.01)
        self.a_max = self.get_parameter('a_max').value
        self.alpha_max = self.get_parameter('alpha_max').value
        self.noise = self.get_parameter('odom_noise').value

        self.x = self.y = self.th = 0.0
        self.v = self.w = 0.0
        self.cmd_v = self.cmd_w = 0.0
        self.dt = 0.05

        self.create_subscription(Twist, 'cmd_vel', self.on_cmd, 10)
        self.odom_pub = self.create_publisher(Odometry, 'odom', 10)
        self.tf = TransformBroadcaster(self)
        self.create_timer(self.dt, self.step)
        self.get_logger().info('fake_robot up (no Gazebo needed)')

    def on_cmd(self, m):
        v, w = m.linear.x, m.angular.z
        self.cmd_v = v if math.isfinite(v) else 0.0
        self.cmd_w = w if math.isfinite(w) else 0.0

    def step(self):
        import random
        dv = max(-self.a_max*self.dt, min(self.a_max*self.dt, self.cmd_v - self.v))
        dw = max(-self.alpha_max*self.dt, min(self.alpha_max*self.dt, self.cmd_w - self.w))
        self.v += dv; self.w += dw
        self.x += self.v*math.cos(self.th)*self.dt
        self.y += self.v*math.sin(self.th)*self.dt
        self.th += self.w*self.dt

        now = self.get_clock().now().to_msg()
        o = Odometry()
        o.header.stamp = now; o.header.frame_id = 'odom'; o.child_frame_id = 'base_link'
        o.pose.pose.position.x = self.x; o.pose.pose.position.y = self.y
        o.pose.pose.orientation.z = math.sin(self.th/2)
        o.pose.pose.orientation.w = math.cos(self.th/2)
        o.twist.twist.linear.x = self.v + self.noise*random.gauss(0, 1)
        o.twist.twist.angular.z = self.w + 2*self.noise*random.gauss(0, 1)
        self.odom_pub.publish(o)

        t = TransformStamped()
        t.header.stamp = now; t.header.frame_id = 'odom'; t.child_frame_id = 'base_link'
        t.transform.translation.x = self.x; t.transform.translation.y = self.y
        t.transform.rotation.z = math.sin(self.th/2); t.transform.rotation.w = math.cos(self.th/2)
        self.tf.sendTransform(t)


def main():
    rclpy.init(); n = FakeRobot()
    try: rclpy.spin(n)
    except KeyboardInterrupt: pass
    finally: n.destroy_node(); rclpy.shutdown()


if __name__ == '__main__':
    main()
