#!/usr/bin/env python3
# =============================================================================
# File        : sim_frames.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# =============================================================================
# Description
# -----------
# Owns the robot's moving TF in the Gazebo bench, and couples RViz to Gazebo.
#
#   /odom          (wheel odometry, gz DiffDrive)  ->  odom  -> base_link
#   /ground_truth  (true pose, gz OdometryPublisher) -> world -> odom
#
# The world->odom transform is the correction between where the wheels think
# the robot is and where Gazebo says it really is:
#
#     T_world_odom = T_world_base(ground truth) * inverse(T_odom_base(wheels))
#
# With fixed frame 'world' in RViz, base_link therefore lands exactly on the
# Gazebo pose, so the robot model and the laser scan always line up with the
# Gazebo world even when wheel odometry drifts or the wheels spin against an
# obstacle. That is the same tree a real robot gets from a localiser
# (map->odom), with Gazebo playing the localiser.
#
# The detector is unaffected: it still reads raw wheel /odom.
#
# Parameters
#   publish_world_odom  (bool, true)  set false when a SLAM node owns the
#                                     odom frame's parent (it publishes map->odom)
#   world_frame         (str, world)
#
# Also publishes /sim/odom_error (Float32, metres): distance between the
# wheel-odometry position and the true position. The robot spawns at the
# world origin, so the two should coincide; the gap is odometry drift as a
# single number (ros2 topic echo /sim/odom_error).
# =============================================================================
import math

import rclpy
from rclpy.node import Node
from geometry_msgs.msg import TransformStamped
from nav_msgs.msg import Odometry
from std_msgs.msg import Float32
from tf2_ros import TransformBroadcaster


def yaw_of(q):
    return math.atan2(2.0 * (q.w * q.z + q.x * q.y), 1.0 - 2.0 * (q.y * q.y + q.z * q.z))


def planar(m):
    """(x, y, yaw) of an Odometry message's pose."""
    p = m.pose.pose
    return p.position.x, p.position.y, yaw_of(p.orientation)


def compose(a, b):
    """a * b for planar transforms (x, y, yaw)."""
    ax, ay, at = a
    bx, by, bt = b
    c, s = math.cos(at), math.sin(at)
    return ax + c * bx - s * by, ay + s * bx + c * by, at + bt


def inverse(a):
    ax, ay, at = a
    c, s = math.cos(at), math.sin(at)
    return -(c * ax + s * ay), -(-s * ax + c * ay), -at


class SimFrames(Node):
    def __init__(self):
        super().__init__('sim_frames')
        self.declare_parameter('publish_world_odom', True)
        self.declare_parameter('world_frame', 'world')
        self.pub_world = bool(self.get_parameter('publish_world_odom').value)
        self.world = str(self.get_parameter('world_frame').value)

        self.tf = TransformBroadcaster(self)
        self.p_err = self.create_publisher(Float32, 'sim/odom_error', 10)
        self.truth = None
        self.create_subscription(Odometry, 'ground_truth', self.on_truth, 20)
        self.create_subscription(Odometry, 'odom', self.on_odom, 20)
        self.get_logger().info(
            'sim_frames up: odom->base_link from /odom'
            + (f', {self.world}->odom from /ground_truth' if self.pub_world else ''))

    def on_truth(self, m):
        if self.truth is None:
            x, y, th = planar(m)
            self.get_logger().info(
                f'ground truth received: robot at ({x:.2f}, {y:.2f}), yaw {math.degrees(th):.1f} deg')
        self.truth = planar(m)

    def on_odom(self, m):
        odom_base = planar(m)
        stamp = m.header.stamp
        msgs = [self.make(stamp, 'odom', 'base_link', odom_base)]
        if self.truth is not None:
            world_odom = compose(self.truth, inverse(odom_base))
            if self.pub_world:
                msgs.append(self.make(stamp, self.world, 'odom', world_odom))
            # drift: the robot spawns at the world origin, so the wheel-odometry
            # position and the true position should coincide; their gap is drift
            err = math.hypot(self.truth[0] - odom_base[0], self.truth[1] - odom_base[1])
            self.p_err.publish(Float32(data=float(err)))
        self.tf.sendTransform(msgs)

    @staticmethod
    def make(stamp, parent, child, pose):
        x, y, th = pose
        t = TransformStamped()
        t.header.stamp = stamp
        t.header.frame_id = parent
        t.child_frame_id = child
        t.transform.translation.x = float(x)
        t.transform.translation.y = float(y)
        t.transform.rotation.z = math.sin(th / 2.0)
        t.transform.rotation.w = math.cos(th / 2.0)
        return t


def main():
    rclpy.init()
    n = SimFrames()
    try:
        rclpy.spin(n)
    except KeyboardInterrupt:
        pass
    finally:
        n.destroy_node()
        rclpy.try_shutdown()


if __name__ == '__main__':
    main()
