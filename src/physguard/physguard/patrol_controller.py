#!/usr/bin/env python3
# =============================================================================
# File        : patrol_controller.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S
# =============================================================================
# Description
# -----------
# The LEGITIMATE controller. Drives a smooth figure-eight patrol and publishes
# on two topics:
#   /cmd_vel_auth : the authorized reference stream, consumed by the detector
#                   as the "what the robot was told to do" ground truth.
#   /cmd_vel_raw  : the wire. The attacker also publishes here, so the two
#                   streams diverge exactly when an injection occurs.
# =============================================================================
import math
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import Twist


class PatrolController(Node):
    def __init__(self):
        super().__init__('patrol_controller')
        self.auth = self.create_publisher(Twist, 'cmd_vel_auth', 10)
        self.wire = self.create_publisher(Twist, 'cmd_vel_raw', 10)
        self.t = 0.0
        self.create_timer(0.05, self.step)
        self.get_logger().info('patrol_controller up (legitimate stream)')

    def step(self):
        self.t += 0.05
        m = Twist()
        m.linear.x = 0.40 + 0.05*math.sin(self.t*0.35)
        m.angular.z = 0.55*math.sin(self.t*0.55)
        self.auth.publish(m)
        self.wire.publish(m)


def main():
    rclpy.init(); n = PatrolController()
    try: rclpy.spin(n)
    except KeyboardInterrupt: pass
    finally: n.destroy_node(); rclpy.shutdown()


if __name__ == '__main__':
    main()
