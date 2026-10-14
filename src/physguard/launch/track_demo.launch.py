#!/usr/bin/env python3
# =============================================================================
# File        : track_demo.launch.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# =============================================================================
# Description
# -----------
# Track demonstration: a differential-drive robot follows an oval track with
# pure pursuit, the cross-layer IDS sits inline on the command path, and RViz2
# shows the track, the robot, its trail and the IDS state.
#
#   sim:=gazebo  Gazebo Harmonic world + ros_gz_bridge  (default)
#   sim:=fake    built-in simulator, no Gazebo needed   (fallback)
#   rviz:=false  skip RViz2
#   calibrate:=20  seconds of benign driving used to learn the threshold
#
# The attacker is NOT launched here; start it in its own terminal so the
# attack is visibly a separate, unauthorised process.
#
#   ros2 launch physguard track_demo.launch.py
#   ros2 launch physguard track_demo.launch.py sim:=fake
# =============================================================================
import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument, ExecuteProcess
from launch.conditions import IfCondition
from launch.substitutions import LaunchConfiguration, PythonExpression
from launch_ros.actions import Node


def generate_launch_description():
    share = get_package_share_directory('physguard')
    world = os.path.join(share, 'worlds', 'oval_track.sdf')
    rviz_cfg = os.path.join(share, 'rviz', 'track_demo.rviz')

    sim = LaunchConfiguration('sim')
    is_gz = IfCondition(PythonExpression(["'", sim, "' == 'gazebo'"]))
    is_fake = IfCondition(PythonExpression(["'", sim, "' == 'fake'"]))

    return LaunchDescription([
        DeclareLaunchArgument('sim', default_value='gazebo'),
        DeclareLaunchArgument('rviz', default_value='true'),
        DeclareLaunchArgument('calibrate', default_value='20.0'),

        # ---- plant ----
        ExecuteProcess(cmd=['gz', 'sim', '-r', world], output='screen', condition=is_gz),
        Node(package='ros_gz_bridge', executable='parameter_bridge', name='gz_bridge',
             arguments=['/cmd_vel@geometry_msgs/msg/Twist]gz.msgs.Twist',
                        '/odom@nav_msgs/msg/Odometry[gz.msgs.Odometry',
                        '/tf@tf2_msgs/msg/TFMessage[gz.msgs.Pose_V'],
             output='screen', condition=is_gz),
        Node(package='physguard', executable='fake_robot', name='fake_robot',
             output='screen', condition=is_fake),

        # ---- legitimate controller, IDS, visualisation ----
        Node(package='physguard', executable='pure_pursuit', name='pure_pursuit',
             output='screen'),
        Node(package='physguard', executable='physguard_node', name='physguard',
             output='screen',
             parameters=[{'auto_calibrate_s': LaunchConfiguration('calibrate')}]),
        Node(package='physguard', executable='track_viz', name='track_viz',
             output='screen'),
        Node(package='rviz2', executable='rviz2', name='rviz2',
             arguments=['-d', rviz_cfg], output='log',
             condition=IfCondition(LaunchConfiguration('rviz'))),
    ])
