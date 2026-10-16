#!/usr/bin/env python3
# =============================================================================
# File        : bench.launch.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# =============================================================================
# Description
# -----------
# One-command launch for the full evaluation bench. Superset of
# track_demo.launch.py: the plant, the legitimate controller, the cross-layer
# IDS and RViz2, plus two optional pieces that otherwise need their own
# terminals:
#
#   attacker:=true   also start attack_injector, idle. Switch attacks live with
#                    `ros2 param set /attack_injector mode <mode>`. OFF by
#                    default, so by default the attacker is still a visibly
#                    separate, unauthorised process (the review story) and you
#                    opt in only for quick solo testing.
#   wire:=true       also start the tshark wire collector on the DDS domain.
#                    Needs tshark and capture privileges; OFF by default.
#
# Arguments
#   sim:=fake|gazebo      plant (default fake; the guaranteed-working path)
#   rviz:=true|false      RViz2 (default true)
#   calibrate:=<seconds>  benign calibration window (default 20)
#   attacker:=true|false  idle attack_injector (default false)
#   wire:=true|false      tshark wire collector (default false)
#
# Examples
#   ros2 launch physguard bench.launch.py
#   ros2 launch physguard bench.launch.py attacker:=true
#   ros2 launch physguard bench.launch.py sim:=fake attacker:=true wire:=true
#
# The attacker is NOT the review demo default; for a clean demonstration keep
# attacker:=false and start the injector in its own terminal.
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
    wire_py = os.path.join(share, 'tools', 'wire_collector.py')

    sim = LaunchConfiguration('sim')
    is_gz = IfCondition(PythonExpression(["'", sim, "' == 'gazebo'"]))
    is_fake = IfCondition(PythonExpression(["'", sim, "' == 'fake'"]))
    if_attacker = IfCondition(LaunchConfiguration('attacker'))
    if_wire = IfCondition(LaunchConfiguration('wire'))
    if_rviz = IfCondition(LaunchConfiguration('rviz'))

    domain = os.environ.get('ROS_DOMAIN_ID', '42')

    return LaunchDescription([
        DeclareLaunchArgument('sim', default_value='fake'),
        DeclareLaunchArgument('rviz', default_value='true'),
        DeclareLaunchArgument('calibrate', default_value='20.0'),
        DeclareLaunchArgument('attacker', default_value='false'),
        DeclareLaunchArgument('wire', default_value='false'),

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
             arguments=['-d', rviz_cfg], output='log', condition=if_rviz),

        # ---- optional: attacker, idle ----
        Node(package='physguard', executable='attack_injector', name='attack_injector',
             output='screen', parameters=[{'mode': 'none'}], condition=if_attacker),

        # ---- optional: tshark wire collector ----
        ExecuteProcess(cmd=['python3', wire_py, '--domain', domain, '--iface', 'any'],
                       output='screen', condition=if_wire),
    ])
