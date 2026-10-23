#!/usr/bin/env python3
# =============================================================================
# File        : slam.launch.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# =============================================================================
# Description
# -----------
# SLAM demonstration on the arena. Brings up the Gazebo bench (robot-free world
# + URDF robot + bridge + pure-pursuit so the robot laps the oval), then runs
# slam_toolbox in online-async mode to build a map from the lidar, and RViz
# with a map-frame view. No teleoperation is needed: the pure-pursuit controller
# drives the oval while the perimeter walls and obstacles are mapped.
#
# The IDS detector is left out here so the view is a clean mapping demo; run the
# IDS bench (gazebo.launch.py) separately when you want the intrusion-detection
# story. 2D Nav Goal / 2D Pose Estimate tools are available in RViz (they
# publish /goal_pose and /initialpose for a Nav2 stack, when one is running).
#
#   ros2 launch physguard slam.launch.py
#   ros2 launch physguard slam.launch.py rviz:=false
# =============================================================================
import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument, IncludeLaunchDescription, TimerAction
from launch.conditions import IfCondition
from launch.launch_description_sources import PythonLaunchDescriptionSource
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node


def generate_launch_description():
    share = get_package_share_directory('physguard')
    slam_params = os.path.join(share, 'config', 'slam_toolbox.yaml')
    slam_rviz = os.path.join(share, 'rviz', 'slam.rviz')
    gazebo_launch = os.path.join(share, 'launch', 'gazebo.launch.py')

    if_rviz = IfCondition(LaunchConfiguration('rviz'))

    return LaunchDescription([
        DeclareLaunchArgument('rviz', default_value='true'),

        # Gazebo world + URDF robot + bridge + pure-pursuit (drives the oval).
        # Its own RViz is suppressed; we open a map-frame RViz below instead.
        IncludeLaunchDescription(
            PythonLaunchDescriptionSource(gazebo_launch),
            launch_arguments={'rviz': 'false'}.items()),

        # slam_toolbox, started once the world and bridge are up
        TimerAction(period=6.0, actions=[
            Node(package='slam_toolbox', executable='async_slam_toolbox_node',
                 name='slam_toolbox', output='screen',
                 parameters=[slam_params, {'use_sim_time': True}]),
        ]),

        Node(package='rviz2', executable='rviz2', name='rviz2',
             arguments=['-d', slam_rviz], output='log', condition=if_rviz),
    ])
