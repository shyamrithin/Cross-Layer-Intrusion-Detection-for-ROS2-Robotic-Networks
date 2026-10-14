#!/usr/bin/env python3
# =============================================================================
# File        : demo.launch.py
# Package     : physguard
# Description : Brings up the complete IDS demonstration: simulated
#               differential-drive robot, legitimate patrol controller, idle
#               attack injector, and the cross-layer detector. Launch RViz2
#               separately with the provided config. Set use_fake:=false to
#               drive Gazebo or real hardware instead.
# =============================================================================
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument
from launch.conditions import IfCondition
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node


def generate_launch_description():
    use_fake = LaunchConfiguration('use_fake')
    return LaunchDescription([
        DeclareLaunchArgument('use_fake', default_value='true',
                              description='use built-in sim instead of Gazebo'),
        Node(package='physguard', executable='fake_robot', name='fake_robot',
             condition=IfCondition(use_fake), output='screen'),
        Node(package='physguard', executable='patrol_controller',
             name='patrol_controller', output='screen'),
        Node(package='physguard', executable='attack_injector',
             name='attack_injector', output='screen'),
        Node(package='physguard', executable='physguard_node',
             name='physguard', output='screen'),
    ])
