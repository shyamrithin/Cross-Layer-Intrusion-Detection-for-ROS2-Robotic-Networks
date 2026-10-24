#!/usr/bin/env python3
# =============================================================================
# File        : gazebo.launch.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# =============================================================================
# Description
# -----------
# The Gazebo Harmonic IDS bench, rebuilt so RViz and Gazebo can never disagree.
#
#   gz sim ids_world.sdf      robot-free arena (oval track, walls, obstacles)
#   robot_state_publisher     /robot_description + fixed robot TF
#   ros_gz_bridge             config/gz_bridge.yaml (one file, no /tf bridge)
#   sim_frames                odom->base_link from wheel /odom,
#                             world->odom from Gazebo /ground_truth
#   ros_gz_sim create         spawns the robot at the origin, wheels on the ground
#   --- once the spawn has completed (event, not a guess) + 2 s to settle ---
#   pure_pursuit              drives the oval
#   physguard_node            the IDS + safety filter, on raw wheel /odom
#   track_viz                 track, trail, metrics
#   attack_injector           optional
#   rviz2                     fixed frame 'world' (rviz/ids_world.rviz)
#
# Frames:  world -> odom -> base_link -> {wheels, caster, lidar_link}
#   world->odom is the wheel-odometry correction taken from Gazebo, so in RViz
#   the robot model and the laser scan sit exactly where Gazebo has the robot.
#
# Which pose drives what
#   detector (physguard_node)   /odom          always - the real-robot input
#   controller + track_viz      pose_topic     default /ground_truth
#     pose_topic:=/ground_truth  clean laps; deviation and recovery metrics
#                                are measured against the TRUE pose
#     pose_topic:=/odom          realistic: controller trusts wheel odometry
#                                and the robot drifts like a real one would
#
#   ros2 launch physguard gazebo.launch.py
#   ros2 launch physguard gazebo.launch.py attacker:=true
#   ros2 launch physguard gazebo.launch.py pose_topic:=/odom
# =============================================================================
import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import (DeclareLaunchArgument, ExecuteProcess, LogInfo,
                            RegisterEventHandler, TimerAction)
from launch.conditions import IfCondition
from launch.event_handlers import OnProcessExit
from launch.substitutions import Command, LaunchConfiguration, PythonExpression
from launch_ros.actions import Node
from launch_ros.parameter_descriptions import ParameterValue

# base_link is at the wheel axle; spawn it at wheel-radius height (+1 mm) so
# the robot starts resting on its wheels instead of dropping onto them.
SPAWN_Z = '0.0335'


def generate_launch_description():
    share = get_package_share_directory('physguard')
    world = os.path.join(share, 'worlds', 'ids_world.sdf')
    xacro_file = os.path.join(share, 'urdf', 'ids_robot.urdf.xacro')
    bridge_cfg = os.path.join(share, 'config', 'gz_bridge.yaml')
    rviz_cfg = os.path.join(share, 'rviz', 'ids_world.rviz')

    rviz = LaunchConfiguration('rviz')
    attacker = LaunchConfiguration('attacker')
    pose_topic = LaunchConfiguration('pose_topic')
    world_tf = LaunchConfiguration('world_tf')
    # track_viz draws in whichever frame its pose source is expressed in
    viz_frame = PythonExpression(
        ["'world' if '", pose_topic, "' == '/ground_truth' else 'odom'"])

    robot_description = ParameterValue(Command(['xacro ', xacro_file]), value_type=str)
    sim = {'use_sim_time': True}

    spawn = Node(
        package='ros_gz_sim', executable='create', name='spawn_ids_robot', output='screen',
        arguments=['-topic', 'robot_description', '-name', 'ids_robot',
                   '-x', '0', '-y', '0', '-z', SPAWN_Z, '-Y', '0'])

    after_spawn = [
        LogInfo(msg='[ids] robot spawned - starting controller and IDS in 2 s'),
        TimerAction(period=2.0, actions=[
            Node(package='physguard', executable='pure_pursuit', name='pure_pursuit',
                 output='screen', parameters=[sim],
                 remappings=[('odom', pose_topic)]),
            Node(package='physguard', executable='physguard_node', name='physguard',
                 output='screen',
                 parameters=[{'auto_calibrate_s': LaunchConfiguration('calibrate')}, sim]),
            Node(package='physguard', executable='track_viz', name='track_viz',
                 output='screen', parameters=[{'frame': viz_frame}, sim],
                 remappings=[('odom', pose_topic)]),
            Node(package='physguard', executable='attack_injector', name='attack_injector',
                 output='screen', parameters=[{'mode': 'none'}, sim],
                 condition=IfCondition(attacker)),
        ]),
    ]

    return LaunchDescription([
        DeclareLaunchArgument('rviz', default_value='true'),
        DeclareLaunchArgument('calibrate', default_value='20.0',
                              description='benign calibration window (s)'),
        DeclareLaunchArgument('attacker', default_value='false'),
        DeclareLaunchArgument('pose_topic', default_value='/ground_truth',
                              description='/ground_truth or /odom for controller + track_viz'),
        DeclareLaunchArgument('world_tf', default_value='true',
                              description='publish world->odom (false when SLAM owns odom)'),

        # ---- simulator ----
        ExecuteProcess(cmd=['gz', 'sim', '-r', world], output='screen'),

        # ---- robot description, bridge, frames ----
        Node(package='robot_state_publisher', executable='robot_state_publisher',
             name='robot_state_publisher', output='screen',
             parameters=[{'robot_description': robot_description}, sim]),
        Node(package='ros_gz_bridge', executable='parameter_bridge', name='gz_bridge',
             output='screen', parameters=[{'config_file': bridge_cfg}, sim]),
        Node(package='physguard', executable='sim_frames', name='sim_frames',
             output='screen', parameters=[{'publish_world_odom': world_tf}, sim]),

        # ---- spawn, then everything that drives or watches the robot ----
        spawn,
        RegisterEventHandler(OnProcessExit(target_action=spawn, on_exit=after_spawn)),

        # ---- visualisation ----
        Node(package='rviz2', executable='rviz2', name='rviz2',
             arguments=['-d', rviz_cfg], output='log', parameters=[sim],
             condition=IfCondition(rviz)),
    ])
