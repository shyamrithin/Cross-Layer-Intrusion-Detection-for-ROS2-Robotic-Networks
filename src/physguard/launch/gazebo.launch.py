#!/usr/bin/env python3
# =============================================================================
# File        : gazebo.launch.py
# Package     : physguard
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# =============================================================================
# Description
# -----------
# Full Gazebo Harmonic bench using the proper URDF workflow:
#
#   gz sim ids_world.sdf        robot-free world (track, ground, sun, sensors)
#   robot_state_publisher       publishes /robot_description (xacro-expanded)
#                               and the base_link->{wheels,casters,lidar} TF
#   ros_gz_sim create           spawns the robot into Gazebo from that topic
#   ros_gz_bridge               /clock /cmd_vel /odom /tf /scan
#   pure_pursuit, physguard_node, track_viz, rviz2
#
# The gz DiffDrive plugin in the URDF consumes /cmd_vel and publishes /odom and
# the odom->base_link TF, so the detector, controller and RViz see exactly the
# same interface they will see on the real robot.
#
#   ros2 launch physguard gazebo.launch.py
#   ros2 launch physguard gazebo.launch.py attacker:=true rviz:=false
# =============================================================================
import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument, ExecuteProcess, TimerAction
from launch.conditions import IfCondition
from launch.substitutions import LaunchConfiguration, Command
from launch_ros.actions import Node
from launch_ros.parameter_descriptions import ParameterValue


def generate_launch_description():
    share = get_package_share_directory('physguard')
    world = os.path.join(share, 'worlds', 'ids_world.sdf')
    xacro_file = os.path.join(share, 'urdf', 'ids_robot.urdf.xacro')
    rviz_cfg = os.path.join(share, 'rviz', 'ids.rviz')

    robot_description = ParameterValue(
        Command(['xacro ', xacro_file]), value_type=str)

    if_rviz = IfCondition(LaunchConfiguration('rviz'))
    if_attacker = IfCondition(LaunchConfiguration('attacker'))

    return LaunchDescription([
        DeclareLaunchArgument('rviz', default_value='true'),
        DeclareLaunchArgument('calibrate', default_value='20.0'),
        DeclareLaunchArgument('attacker', default_value='false'),

        # ---- Gazebo Harmonic ----
        ExecuteProcess(cmd=['gz', 'sim', '-r', world], output='screen'),

        # ---- robot description + TF ----
        Node(package='robot_state_publisher', executable='robot_state_publisher',
             name='robot_state_publisher', output='screen',
             parameters=[{'robot_description': robot_description,
                          'use_sim_time': True}]),

        # ---- spawn the robot into Gazebo from /robot_description ----
        Node(package='ros_gz_sim', executable='create', name='spawn_ids_robot',
             output='screen',
             arguments=['-topic', 'robot_description', '-name', 'ids_robot',
                        '-x', '0', '-y', '0', '-z', '0.05']),

        # ---- ROS <-> Gazebo bridge ----
        Node(package='ros_gz_bridge', executable='parameter_bridge', name='gz_bridge',
             output='screen',
             arguments=[
                 '/clock@rosgraph_msgs/msg/Clock[gz.msgs.Clock',
                 '/cmd_vel@geometry_msgs/msg/Twist]gz.msgs.Twist',
                 '/odom@nav_msgs/msg/Odometry[gz.msgs.Odometry',
                 '/tf@tf2_msgs/msg/TFMessage[gz.msgs.Pose_V',
                 '/scan@sensor_msgs/msg/LaserScan[gz.msgs.LaserScan',
                 '/joint_states@sensor_msgs/msg/JointState[gz.msgs.Model',
             ],
             parameters=[{'use_sim_time': True}]),

        # ---- controller, IDS, visualisation (started after the world settles) ----
        TimerAction(period=3.0, actions=[
            Node(package='physguard', executable='pure_pursuit', name='pure_pursuit',
                 output='screen', parameters=[{'use_sim_time': True}]),
            Node(package='physguard', executable='physguard_node', name='physguard',
                 output='screen',
                 parameters=[{'auto_calibrate_s': LaunchConfiguration('calibrate'),
                              'use_sim_time': True}]),
            Node(package='physguard', executable='track_viz', name='track_viz',
                 output='screen', parameters=[{'use_sim_time': True}]),
            Node(package='physguard', executable='attack_injector', name='attack_injector',
                 output='screen', parameters=[{'mode': 'none', 'use_sim_time': True}],
                 condition=if_attacker),
        ]),

        Node(package='rviz2', executable='rviz2', name='rviz2',
             arguments=['-d', rviz_cfg], output='log', condition=if_rviz),
    ])
