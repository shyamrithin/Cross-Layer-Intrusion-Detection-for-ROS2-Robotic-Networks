#!/usr/bin/env python3
# =============================================================================
# File        : gen_track_world.py
# Package     : physguard (tools)
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# =============================================================================
# Description
# -----------
# Generates worlds/oval_track.sdf for Gazebo Harmonic (gz sim 8).
#
# The world contains
#   - a ground plane and sun
#   - a visual-only oval track (asphalt surface, white edge lines, start line)
#     built from the same OvalTrack geometry the controller uses, so the
#     Gazebo track and the RViz2 track are identical by construction
#   - a differential-drive robot matching the articubot_one parameters:
#     wheel radius 32.5 mm, wheel separation 250 mm, two casters, driven by
#     the gz-sim DiffDrive system. It listens on /cmd_vel and publishes
#     /odom and /tf (odom -> base_link) through ros_gz_bridge.
#
# The robot spawns at the world origin facing +x, which is the middle of the
# bottom straight, so the odometry frame coincides with the track frame.
#
# Usage: python3 gen_track_world.py [--out ../worlds/oval_track.sdf]
# =============================================================================
import argparse
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "physguard"))
from track import OvalTrack  # noqa: E402


def box_visual(name, x, y, yaw, sx, sy, z, rgb):
    r, g, b = rgb
    return f"""      <visual name="{name}">
        <pose>{x:.4f} {y:.4f} {z:.4f} 0 0 {yaw:.5f}</pose>
        <geometry><box><size>{sx:.4f} {sy:.4f} 0.002</size></box></geometry>
        <material><ambient>{r} {g} {b} 1</ambient><diffuse>{r} {g} {b} 1</diffuse></material>
      </visual>
"""


def track_model(t):
    L, R, W = t.L, t.R, t.width
    asphalt, white, start = (0.22, 0.23, 0.25), (0.95, 0.95, 0.95), (0.9, 0.15, 0.15)
    v = []
    # straights
    for k, yc in enumerate((0.0, 2 * R)):
        v.append(box_visual(f"straight_{k}", 0.0, yc, 0.0, L, W, 0.001, asphalt))
        for s, d in (("in", W / 2), ("out", -W / 2)):
            v.append(box_visual(f"line_{k}_{s}", 0.0, yc + d, 0.0, L, 0.04, 0.002, white))
    # arcs
    n = 36
    for side, cx, a0 in (("r", L / 2, -math.pi / 2), ("l", -L / 2, math.pi / 2)):
        for i in range(n):
            a = a0 + math.pi * (i + 0.5) / n
            da = math.pi / n
            yaw = a + math.pi / 2
            seg = (R + W / 2) * da * 1.04
            v.append(box_visual(f"arc_{side}_{i}", cx + R * math.cos(a), R + R * math.sin(a),
                                yaw, seg, W, 0.001, asphalt))
            for s, rr in (("in", R - W / 2), ("out", R + W / 2)):
                v.append(box_visual(f"arcline_{side}_{i}_{s}", cx + rr * math.cos(a),
                                    R + rr * math.sin(a), yaw, rr * da * 1.06, 0.04,
                                    0.002, white))
    v.append(box_visual("start_line", -0.25, 0.0, 0.0, 0.06, W, 0.003, start))
    return f"""    <model name="oval_track">
      <static>true</static>
      <link name="surface">
{''.join(v)}      </link>
    </model>
"""


ROBOT = """    <model name="ids_robot">
      <pose>0 0 0 0 0 0</pose>
      <link name="base_link">
        <pose>0 0 0.06 0 0 0</pose>
        <inertial>
          <mass>1.5</mass>
          <inertia><ixx>0.0065</ixx><iyy>0.0117</iyy><izz>0.0173</izz>
            <ixy>0</ixy><ixz>0</ixz><iyz>0</iyz></inertia>
        </inertial>
        <collision name="chassis_collision">
          <geometry><box><size>0.30 0.22 0.06</size></box></geometry>
        </collision>
        <visual name="chassis_visual">
          <geometry><box><size>0.30 0.22 0.06</size></box></geometry>
          <material><ambient>0.08 0.31 0.61 1</ambient><diffuse>0.08 0.31 0.61 1</diffuse></material>
        </visual>
        <visual name="front_marker">
          <pose>0.13 0 0.035 0 0 0</pose>
          <geometry><box><size>0.04 0.18 0.01</size></box></geometry>
          <material><ambient>0.95 0.95 0.95 1</ambient><diffuse>0.95 0.95 0.95 1</diffuse></material>
        </visual>
        <visual name="lidar_visual">
          <pose>0.02 0 0.05 0 0 0</pose>
          <geometry><cylinder><radius>0.04</radius><length>0.04</length></cylinder></geometry>
          <material><ambient>0.1 0.1 0.1 1</ambient><diffuse>0.1 0.1 0.1 1</diffuse></material>
        </visual>
        <!-- casters sit 3 mm above the ground so the drive wheels carry the load;
             with all four contacts coplanar the wheels lose traction and slip -->
        <collision name="front_caster">
          <pose>0.11 0 -0.037 0 0 0</pose>
          <geometry><sphere><radius>0.02</radius></sphere></geometry>
          <surface><friction><ode><mu>0.0</mu><mu2>0.0</mu2></ode></friction></surface>
        </collision>
        <collision name="rear_caster">
          <pose>-0.11 0 -0.037 0 0 0</pose>
          <geometry><sphere><radius>0.02</radius></sphere></geometry>
          <surface><friction><ode><mu>0.0</mu><mu2>0.0</mu2></ode></friction></surface>
        </collision>
      </link>
WHEELS
      <plugin filename="gz-sim-diff-drive-system" name="gz::sim::systems::DiffDrive">
        <left_joint>left_wheel_joint</left_joint>
        <right_joint>right_wheel_joint</right_joint>
        <wheel_separation>0.25</wheel_separation>
        <wheel_radius>0.0325</wheel_radius>
        <odom_publish_frequency>50</odom_publish_frequency>
        <topic>/cmd_vel</topic>
        <odom_topic>/odom</odom_topic>
        <tf_topic>/tf</tf_topic>
        <frame_id>odom</frame_id>
        <child_frame_id>base_link</child_frame_id>
        <max_linear_acceleration>1.6</max_linear_acceleration>
        <min_linear_acceleration>-1.6</min_linear_acceleration>
        <max_angular_acceleration>4.0</max_angular_acceleration>
        <min_angular_acceleration>-4.0</min_angular_acceleration>
      </plugin>
      <plugin filename="gz-sim-joint-state-publisher-system"
              name="gz::sim::systems::JointStatePublisher"/>
    </model>
"""


def wheel(side, y):
    return f"""      <link name="{side}_wheel">
        <pose>0 {y} 0.0325 -1.5707963 0 0</pose>
        <inertial>
          <mass>0.1</mass>
          <inertia><ixx>2.97e-5</ixx><iyy>2.97e-5</iyy><izz>5.28e-5</izz>
            <ixy>0</ixy><ixz>0</ixz><iyz>0</iyz></inertia>
        </inertial>
        <collision name="collision">
          <geometry><cylinder><radius>0.0325</radius><length>0.02</length></cylinder></geometry>
          <surface><friction><ode><mu>1.0</mu><mu2>1.0</mu2></ode></friction></surface>
        </collision>
        <visual name="visual">
          <geometry><cylinder><radius>0.0325</radius><length>0.02</length></cylinder></geometry>
          <material><ambient>0.12 0.12 0.12 1</ambient><diffuse>0.12 0.12 0.12 1</diffuse></material>
        </visual>
      </link>
      <joint name="{side}_wheel_joint" type="revolute">
        <parent>base_link</parent>
        <child>{side}_wheel</child>
        <axis><xyz expressed_in="__model__">0 1 0</xyz></axis>
      </joint>
"""


def world(t, with_robot=True, name="oval_track"):
    robot = ROBOT.replace("WHEELS", wheel("left", 0.125) + wheel("right", -0.125)) \
        if with_robot else ""
    sensors = "" if with_robot else (
        '    <plugin filename="gz-sim-sensors-system" '
        'name="gz::sim::systems::Sensors">\n'
        '      <render_engine>ogre2</render_engine>\n'
        '    </plugin>\n')
    return f"""<?xml version="1.0" ?>
<!--
================================================================================
 File        : oval_track.sdf   (generated by tools/gen_track_world.py)
 Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
 Author      : Shyam Rithin S
 Description : Gazebo Harmonic world with an oval track ({t.L:.1f} m straights,
               {t.R:.1f} m radius, {t.width:.1f} m wide) and a differential-drive
               robot matching articubot_one (r = 32.5 mm, separation 250 mm).
               with_robot=False emits a robot-free world for the URDF
               spawn workflow (adds the gz Sensors system for the lidar).
               Do not edit by hand; regenerate instead.
================================================================================
-->
<sdf version="1.9">
  <world name="{name}">
    <physics name="1ms" type="ignored">
      <max_step_size>0.001</max_step_size>
      <real_time_factor>1.0</real_time_factor>
    </physics>
    <plugin filename="gz-sim-physics-system" name="gz::sim::systems::Physics"/>
    <plugin filename="gz-sim-user-commands-system" name="gz::sim::systems::UserCommands"/>
    <plugin filename="gz-sim-scene-broadcaster-system" name="gz::sim::systems::SceneBroadcaster"/>
{sensors}
    <gui fullscreen="0">
      <camera name="user_camera">
        <pose>0 -7.5 7.0 0 0.72 1.5708</pose>
      </camera>
    </gui>

    <light type="directional" name="sun">
      <cast_shadows>true</cast_shadows>
      <pose>0 0 10 0 0 0</pose>
      <diffuse>0.9 0.9 0.9 1</diffuse>
      <specular>0.2 0.2 0.2 1</specular>
      <direction>-0.4 0.2 -0.9</direction>
    </light>

    <model name="ground_plane">
      <static>true</static>
      <link name="link">
        <collision name="collision">
          <geometry><plane><normal>0 0 1</normal><size>40 40</size></plane></geometry>
        </collision>
        <visual name="visual">
          <geometry><plane><normal>0 0 1</normal><size>40 40</size></plane></geometry>
          <material><ambient>0.36 0.52 0.34 1</ambient><diffuse>0.36 0.52 0.34 1</diffuse></material>
        </visual>
      </link>
    </model>

{track_model(t)}
{robot}
  </world>
</sdf>
"""


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    here = os.path.dirname(__file__)
    worlds = os.path.join(here, "..", "worlds")
    ap.add_argument("--out", default=None, help="single output path (legacy)")
    a = ap.parse_args()
    os.makedirs(worlds, exist_ok=True)
    t = OvalTrack()
    if a.out:
        open(a.out, "w").write(world(t))
        print("written", a.out); raise SystemExit
    # robot-free world for the URDF spawn workflow (the proper structure)
    open(os.path.join(worlds, "ids_world.sdf"), "w").write(
        world(t, with_robot=False, name="ids_world"))
    # legacy world with the robot embedded, kept for backward compatibility
    open(os.path.join(worlds, "oval_track.sdf"), "w").write(
        world(t, with_robot=True, name="oval_track"))
    print("written worlds/ids_world.sdf and worlds/oval_track.sdf")
