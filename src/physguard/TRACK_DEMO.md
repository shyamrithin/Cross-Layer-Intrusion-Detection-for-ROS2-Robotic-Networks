# Track Demo — Review 2

Robot drives an oval track in Gazebo and RViz2, gets attacked, the IDS catches it,
the safety filter blocks it, and the robot stays on (or returns to) the track.

---

## 0. One-time setup (≈10 min)

```bash
# 1. ROS-Gazebo bridge for Humble + Harmonic (skip if already installed)
ros2 pkg prefix ros_gz_bridge || sudo apt install -y ros-humble-ros-gzharmonic

# 2. Unpack the package into your workspace
mkdir -p ~/physguard_ws/src
tar -xzf ~/Downloads/physguard_pkg.tar.gz -C ~/physguard_ws/src
cd ~/physguard_ws && colcon build --symlink-install --packages-select physguard
```

If `ros-humble-ros-gzharmonic` conflicts with an installed `ros-humble-ros-gz`,
remove the latter first, or just use `sim:=fake` below.

## 1. Every terminal

```bash
source /opt/ros/humble/setup.bash
source ~/physguard_ws/install/setup.bash
source ~/physguard_ws/ids_env.sh
```

Before every Gazebo launch, clear stale processes:

```bash
pkill -f "gz sim"; pkill -f ruby; pkill -f cerebri; ros2 daemon stop
```

## 2. Launch

**T1 — everything except the attacker**
```bash
ros2 launch physguard track_demo.launch.py              # Gazebo + RViz2
# fallback, no Gazebo:
ros2 launch physguard track_demo.launch.py sim:=fake
```

The robot starts driving immediately. For the first **20 s** the IDS is learning
normal behaviour (`CALIBRATING` above the robot). Wait for the log line:

```
calibration done: ... threshold eps = 0.0xxx. IDS armed.
```

**T2 — the attacker (separate process, on purpose)**
```bash
ros2 run physguard attack_injector
```

**T3 — controls**
```bash
ros2 param set /attack_injector mode hijack     # attack
ros2 param set /attack_injector mode none       # stop
ros2 param set /physguard safety_enabled false  # let attacks through
ros2 param set /physguard safety_enabled true
```

**T4 (optional) — live plots**
```bash
ros2 run rqt_plot rqt_plot /track/xte/data /physguard/cusum/data
```

**T5 (optional) — the wire view, start BEFORE T1**
```bash
cd ~/physguard_ws/tools && python3 wire_collector.py --domain 42 --iface any
```

## 3. The 5-minute demo script

| Step | Command (T3) | What they see | What you say |
|---|---|---|---|
| 1 | — | Green robot lapping the track | "Normal operation. The IDS spent 20 s learning what normal looks like, no attack data." |
| 2 | `safety_enabled false`, then `mode hijack` | Robot swerves off the track, trail turns red, `DETECTED +x.xs` pin | "A separate process is publishing to the robot's command topic. DDS has no authentication, so the robot obeys. The IDS detects it, but I've switched the safety filter off." |
| 3 | `mode none` | Amber trail, robot returns, `RECOVERED` pin; T1 log prints detection, peak deviation, recovery time | "Pure pursuit is closed loop, so once the attack stops it brings the robot back." |
| 4 | `safety_enabled true`, then `mode hijack` | Robot barely leaves the track | "Same attack, safety filter on. The command is replaced by the authorised one, so the attack has almost no effect." |
| 5 | `mode none` | Alarm clears 3 s later | "It releases only after the wire has matched the authorised stream for 3 s." |
| 6 | stop T2, restart as `ros2 run physguard attack_injector --ros-args -r __node:=pure_pursuit`, then `mode hijack` | Still detected | "Now the attacker uses the legitimate node's name, so the ROS graph check is fooled. The physics layer still sees the robot not doing what it was told, and the wire collector sees two writers." |

Have a screen recording of a good run ready in case the live demo misbehaves.

## 4. Troubleshooting

| Symptom | Fix |
|---|---|
| Robot doesn't move | `ros2 topic echo /odom --once`. Nothing → bridge not running or Gazebo paused (the launch uses `-r` to start it). |
| Gazebo opens but robot falls/spins | Use `sim:=fake` for the review; debug after. |
| `IDS armed` never printed | Launched with `calibrate:=20` (integer). Use `calibrate:=20.0`. |
| Alarm on with no attack | An old attacker is still running somewhere: `ros2 node list`. |
| Nothing visible in RViz | Fixed Frame must be `odom`; check `ros2 topic hz /track/markers`. |
