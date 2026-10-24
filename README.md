# Cross-Layer Intrusion Detection for ROS 2 Robotic Networks

An inline intrusion detection and prevention system for ROS 2 mobile robots. It
fuses **network-layer evidence** (who is publishing on the command topic, and
how the publisher set changes) with a **physics-layer check** (is the robot
moving the way its authorized controller told it to). Malicious velocity
commands are caught even when every packet is valid, and blocked before they
reach the motors.

Mini-project for **21ECC402P — Computer Communication and Network Security**,
SRM Institute of Science and Technology, Kattankulathur.
**Shyam Rithin S** (RA2311004010308).

![Robot on the oval track under a hijack attack](docs/fig5_track_attack.png)

---

## The problem

ROS 2 carries all node-to-node data over **DDS**, a publish/subscribe
middleware running on UDP. By default DDS performs **no authentication**: any
process that joins the same domain can publish to `/cmd_vel`, and the robot's
motor driver obeys. An injected command is a well-formed RTPS packet with a
plausible value, so packet inspection cannot separate it from legitimate
traffic.

Existing work covers only half of the picture:

- **ROS 2 / DDS security** (SROS 2, ROSPaCe, RIPS) watches the network and the
  ROS graph, but never the robot's physical motion. SROS 2 is also defeated
  once credentials are stolen (Sakib et al., 2025).
- **Control-theoretic detectors** (CUSUM, χ², dynamic watermarking) watch the
  physical process, but have no notion of publishers or middleware.

This project fuses the two on ROS 2, and shows by ablation that **each layer
detects attacks the other is blind to**.

## How it works

```
 controller ──► /cmd_vel_auth ───────────────────────────┐ (authorized reference)
     │                                                   ▼
     └────────► /cmd_vel_raw ──► [ network layer ] ─┐   [ physics layer ]
                (the wire; an    graph identity,    │   feasibility + residual
                 attacker can    publisher churn    │   + CUSUM
                 publish here)                      ▼          │
                                               [ fusion: OR + latch ] ◄─┘
                                                      │
                                               [ safety filter ] ──► /cmd_vel ──► robot
```

**Network layer.** Every control step it reads the live ROS 2 graph. Any node
publishing on the command topic that is not on the allowlist raises an alarm,
as does an abnormal rate of publisher-set changes.

**Physics layer.**
1. *Feasibility*: is the command finite and inside the robot's velocity and
   acceleration envelope?
2. *Prediction*: the authorized command stream is passed through a
   first-order drive model to predict what the robot should be doing.
3. *Residual*: measured wheel odometry is compared against that prediction.
4. *CUSUM*: `S(k) = max(0, S(k-1) + r(k) − ε)`, alarm when `S > τ`. Benign
   noise drains the statistic to zero; a small persistent attack accumulates
   until it fires.

**Attack-data-free calibration.** For the first 20 s of driving the detector
only observes, then sets `ε = mean + 3σ` of the benign residual. No labelled
attack data is needed, and the threshold re-adapts to whichever plant is
running (built-in simulator, Gazebo or hardware).

**Prevention.** The detector sits inline on the command path. When it fires,
a latched safety filter forwards the authorized command instead of the wire.
It releases only after the wire has agreed with the authorized stream for 3 s
and the network layer is quiet.

## Results

**Live, Gazebo Harmonic digital twin of the robot** (hard-spin injection,
w = 4.0 rad/s at 100 Hz on the command wire while the controller commanded
0.18 rad/s):

- Both layers fired: unknown publisher on `/cmd_vel_raw` (network), and
  |w| > w_max plus CUSUM 3.36 > tau 3.0 (physics)
- Safety filter forwarded the authorized command; the robot returned to the
  racing line on its own
- Threshold calibrated in 20 s of benign driving (eps = 0.010, the floor)
- Simulation fidelity: wheel odometry stays within **0.007 m** of Gazebo ground
  truth (it drifted ~3.8 m before the Gazebo layer was rebuilt)

![RViz2 during the injection: red trail under attack, green after recovery](docs/fig8_rviz_recovery.png)

**Live, ROS 2 Humble, built-in kinematic simulator** (hijack attack, attacker on the
command topic):

| Run | Detected after | Peak deviation | Back on track |
|---|---|---|---|
| Safety filter **on** | 0.02 s | **0.019 m** | 3.1 s |
| Safety filter **off** | 0.02 s | **1.94 m** | 3.1 s |

**Offline evaluation** (`evaluate_offline.py`, `offline_track_sim.py`):

- Auto-calibrated threshold ε ≈ 0.019–0.024 depending on the plant
- **0 false alarms** in 10 benign runs
- Stealthy +0.10 m/s injection, feasible and invisible to the feasibility
  test, detected by CUSUM in **1.95 s**
- Node-name-spoofing hijack (network layer fooled) detected by the physics
  layer in **0.9 s**; peak deviation **0.49 m → 0.11 m** with the filter on

| Attack class | Network only | Physics only | Fused |
|---|---|---|---|
| Garbage / non-finite values | ✓ | ✓ | ✓ |
| Command injection | ✓ | ✓ | ✓ |
| Discovery flood | ✓ | — | ✓ |
| Stealthy drift | ✓ | ✓ | ✓ |
| Compromised / spoofed node | — | ✓ | ✓ |

Figures are in [`docs/`](docs/).

## Quick start

Tested on Ubuntu 22.04, ROS 2 Humble, Gazebo Harmonic.

```bash
# build
mkdir -p ~/physguard_ws/src
cp -r src/physguard ~/physguard_ws/src/
cp tools/ids tools/ids_env.sh tools/fastdds_udp_only.xml ~/physguard_ws/
chmod +x ~/physguard_ws/ids
echo "alias ids='~/physguard_ws/ids'" >> ~/.bashrc && source ~/.bashrc
source /opt/ros/humble/setup.bash
cd ~/physguard_ws && colcon build --symlink-install --packages-select physguard
```

The `ids` helper sources ROS, the workspace and the DDS environment on every
call, so no manual sourcing is needed.

```bash
ids demo                 # terminal 1: bench with built-in simulator + RViz2
ids demo gazebo          #             ... or in Gazebo Harmonic
ids attack               # terminal 2: attacker, idle
ids mode hijack          # terminal 3: start an attack ("IDS armed" first)
ids mode none            #             stop it; robot recovers
ids safety off           #             disable prevention to see the difference
ids spoof                # attacker disguised as the legitimate controller
ids help                 # all commands
```

Gazebo needs the Harmonic bridge (`ros-humble-ros-gzharmonic`). Run `ids clean`
before every relaunch to clear stale `gz sim` / ruby processes.

### Gazebo bench

`ids demo gazebo` brings up a robot-free arena (oval track, walls, obstacles),
spawns the robot with the real wheel geometry (r = 32.5 mm, separation 250 mm),
and couples RViz2 to Gazebo exactly:

- the gz DiffDrive system publishes wheel odometry `/odom` (what the detector
  uses, as on the real robot)
- a gz OdometryPublisher publishes the true pose `/ground_truth` (sim only)
- `sim_frames` publishes `odom -> base_link` from `/odom` and `world -> odom`
  from ground truth, so with RViz fixed frame `world` the robot and lidar scan
  sit exactly where Gazebo has them
- the controller and the scorer use `/ground_truth` by default
  (`pose_topic:=/odom` for the realistic, drifting setup); the detector always
  uses raw `/odom`
- all bridged topics are in `config/gz_bridge.yaml`

`ids slam` maps the arena with slam_toolbox while the robot laps.

## IDS Monitor (evaluation console)

A web dashboard (Python standard library only) that launches a fixed catalogue
of 50 attacks and network-analysis tools by id and shows the detector live:

- dataflow view with the firing layer lit, safety-filter state, allowlisted vs
  rogue publishers
- toolbar toggles for the safety filter and each layer (live ablation)
- live charts: residual vs eps, CUSUM vs tau, wire vs authorized command,
  true track deviation and odometry drift, DDS traffic from the wire collector
- episode scoreboard (detection latency, layer, blocked, peak deviation,
  recovery) and CSV recording / export

```bash
ids console              # http://localhost:8088
ids console --demo       # synthetic feed, no ROS needed (UI preview)
ids console --dry-run    # show commands, launch nothing
```

![IDS Monitor during an injection](docs/fig10_dashboard.png)

## Wireshark

[`wireshark/`](wireshark/) holds a per-user Wireshark profile and a Lua
decoder that turn RTPS packets into readable rows: kind (command wire /
authorized / motors, sensor, discovery), ROS topic, writer number (W1 is the
first writer on a topic, W2+ are extra publishers), and decoded velocity
commands flagged when infeasible.

```bash
bash wireshark/install.sh
ids wireshark            # start BEFORE the bench; captures only the domain's DDS ports
```

Two-laptop setup: [`console/README.md`](console/README.md).

## Repository layout

```
├── src/physguard/            ROS 2 package
│   ├── physguard/            detector_core (IDSDetector, SafetyLatch), ROS node,
│   │                         pure-pursuit controller, attack injector, track
│   │                         geometry + RViz visualisation, built-in simulator,
│   │                         offline evaluation scripts
│   ├── launch/               gazebo.launch.py (Gazebo bench), slam.launch.py,
│   │                         bench.launch.py (built-in simulator), track_demo.launch.py
│   ├── urdf/                 robot description (3-point contact, ground-truth plugin)
│   ├── config/               gz_bridge.yaml, slam_toolbox.yaml
│   ├── worlds/               Gazebo Harmonic arena worlds (generated)
│   ├── rviz/                 RViz2 configs (ids_world.rviz for Gazebo)
│   └── tools/                wire_collector.py (tshark DDS sensor),
│                             gen_track_world.py
├── console/                  IDS Monitor (server, catalogue, UI)
├── wireshark/                ROS2-IDS Wireshark profile + ros2_ids.lua decoder
├── tools/                    ids helper, DDS environment, Fast DDS UDP profile
└── docs/                     result figures, review2/ presentation
```

The ROS package is named `physguard` for historical reasons; it is the
cross-layer IDS.

## Limitations

- Results so far are from simulation. Hardware deployment on a Raspberry Pi 4
  differential-drive robot is the next phase.
- Drive time constants (`tau_v`, `tau_w`) are estimates until identified on
  hardware.
- Attacks slower than about 0.02 m/s are below the detection floor; they also
  barely move the robot.
- The threat model assumes wheel odometry is not itself forged. Sensor
  spoofing is out of scope (IMU cross-checking is future work).
- The authorized command stream is assumed local to the robot; the
  network-exposed path is the wire.
- In the live node the network layer watches publishers on the command topic;
  DDS-wide discovery and traffic rates are measured by the separate wire
  collector and shown on the monitor, but are not yet fused into the detector.
- In the Gazebo bench the residual noise is low enough that the calibrated
  threshold sits at its 0.010 floor; it is recalibrated on hardware.

## Scope and ethics

Every attack targets the author's own robot on an isolated `ROS_DOMAIN_ID`.
This is a defensive evaluation testbed: the attacks exist only to measure the
detector. Do not run them against systems you do not own.

## License

MIT. See [LICENSE](LICENSE).
