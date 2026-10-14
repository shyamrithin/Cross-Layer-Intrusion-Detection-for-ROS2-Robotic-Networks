# IDS — Review 1 Runbook

## 0. Before anything (2 min)

```bash
sudo tailscale down                 # Tailscale breaks DDS discovery
export ROS_DOMAIN_ID=42             # isolate from the NXP B3RB stack
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
pkill -f "gz sim"; pkill -f ruby    # clear stale Gazebo if it ran earlier
```

## 1. Build (3 min)

```bash
mkdir -p ~/physguard_ws/src && cd ~/physguard_ws/src
cp -r /path/to/physguard .
cd ~/physguard_ws && colcon build --symlink-install
source install/setup.bash
```

## 2. Run the demo (1 terminal + 3 small ones)

**T1 — the stack**
```bash
ros2 launch physguard demo.launch.py
```

**T2 — RViz2**
```bash
rviz2
# Add: TF, MarkerArray on /physguard/markers, Odometry on /odom
# Fixed frame: odom
```

**T3 — live plots**
```bash
ros2 run rqt_plot rqt_plot /physguard/residual/data /physguard/cusum/data
```

**T4 — the attack console (this is what you drive during the review)**
```bash
# baseline, let it run 20 s clean first
ros2 param set /attack_injector mode inject      # crude takeover
ros2 param set /attack_injector mode stealth     # feasible, slow burn
ros2 param set /attack_injector mode compromise  # network layer blind
ros2 param set /attack_injector mode flood       # physics layer blind
ros2 param set /attack_injector mode none        # stand down

# the ablation — this is the money shot
ros2 param set /physguard phy_enabled false      # watch compromise go undetected
ros2 param set /physguard phy_enabled true       # watch it get caught
ros2 param set /physguard net_enabled false      # watch flood go undetected

# safety layer on/off
ros2 param set /physguard safety_enabled false   # robot obeys the attacker
ros2 param set /physguard safety_enabled true    # robot holds its safe path
```

Watch: `/physguard/status` prints the reason string.
```bash
ros2 topic echo /physguard/status
```

## 3. The 4-minute demo script for the reviewer

1. **Baseline (30 s).** Robot patrols. Residual flat, status CLEAR.
2. **"ROS 2 has no publisher authentication."** Start `inject`. Robot lurches;
   detector fires instantly; feasibility violated. Point at the reason string.
3. **"But a smart attacker stays feasible."** Switch to `stealth`. Feasibility
   check stays silent — CUSUM climbs and fires ~2 s later. This is the paper's
   core mechanism.
4. **The blind spots.** `compromise` with `net_enabled false` → missed.
   Re-enable physics → caught. Then `flood` with `phy_enabled false` → missed,
   network catches it. **Each layer covers the other's blind spot.**
5. **Safety layer.** Toggle `safety_enabled` during `inject` and show the
   trajectory in RViz staying on the patrol path vs. being driven off.

## 4. If Gazebo is wanted

`use_fake:=false` and launch your articubot_one sim instead; the stack only
needs `/odom` in and `/cmd_vel` out. **Do not attempt this the night before.**

## 5. Regenerate the figures

```bash
cd physguard/physguard && python3 evaluate_offline.py --outdir ../figs
```
