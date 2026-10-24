# Wireshark view for the ROS 2 IDS bench

A per-user Wireshark profile (`ROS2-IDS`) and a Lua post-dissector (`ros2_ids.lua`)
that turn raw RTPS (DDS) packets into readable ROS 2 rows. Nothing in the system
Wireshark installation is changed.

## Install

```bash
bash wireshark/install.sh      # profile -> ~/.config/wireshark/profiles/ROS2-IDS
                               # plugin  -> ~/.local/lib/wireshark/plugins/ros2_ids.lua
```

Check: Help > About Wireshark > Plugins lists `ros2_ids.lua`.

## Run

Start it **before** the bench, so topic names are learned from discovery:

```bash
ids clean
ids wireshark        # captures only UDP 17900-18149 (domain 42) on lo, opens the demo view
ids demo gazebo
```

## What you see

Columns: No. | Time | Port | Kind | Topic | Writer | Summary | Len

- **Kind**: CMD wire (/cmd_vel_raw), CMD auth (/cmd_vel_auth), CMD motors (/cmd_vel),
  IDS, SENSOR, SIM (/clock), VIZ, DISCOVERY, RELIABILITY
- **Writer**: W1, W2, ... = n-th distinct writer seen on that topic in the capture.
  The controller starts first, so on /cmd_vel_raw W1 is the controller and W2+ are
  extra publishers.
- **Summary**: decoded geometry_msgs/Twist values (v, w) on command topics, flagged
  `!! INFEASIBLE` beyond |v| 1.2 m/s or |w| 2.5 rad/s; plain-language discovery events.

Filter buttons: Demo view, Commands, Wire, Wire vs motors, Extra writers, Infeasible,
Discovery, IDS, All.

Remove: `rm -rf ~/.config/wireshark/profiles/ROS2-IDS ~/.local/lib/wireshark/plugins/ros2_ids.lua`
