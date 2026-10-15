# Attack / analysis console

A small web dashboard for **evaluating** the cross-layer IDS. It launches a
fixed catalogue of attacks and network-analysis tools against your own robot,
shows the exact command for each, streams output, and displays the live
detector verdict. No Flask, no build step — Python standard library only.

## Topology

```
   Laptop A (robot)                     Laptop B (attacker + analyst)
 ┌────────────────────┐    DDS /       ┌──────────────────────────┐
 │ Gazebo + RViz2     │    domain 42   │ ids_console.py  :8088     │
 │ pure_pursuit       │◀──────────────▶│  browser dashboard        │
 │ IDS + safety filter│    LAN/switch  │  attacks + tshark/nmap/…  │
 └────────────────────┘                └──────────────────────────┘
```

Run the console on Laptop B; open its dashboard from any browser on the lab
network. Attacks published from B reach A over DDS, which is the realistic
two-machine attack.

## Run

```bash
# source the same ROS 2 env as the robot (so ROS_DOMAIN_ID and the DDS profile match)
source /opt/ros/humble/setup.bash
source ~/physguard_ws/install/setup.bash
source ~/physguard_ws/ids_env.sh   # or wherever ids_env.sh lives

cd console
python3 ids_console.py                 # http://<laptop-B-ip>:8088
python3 ids_console.py --dry-run       # preview commands only, launch nothing
python3 ids_console.py --status-topic /physguard/status --track-topic /track/state
```

## Before a two-laptop run

1. Put both laptops on a network that passes **multicast** between clients —
   a dedicated travel router, an ethernet switch, or a phone hotspot. **Campus
   Wi-Fi usually blocks client-to-client multicast**, which breaks DDS
   discovery.
2. In `fastdds_udp_only.xml`, **remove the `127.0.0.1` interface whitelist** (or
   replace it with each laptop's LAN address) so DDS uses the real interface.
3. Set the same `ROS_DOMAIN_ID=42` on both.
4. Edit the `config` block in `attacks.json`: `robot_ip`, `iface`, `rtps_port`
   (domain 42 → user-data port ~17912).

## Catalogue

`attacks.json` — 26 attacks in four categories plus 5 tools. Each entry
declares the detector layer **expected** to catch it (`physics`, `network`, or
`none` for passive/out-of-scope), so the console doubles as the cross-layer
scoreboard. Add an attack by appending one JSON object; no code change.

## Safety model

- **ID-based only.** The browser sends an attack *id*; the server runs the
  fixed command bound to that id in `attacks.json`. Arbitrary text from the
  browser is never executed — this is a controlled test bench, not a shell.
- Entries marked `sudo/danger` need elevated privileges (hping3, tc); entries
  marked `robot host` must be run on Laptop A, not the attacker.
- Lab use only, against your own robot on an isolated domain.
