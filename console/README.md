# IDS Monitor — attack / analysis console

A standard-library web dashboard for **evaluating** the cross-layer IDS. It
launches a fixed catalogue of attacks and tools against your own robot, drives
the detector's controls, streams live charts, scores each attack episode, and
records everything to CSV. No Flask, no build step — Python standard library
and one static page.

## Run

```bash
# source the same ROS 2 env as the bench (ROS_DOMAIN_ID + DDS profile match)
source /opt/ros/humble/setup.bash
source ~/physguard_ws/install/setup.bash
source ~/physguard_ws/ids_env.sh

cd console
python3 ids_console.py            # http://localhost:8088
python3 ids_console.py --demo     # synthetic feed, no ROS/Gazebo needed (UI preview)
python3 ids_console.py --dry-run  # show commands, launch nothing
```

The `ids console` helper sources the environment and runs this for you.

## What it shows

- **Toolbar toggles** — Safety filter, Network layer, Physics layer. Each one
  calls `ros2 param set /physguard <name> <bool>`, so you flip the safety
  filter or ablate a layer from the dashboard (the Detector menu does the same).
- **Detector dataflow** — Controller → Wire → Network / Physics → Fusion →
  Safety filter → Robot, with the firing component lit.
- **Live charts** (rolling 120 s): residual r vs ε, CUSUM S vs τ, commanded ω
  (wire vs authorized), **track deviation from the true pose and wheel-odom
  drift**, and **DDS traffic** (packets/s and endpoint announcements/s) when a
  wire capture is running. Attack windows are shaded; detection is marked.
- **Safety filter panel** — engaged / bypassed, what is driving the motors.
- **Publishers** on `/cmd_vel_raw`, allowlisted vs rogue.
- **Episode scoreboard** — every attack scored: detection latency, layer,
  blocked or not, **peak deviation**, recovery time. Run an attack with the
  Safety toggle on, then off; the two rows are your safety-on-vs-off result.
- **Event log** — a packet-list of detector alarms, blocks/releases, publisher
  changes, wire alerts and launches; click a row for detail.

## Capture (Wireshark)

- **Capture ▸ Start wire capture** runs the tshark RTPS collector; its
  per-second metrics feed the DDS-traffic chart and the wire alerts
  (multi-writer, discovery flood, endpoint churn) go to the event log. It
  writes `logs/wire_<time>.csv`.
- **Capture ▸ Open Wireshark** opens Wireshark live on the capture interface
  with the `rtps` display filter. During a flood, `Statistics ▸ I/O Graphs`
  shows the attack traffic. Useful display filters:
  - `rtps` — all ROS 2 / DDS traffic
  - `rtps.sm.id == 0x15` — command DATA submessages
  - `rtps.sm.wrEntityId == 0x000003c2` — endpoint announcements (flood)
- Single laptop: all DDS is on loopback, so capture on **`lo`**.

## Recording

- **Record** (toolbar) writes every telemetry sample to
  `logs/session_<time>.csv` — the time series behind the charts, for report
  figures.
- **Capture ▸ Export sample history / episode table** download the current
  in-memory data as CSV without stopping anything.

## Configuration — `attacks.json`

The `config` block is filled into every command. Defaults are set for a
**single laptop**:

```json
"robot_ip": "127.0.0.1",
"iface": "lo",
"domain": "42"
```

Two laptops: set `robot_ip` to the robot's LAN address, `iface` to your
Wi-Fi/Ethernet interface, put both machines on a multicast-passing network,
and remove the `127.0.0.1` whitelist from `fastdds_udp_only.xml`.

## Safety model

- **ID-based only.** The browser sends an attack *id*; the server runs the
  fixed command bound to that id. Arbitrary text from the browser is never
  executed — a controlled test bench, not a shell.
- Entries flagged `sudo` need privileges; entries flagged `host` run on the
  robot machine.
- Lab use only, against your own robot on an isolated domain.

## Files

```
console/
  ids_console.py   back end: launcher, ROS readers, history, controls, CSV
  index.html       the page (layout + styles)
  app.js           front-end logic (charts, menus, log, episodes)
  attacks.json     catalogue: 50 attacks + tools, console config
  logs/            created on first capture/record
```
