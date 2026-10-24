#!/usr/bin/env bash
# =============================================================================
# File        : install.sh
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S (RA2311004010308)
# =============================================================================
# Description
# -----------
# Installs the ROS2-IDS Wireshark profile and the ROS 2 decoder plugin for the
# current user (no sudo):
#   profile -> ~/.config/wireshark/profiles/ROS2-IDS/
#              colorfilters    colouring rules per topic / discovery / alerts
#              dfilter_buttons filter-toolbar buttons (No clock, Wire, ...)
#              preferences     columns: port, kind, topic, writer, summary
#   plugin  -> ~/.local/lib/wireshark/plugins/ros2_ids.lua    (Wireshark 3.x/4.x)
#
# Usage:  bash install.sh        then: ids wireshark
# =============================================================================
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROFILE="$HOME/.config/wireshark/profiles/ROS2-IDS"
mkdir -p "$PROFILE"
cp "$HERE/ROS2-IDS/colorfilters" "$HERE/ROS2-IDS/dfilter_buttons" "$HERE/ROS2-IDS/preferences" "$PROFILE/"
echo "[ws] profile   -> $PROFILE"

PLUG="$HOME/.local/lib/wireshark/plugins"
mkdir -p "$PLUG"
cp "$HERE/plugins/ros2_ids.lua" "$PLUG/"
# remove the v1 decoder and any legacy-folder copy (would load twice)
rm -f "$PLUG/ros2_twist.lua" "$HOME/.config/wireshark/plugins/ros2_twist.lua" \
      "$HOME/.config/wireshark/plugins/ros2_ids.lua"
echo "[ws] plugin    -> $PLUG/ros2_ids.lua"

echo "[ws] done. Start it BEFORE the bench:   ids wireshark"
echo "     Check: Help > About Wireshark > Plugins lists ros2_ids.lua"
