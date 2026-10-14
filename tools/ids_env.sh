#!/usr/bin/env bash
# =============================================================================
# File        : ids_env.sh
# Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
# Author      : Shyam Rithin S
# Description : Per-terminal environment for the IDS experiments. Pins the DDS
#               domain and RMW, and loads the Fast DDS UDP-only profile so that
#               traffic, including same-host traffic, is visible to tshark.
#               Source it in every experiment terminal; do not add to .bashrc.
# Usage       : source tools/ids_env.sh
# =============================================================================
export ROS_DOMAIN_ID=42
export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
export FASTRTPS_DEFAULT_PROFILES_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fastdds_udp_only.xml"
echo "[ids] domain=$ROS_DOMAIN_ID rmw=$RMW_IMPLEMENTATION profile=udp_only"
