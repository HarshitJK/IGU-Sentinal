#!/bin/bash

# Red button: unconditionally revert all sandbox changes
# Every deletion suffixed with || true so steps that were never set up don't halt the script
# Safe to run multiple times; stops router/diode containers

echo "=== RED BUTTON: Reverting sandbox ==="

# Constants
ROUTER_IP="192.168.2.254"
HOST_IP="192.168.1.41"
ROUTING_TABLE="diode"

# 1. Stop containers (if running)
echo "Stopping router and diode containers..."
$(docker compose version >/dev/null 2>&1 && echo "docker compose" || echo docker-compose) stop router diode || true
echo "✓ Containers stopped (or were not running)"

# 2. Delete routing rules (idempotent: || true if not present)
echo "Removing routing rules..."
sudo ip rule del from "$HOST_IP" table "$ROUTING_TABLE" priority 100 || true
echo "✓ Host IP rule deleted"

sudo ip rule del dport 53 table main priority 50 || true
echo "✓ DNS exclusion rule deleted"

# 3. Delete the default route from diode table
echo "Removing diode route table entries..."
sudo ip route del default via "$ROUTER_IP" table "$ROUTING_TABLE" || true
echo "✓ Default route from diode table deleted"

# 4. Remove the routing table entry from /etc/iproute2/rt_tables
# (Note: removing a table entry from rt_tables is safe but the table itself lingers;
#  the rules reference it so we leave it for re-setup stability)
echo ""
echo "=== Sandbox offline. Verifying host connectivity... ==="
echo ""

# Show current routing state
echo "Current routing table:"
sudo ip route show

echo ""
echo "Testing connectivity to 8.8.8.8..."
sudo ping -c 2 8.8.8.8

echo ""
echo "✓ Red button pressed. Sandbox reverted. Normal routing restored."
