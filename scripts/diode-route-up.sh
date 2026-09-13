#!/bin/bash
set -e

# Bring the host-routing sandbox online
# Creates routing table and rules to redirect host traffic through router/diode
# All steps are idempotent — safe to run multiple times

echo "=== Diode sandbox: bringing online ==="

# Constants
ROUTER_IP="192.168.2.254"        # Router's IP on macvlan-prod (gateway)
HOST_IP="192.168.1.41"           # Host's primary interface IP
ROUTING_TABLE="diode"
RULE_PRIORITY_DIODE=100
RULE_PRIORITY_DNS=50

# 1. Add routing table entry to /etc/iproute2/rt_tables (idempotent: check before appending)
if ! sudo grep -q "^[0-9]* $ROUTING_TABLE$" /etc/iproute2/rt_tables; then
    TABLE_NUM=$(sudo awk '{print $1}' /etc/iproute2/rt_tables | sort -n | tail -1)
    TABLE_NUM=$((TABLE_NUM + 1))
    echo "$TABLE_NUM $ROUTING_TABLE" | sudo tee -a /etc/iproute2/rt_tables > /dev/null
    echo "✓ Added routing table entry: $TABLE_NUM $ROUTING_TABLE"
else
    echo "✓ Routing table entry already exists"
fi

# 2. Add default route via router to diode table (idempotent: check before adding)
if ! sudo ip route show table "$ROUTING_TABLE" | grep -q "default via $ROUTER_IP"; then
    sudo ip route add default via "$ROUTER_IP" table "$ROUTING_TABLE"
    echo "✓ Added default route via $ROUTER_IP to table $ROUTING_TABLE"
else
    echo "✓ Default route via $ROUTER_IP already exists"
fi

# 3. Add rule to send traffic from host IP to diode table (idempotent)
if ! sudo ip rule show | grep -q "from $HOST_IP .* lookup $ROUTING_TABLE"; then
    sudo ip rule add from "$HOST_IP" table "$ROUTING_TABLE" priority "$RULE_PRIORITY_DIODE"
    echo "✓ Added rule: traffic from $HOST_IP → table $ROUTING_TABLE (priority $RULE_PRIORITY_DIODE)"
else
    echo "✓ Rule for host IP → $ROUTING_TABLE already exists"
fi

# 4. Add DNS exclusion rule at higher priority (lower number) — send DNS through table main
# This ensures DNS resolution continues to work while general routing is redirected
if ! sudo ip rule show | grep -q "dport 53 .* lookup main"; then
    sudo ip rule add dport 53 table main priority "$RULE_PRIORITY_DNS"
    echo "✓ Added DNS exclusion rule: port 53 → table main (priority $RULE_PRIORITY_DNS)"
else
    echo "✓ DNS exclusion rule already exists"
fi

echo ""
echo "=== Current routing rules ==="
sudo ip rule show

echo ""
echo "=== Current diode routing table ==="
sudo ip route show table "$ROUTING_TABLE"

echo ""
echo "✓ Sandbox online. Operator can verify: nslookup google.com should succeed, general routing redirected."
