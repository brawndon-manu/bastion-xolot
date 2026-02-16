#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# Bastion Xólot - Phase 3 DNS Sinkhole Setup
# Installs and configures:
# - dnsmasq (LAN-facing DHCP + DNS)
# - unbound (localhost recursive DNSSEC resolver)
# - Bastion sinkhole include model
# ==========================================================

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi

LAN_INTERFACE="eth0"
WAN_INTERFACE="eth1"

LAN_IP="192.168.50.1"
UNBOUND_PORT="5335"

PRIMARY_DNS="$LAN_IP"
SECONDARY_DNS="1.1.1.1"

BASTION_DNS_ROOT="/var/lib/bastion/dns"

log() {
    echo "[bastion:phase3:dns] $*"
}

log "Starting Phase 3 DNS Sinkhole Setup"
log "LAN_INTERFACE=$LAN_INTERFACE WAN_INTERFACE=$WAN_INTERFACE"
log "LAN_IP=$LAN_IP unbound=127.0.0.1:$UNBOUND_PORT"
log "DHCP DNS: primary=$PRIMARY_DNS secondary=$SECONDARY_DNS (fail-open)"
log "Bastion DNS root: $BASTION_DNS_ROOT"


# =========================
# Phase 3 safety principle: 
# fail closed during install
# fail open during runtime
# ==========================

die() {
    echo "[bastion:phase3:dns] ERROR: $*" >&2
    exit 1
}

# checks if command exist
require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

# Basic tools we rely on
# Debian base should have these, but we enforce it
require_cmd apt-get
require_cmd systemctl
require_cmd ip

# Refuse unsafe interface config
[[ "$LAN_INTERFACE" != "$WAN_INTERFACE" ]] || die "LAN_INTERFACE and WAN_INTERFACE must be different!"

# Ensure LAN IP is actually assigned
# Prevents writing configs for the wrong IP

if ! ip -4 addr show dev "$LAN_INTERFACE" | grep -q "$LAN_IP"; then
    die "LAN_IP $LAN_IP is not currently assigned to interface $LAN_INTERFACE"
fi

# =====================================
# Install required packages (Debian 12)
# =====================================
log "Updating package index..."
DEBIAN_FRONTEND=noninteractive apt-get update

log "Installing dnsmasq and unbound..."
DEBIAN_FRONTEND=noninteractive apt-get install -y dnsmasq unbound ca-certificates

# ====================================================
# Bastion DNS directory model (Phase 3)
# Must match exact existing manual Pi structure exactly
# =====================================================
log "Creating Bastion DNS directory structure..."

install -d -m 0755 -o root -g root \
  "$BASTION_DNS_ROOT" \
  "$BASTION_DNS_ROOT/builds" \
  "$BASTION_DNS_ROOT/builds/active" \
  "$BASTION_DNS_ROOT/builds/versions" \
  "$BASTION_DNS_ROOT/metadata" \
  "$BASTION_DNS_ROOT/sources" \
  "$BASTION_DNS_ROOT/sources/cache" \
  "$BASTION_DNS_ROOT/sources/manual" \
  "$BASTION_DNS_ROOT/tmp"

  # Create bootstrap block if file is misisng
  BOOTSTRAP