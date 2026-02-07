# ===============
# Saftey modes
# ===============

# When true:
# - detection still runs
# - detection becomes no-op
MONITOR_ONLY = True

# When true: 
# - enforcement prints commands instead of executing (for testing)
# - simulate only, never enforce
DRY_RUN = True

# When false (default):
# - enforcement is completely disabled
# - prevents accidental blocking on first boot or misconfiguration
# - must be explicitly set to True by a human operator
# NOTE: This does NOT override MONITOR_ONLY or DRY_RUN
ALLOW_ENFORCEMENT = False

# Interface facing the internal network/router
LAN_IFACE = "CHANGE ME"

# Interface facing the modem/internet
WAN_IFACE = "CHANGE ME"

# Safety gate: enforcement is denied unless ALL conditions are satisfied
# Fail-closed design: any missing/unsafe configuration returns False
# Prevents accidental blocking during setup, demos, or misconfiguration
def enforcement_allowed():
    if MONITOR_ONLY:
        return False
    if DRY_RUN:
        return False
    if not ALLOW_ENFORCEMENT:
        return False
    if LAN_IFACE == WAN_IFACE:
        return False
    if LAN_IFACE == "CHANGE ME" or WAN_IFACE == "CHANGE ME":
        return False
    if not LAN_IFACE.strip() or not WAN_IFACE.strip():
        return False

    return True
    
