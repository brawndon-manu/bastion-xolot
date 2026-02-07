MONITOR_ONLY = True
DRY_RUN = True
ALLOW_ENFORECMENT = False

def enforcement_allowed():
    if MONITOR_ONLY:
        return False
    if DRY_RUNa:
        return False # testing webhook