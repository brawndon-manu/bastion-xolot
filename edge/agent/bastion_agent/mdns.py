"""
Bastión Xólot — mDNS Hostname Cache

Passively listens for mDNS announcements on the local network and
builds an IP → hostname cache. Discovery uses this to name devices
the way Eero does — from the device's own self-announced name.
"""

import logging
import socket
import threading
from typing import Optional

logger = logging.getLogger(__name__)

_cache: dict[str, str] = {}
_lock = threading.Lock()
_started = False


def get_mdns_hostname(ip: str) -> Optional[str]:
    with _lock:
        return _cache.get(ip)


def _update_cache(ip: str, hostname: str) -> None:
    clean = hostname.rstrip(".")
    if not clean:
        return
    with _lock:
        if _cache.get(ip) != clean:
            logger.info("mDNS: %s → %s", ip, clean)
            _cache[ip] = clean


def _addr_bytes_to_ip(addr_bytes: bytes) -> Optional[str]:
    try:
        if len(addr_bytes) == 4:
            return socket.inet_ntop(socket.AF_INET, addr_bytes)
        if len(addr_bytes) == 16:
            return socket.inet_ntop(socket.AF_INET6, addr_bytes)
    except OSError:
        pass
    return None


def start() -> None:
    global _started
    if _started:
        return

    try:
        from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange

        zc = Zeroconf()

        SERVICE_TYPES = [
            "_http._tcp.local.",
            "_https._tcp.local.",
            "_workstation._tcp.local.",
            "_apple-mobdev2._tcp.local.",
            "_companion-link._tcp.local.",
            "_airplay._tcp.local.",
            "_googlecast._tcp.local.",
            "_printer._tcp.local.",
            "_smb._tcp.local.",
            "_device-info._tcp.local.",
            "_srpl-tls._tcp.local.",
            "_remotepairing._tcp.local.",
            "_sleep-proxy._udp.local.",
            "_eero._tcp.local.",
            "_raop._tcp.local.",
            "_homekit._tcp.local.",
        ]

        def on_service_state_change(zeroconf, service_type, name, state_change):
            if state_change not in (ServiceStateChange.Added, ServiceStateChange.Updated):
                return
            try:
                info = zeroconf.get_service_info(service_type, name)
                if not info:
                    return
                hostname = info.server or ""
                for addr_bytes in info.addresses:
                    ip = _addr_bytes_to_ip(addr_bytes)
                    if ip and hostname:
                        _update_cache(ip, hostname)
            except Exception:
                pass

        ServiceBrowser(zc, SERVICE_TYPES, handlers=[on_service_state_change])
        _started = True
        logger.info("mDNS listener started — watching %d service types", len(SERVICE_TYPES))

    except ImportError:
        logger.warning("zeroconf not installed — mDNS hostname discovery disabled")
    except Exception as e:
        logger.warning("mDNS listener failed to start: %s", e)
