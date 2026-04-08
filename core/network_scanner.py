import ipaddress
import psutil
import socket
import time


PROCESS_CACHE_TTL_SEC = 10
_PROCESS_CACHE = {}


def _is_internal_ip(ip_text):
    """Treat RFC1918, loopback, and link-local as internal/private scope."""
    if not ip_text or ip_text == "*":
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_text)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
        )
    except ValueError:
        return False


def _classify_zone(local_ip, remote_ip):
    """
    Classify socket direction from host perspective.
    - local-only: loopback or no remote endpoint (e.g., LISTEN, localhost)
    - internal: private LAN -> private LAN (non-loopback)
    - outbound: internal -> external
    - inbound: external -> internal
    - external: external -> external
    """
    if not remote_ip or remote_ip == "*":
        return "local-only", "LOCAL LISTENER"

    # Treat loopback-to-loopback as local, not internal
    try:
        local_obj = ipaddress.ip_address(local_ip)
        remote_obj = ipaddress.ip_address(remote_ip)
        if local_obj.is_loopback and remote_obj.is_loopback:
            return "local-only", "LOOPBACK"
    except ValueError:
        pass

    local_internal = _is_internal_ip(local_ip)
    remote_internal = _is_internal_ip(remote_ip)

    if local_internal and remote_internal:
        return "internal", "LAN -> LAN"
    if local_internal and not remote_internal:
        return "outbound", "LAN -> WAN"
    if not local_internal and remote_internal:
        return "inbound", "WAN -> LAN"
    return "external", "WAN -> WAN"


def _risk_hint(protocol, status, zone):
    """
    Lightweight heuristic risk hint for UI prioritization.
    This is not a security verdict; only an operator triage signal.
    """
    proto = str(protocol).upper()
    st = str(status).upper()

    if zone in ("inbound", "external") and st not in ("ESTABLISHED", "LISTEN", "NONE"):
        return "high"
    if proto.startswith("UDP") and zone != "internal":
        return "medium"
    if st in ("TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "SYN_RECV"):
        return "medium"
    return "low"


def _family_name(family):
    if family == socket.AF_INET:
        return "IPv4"
    if family == socket.AF_INET6:
        return "IPv6"
    return "UNKNOWN"


def _protocol_name(family, sock_type):
    if sock_type == socket.SOCK_STREAM:
        return "TCP6" if family == socket.AF_INET6 else "TCP"
    if sock_type == socket.SOCK_DGRAM:
        return "UDP6" if family == socket.AF_INET6 else "UDP"
    return "UNKNOWN"


def _process_info(pid):
    if not pid:
        return {"pid": None, "name": "system", "exe": ""}

    now = time.time()
    cached = _PROCESS_CACHE.get(pid)
    if cached and (now - cached["ts"] < PROCESS_CACHE_TTL_SEC):
        return cached["data"]

    data = {"pid": pid, "name": "unknown", "exe": ""}
    try:
        p = psutil.Process(pid)
        data = {"pid": pid, "name": p.name() or "unknown", "exe": p.exe() or ""}
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    _PROCESS_CACHE[pid] = {"ts": now, "data": data}
    return data


def get_live_connections():
    """
    Return live socket metadata from psutil.
    This is real host socket state (L3/L4 + process context), not mocked data.
    """
    rows = []
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S")

    try:
        net_conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return []

    for conn in net_conns:
        local_ip = conn.laddr.ip if conn.laddr else "*"
        local_port = conn.laddr.port if conn.laddr else None
        remote_ip = conn.raddr.ip if conn.raddr else "*"
        remote_port = conn.raddr.port if conn.raddr else None
        status = conn.status or "NONE"
        family = _family_name(conn.family)
        protocol = _protocol_name(conn.family, conn.type)

        zone, direction = _classify_zone(local_ip, remote_ip)
        proc = _process_info(conn.pid)
        risk = _risk_hint(protocol, status, zone)

        stable_id = (
            f"{proc['pid'] or 0}:{protocol}:{local_ip}:{local_port or 0}"
            f"->{remote_ip}:{remote_port or 0}:{status}"
        )

        rows.append(
            {
                "id": stable_id,
                "timestamp": now_iso,
                "family": family,
                "protocol": protocol,
                "state": status,
                "zone": zone,
                "direction": direction,
                "risk": risk,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "source": f"{local_ip}:{local_port}" if local_port else local_ip,
                "destination": (
                    f"{remote_ip}:{remote_port}" if remote_port else remote_ip
                ),
                "pid": proc["pid"],
                "process_name": proc["name"],
                "process_path": proc["exe"],
                "info": f"State: {status}",
            }
        )

    # Prioritize potentially more relevant sockets for operators.
    risk_order = {"high": 0, "medium": 1, "low": 2}
    rows.sort(
        key=lambda r: (
            risk_order.get(r["risk"], 3),
            0 if r["zone"] in ("inbound", "outbound", "external") else 1,
            r["process_name"],
        )
    )

    return rows[:100]
