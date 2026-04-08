"""
Firewall Logic Engine
---------------------
Implements a packet-stream processing engine with modular filters.

Key requirement covered:
- Stateful inspection for TCP:
  Incoming packets are allowed only when they belong to an established
  session initiated from the internal network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import time
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


class Decision(str, Enum):
    ALLOW = "allow"
    DROP = "drop"


@dataclass
class SimulatedPacket:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str = "TCP"
    flags: Sequence[str] | str | None = None
    payload_size: int = 0
    timestamp: float = field(default_factory=time.time)


@dataclass
class FilterResult:
    decision: Decision
    module: str
    reason: str


@dataclass
class ConnectionEntry:
    """Tracks one TCP flow initiated by internal network."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    state: str
    created_at: float
    last_seen: float
    initiated_by_internal: bool = True

    def key(self) -> Tuple[str, int, str, int]:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    def reverse_key(self) -> Tuple[str, int, str, int]:
        return (self.dst_ip, self.dst_port, self.src_ip, self.src_port)


class PacketFilter:
    """Base interface for packet filters."""

    def evaluate(self, packet: SimulatedPacket) -> FilterResult:
        raise NotImplementedError


class StatefulInspectionFilter(PacketFilter):
    """
    Stateful TCP filter using a connection table.

    Policy:
    - Outbound TCP packets from internal hosts can create/update state.
    - Inbound TCP packets are allowed only if they match a flow that was
      initiated by internal network and is progressing through valid states.
    """

    def __init__(
        self,
        state_table: Dict[Tuple[str, int, str, int], ConnectionEntry],
        internal_networks: Sequence[str],
        idle_timeout_sec: int = 300,
    ) -> None:
        self.state_table = state_table
        self.internal_networks = [ipaddress.ip_network(c) for c in internal_networks]
        self.idle_timeout_sec = idle_timeout_sec

    def _is_internal(self, ip_text: str) -> bool:
        ip_obj = ipaddress.ip_address(ip_text)
        return any(ip_obj in net for net in self.internal_networks)

    def _direction(self, packet: SimulatedPacket) -> str:
        src_internal = self._is_internal(packet.src_ip)
        dst_internal = self._is_internal(packet.dst_ip)
        if src_internal and not dst_internal:
            return "outbound"
        if not src_internal and dst_internal:
            return "inbound"
        if src_internal and dst_internal:
            return "internal"
        return "external"

    def _parse_flags(self, flags: Sequence[str] | str | None) -> Set[str]:
        if flags is None:
            return set()
        if isinstance(flags, str):
            normalized = flags.replace("|", ",").replace(" ", "")
            return {f.upper() for f in normalized.split(",") if f}
        return {str(f).upper() for f in flags}

    def _cleanup_expired(self, now: float) -> None:
        stale_keys = [
            k for k, v in self.state_table.items() if now - v.last_seen > self.idle_timeout_sec
        ]
        for key in stale_keys:
            self.state_table.pop(key, None)

    def evaluate(self, packet: SimulatedPacket) -> FilterResult:
        now = packet.timestamp or time.time()
        self._cleanup_expired(now)

        # Stateful requirement is TCP-specific; other protocols pass here.
        if packet.protocol.upper() != "TCP":
            return FilterResult(Decision.ALLOW, "stateful_inspection", "Non-TCP packet")

        flags = self._parse_flags(packet.flags)
        direction = self._direction(packet)
        flow_key = (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port)
        rev_key = (packet.dst_ip, packet.dst_port, packet.src_ip, packet.src_port)

        # Reset tears down state immediately for either direction.
        if "RST" in flags:
            self.state_table.pop(flow_key, None)
            self.state_table.pop(rev_key, None)
            return FilterResult(Decision.ALLOW, "stateful_inspection", "TCP reset observed")

        if direction == "outbound":
            entry = self.state_table.get(flow_key)

            # New session initiation: internal SYN without ACK.
            if "SYN" in flags and "ACK" not in flags:
                self.state_table[flow_key] = ConnectionEntry(
                    src_ip=packet.src_ip,
                    src_port=packet.src_port,
                    dst_ip=packet.dst_ip,
                    dst_port=packet.dst_port,
                    state="SYN_SENT",
                    created_at=now,
                    last_seen=now,
                )
                return FilterResult(
                    Decision.ALLOW,
                    "stateful_inspection",
                    "Outbound SYN started internal session",
                )

            if entry:
                # Third handshake packet from client.
                if entry.state == "SYN_RECEIVED" and "ACK" in flags and "SYN" not in flags:
                    entry.state = "ESTABLISHED"
                elif entry.state == "ESTABLISHED" and "FIN" in flags:
                    entry.state = "CLOSING"
                elif entry.state == "CLOSING" and "ACK" in flags:
                    self.state_table.pop(flow_key, None)
                    return FilterResult(
                        Decision.ALLOW,
                        "stateful_inspection",
                        "Connection closed after FIN/ACK",
                    )

                entry.last_seen = now
                return FilterResult(
                    Decision.ALLOW,
                    "stateful_inspection",
                    f"Outbound packet matched state {entry.state}",
                )

            # Outbound packet without known state: conservative allow for non-init traffic
            # can be handled by other filters in the chain if needed.
            return FilterResult(
                Decision.ALLOW,
                "stateful_inspection",
                "Outbound packet without existing session state",
            )

        if direction == "inbound":
            entry = self.state_table.get(rev_key)
            if not entry or not entry.initiated_by_internal:
                return FilterResult(
                    Decision.DROP,
                    "stateful_inspection",
                    "Inbound packet not tied to internal-initiated session",
                )

            # SYN+ACK for valid handshake response.
            if entry.state == "SYN_SENT" and "SYN" in flags and "ACK" in flags:
                entry.state = "SYN_RECEIVED"
                entry.last_seen = now
                return FilterResult(
                    Decision.ALLOW,
                    "stateful_inspection",
                    "Inbound SYN+ACK matched outbound SYN",
                )

            # Inbound data/control allowed only after established.
            if entry.state == "ESTABLISHED":
                if "FIN" in flags:
                    entry.state = "CLOSING"
                entry.last_seen = now
                return FilterResult(
                    Decision.ALLOW,
                    "stateful_inspection",
                    "Inbound packet matched established internal session",
                )

            # Allow ACK during closing handshake.
            if entry.state == "CLOSING" and "ACK" in flags:
                self.state_table.pop(rev_key, None)
                return FilterResult(
                    Decision.ALLOW,
                    "stateful_inspection",
                    "Inbound ACK completed connection close",
                )

            return FilterResult(
                Decision.DROP,
                "stateful_inspection",
                f"Inbound packet blocked in state {entry.state}",
            )

        # Internal↔internal and external↔external are outside inbound policy scope.
        return FilterResult(
            Decision.ALLOW,
            "stateful_inspection",
            f"{direction} traffic not subject to inbound-stateful gate",
        )


class FirewallLogicEngine:
    """Processes packet streams through ordered filtering modules."""

    def __init__(
        self,
        internal_networks: Optional[Sequence[str]] = None,
        idle_timeout_sec: int = 300,
        extra_filters: Optional[List[PacketFilter]] = None,
    ) -> None:
        self.internal_networks = internal_networks or [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
        ]
        self.state_table: Dict[Tuple[str, int, str, int], ConnectionEntry] = {}
        self.filters: List[PacketFilter] = [
            StatefulInspectionFilter(
                state_table=self.state_table,
                internal_networks=self.internal_networks,
                idle_timeout_sec=idle_timeout_sec,
            )
        ]
        if extra_filters:
            self.filters.extend(extra_filters)

    def process_packet(self, packet: SimulatedPacket) -> Dict[str, str]:
        last_result: Optional[FilterResult] = None
        for packet_filter in self.filters:
            result = packet_filter.evaluate(packet)
            last_result = result
            if result.decision == Decision.DROP:
                return {
                    "decision": result.decision.value,
                    "module": result.module,
                    "reason": result.reason,
                }

        if last_result:
            return {
                "decision": Decision.ALLOW.value,
                "module": last_result.module,
                "reason": last_result.reason,
            }

        return {
            "decision": Decision.ALLOW.value,
            "module": "pipeline",
            "reason": "Packet passed all filtering modules",
        }

    def process_stream(self, packets: Iterable[SimulatedPacket]) -> List[Dict[str, str]]:
        return [self.process_packet(pkt) for pkt in packets]

    def get_state_table(self) -> List[Dict[str, str | int | float]]:
        rows = []
        for entry in self.state_table.values():
            rows.append(
                {
                    "src_ip": entry.src_ip,
                    "src_port": entry.src_port,
                    "dst_ip": entry.dst_ip,
                    "dst_port": entry.dst_port,
                    "state": entry.state,
                    "created_at": entry.created_at,
                    "last_seen": entry.last_seen,
                    "initiated_by_internal": entry.initiated_by_internal,
                }
            )
        return rows

    def reset(self) -> None:
        self.state_table.clear()


def packet_from_dict(data: Dict[str, object]) -> SimulatedPacket:
    """Utility for API/CLI ingestion."""
    return SimulatedPacket(
        src_ip=str(data["src_ip"]),
        dst_ip=str(data["dst_ip"]),
        src_port=int(data["src_port"]),
        dst_port=int(data["dst_port"]),
        protocol=str(data.get("protocol", "TCP")),
        flags=data.get("flags"),
        payload_size=int(data.get("payload_size", 0)),
        timestamp=float(data.get("timestamp", time.time())),
    )
