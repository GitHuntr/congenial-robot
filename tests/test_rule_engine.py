import time

from core.rule_engine import FirewallLogicEngine, SimulatedPacket


def pkt(
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    flags,
    protocol="TCP",
):
    return SimulatedPacket(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        flags=flags,
        timestamp=time.time(),
    )


def test_unsolicited_inbound_syn_is_dropped():
    engine = FirewallLogicEngine()
    decision = engine.process_packet(
        pkt("8.8.8.8", "192.168.1.10", 443, 50000, ["SYN"])
    )
    assert decision["decision"] == "drop"
    assert "internal-initiated session" in decision["reason"]


def test_internal_initiated_handshake_allows_established_inbound():
    engine = FirewallLogicEngine()

    # 1) outbound SYN from internal host starts session state
    d1 = engine.process_packet(
        pkt("192.168.1.10", "8.8.8.8", 50000, 443, ["SYN"])
    )
    assert d1["decision"] == "allow"

    # 2) inbound SYN+ACK should be accepted as part of handshake
    d2 = engine.process_packet(
        pkt("8.8.8.8", "192.168.1.10", 443, 50000, ["SYN", "ACK"])
    )
    assert d2["decision"] == "allow"

    # 3) outbound ACK establishes flow
    d3 = engine.process_packet(
        pkt("192.168.1.10", "8.8.8.8", 50000, 443, ["ACK"])
    )
    assert d3["decision"] == "allow"

    # 4) inbound packet is now allowed only because session is established
    d4 = engine.process_packet(
        pkt("8.8.8.8", "192.168.1.10", 443, 50000, ["ACK"])
    )
    assert d4["decision"] == "allow"
    assert "established internal session" in d4["reason"]


def test_inbound_data_before_established_is_dropped():
    engine = FirewallLogicEngine()

    # Internal host starts with SYN
    engine.process_packet(pkt("192.168.1.10", "1.1.1.1", 50001, 443, ["SYN"]))

    # Inbound ACK without SYN+ACK is invalid for current state (SYN_SENT)
    d = engine.process_packet(pkt("1.1.1.1", "192.168.1.10", 443, 50001, ["ACK"]))
    assert d["decision"] == "drop"


def test_non_tcp_packets_pass_stateful_filter():
    engine = FirewallLogicEngine()
    d = engine.process_packet(
        SimulatedPacket(
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            src_port=53000,
            dst_port=53,
            protocol="UDP",
            flags=None,
            timestamp=time.time(),
        )
    )
    assert d["decision"] == "allow"


def test_state_table_exposes_entries_and_reset_clears():
    engine = FirewallLogicEngine()
    engine.process_packet(pkt("192.168.1.10", "8.8.8.8", 50000, 443, ["SYN"]))
    rows = engine.get_state_table()
    assert len(rows) == 1
    assert rows[0]["state"] == "SYN_SENT"

    engine.reset()
    assert engine.get_state_table() == []
