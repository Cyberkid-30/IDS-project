from app.services.matcher import SignatureMatcher
from app.services.parser import ParsedPacket
from app.models.signature import Signature
from app.core.enums import SeverityLevel, ProtocolType


def make_sig(**kwargs) -> Signature:
    defaults = dict(
        name="test",
        description=None,
        protocol=ProtocolType.ANY,
        source_ip=None,
        source_port=None,
        dest_ip=None,
        dest_port=None,
        tcp_flags=None,
        pattern=None,
        severity=SeverityLevel.MEDIUM,
        enabled=True,
        category=None,
        reference=None,
    )
    defaults.update(kwargs)
    return Signature(**defaults)


def make_packet(**kwargs) -> ParsedPacket:
    defaults = dict(
        timestamp=1000.0,
        protocol="TCP",
        source_ip="10.0.0.1",
        source_port=12345,
        dest_ip="192.168.1.1",
        dest_port=80,
        payload_text="GET /index.html HTTP/1.1",
        payload_hex="",
        payload_size=0,
        flags=None,
        icmp_type=None,
        icmp_code=None,
        raw_hex="",
    )
    defaults.update(kwargs)
    return ParsedPacket(**defaults)


class TestMatchProtocol:
    def setup_method(self):
        self.matcher = SignatureMatcher()

    def test_any_matches_all(self):
        sig = make_sig(protocol=ProtocolType.ANY)
        assert self.matcher._match_protocol("TCP", "any") is True
        assert self.matcher._match_protocol("UDP", "any") is True
        assert self.matcher._match_protocol("ICMP", "any") is True

    def test_exact_match(self):
        assert self.matcher._match_protocol("TCP", "tcp") is True
        assert self.matcher._match_protocol("TCP", "TCP") is True

    def test_mismatch(self):
        assert self.matcher._match_protocol("TCP", "udp") is False
        assert self.matcher._match_protocol("ICMP", "tcp") is False


class TestMatchPort:
    def setup_method(self):
        self.matcher = SignatureMatcher()

    def test_any_port(self):
        assert self.matcher._match_port(80, None) is True
        assert self.matcher._match_port(80, "any") is True
        assert self.matcher._match_port(80, "ANY") is True

    def test_single_port(self):
        assert self.matcher._match_port(80, "80") is True
        assert self.matcher._match_port(443, "80") is False

    def test_port_range(self):
        assert self.matcher._match_port(50, "1-1024") is True
        assert self.matcher._match_port(1024, "1-1024") is True
        assert self.matcher._match_port(0, "1-1024") is False
        assert self.matcher._match_port(1025, "1-1024") is False

    def test_port_list(self):
        assert self.matcher._match_port(80, "80,443,8080") is True
        assert self.matcher._match_port(443, "80,443,8080") is True
        assert self.matcher._match_port(22, "80,443,8080") is False

    def test_none_packet_port(self):
        assert self.matcher._match_port(None, "80") is False
        assert self.matcher._match_port(None, None) is True

    def test_invalid_spec_returns_false(self):
        assert self.matcher._match_port(80, "not-a-port") is False


class TestMatchPayload:
    def setup_method(self):
        self.matcher = SignatureMatcher()

    def test_no_pattern_matches_any(self):
        assert self.matcher._match_payload("anything", None) is True

    def test_matching_pattern(self):
        assert self.matcher._match_payload("select * from users", r"(?i)select") is True

    def test_non_matching_pattern(self):
        assert self.matcher._match_payload("hello world", r"\d+") is False

    def test_case_insensitive(self):
        assert self.matcher._match_payload("UNION SELECT", r"union.*select") is True


class TestMatchTCPFlags:
    def setup_method(self):
        self.matcher = SignatureMatcher()

    def test_no_signature_flags_matches_any(self):
        assert self.matcher._match_tcp_flags("S", "") is True

    def test_empty_signature_flags_matches_any(self):
        assert self.matcher._match_tcp_flags("SA", "") is True

    def test_single_flag_match(self):
        assert self.matcher._match_tcp_flags("S", "S") is True

    def test_multi_flag_match(self):
        assert self.matcher._match_tcp_flags("SA", "SA") is True
        assert self.matcher._match_tcp_flags("SA", "S") is True

    def test_flag_mismatch(self):
        assert self.matcher._match_tcp_flags("A", "S") is False
        assert self.matcher._match_tcp_flags("R", "S") is False

    def test_no_packet_flags(self):
        assert self.matcher._match_tcp_flags(None, "S") is False
        assert self.matcher._match_tcp_flags("", "S") is False


class TestMatchSingle:
    def setup_method(self):
        self.matcher = SignatureMatcher()

    def test_all_criteria_match(self):
        sig = make_sig(
            protocol=ProtocolType.TCP,
            dest_port="80",
            pattern=r"GET",
        )
        packet = make_packet()
        result = self.matcher._match_single(packet, sig)
        assert result.matched is True
        assert result.signature is sig

    def test_protocol_mismatch(self):
        sig = make_sig(protocol=ProtocolType.UDP)
        packet = make_packet(protocol="TCP")
        result = self.matcher._match_single(packet, sig)
        assert result.matched is False

    def test_port_mismatch(self):
        sig = make_sig(dest_port="443")
        packet = make_packet(dest_port=80)
        result = self.matcher._match_single(packet, sig)
        assert result.matched is False

    def test_ip_match(self):
        sig = make_sig(dest_ip="192.168.1.1")
        packet = make_packet(dest_ip="192.168.1.1")
        result = self.matcher._match_single(packet, sig)
        assert result.matched is True

    def test_ip_mismatch(self):
        sig = make_sig(dest_ip="10.0.0.1")
        packet = make_packet(dest_ip="192.168.1.1")
        result = self.matcher._match_single(packet, sig)
        assert result.matched is False

    def test_payload_pattern_match(self):
        sig = make_sig(pattern=r"(?i)select.*from")
        packet = make_packet(payload_text="SELECT * FROM users")
        result = self.matcher._match_single(packet, sig)
        assert result.matched is True

    def test_tcp_flags_match(self):
        sig = make_sig(protocol=ProtocolType.TCP, tcp_flags="S")
        packet = make_packet(protocol="TCP", flags="S")
        result = self.matcher._match_single(packet, sig)
        assert result.matched is True

    def test_tcp_flags_mismatch(self):
        sig = make_sig(protocol=ProtocolType.TCP, tcp_flags="S")
        packet = make_packet(protocol="TCP", flags="A")
        result = self.matcher._match_single(packet, sig)
        assert result.matched is False

    def test_tcp_flags_ignored_for_non_tcp(self):
        sig = make_sig(protocol=ProtocolType.ICMP, tcp_flags="S")
        packet = make_packet(protocol="ICMP", flags=None)
        result = self.matcher._match_single(packet, sig)
        assert result.matched is True


class TestMatchPacket:
    def setup_method(self):
        self.matcher = SignatureMatcher()

    def test_no_matches_with_no_signatures(self):
        packet = make_packet()
        results = self.matcher.match_packet(packet, [])
        assert results == []

    def test_skips_disabled_signatures(self):
        sig = make_sig(enabled=False, pattern=r"GET")
        packet = make_packet()
        results = self.matcher.match_packet(packet, [sig])
        assert results == []

    def test_matches_enabled_signature(self):
        sig = make_sig(enabled=True, pattern=r"GET")
        packet = make_packet()
        results = self.matcher.match_packet(packet, [sig])
        assert len(results) == 1
        assert results[0].matched is True

    def test_multiple_matches(self):
        sig1 = make_sig(name="sig1", pattern=r"GET")
        sig2 = make_sig(name="sig2", pattern=r"HTTP")
        packet = make_packet()
        results = self.matcher.match_packet(packet, [sig1, sig2])
        assert len(results) == 2


class TestTestSignature:
    def setup_method(self):
        self.matcher = SignatureMatcher()

    def test_signature_matches_packets(self):
        sig = make_sig(pattern=r"admin")
        packets = [
            make_packet(payload_text="user=admin&pass=123"),
            make_packet(payload_text="user=guest"),
        ]
        result = self.matcher.test_signature(sig, packets)
        assert result["total_packets"] == 2
        assert result["matches"] == 1
        assert len(result["match_details"]) == 1

    def test_no_matches(self):
        sig = make_sig(pattern=r"\d{10}")
        packets = [make_packet(payload_text="hello")]
        result = self.matcher.test_signature(sig, packets)
        assert result["matches"] == 0
