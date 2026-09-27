import binascii
import struct
import unittest

from dnsprobe.packet import (
    CLASS_IN, DNSFormatError, TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_MX,
    TYPE_NS, TYPE_SOA, TYPE_TXT, build_query, build_response, decode_name,
    encode_name, encode_rr, hexdump, parse_message, parse_rdata,
)


class NameEncodingTests(unittest.TestCase):
    def test_roundtrip_simple(self):
        wire = encode_name("www.example.com")
        self.assertEqual(wire, b"\x03www\x07example\x03com\x00")
        name, offset = decode_name(wire, 0)
        self.assertEqual(name, "www.example.com.")
        self.assertEqual(offset, len(wire))

    def test_root(self):
        self.assertEqual(encode_name("."), b"\x00")
        self.assertEqual(decode_name(b"\x00", 0), (".", 1))

    def test_trailing_dot_accepted(self):
        self.assertEqual(encode_name("example.com."), encode_name("example.com"))

    def test_single_label_max(self):
        wire = encode_name("a" * 63)
        self.assertEqual(len(wire), 65)
        name, _ = decode_name(wire, 0)
        self.assertEqual(name, "a" * 63 + ".")

    def test_label_too_long(self):
        with self.assertRaises(DNSFormatError):
            encode_name("a" * 64 + ".com")

    def test_total_name_too_long(self):
        name = ".".join(["abcdefghij"] * 24)  # 10+1 per label -> > 255
        with self.assertRaises(DNSFormatError):
            encode_name(name)

    def test_empty_label_rejected(self):
        with self.assertRaises(DNSFormatError):
            encode_name("example..com")

    def test_empty_name_rejected(self):
        with self.assertRaises(DNSFormatError):
            encode_name("")

    def test_compression_pointer(self):
        # message: <question name at 12> ... then pointer to it
        wire = encode_name("www.example.com")
        msg = b"\x00" * 12 + wire + b"\xc0\x0c"
        name, offset = decode_name(msg, len(msg) - 2)
        self.assertEqual(name, "www.example.com.")
        self.assertEqual(offset, len(msg))

    def test_compression_loop_rejected(self):
        # pointer at 0 pointing to itself
        with self.assertRaises(DNSFormatError):
            decode_name(b"\xc0\x00", 0)

    def test_forward_pointer_rejected(self):
        # pointer at byte 2 pointing forward to byte 5
        with self.assertRaises(DNSFormatError):
            decode_name(b"\x01a\xc0\x05\x00", 0)

    def test_truncated_label_rejected(self):
        with self.assertRaises(DNSFormatError):
            decode_name(b"\x05ab", 0)

    def test_non_ascii_label_rejected(self):
        with self.assertRaises(DNSFormatError):
            encode_name("başka.example.com")


class QueryTests(unittest.TestCase):
    def test_build_query_rd(self):
        wire = build_query(0x1234, "example.com", "A", rd=True)
        msg_id, flags, qd, an, ns, ar = struct.unpack(">6H", wire[:12])
        self.assertEqual(msg_id, 0x1234)
        self.assertEqual(flags, 0x0100)
        self.assertEqual((qd, an, ns, ar), (1, 0, 0, 0))
        self.assertEqual(wire[12:], encode_name("example.com") + b"\x00\x01\x00\x01")

    def test_build_query_iterative_no_rd(self):
        wire = build_query(1, "example.com", "AAAA", rd=False)
        flags = struct.unpack(">H", wire[2:4])[0]
        self.assertEqual(flags, 0)

    def test_build_query_accepts_numeric_type(self):
        wire = build_query(1, "example.com", 28, rd=False)
        self.assertEqual(wire[-4:], struct.pack(">2H", 28, 1))

    def test_query_parses_back(self):
        parsed = parse_message(build_query(0x00ff, "a.b.c", "MX"))
        self.assertEqual(parsed["id"], 0x00FF)
        self.assertFalse(parsed["response"])
        self.assertTrue(parsed["recursion_desired"])
        self.assertEqual(parsed["questions"][0]["name"], "a.b.c.")
        self.assertEqual(parsed["questions"][0]["type_name"], "MX")


class RdataTests(unittest.TestCase):
    def test_a(self):
        import socket
        wire = socket.inet_aton("93.184.216.34")
        self.assertEqual(parse_rdata(TYPE_A, wire, 0, 4), "93.184.216.34")

    def test_a_bad_length(self):
        with self.assertRaises(DNSFormatError):
            parse_rdata(TYPE_A, b"\x01\x02\x03", 0, 3)

    def test_aaaa(self):
        import socket
        wire = socket.inet_pton(socket.AF_INET6, "2606:2800:220:1:248:1893:25c8:1946")
        parsed = parse_rdata(TYPE_AAAA, wire, 0, 16)
        self.assertEqual(parsed, "2606:2800:220:1:248:1893:25c8:1946")

    def test_cname(self):
        wire = encode_name("target.example.com")
        self.assertEqual(parse_rdata(TYPE_CNAME, wire, 0, len(wire)),
                         "target.example.com.")

    def test_mx(self):
        import socket
        wire = struct.pack(">H", 10) + encode_name("mail.example.com")
        parsed = parse_rdata(TYPE_MX, wire, 0, len(wire))
        self.assertEqual(parsed, {"preference": 10, "exchange": "mail.example.com."})

    def test_txt_multiple_strings(self):
        wire = b"\x05hello\x02wo"
        self.assertEqual(parse_rdata(TYPE_TXT, wire, 0, len(wire)), ["hello", "wo"])

    def test_soa(self):
        import struct as s
        wire = (encode_name("ns1.example.com") + encode_name("host.example.com") +
                s.pack(">5I", 2026092701, 7200, 3600, 1209600, 3600))
        parsed = parse_rdata(TYPE_SOA, wire, 0, len(wire))
        self.assertEqual(parsed["mname"], "ns1.example.com.")
        self.assertEqual(parsed["serial"], 2026092701)
        self.assertEqual(parsed["minimum"], 3600)

    def test_unknown_type_is_hex(self):
        wire = binascii.unhexlify("deadbeef")
        self.assertEqual(parse_rdata(99, wire, 0, 4), "deadbeef")

    def test_rdata_past_end_rejected(self):
        with self.assertRaises(DNSFormatError):
            parse_rdata(TYPE_A, b"\x01\x02", 0, 4)


class ResponseTests(unittest.TestCase):
    def _response(self, **kw):
        answers = kw.pop("answers", [
            {"name": "example.com.", "type": TYPE_A, "ttl": 3600,
             "rdata": "93.184.216.34"},
        ])
        return build_response(0x4242, kw.pop("qname", "example.com."),
                              kw.pop("qtype", "A"), answers=answers, **kw)

    def test_roundtrip_header_and_answer(self):
        parsed = parse_message(self._response())
        self.assertEqual(parsed["id"], 0x4242)
        self.assertTrue(parsed["response"])
        self.assertTrue(parsed["authoritative"])
        self.assertEqual(parsed["rcode_name"], "NOERROR")
        self.assertEqual(len(parsed["answers"]), 1)
        rr = parsed["answers"][0]
        self.assertEqual(rr["name"], "example.com.")
        self.assertEqual(rr["type_name"], "A")
        self.assertEqual(rr["ttl"], 3600)
        self.assertEqual(rr["rdata"], "93.184.216.34")

    def test_nxdomain_flags(self):
        parsed = parse_message(self._response(rcode=3, answers=[]))
        self.assertEqual(parsed["rcode_name"], "NXDOMAIN")
        self.assertEqual(parsed["answers"], [])

    def test_not_authoritative(self):
        parsed = parse_message(self._response(authoritative=False))
        self.assertFalse(parsed["authoritative"])

    def test_multiple_answers_and_sections(self):
        authority = [{"name": "example.com.", "type": TYPE_NS, "ttl": 172800,
                      "rdata": "ns1.example.com."}]
        additional = [{"name": "ns1.example.com.", "type": TYPE_A, "ttl": 172800,
                       "rdata": "192.0.2.1"}]
        answers = [
            {"name": "x.example.com.", "type": TYPE_A, "ttl": 300, "rdata": "192.0.2.10"},
            {"name": "x.example.com.", "type": TYPE_TXT, "ttl": 300,
             "rdata": ["hello world"]},
        ]
        parsed = parse_message(self._response(
            qname="x.example.com.", answers=answers,
            authority=authority, additional=additional))
        self.assertEqual(len(parsed["answers"]), 2)
        self.assertEqual(parsed["answers"][1]["rdata"], ["hello world"])
        self.assertEqual(parsed["authority"][0]["rdata"], "ns1.example.com.")
        self.assertEqual(parsed["additional"][0]["rdata"], "192.0.2.1")

    def test_encode_rr_length_prefix(self):
        rr = encode_rr("a.b.", TYPE_A, 60, "1.2.3.4")
        # last 4 bytes are rdata; rdlength byte before them is 4
        self.assertEqual(rr[-5], 4)
        self.assertEqual(len(rr), len(encode_name("a.b.")) + 10 + 4)


class MessageGuardsTests(unittest.TestCase):
    def test_too_short(self):
        with self.assertRaises(DNSFormatError):
            parse_message(b"\x00" * 11)

    def test_question_count_overrun(self):
        header = struct.pack(">6H", 1, 0x8180, 3, 0, 0, 0)
        with self.assertRaises(DNSFormatError):
            parse_message(header + encode_name("a.b") + b"\x00\x01\x00\x01")

    def test_hexdump_layout(self):
        lines = hexdump(bytes(range(20)))
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("0000"))
        self.assertTrue(lines[1].startswith("0010"))
        self.assertIn("|", lines[0])


if __name__ == "__main__":
    unittest.main()
