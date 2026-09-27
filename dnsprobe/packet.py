"""DNS wire-format encoder/decoder (RFC 1035). No dependencies, no magic.

Building a query is deterministic: header + question, no name compression.
Parsing supports compression pointers but rejects loops and forward jumps.
"""
import binascii
import socket
import struct

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28

TYPE_CODES = {
    "A": TYPE_A, "NS": TYPE_NS, "CNAME": TYPE_CNAME, "SOA": TYPE_SOA,
    "PTR": TYPE_PTR, "MX": TYPE_MX, "TXT": TYPE_TXT, "AAAA": TYPE_AAAA,
}
TYPE_NAMES = {num: name for name, num in TYPE_CODES.items()}
CLASS_IN = 1
CLASS_NAMES = {1: "IN", 3: "CH", 255: "ANY"}
RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}

MAX_LABEL_LEN = 63
MAX_NAME_LEN = 255
MAX_JUMPS = 20


class DNSFormatError(ValueError):
    """Malformed name or message."""


def encode_name(name):
    """Encode a dotted name to wire format (no compression)."""
    if not name:
        raise DNSFormatError("empty domain name")
    if name == ".":
        return b"\x00"
    labels = name.rstrip(".").split(".")
    wire = b""
    for label in labels:
        if not label:
            raise DNSFormatError(f"empty label in {name!r}")
        if not label.isascii():
            raise DNSFormatError(f"non-ASCII label {label!r} (no IDNA)")
        raw = label.encode("ascii")
        if len(raw) > MAX_LABEL_LEN:
            raise DNSFormatError(f"label {label!r} exceeds {MAX_LABEL_LEN} bytes")
        wire += bytes([len(raw)]) + raw
    if len(wire) + 1 > MAX_NAME_LEN:
        raise DNSFormatError(f"name {name!r} exceeds {MAX_NAME_LEN} bytes")
    return wire + b"\x00"


def decode_name(data, offset):
    """Decode a possibly-compressed name. Returns (name, next_offset)."""
    labels = []
    pos = offset
    next_offset = None
    jumps = 0
    while True:
        if pos >= len(data):
            raise DNSFormatError("name runs past end of message")
        length = data[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise DNSFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if pointer >= pos:
                raise DNSFormatError("compression pointer does not point backwards")
            if next_offset is None:
                next_offset = pos + 2
            jumps += 1
            if jumps > MAX_JUMPS:
                raise DNSFormatError("too many compression jumps")
            pos = pointer
            continue
        if length == 0:
            if next_offset is None:
                next_offset = pos + 1
            return ".".join(labels) + ".", next_offset
        if length & 0xC0:
            raise DNSFormatError(f"invalid label length byte 0x{length:02x}")
        if pos + 1 + length > len(data):
            raise DNSFormatError("label runs past end of message")
        labels.append(data[pos + 1:pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length


def build_query(qid, name, qtype, rd=True, qclass=CLASS_IN):
    """Build a standard query: one question, no EDNS, no compression."""
    type_num = TYPE_CODES[qtype.upper()] if isinstance(qtype, str) else qtype
    flags = 0x0100 if rd else 0
    header = struct.pack(">6H", qid & 0xFFFF, flags, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack(">2H", type_num, qclass)


def encode_rdata(type_num, value):
    """Encode parsed rdata back to wire bytes (used by test fixtures)."""
    if type_num == TYPE_A:
        return socket.inet_aton(value)
    if type_num == TYPE_AAAA:
        return socket.inet_pton(socket.AF_INET6, value)
    if type_num in (TYPE_NS, TYPE_CNAME, TYPE_PTR):
        return encode_name(value)
    if type_num == TYPE_MX:
        return struct.pack(">H", value["preference"]) + encode_name(value["exchange"])
    if type_num == TYPE_TXT:
        out = b""
        for part in value:
            raw = part.encode("utf-8")
            if len(raw) > 255:
                raise DNSFormatError("TXT string exceeds 255 bytes")
            out += bytes([len(raw)]) + raw
        return out
    if type_num == TYPE_SOA:
        return (encode_name(value["mname"]) + encode_name(value["rname"]) +
                struct.pack(">5I", value["serial"], value["refresh"],
                            value["retry"], value["expire"], value["minimum"]))
    return binascii.unhexlify(value)


def parse_rdata(type_num, data, rdata_offset, rdlength):
    """Parse one RR's rdata given its absolute offset in the full message."""
    end = rdata_offset + rdlength
    if end > len(data):
        raise DNSFormatError("rdata runs past end of message")
    if type_num == TYPE_A:
        if rdlength != 4:
            raise DNSFormatError(f"A rdata must be 4 bytes, got {rdlength}")
        return socket.inet_ntoa(data[rdata_offset:end])
    if type_num == TYPE_AAAA:
        if rdlength != 16:
            raise DNSFormatError(f"AAAA rdata must be 16 bytes, got {rdlength}")
        return socket.inet_ntop(socket.AF_INET6, data[rdata_offset:end])
    if type_num in (TYPE_NS, TYPE_CNAME, TYPE_PTR):
        name, _ = decode_name(data, rdata_offset)
        return name
    if type_num == TYPE_MX:
        preference = struct.unpack(">H", data[rdata_offset:rdata_offset + 2])[0]
        exchange, _ = decode_name(data, rdata_offset + 2)
        return {"preference": preference, "exchange": exchange}
    if type_num == TYPE_TXT:
        strings = []
        pos = rdata_offset
        while pos < end:
            slen = data[pos]
            if pos + 1 + slen > end:
                raise DNSFormatError("TXT string runs past rdata")
            strings.append(data[pos + 1:pos + 1 + slen].decode("utf-8", "replace"))
            pos += 1 + slen
        return strings
    if type_num == TYPE_SOA:
        mname, pos = decode_name(data, rdata_offset)
        rname, pos = decode_name(data, pos)
        if pos + 20 > end:
            raise DNSFormatError("SOA numbers run past rdata")
        serial, refresh, retry, expire, minimum = struct.unpack(
            ">5I", data[pos:pos + 20])
        return {"mname": mname, "rname": rname, "serial": serial,
                "refresh": refresh, "retry": retry, "expire": expire,
                "minimum": minimum}
    return binascii.hexlify(data[rdata_offset:end]).decode("ascii")


def parse_message(data):
    """Parse a DNS message into plain dicts. Raises DNSFormatError on junk."""
    if len(data) < 12:
        raise DNSFormatError(f"message shorter than header: {len(data)} bytes")
    msg_id, flags, qd, an, ns, ar = struct.unpack(">6H", data[:12])
    message = {
        "id": msg_id,
        "response": bool(flags & 0x8000),
        "opcode": (flags >> 11) & 0xF,
        "authoritative": bool(flags & 0x0400),
        "truncated": bool(flags & 0x0200),
        "recursion_desired": bool(flags & 0x0100),
        "recursion_available": bool(flags & 0x0080),
        "rcode": flags & 0xF,
        "rcode_name": RCODE_NAMES.get(flags & 0xF, f"RCODE{flags & 0xF}"),
        "questions": [],
        "answers": [],
        "authority": [],
        "additional": [],
    }
    offset = 12
    for _ in range(qd):
        name, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise DNSFormatError("question runs past end of message")
        type_num, qclass = struct.unpack(">2H", data[offset:offset + 4])
        offset += 4
        message["questions"].append({
            "name": name,
            "type": type_num,
            "type_name": TYPE_NAMES.get(type_num, f"TYPE{type_num}"),
            "class": qclass,
            "class_name": CLASS_NAMES.get(qclass, f"CLASS{qclass}"),
        })
    for section, count in (("answers", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            name, offset = decode_name(data, offset)
            if offset + 10 > len(data):
                raise DNSFormatError("rr runs past end of message")
            type_num, rclass, ttl, rdlength = struct.unpack(
                ">2HIH", data[offset:offset + 10])
            offset += 10
            message[section].append({
                "name": name,
                "type": type_num,
                "type_name": TYPE_NAMES.get(type_num, f"TYPE{type_num}"),
                "class": rclass,
                "ttl": ttl,
                "rdata": parse_rdata(type_num, data, offset, rdlength),
            })
            offset += rdlength
    return message


def encode_rr(name, type_num, ttl, rdata_value, rclass=CLASS_IN):
    """Encode one resource record from parsed values (no compression)."""
    rdata = encode_rdata(type_num, rdata_value)
    return (encode_name(name) + struct.pack(">2HIH", type_num, rclass,
                                            ttl, len(rdata)) + rdata)


def build_response(qid, qname, qtype, answers=(), authority=(), additional=(),
                   rcode=0, authoritative=True, recursion_desired=True):
    """Build a reply message — used by tests and the local fake-server mode."""
    type_num = TYPE_CODES[qtype.upper()] if isinstance(qtype, str) else qtype
    flags = 0x8000 | (0x0400 if authoritative else 0) | (0x0100 if recursion_desired else 0)
    flags |= rcode & 0xF
    out = struct.pack(">6H", qid & 0xFFFF, flags, 1, len(answers),
                      len(authority), len(additional))
    out += encode_name(qname) + struct.pack(">2H", type_num, CLASS_IN)
    for rr in answers:
        out += encode_rr(rr["name"], rr["type"], rr["ttl"], rr["rdata"])
    for rr in authority:
        out += encode_rr(rr["name"], rr["type"], rr["ttl"], rr["rdata"])
    for rr in additional:
        out += encode_rr(rr["name"], rr["type"], rr["ttl"], rr["rdata"])
    return out


def hexdump(data, width=16):
    """Classic offset/hex/ascii dump, one string per line."""
    lines = []
    for start in range(0, len(data), width):
        chunk = data[start:start + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        hexpart = hexpart.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{start:04x}  {hexpart}  |{ascii_part}|")
    return lines
