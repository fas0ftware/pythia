"""Just enough of the DNS wire format (RFC 1035) for a filtering forwarder.

Pythia never builds answers from upstream data itself: it reads the question, decides,
and either answers "blocked" or forwards the client's own bytes (with a new id) and
relays the upstream answer. So parsing is limited to the header, the question, and
walking resource records to find TTLs for the cache. Everything is bounds-checked;
a malformed packet raises FormatError and gets FORMERR (or is dropped).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

HEADER = struct.Struct("!HHHHHH")
MAX_LABELS = 128

# types
A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, OPT, SVCB, HTTPS, ANY = 1, 2, 5, 6, 12, 15, 16, 28, 33, 41, 64, 65, 255
TYPE_NAMES = {A: "A", NS: "NS", CNAME: "CNAME", SOA: "SOA", PTR: "PTR", MX: "MX", TXT: "TXT", AAAA: "AAAA",
              SRV: "SRV", OPT: "OPT", SVCB: "SVCB", HTTPS: "HTTPS", ANY: "ANY"}
CLASS_IN = 1

# rcodes
NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED = 0, 1, 2, 3, 4, 5

QR, AA, TC, RD, RA = 0x8000, 0x0400, 0x0200, 0x0100, 0x0080


class FormatError(ValueError):
    pass


@dataclass
class Query:
    id: int
    flags: int
    name: str              # lower case, no trailing dot; "" for the root
    qtype: int
    qclass: int
    question: bytes        # the raw question section, copied into answers

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0xF

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.qtype, str(self.qtype))


def read_name(data: bytes, off: int) -> tuple[str, int]:
    """Decode a (possibly compressed) name. Returns (name, offset after the name in place)."""
    labels, end, jumps = [], None, 0
    while True:
        if off >= len(data):
            raise FormatError("name runs past the end")
        n = data[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise FormatError("truncated pointer")
            if end is None:
                end = off + 2
            jumps += 1
            if jumps > MAX_LABELS:
                raise FormatError("pointer loop")
            off = ((n & 0x3F) << 8) | data[off + 1]
            continue
        if n & 0xC0:
            raise FormatError("unsupported label type")
        off += 1
        if n == 0:
            break
        if off + n > len(data):
            raise FormatError("label runs past the end")
        labels.append(data[off:off + n])
        off += n
        if len(labels) > MAX_LABELS:
            raise FormatError("too many labels")
    name = b".".join(labels)
    if len(name) > 253:
        raise FormatError("name too long")
    # Names are bytes on the wire; keep them printable and lower case.
    text = name.decode("ascii", errors="replace").lower()
    return text, end if end is not None else off


def parse_query(data: bytes) -> Query:
    if len(data) < HEADER.size:
        raise FormatError("shorter than a header")
    qid, flags, qd, an, ns, ar = HEADER.unpack_from(data)
    if flags & QR:
        raise FormatError("a response, not a query")
    if qd != 1:
        raise FormatError(f"{qd} questions")
    name, off = read_name(data, HEADER.size)
    if off + 4 > len(data):
        raise FormatError("truncated question")
    qtype, qclass = struct.unpack_from("!HH", data, off)
    return Query(qid, flags, name, qtype, qclass, data[HEADER.size:off + 4])


def _header(q: Query, rcode: int, answers: int) -> bytes:
    flags = QR | (q.flags & (0x7800 | RD)) | RA | rcode   # keep opcode and RD
    return HEADER.pack(q.id, flags, 1, answers, 0, 0)


def error_response(q: Query, rcode: int) -> bytes:
    return _header(q, rcode, 0) + q.question


def bare_error(data: bytes, rcode: int) -> bytes | None:
    """FORMERR/NOTIMP for packets whose question cannot be trusted: header only."""
    if len(data) < 2:
        return None
    return HEADER.pack(struct.unpack_from("!H", data)[0], QR | RA | rcode, 0, 0, 0, 0)


def blocked_response(q: Query, ttl: int) -> bytes:
    """A -> 0.0.0.0, AAAA -> ::, anything else -> no data. Browsers then fail fast."""
    if q.qclass == CLASS_IN and q.qtype in (A, AAAA):
        rdata = bytes(4 if q.qtype == A else 16)
        rr = struct.pack("!HHHIH", 0xC00C, q.qtype, CLASS_IN, ttl, len(rdata)) + rdata
        return _header(q, NOERROR, 1) + q.question + rr
    return _header(q, NOERROR, 0) + q.question


def with_id(data: bytes, qid: int) -> bytes:
    return struct.pack("!H", qid) + data[2:]


def response_id(data: bytes) -> int:
    return struct.unpack_from("!H", data)[0]


def rcode(data: bytes) -> int:
    return HEADER.unpack_from(data)[1] & 0xF


def has_additional(data: bytes) -> bool:
    """The query carries additional records: in practice an EDNS OPT with a bigger UDP size."""
    return HEADER.unpack_from(data)[5] > 0


def is_truncated(data: bytes) -> bool:
    return bool(HEADER.unpack_from(data)[1] & TC)


def ttl_offsets(data: bytes) -> tuple[list[int], int | None]:
    """Offsets of the TTL field of every record outside OPT, and the smallest TTL
    (None when there are no records). Used to age cached answers."""
    if len(data) < HEADER.size:
        raise FormatError("short response")
    _, _, qd, an, ns, ar = HEADER.unpack_from(data)
    off = HEADER.size
    for _ in range(qd):
        _, off = read_name(data, off)
        off += 4
    offsets, smallest = [], None
    for _ in range(an + ns + ar):
        _, off = read_name(data, off)
        if off + 10 > len(data):
            raise FormatError("truncated record")
        rtype, _, ttl, rdlen = struct.unpack_from("!HHIH", data, off)
        if rtype != OPT:
            offsets.append(off + 4)
            smallest = ttl if smallest is None else min(smallest, ttl)
        off += 10 + rdlen
        if off > len(data):
            raise FormatError("record runs past the end")
    return offsets, smallest


def age_ttls(data: bytes, offsets: list[int], elapsed: int) -> bytes:
    """Subtract the seconds an answer spent in the cache from every TTL (never below 0)."""
    buf = bytearray(data)
    for o in offsets:
        old = struct.unpack_from("!I", buf, o)[0]
        struct.pack_into("!I", buf, o, max(0, old - elapsed))
    return bytes(buf)


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        if label:
            raw = label.encode("idna") if not label.isascii() else label.encode()
            if len(raw) > 63:
                raise FormatError("label too long")
            out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name: str, qtype: int, qid: int = 0x1234, rd: bool = True) -> bytes:
    """A plain query (tests, health checks)."""
    return HEADER.pack(qid, RD if rd else 0, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)
