#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# CTAPHID reassembly vectors (CTAP2.1 11.2.9): one 64-byte report per
# line, 128 hex chars, '#' comments. Frame layout per the shipping
# contract: cid[4 LE], type|0x80 or seq, bcnt[2 BE] (INIT), data.

import struct

CID = 0x11223344
CID2 = 0xAABBCCDD
CID3 = 0x01020304
BROADCAST = 0xFFFFFFFF
CTAPHID_INIT = 0x86
MSG_CAP = 7609  # 57 + 128*59


def pat(n):
    return bytes((i * 7 + 3) & 0xFF for i in range(n))


def init(cid, cmd, payload):
    r = bytearray(64)
    r[0:4] = struct.pack("<I", cid)
    r[4] = 0x80 | cmd
    r[5:7] = struct.pack(">H", len(payload))
    n = min(len(payload), 57)
    r[7 : 7 + n] = payload[:n]
    return bytes(r)


def cont(cid, seq, payload):
    r = bytearray(64)
    r[0:4] = struct.pack("<I", cid)
    r[4] = seq & 0x7F
    n = min(len(payload), 59)
    r[5 : 5 + n] = payload[:n]
    return bytes(r)


frames = []


def case(name, fs):
    frames.append("# " + name)
    frames.extend(f.hex() for f in fs)


case("single-packet message", [init(CID, 3, pat(5))])
case("two-packet message", [init(CID, 3, pat(100)), cont(CID, 0, pat(100)[57:])])
case("sequence gap aborts", [init(CID, 3, pat(100)), cont(CID, 1, pat(100)[57:])])
case("post-gap continuation", [cont(CID, 1, pat(100)[57:])])
case(
    "cross-channel CONT is busy, tx intact",
    [
        init(CID2, 3, pat(100)),
        cont(CID3, 0, pat(100)[57:]),
        cont(CID2, 0, pat(100)[57:]),
    ],
)
case("stray continuation ignored", [cont(CID, 0, pat(59))])
case("zero bcnt is an empty message", [init(CID, 3, b"")])
case("bcnt over cap rejected", [init(CID, 3, pat(MSG_CAP + 1))])
case(
    "mid-tx INIT on the same channel aborts",
    [init(CID, 3, pat(100)), init(CID, 3, pat(4))],
)
case("continuation after the abort is stray", [cont(CID, 0, pat(100)[57:])])
case(
    "mid-tx INIT on another channel is busy",
    [init(CID2, 3, pat(100)), init(CID3, 3, pat(4)), cont(CID2, 0, pat(100)[57:])],
)
case("exact single-frame fill (57)", [init(CID, 3, pat(57))])
case("one byte into a second frame (58)", [init(CID, 3, pat(58)), cont(CID, 0, pat(58)[57:])])
case("exact two-frame fill (116)", [init(CID, 3, pat(116)), cont(CID, 0, pat(116)[57:])])

maxp = pat(MSG_CAP)
maxframes = [init(CID, 3, maxp)]
off = 57
seq = 0
while off < MSG_CAP:
    maxframes.append(cont(CID, seq, maxp[off:]))
    off += 59
    seq += 1
case("maximum message (7609)", maxframes)
case("second message after done", [init(CID, 2, pat(10))])
case("cid zero rejected", [init(0, 3, pat(5))])
case("broadcast MSG rejected", [init(BROADCAST, 3, pat(5))])
case("broadcast CONT rejected", [cont(BROADCAST, 0, pat(59))])
case("broadcast INIT command accepted", [init(BROADCAST, CTAPHID_INIT & 0x7F, b"")])

# TX framing: "T <cid> <cmd> <payload-hex>" lines; both sides split the
# response and must emit identical F-frames.


def tcase(name, cid, cmd, payload):
    frames.append("# " + name)
    frames.append("T {:08x} {:02x} {}".format(cid, cmd & 0xFF, payload.hex()))


tcase("tx: empty message is a bare INIT", CID, 0x86, b"")
tcase("tx: single byte", CID, 0x83, pat(1))
tcase("tx: exact INIT fill (57)", CID, 0x83, pat(57))
tcase("tx: one byte into a CONT (58)", CID, 0x83, pat(58))
tcase("tx: exact two-frame fill (116)", CID, 0x83, pat(116))
tcase("tx: 117", CID, 0x83, pat(117))
tcase("tx: keepalive is a one-byte response", CID, 0xBB, b"\x01")
tcase("tx: error frame shape", CID, 0xBF, b"\x2c")
tcase("tx: cmd passes through verbatim (no bit forcing)", CID, 0x03, pat(5))
tcase("tx: maximum message (7609)", CID, 0x83, pat(MSG_CAP))
tcase("tx: one short of the maximum (7608)", CID, 0x83, pat(MSG_CAP - 1))
tcase("tx: broadcast cid passthrough", BROADCAST, 0x86, pat(100))
tcase("tx: cid zero passthrough", 0, 0x83, pat(100))
tcase("tx: cid one", 1, 0x83, pat(60))

# Harness parse-parity: trailing whitespace and CRLF must trim identically
# on both sides of the differential (the C harness mirrors the oracle's
# trim() in both directions).
frames.append("# tx: trailing spaces after the payload hex")
frames.append("T {:08x} {:02x} {}  ".format(CID, 0x83, pat(5).hex()))
frames.append("# frame line with a trailing \\r (CRLF input)")
frames.append(init(CID, 3, pat(5)).hex() + "\r")
frames.append("# frame line with trailing spaces")
frames.append(init(CID2, 3, pat(57)).hex() + "  ")

print("\n".join(frames))
