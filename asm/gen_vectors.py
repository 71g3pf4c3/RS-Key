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

print("\n".join(frames))
