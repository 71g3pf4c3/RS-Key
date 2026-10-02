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

# INIT allocation: "I <can_wink> <nonce-hex>" lines; both sides allocate a
# persistent next_cid from FIRST_CID and compose, then broadcast-frame the
# 17-byte reply (nonce||newcid LE||iface 2||major||minor||build||caps).


def icase(name, can_wink, nonce):
    frames.append("# " + name)
    frames.append("I {} {}".format(can_wink, nonce.hex()))


icase("init: broadcast reply, can_wink off", 0, b"\x01\x02\x03\x04\x05\x06\x07\x08")
icase("init: broadcast reply, can_wink on", 1, bytes(range(8)))
icase("init: cid sequence step 1", 0, b"\x00" * 8)
icase("init: cid sequence step 2", 0, b"\x00" * 8)
icase("init: cid sequence step 3", 0, b"\x00" * 8)
icase("init: nonce all-zero", 1, b"\x00" * 8)
icase("init: nonce all-ff", 0, b"\xff" * 8)
icase("init: nonce mixed", 1, bytes([0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]))
frames.append("# init: odd nonce length X-parses identically")
frames.append("I 0 deadbeef")

# Transport control: keepalive / cancel / channel lock. "K <is_cbor> <up_pending>"
# -> "S 00|01|02"; "C <128-hex frame> <n dec> <cid 8-hex>" -> "C 0|1";
# "L arm <cid 8-hex> <secs dec> <now_ms dec>" persists the lock (no output);
# "L refuse <cid 8-hex> <cmd 2-hex> <now_ms dec>" -> "R 0|1".

LOWN = 0x11223344
LOTH = 0x01000001


def kcase(name, is_cbor, up):
    frames.append("# keepalive: " + name)
    frames.append("K {} {}".format(is_cbor, up))


kcase("u2f fast op stays silent", 0, 0)      # None
kcase("u2f touch wait", 0, 1)                # UPNEEDED
kcase("cbor slow op", 1, 0)                  # PROCESSING
kcase("cbor touch wait", 1, 1)               # UPNEEDED (touch wins)


def cframe(cid, cmd):
    b = bytearray(64)
    b[0:4] = struct.pack("<I", cid)
    b[4] = cmd
    return bytes(b)


def ccase(name, cid, cmd, n, want):
    frames.append("# cancel: {0} -> C {1}".format(name, want))
    frames.append("C {} {} {:08x}".format(cframe(cid, cmd).hex(), n, cid))


ccase("full 64-byte frame, matching cid", LOWN, 0x91, 64, 1)
ccase("n=63 matching", LOWN, 0x91, 63, 1)
ccase("n=6 matching", LOWN, 0x91, 6, 1)
ccase("n=5 boundary matching", LOWN, 0x91, 5, 1)
ccase("n=4 too short to carry a command byte", LOWN, 0x91, 4, 0)
ccase("n=64 wrong command byte is not a cancel", LOWN, 0x86, 64, 0)
ccase("n=64 mismatched cid", LOTH, 0x91, 64, 0)
ccase("broadcast frame matching broadcast cid", BROADCAST, 0x91, 5, 1)
ccase("broadcast frame, mismatched cid", LOWN, 0x91, 5, 0)

# the 2x2 keepalive table lives in difftest output already; finish the cancel
# family with the tiny-n differential gold rows
ccase("n=63 mismatched", LOTH, 0x91, 63, 0)
ccase("n=6 non-cancel cmd", LOWN, 0x81, 6, 0)

# channel lock: expiry boundary, strict < (until == now is unblocked). arm
# owner t=2s at now=1000 -> until=3000, then probe at 2999/3000/3001.


def larm(name, cid, secs, now):
    frames.append("# lock: " + name)
    frames.append("L arm {:08x} {} {}".format(cid, secs, now))


def lrefuse(name, cid, cmd, now):
    frames.append("# lock: " + name)
    frames.append("L refuse {:08x} {:02x} {}".format(cid, cmd & 0xFF, now))


larm("expiry boundary cluster: arm owner 2s", LOWN, 2, 1000)
lrefuse("owner at until-1 not blocked", LOWN, 0x81, 2999)
lrefuse("other at until-1 blocked", LOTH, 0x81, 2999)
lrefuse("owner at until not blocked", LOWN, 0x81, 3000)
lrefuse("other at until == unblocked (strict <)", LOTH, 0x81, 3000)
lrefuse("owner at until+1 not blocked", LOWN, 0x81, 3001)
lrefuse("other at until+1 unblocked", LOTH, 0x81, 3001)
lrefuse("broadcast INIT at until-1 carve-out", BROADCAST, 0x86, 2999)
lrefuse("broadcast INIT at until+1 carve-out", BROADCAST, 0x86, 3001)

# carve-out matrix: cmd x cid at a now well before any expiry (arm holds for 5s)
larm("carve-out matrix: owner locks 5s", LOWN, 5, 1000)
for cmd in (0x86, 0x81, 0x83, 0x91, 0xBB):
    for cid, tag in ((LOWN, "owner"), (LOTH, "other"), (BROADCAST, "broadcast")):
        want = "unblocked"
        if cid != LOWN and not (cmd == 0x86 and cid == BROADCAST):
            want = "blocked"
        lrefuse("carve-out cmd=0x{0:02x} cid={1} -> {2}".format(cmd, tag, want),
                cid, cmd, 1500)

# release ownership: only the owner may release
larm("release: owner locks 10s", LOWN, 10, 1000)
lrefuse("other blocked before release", LOTH, 0x81, 1500)
larm("non-owner release is ignored", LOTH, 0, 1500)
lrefuse("still blocked after non-owner release attempt", LOTH, 0x81, 1500)
larm("owner release clears", LOWN, 0, 1500)
lrefuse("other unblocked after owner release", LOTH, 0x81, 1500)
lrefuse("other unblocked after owner release, later now", LOTH, 0x83, 3000)

# secs=0 on a fresh lock is a harmless no-op (no lock was ever taken)
lrefuse("fresh lock refuses nothing", LOTH, 0x81, 500)
larm("secs=0 on a fresh lock is a no-op", LOTH, 0, 500)
lrefuse("still nothing refused", LOTH, 0x81, 1500)

# non-monotonic now_ms: the kernel must not assume a clock that advances
larm("non-monotonic now: arm owner 2s", LOWN, 2, 1000)
lrefuse("refuse at an earlier now still respects the lock", LOTH, 0x81, 500)

# malformed control lines: both sides must X-parse identically
frames.append("# malformed: cancel n out of range (65) X-parses")
frames.append("C {} 65 {:08x}".format(cframe(LOWN, 0x91).hex(), LOWN))
frames.append("# malformed: cancel frame short of 128 hex X-parses")
frames.append("C {} 64 {:08x}".format(cframe(LOWN, 0x91).hex()[:-2], LOWN))
frames.append("# malformed: keepalive is_cbor not 0/1 X-parses")
frames.append("K 2 0")
frames.append("# malformed: keepalive missing the up_pending field X-parses")
frames.append("K 1")
frames.append("# malformed: arm secs not decimal X-parses")
frames.append("L arm {:08x} abc 1000".format(LOWN))
frames.append("# malformed: refuse cmd not 2 hex digits X-parses")
frames.append("L refuse {:08x} 0 1000".format(LOWN))
frames.append("# malformed: refuse unknown op X-parses")
frames.append("L bogus {:08x} 81 1000".format(LOWN))
frames.append("# malformed: refuse cid short of 8 hex X-parses")
frames.append("L refuse 1122 81 1000")

print("\n".join(frames))
