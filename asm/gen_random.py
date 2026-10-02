#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Seeded random CTAPHID frames for the differential harness.

usage: gen_random.py SEED N [noise|mixed]

noise: every frame is uniform garbage around the framing (wrong cids, seqs,
        bcnts past the cap, broadcast, cid zero).
mixed: valid transactions with random lengths (including empty, exact-fit and
        full 7609) with noise frames interleaved mid-transaction — restarts,
        cross-channel injections and gaps land on live state.
tx:    "T cid cmd payload" lines — response framing with random lengths,
        cmds with and without the INIT bit, and edge cids; roughly every
        third line is instead an "I can_wink nonce-hex" INIT allocation
        demand, so the differential also fuzzes the reply composition.
ctrl:  transport-control lines — "K is_cbor up_pending" keepalive, "C frame
        n cid" cancel detection, and "L arm/refuse ..." channel-lock lines
        with random lock times (0..10 s and occasionally past the dispatcher's
        LOCK_MAX_SECONDS clamp, which neither side may apply) and now_ms drift
        that crosses lock expiry.
"""

import random
import struct
import sys

CIDS = [0x11223344, 0xAABBCCDD, 0x01020304, 0xFFFFFFFF, 0]
LOWNCIDS = [0x11223344, 0xAABBCCDD, 0x01020304]
CONTROL_CMDS = [0x86, 0x81, 0x83, 0x91, 0xBB]
LOCK_SECS = [0, 1, 2, 5, 9, 10, 11, 12, 15, 20, 30, 40]


def pat(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def init_frame(cid, cmd, payload):
    b = bytearray(64)
    b[0:4] = struct.pack("<I", cid)
    b[4] = 0x80 | cmd
    b[5:7] = struct.pack(">H", len(payload))
    n = min(len(payload), 57)
    b[7 : 7 + n] = payload[:n]
    return bytes(b)


def cont_frame(cid, seq, payload):
    b = bytearray(64)
    b[0:4] = struct.pack("<I", cid)
    b[4] = seq & 0x7F
    n = min(len(payload), 59)
    b[5 : 5 + n] = payload[:n]
    return bytes(b)


def noise_frame(rng):
    cid = rng.choice(CIDS)
    if rng.randrange(100) < 35:
        b = bytearray(64)
        b[0:4] = struct.pack("<I", cid)
        b[4] = 0x80 | rng.choice([3, 2, 6, rng.randrange(0x80)])
        bcnt = rng.choice([0, 5, 57, 58, 59, 116, rng.randrange(7700), 7610])
        b[5:7] = struct.pack(">H", bcnt)
        d = pat(rng, min(bcnt, 57))
        b[7 : 7 + len(d)] = d
        return bytes(b)
    b = bytearray(64)
    b[0:4] = struct.pack("<I", cid)
    b[4] = rng.randrange(0x88)  # seq, sometimes with the INIT bit set
    d = pat(rng, rng.randrange(60))
    b[5 : 5 + len(d)] = d
    return bytes(b)


def tx_line(rng):
    cid = rng.choice(CIDS)
    cmd = rng.choice(
        [0x83, 0x86, 0xBB, 0xBF, 0x80 | rng.randrange(8), rng.randrange(0x80)]
    )
    ln = rng.choice(
        [0, 1, 56, 57, 58, 59, 116, 117, rng.randrange(1, 2000), rng.randrange(2000, 7610)]
    )
    return "T {:08x} {:02x} {}".format(cid, cmd, pat(rng, ln).hex())


def cancel_frame(cid, cmd):
    b = bytearray(64)
    b[0:4] = struct.pack("<I", cid)
    b[4] = cmd
    return bytes(b)


def ctrl_lines(rng, n):
    """Random transport-control lines. The lock context is threaded through so
    refuse lines land at random now_ms around a just-taken lock's expiry —
    exercising the strict-boundary comparison the expiry tests pin."""
    out = []
    active = None  # (cid, until_ms) of the last arm(secs>0), or None

    def arm_line():
        nonlocal active
        cid = rng.choice(LOWNCIDS + [0xFFFFFFFF])
        secs = rng.choice(LOCK_SECS)
        now = rng.randrange(0, 10_000_000)
        if secs > 0:
            active = (cid, now + secs * 1000)
        elif active and active[0] == cid:
            active = None  # an owner release clears; a non-owner's is ignored
        return "L arm {:08x} {} {}".format(cid, secs, now)

    def refuse_line():
        cid = rng.choice(CIDS)
        cmd = rng.choice(CONTROL_CMDS)
        if active and rng.random() < 0.8:
            # probe across the active lock's expiry instant
            until = active[1]
            now = rng.choice(
                [until - rng.randrange(0, 3000), until - 1, until, until + 1,
                 until + rng.randrange(0, 3000)]
            )
        else:
            now = rng.randrange(0, 10_000_000)
        return "L refuse {:08x} {:02x} {}".format(cid, cmd, max(now, 0))

    for _ in range(n):
        r = rng.random()
        if r < 0.25:
            out.append("K {} {}".format(
                rng.choice(["0", "1"]), rng.choice(["0", "1"])))
        elif r < 0.55:
            out.append(refuse_line())
        elif r < 0.80:
            out.append(arm_line())
            if active and rng.random() < 0.4:
                # a short burst of refuses right at the new lock's boundary
                for _ in range(rng.randrange(1, 4)):
                    out.append(refuse_line())
        else:
            cid = rng.choice(CIDS)
            b = cancel_frame(cid, rng.choice([0x91, 0x86, 0x81, rng.randrange(0x100)]))
            nf = rng.randrange(0, 66)  # 0..65; 65 X-parses identically both sides
            out.append("C {} {} {:08x}".format(b.hex(), nf, cid))
    return out


def main():
    seed = int(sys.argv[1])
    n = int(sys.argv[2])
    mode = sys.argv[3] if len(sys.argv) > 3 else "noise"
    rng = random.Random(seed)

    out = []
    if mode == "tx":
        for _ in range(n):
            if rng.randrange(3) == 0:
                out.append("I {} {}".format(rng.choice(["0", "1"]), pat(rng, 8).hex()))
            else:
                out.append(tx_line(rng))
        print("\n".join(out))
        return
    if mode == "ctrl":
        print("\n".join(ctrl_lines(rng, n)))
        return
    tx = None  # live valid transaction: (cid, payload, off, seq)
    for _ in range(n):
        if mode == "mixed":
            if tx is None:
                if rng.random() < 0.55:
                    cid = rng.choice([0x11223344, 0xAABBCCDD, 0x01020304])
                    bcnt = rng.choice(
                        [0, 5, 57, 58, 59, 116, rng.randrange(1, 2000), rng.randrange(2000, 7610)]
                    )
                    payload = pat(rng, bcnt)
                    out.append(init_frame(cid, rng.choice([3, 2]), payload))
                    if bcnt > 57:
                        tx = (cid, payload, 57, 0)
                    continue
            else:
                if rng.random() < 0.75:
                    cid, payload, off, seq = tx
                    out.append(cont_frame(cid, seq, payload[off:]))
                    off += 59
                    seq += 1
                    tx = (cid, payload, off, seq) if off < len(payload) else None
                    continue
                # fall through: noise lands mid-transaction
        out.append(noise_frame(rng))

    print("\n".join(f.hex() for f in out))


if __name__ == "__main__":
    main()
