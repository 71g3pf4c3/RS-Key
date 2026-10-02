// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_usb::ctaphid::{
    init_capabilities, CidAllocator, Outcome, Reassembler, TxFrames, CTAPHID_IF_VERSION,
    HID_RPT_SIZE,
};
use std::io::Read;

const TX_CAP: usize = 7609; // CTAP_MAX_MESSAGE: 57 + 128*59
const CID_BROADCAST: u32 = 0xFFFF_FFFF;
const INIT_CMD: u8 = 0x86;

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..b.len() / 2 {
        let pair = std::str::from_utf8(&b[2 * i..2 * i + 2]).ok()?;
        out.push(u8::from_str_radix(pair, 16).ok()?);
    }
    Some(out)
}

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let mut re = Reassembler::new();
    let mut allocator = CidAllocator::new();
    let mut out = String::new();

    for line in input.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }

        if let Some(rest) = l.strip_prefix("T ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            if parts.len() < 2 || parts[0].len() != 8 || parts[1].len() != 2 {
                out.push_str("X parse\n");
                continue;
            }
            let (cid, cmd, data) = (
                u32::from_str_radix(parts[0], 16),
                u8::from_str_radix(parts[1], 16),
                parse_hex(parts.get(2).copied().unwrap_or("")),
            );
            let (cid, cmd, data) = match (cid, cmd, data) {
                (Ok(c), Ok(m), Some(d)) if d.len() <= TX_CAP => (c, m, d),
                _ => {
                    out.push_str("X parse\n");
                    continue;
                }
            };
            for f in TxFrames::new(cid, cmd, &data) {
                out.push_str("F ");
                for b in f {
                    out.push_str(&format!("{:02x}", b));
                }
                out.push('\n');
            }
            continue;
        }

        if let Some(rest) = l.strip_prefix("I ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            let (can_wink, nonce) = match parts.as_slice() {
                [w, h] if (*w == "0" || *w == "1") && h.len() == 16 => match parse_hex(h) {
                    Some(b) if b.len() == 8 => (*w == "1", b),
                    _ => {
                        out.push_str("X parse\n");
                        continue;
                    }
                },
                _ => {
                    out.push_str("X parse\n");
                    continue;
                }
            };
            let cid = allocator.allocate();
            let mut payload = nonce;
            payload.extend_from_slice(&cid.to_le_bytes());
            payload.push(CTAPHID_IF_VERSION);
            let (maj, min, bld) = rsk_sdk::FIRMWARE_VERSION;
            payload.extend_from_slice(&[maj, min, bld]);
            payload.push(init_capabilities(can_wink));
            assert_eq!(payload.len(), 17);
            for f in TxFrames::new(CID_BROADCAST, INIT_CMD, &payload) {
                out.push_str("F ");
                for b in f {
                    out.push_str(&format!("{:02x}", b));
                }
                out.push('\n');
            }
            continue;
        }

        let mut rpt = [0u8; HID_RPT_SIZE];
        let b = l.as_bytes();
        let mut ok = true;
        for i in 0..HID_RPT_SIZE {
            if b.len() < 2 * i + 2 {
                ok = false;
                break;
            }
            rpt[i] = match u8::from_str_radix(&l[2 * i..2 * i + 2], 16) {
                Ok(v) => v,
                Err(_) => {
                    ok = false;
                    break;
                }
            };
        }
        if !ok {
            out.push_str("X parse\n");
            continue;
        }

        match re.feed(&rpt) {
            Outcome::None => {
                if re.in_progress() {
                    out.push_str("B\n");
                } else {
                    out.push_str("I\n");
                }
            }
            Outcome::Error(cid, code) => {
                out.push_str(&format!("E {:08x} {:02x}\n", cid, code));
            }
            Outcome::Message(cid, cmd) => {
                let m = re.message();
                out.push_str(&format!("D {:08x} {:02x} {:x} ", cid, cmd, m.len()));
                for byte in m {
                    out.push_str(&format!("{:02x}", byte));
                }
                out.push('\n');
            }
        }
    }
    print!("{out}");
}
