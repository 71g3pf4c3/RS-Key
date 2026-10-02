// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_usb::ctaphid::{HID_RPT_SIZE, Outcome, Reassembler};
use std::io::Read;

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let mut re = Reassembler::new();
    let mut out = String::new();

    for line in input.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
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
