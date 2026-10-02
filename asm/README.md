/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

# asm/ — the parallel assembly rewrite track

Hand-written RP2350 assembly for the RS-Key authenticator, built and verified
**outside** the firmware tree. It is a parallel track: `asm/` must never touch
`firmware/`. The shipping Rust+embassy firmware remains the product; this
directory is a ground-up rewrite of selected pieces — boot image, CTAPHID
reassembly kernel, USB device driver — to prove the register facts and framing
contract independently of the Rust implementation.

Everything is host-verified: the stateful logic is differentially tested against
the shipping Rust code, and the `firmware/` tree is not modified by anything in
here. No file here is linked into a firmware binary.

## Layout

| File | What |
|---|---|
| `boot.S` | M2 boot image: vector table, reset handler (.data/.bss copy), pad/FUNCSEL + GPIO blink. Publishes a `__image_def` block byte-identical to the shipping `image_def` at `0x10000114` — the pre-`pt.sh`, unpartitioned form. |
| `link.ld` | M2 memory map: 16 MiB XIP flash window + 520 KiB SRAM. Full region-by-region map with security classification is deferred to M3. |
| `build.sh` | asm → ELF → `.bin`/`.uf2`, deterministic. Dumps `target/asm/ref.disasm` from the shipping firmware for the audit trail. Requires the `nix develop` devshell (`arm-none-eabi-gcc`, `picotool`). |
| `ctaphid.S` | CTAPHID reassembly kernel (CTAP 2.1 §11.2.9). Pure: no hardware, no allocator; parses host-controlled framing and emits events (busy/done/error/ignored). The differentially tested core. |
| `difftest.S` | Linux user-mode entry for the differential harness: raw EABI syscalls, no libc. |
| `difftest.c` | Differential harness driver: one 64-byte report per stdin line → `ctaphid_feed`, prints the event stream in the oracle's exact format. |
| `difftest.sh` | Builds the ARM side + Rust oracle, then requires byte-identical event streams over the spec vectors and seeded random frames. |
| `gen_vectors.py` | Spec/reassembly vectors (CTAP 2.1 §11.2.9): single/multi-packet, gaps, cross-channel, broadcast, cap-overflow, maximum 7609-byte message. |
| `gen_random.py` | Seeded random frames for the fuzz differential: `noise` (uniform garbage around the framing) and `mixed` (valid transactions with noise interleaved on live state). |
| `oracle/` | Rust differential oracle over rsk-usb's `Reassembler` — the **shipping** implementation. A detached cargo workspace (the `tools/emu` pattern); links `rsk-usb` from `../../crates/rsk-usb` for host execution only. |
| `usb.S` | USB device-side driver for the RP2350 USBCTRL block: chapter-9 EP0 control transfers plus the EP1 interrupt endpoints that carry CTAPHID. Plain MMIO, one event per `usb_task`; register facts cite pico-sdk 2.2.0 headers. |
| `usbtest.c` | Model-level USB harness: maps the USBCTRL register file + DPSRAM as plain memory under qemu-user and runs the driver against a datasheet-derived SIE model. |
| `usbtest.sh` | Builds `usb.S` + the SIE-model harness into a static ARM ELF and runs it under `qemu-arm`. |

## Running it

Everything builds inside `nix develop` — `arm-none-eabi-gcc` and `picotool`
live only in the devshell. `qemu-arm` does **not**; the devshell does not ship
it (flakes are maintainer-only). Point `QEMU=` at any `qemu-arm`, e.g. the
store path.

### Boot image

```
nix develop -c ./asm/build.sh
```

Outputs `target/asm/boot.{elf,bin,uf2}` + `boot.disasm`/`ref.disasm`. The build
is deterministic: two runs produce byte-identical `.bin` and `.elf` (buried
timestamps and build paths are none). The boot image's `__image_def` block
matches the shipping `image_def` byte-for-byte; `ref.disasm` backs the pad/SIO
register facts the source cites.

### CTAPHID differential

```
QEMU=/nix/store/m4qamr94ba84viib1l2wskzwr90hbmmn-qemu-10.2.4/bin/qemu-arm \
nix develop -c ./asm/difftest.sh [frames_per_seed]
```

Default 700 frames/seed × 5 seeds × {noise, mixed}; spec vectors always run
first. The oracle builds with an explicit host target triple (`HOST_TARGET`,
defaulting to the current `rustc` host). Green means the ARM reassembly kernel
and the shipping `rsk-usb` `Reassembler` emit **byte-identical** event streams
— a divergence is an asm bug or a spec reading to adjudicate, never noise.

### USB model tests

```
QEMU=... nix develop -c ./asm/usbtest.sh
```

63 checks: chapter-9 EP0 enumeration (device/config/HID-report descriptors,
wLength clamp, SET_ADDRESS latch + §9.6.2 overflow stall, GET_STATUS/interface,
unknown-request stall, bus-reset address/pid clearing) and the EP1 CTAPHID data
path (single/multi-packet, out-of-sequence abort, short-packet tail zeroing,
IN data-toggle tracking).
Fails if a wrong-register poll would hang the driver (guarded by `timeout 60`).

## Verification status

- **CTAPHID kernel — differentially tested.** Byte-identical to the shipping
  Rust implementation over the spec vectors *and* hundreds of thousands of
  seeded random frames (5 seeds × 700 × 2 modes = 7 k-frames per run). The
  oracle links the shipping `rsk-usb` `Reassembler`; the two event streams must
  `cmp` clean.
- **USB driver — verified against a MODEL.** The SIE model is derived from the
  datasheet, with write-to-clear behaviour and explicit host-driven EP1 OUT
  delivery. Green here means datasheet-model agreement only — real-silicon
  enumeration is **untested** and is the next gate.
- **Boot image — byte-identical `image_def`.** Matches the shipping block at
  `0x10000114` (picotool parses it as `image def / RP2350 / ARM Secure`). The
  `ref.disasm` audit trail is produced by `build.sh`.

## Not here yet

- **CTAPHID TX response framing.** `ctaphid.S` reassembles host→device only
  (the `IN` half of the contract); multi-packet *responses* are unwritten.
- **Hardware bring-up.** The USB driver is model-tested; nothing here has run
  against real silicon.
- **String descriptors.** `usb_dev_desc`/`usb_cfg_desc`/`usb_report_desc`
  exist; the string descriptor path that serviceable auths want is absent.