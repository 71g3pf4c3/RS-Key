#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# Model-level USB test: builds the EP0 driver (asm/usb.S) plus its SIE-model
# harness into a static ARM Linux ELF and runs it under qemu-arm. Green here
# means datasheet-model agreement only — hardware execution is untested.

set -euo pipefail
cd "$(dirname "$0")"
OUT="$(git rev-parse --show-toplevel 2>/dev/null || echo ..)/target/asm"
QEMU_BIN="${QEMU:-qemu-arm}"
command -v "$QEMU_BIN" >/dev/null || { echo "qemu-arm not found; set QEMU=" >&2; exit 2; }

CFLAGS="-mcpu=cortex-m33 -mthumb -mfloat-abi=soft -ffreestanding -fno-builtin -nostdlib"
arm-none-eabi-gcc $CFLAGS -c difftest.S -o "$OUT/difftest-s.o"
arm-none-eabi-gcc $CFLAGS -c usb.S -o "$OUT/usb.o"
arm-none-eabi-gcc $CFLAGS -Os -c usbtest.c -o "$OUT/usbtest-c.o"
arm-none-eabi-gcc -nostdlib -static -Wl,--build-id=none -e _start \
    -o "$OUT/usbtest.elf" "$OUT/usb.o" "$OUT/difftest-s.o" "$OUT/usbtest-c.o"
arm-none-eabi-objdump -d "$OUT/usbtest.elf" > "$OUT/usbtest.disasm"
arm-none-eabi-size "$OUT/usbtest.elf"

"$QEMU_BIN" "$OUT/usbtest.elf"
