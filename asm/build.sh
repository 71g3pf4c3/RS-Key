#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# M2 build: asm -> ELF -> bin/UF2, deterministic. Run inside nix develop
# (arm-none-eabi-gcc and picotool live there; no new dependencies).

set -euo pipefail
cd "$(dirname "$0")"

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo ..)"
OUT="$ROOT/target/asm"
mkdir -p "$OUT"

# Audit trail: the pad/SIO register facts in boot.S cite these sites.
arm-none-eabi-objdump -d "$ROOT/target/thumbv8m.main-none-eabihf/release/firmware" \
    > "$OUT/ref.disasm" 2>/dev/null || true

arm-none-eabi-gcc -mcpu=cortex-m33 -mthumb -mfloat-abi=hard \
    -c boot.S -o "$OUT/boot.o"
arm-none-eabi-gcc -nostdlib -static -Wl,--build-id=none \
    -Wl,-T,link.ld -o "$OUT/boot.elf" "$OUT/boot.o"
arm-none-eabi-objcopy -O binary "$OUT/boot.elf" "$OUT/boot.bin"
arm-none-eabi-objdump -d "$OUT/boot.elf" > "$OUT/boot.disasm"
arm-none-eabi-size "$OUT/boot.elf"
sha256sum "$OUT/boot.bin" "$OUT/boot.elf"
picotool uf2 convert "$OUT/boot.elf" -t elf "$OUT/boot.uf2" --family rp2350-arm-s >/dev/null
picotool info -a "$OUT/boot.uf2" | head -20
