/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* M2 memory map: the 16 MiB XIP flash window + 520 KiB SRAM. The full
 * region-by-region map with security classification lands with M3. */

ENTRY(reset_handler)

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x10000000, LENGTH = 0x1000000
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 0x82000
}

SECTIONS
{
    .vectors   : { KEEP(*(.vectors)) } > FLASH
    .image_def : { KEEP(*(.image_def)) } > FLASH
    .text      : { *(.text*) } > FLASH
    .rodata  : { *(.rodata*) } > FLASH

    .data : {
        __data_start = .;
        *(.data*)
        __data_end = .;
    } > RAM AT > FLASH
    __data_load = LOADADDR(.data);

    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss*) *(COMMON)
        __bss_end = .;
    } > RAM

    /* MPU-granularity guard between statics and the descending stack. */
    .stack_guard (NOLOAD) : {
        . = ALIGN(32);
        __stack_guard = .;
        . += 32;
        __stack_bottom = .;
    } > RAM

    __stack_top = ORIGIN(RAM) + LENGTH(RAM);

    ASSERT(SIZEOF(.vectors) == 64, "vector table must be 16 words")
    ASSERT(SIZEOF(.image_def) == 40, "image_def must be two blocks")
    ASSERT(ADDR(.text) == ADDR(.image_def) + SIZEOF(.image_def),
           "code must directly follow the image def")
    ASSERT(__stack_top - __stack_bottom >= 0x800, "stack must be at least 2 KiB")
}
