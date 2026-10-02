/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* USB device-side EP0 driver (chapter-9 control transfers) for the RP2350
 * USBCTRL block. Plain MMIO, one event per usb_task call; the model harness
 * (asm/usbtest.c) runs it against a datasheet-derived SIE simulation. */

.equ USB_REGS,    0x50110000
.equ USB_DPRAM,   0x50100000

/* register offsets (pico-sdk 2.2.0, hardware/regs/usb.h) */
.equ R_ADDR_ENDP,   0x00
.equ R_MAIN_CTRL,   0x40
.equ R_SIE_CTRL,    0x4c
.equ R_SIE_STATUS,  0x50
.equ R_BUFF_STATUS,  0x58

.equ MAIN_CTRL_EN,  0x00000001
.equ SIE_PULLUP,     0x00010000
.equ ST_BUS_RESET,   0x00080000
.equ ST_SETUP_REC,   0x00020000
.equ BS_EP0_IN,      0x00000001
.equ BS_EP0_OUT,     0x00000002

/* DPSRAM layout (hardware/structs/usb_dpram.h) */
.equ D_SETUP,    0x000
.equ D_BC_IN,    0x080
.equ D_BC_OUT,   0x084
.equ D_EP0_BUF,  0x100

/* buffer control word */
.equ BC_LAST,    0x4000
.equ BC_DATA1,   0x2000
.equ BC_STALL,   0x0800
.equ BC_AVAIL,   0x0400

/* chapter-9 requests */
.equ REQ_GET_STATUS,     0x00
.equ REQ_SET_ADDRESS,    0x05
.equ REQ_GET_DESCRIPTOR, 0x06
.equ REQ_SET_CONFIG,     0x09
.equ DESC_DEVICE, 0x01
.equ DESC_CONFIG,  0x02
.equ DESC_REPORT,  0x22

.syntax unified
.cpu cortex-m33
.thumb

.section .bss
.align 2
.global usb_state
/* +0 addr_pending (bit 31 marks pending), +4 configured */
usb_state:
    .space 8

.section .rodata
.align 2
.global usb_dev_desc
usb_dev_desc:
    .byte 0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40
    .byte 0x09, 0x12, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01

.global usb_cfg_desc
usb_cfg_desc:
    .byte 0x09, 0x02, 0x29, 0x00, 0x01, 0x01, 0x00, 0x80, 0x19
    .byte 0x09, 0x04, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00
    .byte 0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x21, 0x00
    .byte 0x07, 0x05, 0x81, 0x03, 0x40, 0x00, 0x05
    .byte 0x07, 0x05, 0x01, 0x03, 0x40, 0x00, 0x05

.global usb_report_desc
usb_report_desc:
    .byte 0x05, 0xF1, 0x09, 0x00, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00
    .byte 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09
    .byte 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40
    .byte 0x91, 0x02, 0xC0

.section .text
.thumb_func
.global usb_init
usb_init:
        ldr  r0, =USB_REGS
        movs r1, #0
        str  r1, [r0, #R_ADDR_ENDP]
        movs r1, #MAIN_CTRL_EN
        str  r1, [r0, #R_MAIN_CTRL]
        ldr  r1, =SIE_PULLUP
        str  r1, [r0, #R_SIE_CTRL]
        bx   lr

/* one event per call: bus reset, then setup, then one buffer completion */
.thumb_func
.global usb_task
usb_task:
        push {r4, r5, r6, lr}
        ldr  r4, =USB_REGS
        ldr  r5, =USB_DPRAM

        ldr  r0, [r4, #R_SIE_STATUS]
        ldr  r1, =ST_BUS_RESET
        tst  r0, r1
        beq  1f
        str  r1, [r4, #R_SIE_STATUS]
        movs r2, #0
        str  r2, [r4, #R_ADDR_ENDP]
        ldr  r3, =usb_state
        str  r2, [r3, #0]
        str  r2, [r3, #4]
        b    task_done

1:      ldr  r1, =ST_SETUP_REC
        tst  r0, r1
        beq  2f
        str  r1, [r4, #R_SIE_STATUS]
        movs r2, #0
        str  r2, [r5, #D_BC_IN]           /* the SIE resets EP0 on setup */
        str  r2, [r5, #D_BC_OUT]

        ldrb r0, [r5, #D_SETUP+0]         /* bmRequestType */
        ldrb r1, [r5, #D_SETUP+1]         /* bRequest */
        ldrb r2, [r5, #D_SETUP+3]         /* wValue hi */
        ldrb r6, [r5, #D_SETUP+7]         /* wLength is little-endian */
        ldrb r3, [r5, #D_SETUP+6]
        lsls r6, r6, #8
        orrs r6, r6, r3                   /* r6 = wLength */

        movs r3, #0xE0
        ands r3, r0                       /* direction + type */
        cmp  r3, #0x80                    /* IN + standard, any recipient */
        beq  in_std
        cmp  r0, #0x00                    /* OUT + standard + device */
        bne  stall_both
        cmp  r1, #REQ_SET_ADDRESS
        beq  set_address
        cmp  r1, #REQ_SET_CONFIG
        beq  set_config
        b    stall_both

in_std:
        cmp  r1, #REQ_GET_DESCRIPTOR
        beq  get_descriptor
        cmp  r1, #REQ_GET_STATUS
        beq  get_status
        b    stall_both

get_status:
        movs r2, #0
        str  r2, [r5, #D_EP0_BUF]
        str  r2, [r5, #D_EP0_BUF+1]
        ldr  r2, =BC_AVAIL|BC_DATA1|BC_LAST|2
        str  r2, [r5, #D_BC_IN]
        b    task_done

get_descriptor:
        cmp  r2, #DESC_DEVICE
        bne  3f
        ldr  r3, =usb_dev_desc
        movs r0, #18
        b    send_desc
3:      cmp  r2, #DESC_CONFIG
        bne  4f
        ldr  r3, =usb_cfg_desc
        movs r0, #41
        b    send_desc
4:      cmp  r2, #DESC_REPORT
        bne  stall_both
        ldr  r3, =usb_report_desc
        movs r0, #33
send_desc:
        cmp  r0, r6
        bls  5f
        movs r0, r6                       /* min(desc_len, wLength) */
5:      adds r2, r5, #D_EP0_BUF
        movs r1, #0
6:      cmp  r1, r0
        bcs  7f
        ldrb r6, [r3, r1]
        strb r6, [r2, r1]
        adds r1, #1
        b    6b
7:      ldr  r6, =BC_AVAIL|BC_DATA1|BC_LAST
        orrs r6, r6, r0
        str  r6, [r5, #D_BC_IN]
        b    task_done

set_address:
        ldrb r2, [r5, #D_SETUP+2]         /* wValue lo = address */
        movs r3, #0x7F
        ands r2, r2, r3
        movs r3, #1
        lsls r3, r3, #31
        orrs r2, r2, r3                   /* pending marker */
        ldr  r3, =usb_state
        str  r2, [r3, #0]
        ldr  r2, =BC_AVAIL|BC_DATA1
        str  r2, [r5, #D_BC_OUT]
        b    task_done

set_config:
        ldrb r2, [r5, #D_SETUP+2]
        subs r2, #1
        bne  8f                           /* only config value 1 */
        movs r2, #1
9:      ldr  r3, =usb_state
        str  r2, [r3, #4]
        ldr  r2, =BC_AVAIL|BC_DATA1
        str  r2, [r5, #D_BC_OUT]
        b    task_done
8:      movs r2, #0
        b    9b

stall_both:
        ldr  r2, =BC_STALL
        str  r2, [r5, #D_BC_IN]
        str  r2, [r5, #D_BC_OUT]
        b    task_done

2:      ldr  r0, [r4, #R_BUFF_STATUS]
        movs r1, #BS_EP0_IN
        tst  r0, r1
        beq  10f
        str  r1, [r4, #R_BUFF_STATUS]
        ldr  r2, =BC_AVAIL|BC_DATA1
        str  r2, [r5, #D_BC_OUT]          /* status stage */
        b    task_done

10:     movs r1, #BS_EP0_OUT
        tst  r0, r1
        beq  task_done
        str  r1, [r4, #R_BUFF_STATUS]
        ldr  r2, =usb_state
        ldr  r3, [r2, #0]
        cmp  r3, #0
        bpl  task_done                    /* bit 31 clear: nothing pending */
        lsls r3, r3, #1                   /* drop the pending flag */
        lsrs r3, r3, #1
        str  r3, [r4, #R_ADDR_ENDP]
        movs r3, #0
        str  r3, [r2, #0]

task_done:
        pop  {r4, r5, r6, pc}
