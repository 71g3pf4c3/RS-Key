/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* Model-level USB harness: maps the RP2350 USBCTRL register file and DPSRAM
 * as plain memory (qemu-user MAP_FIXED), then runs the asm EP0 driver
 * against a datasheet-derived model of the SIE. The model owns the
 * write-to-clear status registers — it rewrites them from its shadow each
 * cycle, so the driver's own WC writes (correct for hardware) are absorbed.
 * Hardware execution remains the unverified step. */

#define REGS_BASE 0x50110000u
#define DPRAM_BASE 0x50100000u

#define REG(n) (*(volatile unsigned *)(REGS_BASE + (n)))
#define BC_IN (*(volatile unsigned *)(DPRAM_BASE + 0x80))
#define BC_OUT (*(volatile unsigned *)(DPRAM_BASE + 0x84))
#define EPBUF(i) (*(volatile unsigned char *)(DPRAM_BASE + 0x100 + (i)))

#define R_ADDR_ENDP 0x00
#define R_MAIN_CTRL 0x40
#define R_SIE_CTRL 0x4c
#define R_SIE_STATUS 0x50
#define R_BUFF_STATUS 0x58

#define ST_SETUP_REC 0x20000u
#define ST_BUS_RESET 0x80000u
#define BC_AVAIL 0x400u
#define BC_STALL 0x800u
#define BC_DATA1 0x2000u
#define BC_LAST 0x4000u

extern void usb_init(void);
extern void usb_task(void);
extern unsigned usb_state[2];

extern long sys_mmap2(long addr, long len, long prot, long flags, long fd, long off);
extern long sys_write(long fd, const void *buf, long n);

static const unsigned char DEV[18] = {
    0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40,
    0x09, 0x12, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
};
static const unsigned char CFG[41] = {
    0x09, 0x02, 0x29, 0x00, 0x01, 0x01, 0x00, 0x80, 0x19,
    0x09, 0x04, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00,
    0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x21, 0x00,
    0x07, 0x05, 0x81, 0x03, 0x40, 0x00, 0x05,
    0x07, 0x05, 0x01, 0x03, 0x40, 0x00, 0x05,
};
static const unsigned char RPT[33] = {
    0x05, 0xF1, 0x09, 0x00, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00,
    0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09,
    0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40,
    0x91, 0x02, 0xC0,
};

static unsigned sie_shadow, buff_shadow;
static int fails;

static void say(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    sys_write(1, s, n);
}

#define CHECK(cond, name) \
    do { if (cond) { say("ok   " name "\n"); } else { fails++; say("FAIL " name "\n"); } } while (0)

static void cycle(void)
{
    REG(R_SIE_STATUS) = sie_shadow;
    REG(R_BUFF_STATUS) = buff_shadow;
    usb_task();
    /* one-shot: an event is visible to exactly one usb_task call, matching
     * what the driver's write-to-clear achieves on hardware */
    sie_shadow = 0;
    buff_shadow = 0;
    if (BC_IN & BC_AVAIL) {
        BC_IN &= ~BC_AVAIL;
        buff_shadow |= 1u;
    }
    if (BC_OUT & BC_AVAIL) {
        BC_OUT &= ~BC_AVAIL;
        buff_shadow |= 2u;
    }
}

static void pump(int n)
{
    while (n-- > 0) cycle();
}

static void inject(const unsigned char *s)
{
    volatile unsigned char *d = (volatile unsigned char *)DPRAM_BASE;
    for (int i = 0; i < 8; i++) d[i] = s[i];
    sie_shadow |= ST_SETUP_REC;
}

static int buf_matches(const unsigned char *exp, int n)
{
    for (int i = 0; i < n; i++)
        if (EPBUF(i) != exp[i]) return 0;
    return 1;
}

int harness_main(void)
{
    long m = sys_mmap2(DPRAM_BASE, 0x20000, 3, 0x32, -1, 0);
    if ((unsigned long)m > 0xfffff000u) {
        say("FAIL mmap\n");
        return 1;
    }

    usb_init();
    CHECK((REG(R_MAIN_CTRL) & 1) != 0, "init main_ctrl en");
    CHECK((REG(R_SIE_CTRL) & 0x10000) != 0, "init pullup");
    CHECK(REG(R_ADDR_ENDP) == 0, "init addr 0");

    /* device descriptor, full length */
    inject((const unsigned char[]){0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 18, "devdesc len 18");
    CHECK((BC_IN & (BC_DATA1 | BC_LAST)) == (BC_DATA1 | BC_LAST), "devdesc pid/last");
    CHECK(buf_matches(DEV, 18), "devdesc bytes");

    /* wLength clamp */
    inject((const unsigned char[]){0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x08, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 8, "devdesc clamped to 8");
    CHECK(buf_matches(DEV, 8), "devdesc clamp bytes");

    /* SET_ADDRESS latches after the status stage */
    inject((const unsigned char[]){0x00, 0x05, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(REG(R_ADDR_ENDP) == 5, "set_address 5");

    /* bus reset clears address and configuration */
    sie_shadow |= ST_BUS_RESET;
    pump(1);
    CHECK(REG(R_ADDR_ENDP) == 0, "bus reset clears addr");

    inject((const unsigned char[]){0x00, 0x05, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(REG(R_ADDR_ENDP) == 7, "set_address 7");

    inject((const unsigned char[]){0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(usb_state[1] == 1, "set_config 1");

    inject((const unsigned char[]){0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(usb_state[1] == 0, "set_config 0");

    /* config descriptor */
    inject((const unsigned char[]){0x80, 0x06, 0x00, 0x02, 0x00, 0x00, 0x29, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 41, "cfgdesc len 41");
    CHECK(buf_matches(CFG, 41), "cfgdesc bytes");

    /* HID report descriptor (recipient = interface) */
    inject((const unsigned char[]){0x81, 0x06, 0x00, 0x22, 0x00, 0x00, 0x21, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 33, "reportdesc len 33");
    CHECK(buf_matches(RPT, 33), "reportdesc bytes");

    /* GET_STATUS */
    inject((const unsigned char[]){0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 2, "get_status len 2");
    CHECK(EPBUF(0) == 0 && EPBUF(1) == 0, "get_status zeros");

    /* unknown request stalls both directions */
    inject((const unsigned char[]){0x80, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK((BC_IN & BC_STALL) && (BC_OUT & BC_STALL), "unknown stalls");

    say(fails ? "USB MODEL TESTS: FAILED\n" : "USB MODEL TESTS: PASSED\n");
    return fails;
}
