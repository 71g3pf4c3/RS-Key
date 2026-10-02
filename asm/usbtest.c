/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* Model-level USB harness: maps the RP2350 USBCTRL register file and DPSRAM
 * as plain memory (qemu-user MAP_FIXED), then runs the asm USB driver
 * against a datasheet-derived model of the SIE. The model owns the
 * write-to-clear status registers — it rewrites them from its shadow each
 * cycle, so the driver's own WC writes (correct for hardware) are absorbed.
 * EP1 OUT packets are delivered explicitly by the test (the host decides
 * when to talk); EP1 IN completes on the next cycle (the host is polling).
 * Hardware execution remains the unverified step. */

#define REGS_BASE 0x50110000u
#define DPRAM_BASE 0x50100000u
#define RESETS_BASE 0x40020000u

#define REG(n) (*(volatile unsigned *)(REGS_BASE + (n)))
#define REGS2(n) (*(volatile unsigned *)(RESETS_BASE + (n)))
#define BC_IN (*(volatile unsigned *)(DPRAM_BASE + 0x80))
#define BC_OUT (*(volatile unsigned *)(DPRAM_BASE + 0x84))
#define BC1_IN (*(volatile unsigned *)(DPRAM_BASE + 0x88))
#define BC1_OUT (*(volatile unsigned *)(DPRAM_BASE + 0x8c))
#define EP1_CTRL_IN (*(volatile unsigned *)(DPRAM_BASE + 0x008))
#define EP1_CTRL_OUT (*(volatile unsigned *)(DPRAM_BASE + 0x00c))
#define EPBUF(i) (*(volatile unsigned char *)(DPRAM_BASE + 0x100 + (i)))
#define EP1_OUT_BUF(i) (*(volatile unsigned char *)(DPRAM_BASE + 0x180 + (i)))
#define EP1_IN_BUF(i) (*(volatile unsigned char *)(DPRAM_BASE + 0x1c0 + (i)))

#define R_ADDR_ENDP 0x00
#define R_MAIN_CTRL 0x40
#define R_SIE_CTRL 0x4c
#define R_SIE_STATUS 0x50
#define R_BUFF_STATUS 0x58
#define R_MUXING 0x74
#define R_PWR 0x78

#define ST_SETUP_REC 0x20000u
#define ST_BUS_RESET 0x80000u
#define BC_AVAIL 0x400u
#define BC_STALL 0x800u
#define BC_DATA1 0x2000u
#define BC_LAST 0x4000u
#define BC_FULL 0x8000u

/* ctaphid reassembler state, as words (asm/ctaphid.S layout) */
#define CS_CID 0
#define CS_CUR 3
#define CS_IN_TX 5
#define CS_EV_TAG 8
#define CS_EV_VAL 9
#define EV_DONE 1
#define EV_ERROR 2
#define ERR_INVALID_SEQ 4

extern void usb_init(void);
extern void usb_task(void);
extern void usb_send_ep1(const unsigned char *buf, unsigned len);
extern unsigned usb_state[5];       /* pending, configured, out_pid, in_pid, tx_done */
extern unsigned ctaphid_state[12];
extern unsigned char ctaphid_msg[7609];

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
    if (BC1_IN & BC_AVAIL) {
        BC1_IN &= ~BC_AVAIL;
        buff_shadow |= 4u;
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

/* the host sends an EP1 OUT packet into the armed receive buffer */
static void host_send_ep1(const unsigned char *data, int n)
{
    for (int i = 0; i < n; i++) EP1_OUT_BUF(i) = data[i];
    BC1_OUT = (BC1_OUT & ~(BC_AVAIL | 0x3ffu)) | BC_FULL | n;
    buff_shadow |= 8u;
}

static int buf_matches(const unsigned char *exp, int n)
{
    for (int i = 0; i < n; i++)
        if (EPBUF(i) != exp[i]) return 0;
    return 1;
}

static int msg_matches(const unsigned char *exp, int n)
{
    for (int i = 0; i < n; i++)
        if (ctaphid_msg[i] != exp[i]) return 0;
    return 1;
}

/* one CTAPHID frame padded to a 64-byte USB report */
static void ctaphid_packet(unsigned char *p, unsigned cid, int is_init,
                           unsigned char type_or_seq, int bcnt,
                           const unsigned char *data, int dlen)
{
    for (int i = 0; i < 64; i++) p[i] = 0;
    p[0] = cid & 0xff; p[1] = (cid >> 8) & 0xff;
    p[2] = (cid >> 16) & 0xff; p[3] = (cid >> 24) & 0xff;
    p[4] = type_or_seq;
    int off, cap;
    if (is_init) {
        p[5] = (bcnt >> 8) & 0xff; p[6] = bcnt & 0xff;
        off = 7; cap = 57;
    } else {
        off = 5; cap = 59;
    }
    int n = bcnt < cap ? bcnt : cap;
    if (n > dlen) n = dlen;
    for (int i = 0; i < n; i++) p[off + i] = data[i];
}

int harness_main(void)
{
    long m = sys_mmap2(DPRAM_BASE, 0x20000, 3, 0x32, -1, 0);
    if ((unsigned long)m > 0xfffff000u) {
        say("FAIL mmap dpram\n");
        return 1;
    }
    m = sys_mmap2(RESETS_BASE, 0x1000, 3, 0x32, -1, 0);
    if ((unsigned long)m > 0xfffff000u) {
        say("FAIL mmap resets\n");
        return 1;
    }
    /* pretend the reset sequencer already finished, so usb_init's poll
     * passes; the pre-set RESET word lets us check the release write */
    REGS2(0x8) = 0x10000000u;
    REGS2(0x0) = 0xffffffffu;

    usb_init();
    CHECK(REGS2(0x0) == 0xefffffffu, "init releases usbctrl reset");
    CHECK(REG(R_MUXING) == 0x9, "init muxing to_phy|softcon");
    CHECK(REG(R_PWR) == 0xc, "init pwr vbus forced");
    CHECK(REG(R_MAIN_CTRL) & 1, "init main_ctrl en");
    CHECK(REG(R_SIE_CTRL) == 0x20010000u, "init pullup + ep0_int_1buf");
    CHECK(REG(R_ADDR_ENDP) == 0, "init addr 0");
    CHECK(EP1_CTRL_OUT == 0xAC000180u, "init ep1 out ctrl");
    CHECK(EP1_CTRL_IN == 0xAC0001C0u, "init ep1 in ctrl");
    CHECK(ctaphid_state[6] == 7609, "init ctaphid buf_max");
    CHECK((unsigned)ctaphid_state[7] == (unsigned)ctaphid_msg, "init ctaphid buf");

    /* device descriptor, full length */
    inject((const unsigned char[]){0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 18, "devdesc len 18");
    CHECK((BC_IN & (BC_FULL | BC_DATA1 | BC_LAST)) == (BC_FULL | BC_DATA1 | BC_LAST), "devdesc full/pid/last");
    CHECK(buf_matches(DEV, 18), "devdesc bytes");

    /* wLength clamp */
    inject((const unsigned char[]){0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x08, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 8, "devdesc clamped to 8");
    CHECK(buf_matches(DEV, 8), "devdesc clamp bytes");

    /* SET_ADDRESS latches after the zero-length IN status stage */
    inject((const unsigned char[]){0x00, 0x05, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(REG(R_ADDR_ENDP) == 5, "set_address 5");

    /* bus reset clears address, configuration and the data toggles */
    sie_shadow |= ST_BUS_RESET;
    pump(1);
    CHECK(REG(R_ADDR_ENDP) == 0, "bus reset clears addr");

    inject((const unsigned char[]){0x00, 0x05, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(REG(R_ADDR_ENDP) == 7, "set_address 7");

    inject((const unsigned char[]){0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(usb_state[1] == 1, "set_config 1");
    CHECK((BC1_OUT & (BC_AVAIL | 0x3ff)) == (BC_AVAIL | 64), "config arms ep1 out");
    CHECK(!(BC1_OUT & BC_DATA1), "first ep1 out is DATA0");

    /* §9.6.2: an address above 0x7F is a request error */
    inject((const unsigned char[]){0x00, 0x05, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK((BC_IN & BC_STALL) && (BC_OUT & BC_STALL), "set_address 0xff stalls");
    CHECK(REG(R_ADDR_ENDP) == 7, "stalled address not latched");

    /* wValue 0x0109 has the same low byte as address 9 but is not one */
    inject((const unsigned char[]){0x00, 0x05, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK((BC_IN & BC_STALL) && (BC_OUT & BC_STALL), "set_address 0x109 stalls");

    /* GET_CONFIGURATION follows the configured state */
    inject((const unsigned char[]){0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 1, "get_configuration len 1");
    CHECK(EPBUF(0) == 1, "get_configuration value 1");

    /* GET_INTERFACE: one interface, alternate setting 0 */
    inject((const unsigned char[]){0x81, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 1, "get_interface len 1");
    CHECK(EPBUF(0) == 0, "get_interface alt 0");

    inject((const unsigned char[]){0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(usb_state[1] == 0, "set_config 0");

    inject((const unsigned char[]){0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 1, "get_configuration after unconfig");
    CHECK(EPBUF(0) == 0, "unconfigured reports 0");

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

    /* ---- EP1 data path: configure, then talk CTAPHID over interrupt ---- */
    inject((const unsigned char[]){0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK((BC1_OUT & (BC_AVAIL | 0x3ff)) == (BC_AVAIL | 64), "reconfig rearms ep1 out");

    unsigned char pkt[64];
    unsigned char payload[64];
    for (int i = 0; i < 64; i++) payload[i] = (unsigned char)(i * 7 + 3);

    /* single-packet message completes on the INIT report */
    ctaphid_packet(pkt, 0xA1B2C3D4u, 1, 0x90, 16, payload, 16);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "ep1 single packet done");
    CHECK(ctaphid_state[CS_CUR] == 16, "ep1 single length");
    CHECK(msg_matches(payload, 16), "ep1 single bytes");
    CHECK((BC1_OUT & (BC_AVAIL | BC_DATA1)) == (BC_AVAIL | BC_DATA1), "ep1 out re-armed DATA1");

    /* multi-packet: INIT carries 57, CONT 0 carries the rest */
    ctaphid_packet(pkt, 0xA1B2C3D4u, 1, 0x90, 100, payload, 100);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_IN_TX] == 1, "ep1 mid-transaction");
    CHECK(ctaphid_state[CS_EV_TAG] == 0, "ep1 no event mid-transaction");
    ctaphid_packet(pkt, 0xA1B2C3D4u, 0, 0x00, 100, payload + 57, 43);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "ep1 multi done");
    CHECK(ctaphid_state[CS_CUR] == 100, "ep1 multi length");
    CHECK(msg_matches(payload, 100), "ep1 multi bytes");

    /* out-of-sequence CONT aborts with INVALID_SEQ */
    ctaphid_packet(pkt, 0xA1B2C3D4u, 1, 0x90, 200, payload, 57);
    host_send_ep1(pkt, 64);
    pump(2);
    ctaphid_packet(pkt, 0xA1B2C3D4u, 0, 0x01, 200, payload + 57, 59);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_ERROR, "ep1 bad seq error");
    CHECK(ctaphid_state[CS_EV_VAL] == ERR_INVALID_SEQ, "ep1 bad seq code");

    /* short host packet: the stale DPRAM tail must not reach the message */
    ctaphid_packet(pkt, 0x11223344u, 1, 0x90, 16, payload, 16);
    for (int i = 10; i < 64; i++) pkt[i] = 0xBB;   /* would-be stale bytes */
    host_send_ep1(pkt, 10);                        /* host stops at byte 10 */
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "ep1 short packet done");
    CHECK(ctaphid_state[CS_CUR] == 16, "ep1 short length");
    {
        int stale = 0;
        for (int i = 10; i < 16; i++)
            if (ctaphid_msg[i] != 0) stale = 1;
        CHECK(!stale, "ep1 short tail zeroed");
    }

    /* ---- EP1 IN: transmit with data-toggle tracking ---- */
    usb_send_ep1(payload, 32);
    CHECK((BC1_IN & (BC_AVAIL | BC_FULL | 0x3ff)) == (BC_AVAIL | BC_FULL | 32), "ep1 in armed");
    CHECK(!(BC1_IN & BC_DATA1), "first ep1 in is DATA0");
    pump(2);
    CHECK(usb_state[4] == 1, "ep1 tx_done");
    CHECK(usb_state[3] == 1, "ep1 in pid toggled");

    usb_send_ep1(payload, 32);
    CHECK((BC1_IN & BC_DATA1) != 0, "second ep1 in is DATA1");
    pump(2);
    CHECK(usb_state[4] == 1, "ep1 tx_done again");

    /* tx payload lands in the EP1 IN buffer */
    usb_send_ep1(payload, 8);
    int ok = 1;
    for (int i = 0; i < 8; i++)
        if (EP1_IN_BUF(i) != payload[i]) ok = 0;
    pump(2);
    CHECK(ok, "ep1 in bytes");

    /* bus reset returns the data toggles to DATA0 */
    sie_shadow |= ST_BUS_RESET;
    pump(1);
    CHECK(usb_state[2] == 0 && usb_state[3] == 0, "bus reset clears pids");

    inject((const unsigned char[]){0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(!(BC1_OUT & BC_DATA1), "post-reset ep1 out DATA0");
    usb_send_ep1(payload, 16);
    CHECK(!(BC1_IN & BC_DATA1), "post-reset ep1 in DATA0");
    pump(2);

    say(fails ? "USB MODEL TESTS: FAILED\n" : "USB MODEL TESTS: PASSED\n");
    return fails;
}
