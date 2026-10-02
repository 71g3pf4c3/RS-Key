/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* Differential harness: one 64-byte CTAPHID report per stdin line (128 hex
 * chars, '#' comments); feeds each to asm/ctaphid.S and prints the event
 * stream. The Rust oracle over rsk-usb's Reassembler prints the identical
 * format; the two outputs must be byte-identical. */

struct state {
    unsigned cid, cmd, bcnt, cur, seq, in_tx, buf_max;
    unsigned char *buf;
    unsigned ev_tag, ev_val, ev_cid, ev_cmd;
};

#define MSG_CAP 7609 /* CTAP_MAX_MESSAGE: 57 + 128*59 */

extern void ctaphid_feed(struct state *st, const unsigned char *rpt);
extern long sys_read(long fd, void *buf, long n);
extern long sys_write(long fd, const void *buf, long n);

static struct state st;
static unsigned char msgbuf[MSG_CAP];
static unsigned char inbuf[16 << 20];

/* CTAPHID framing offsets, mirroring asm/ctaphid.S. */
#define RPT_CMD     0
#define RPT_CID     1
#define RPT_BCNT_HI 5
#define RPT_BCNT_LO 6

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned char *hex2(unsigned char *p, unsigned v)
{
    static const char d[] = "0123456789abcdef";
    *p++ = d[(v >> 4) & 0xf];
    *p++ = d[v & 0xf];
    return p;
}

static unsigned char *hexp(unsigned char *p, unsigned v)
{
    /* plain hex, no leading zeros — matches the oracle's {:x} */
    static const char d[] = "0123456789abcdef";
    int started = 0;
    for (int i = 7; i >= 0; i--) {
        unsigned n = (v >> (4 * i)) & 0xf;
        if (n || started || i == 0) {
            *p++ = d[n];
            started = 1;
        }
    }
    return p;
}

static unsigned char *hex8(unsigned char *p, unsigned v)
{
    static const char d[] = "0123456789abcdef";
    for (int i = 7; i >= 0; i--) *p++ = d[(v >> (4 * i)) & 0xf];
    return p;
}

static unsigned char *hexn(unsigned char *p, const unsigned char *b, unsigned n)
{
    static const char d[] = "0123456789abcdef";
    for (unsigned i = 0; i < n; i++) {
        *p++ = d[b[i] >> 4];
        *p++ = d[b[i] & 0xf];
    }
    return p;
}

static void emit(const unsigned char *p, unsigned len)
{
    sys_write(1, p, len);
}

int harness_main(void)
{
    st.buf_max = MSG_CAP;
    st.buf = msgbuf;

    long total = 0;
    for (;;) {
        long n = sys_read(0, inbuf + total, sizeof inbuf - total);
        if (n <= 0) break;
        total += n;
        if ((unsigned long)total >= sizeof inbuf) break;
    }

    unsigned char rpt[64];
    unsigned char out[2 * MSG_CAP + 64];
    unsigned char *line = inbuf;
    unsigned char *end = inbuf + total;

    while (line < end) {
        unsigned char *eol = line;
        while (eol < end && *eol != '\n') eol++;
        unsigned char *p = line;
        line = (eol < end) ? eol + 1 : end;
        while (p < eol && (*p == ' ' || *p == '\t' || *p == '\r')) p++;
        if (p >= eol || *p == '#') continue;

        for (int i = 0; i < 64; i++) rpt[i] = 0;
        int ok = 1;
        for (int i = 0; i < 64; i++) {
            int hi = hexval(*p++);
            int lo = (p < eol) ? hexval(*p++) : -1;
            if (hi < 0 || lo < 0) { ok = 0; break; }
            rpt[i] = (unsigned char)((hi << 4) | lo);
        }
        if (!ok) {
            emit((const unsigned char *)"X parse\n", 8);
            continue;
        }

        ctaphid_feed(&st, rpt);
        unsigned tag = st.ev_tag, val = st.ev_val;
        unsigned char *o = out;
        switch (tag) {
        case 0:
            *o++ = 'B'; *o++ = '\n';
            break;
        case 1:
            *o++ = 'D'; *o++ = ' ';
            o = hex8(o, st.ev_cid); *o++ = ' ';
            o = hex2(o, st.ev_cmd); *o++ = ' ';
            o = hexp(o, val); *o++ = ' ';
            o = hexn(o, msgbuf, val); *o++ = '\n';
            break;
        case 2:
            *o++ = 'E'; *o++ = ' ';
            o = hex8(o, st.ev_cid); *o++ = ' ';
            o = hex2(o, val); *o++ = '\n';
            break;
        default:
            *o++ = 'I'; *o++ = '\n';
            break;
        }
        emit(out, o - out);
    }
    return 0;
}
