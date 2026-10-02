/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* Differential harness: one 64-byte CTAPHID report per stdin line (128 hex
 * chars, '#' comments); feeds each to asm/ctaphid.S and prints the event
 * stream. "T <cid> <cmd> <payload-hex>" lines instead drive asm/ctaphid_tx.S
 * and print the resulting frame stream. The Rust oracle over rsk-usb's
 * Reassembler / TxFrames prints the identical format; the two outputs must
 * be byte-identical. Input is streamed line-by-line so no input size is
 * silently truncated. */

struct state {
    unsigned cid, cmd, bcnt, cur, seq, in_tx, buf_max;
    unsigned char *buf;
    unsigned ev_tag, ev_val, ev_cid, ev_cmd;
};

/* mirror of asm/ctaphid_tx.S's caller-owned state */
struct tx_state {
    unsigned cid, cmd;
    const unsigned char *data;
    unsigned len, off, seq, started;
};

/* mirror of asm/ctaphid_init.S's caller-owned state */
struct init_state {
    unsigned next_cid;
};

#define MSG_CAP 7609 /* CTAP_MAX_MESSAGE: 57 + 128*59 */

extern void ctaphid_feed(struct state *st, const unsigned char *rpt);
extern void ctaphid_tx_init(struct tx_state *st, unsigned cid, unsigned cmd,
                            const unsigned char *data, unsigned len);
extern unsigned ctaphid_tx_next(struct tx_state *st, unsigned char *out);
extern void ctaphid_init_init(struct init_state *st);
extern unsigned ctaphid_init_run(struct init_state *st,
                                 const unsigned char *nonce, unsigned nonce_len,
                                 unsigned can_wink, unsigned char *out17);
extern long sys_read(long fd, void *buf, long n);
extern long sys_write(long fd, const void *buf, long n);

static struct state st;
static struct tx_state txs;
static struct init_state inis;
static unsigned char msgbuf[MSG_CAP];
static unsigned char paybuf[MSG_CAP];
static unsigned char tframe[64];

/* any real line fits with two orders of magnitude to spare: the longest is
 * a maximum-size T payload at ~15.3 KB */
static unsigned char inbuf[1 << 20];

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

static void process_line(unsigned char *p, unsigned char *eol)
{
    unsigned char rpt[64];
    unsigned char out[2 * MSG_CAP + 64];

    while (p < eol && (*p == ' ' || *p == '\t' || *p == '\r')) p++;
    /* mirror the oracle's trim(): trailing whitespace too, so \r\n and
     * padded lines parse identically on both sides */
    while (eol > p && (eol[-1] == ' ' || eol[-1] == '\t' || eol[-1] == '\r')) eol--;
    if (p >= eol || *p == '#') return;

    if (*p == 'T' && p + 1 < eol && *(p + 1) == ' ') {
        p += 2;
        unsigned cid = 0, cmd = 0, plen = 0;
        int ok = 1;
        for (int i = 0; i < 8 && ok; i++) {
            int v = (p < eol) ? hexval(*p++) : -1;
            if (v < 0) ok = 0; else cid = (cid << 4) | v;
        }
        if (ok && p < eol && *p == ' ') p++; else ok = 0;
        for (int i = 0; i < 2 && ok; i++) {
            int v = (p < eol) ? hexval(*p++) : -1;
            if (v < 0) ok = 0; else cmd = (cmd << 4) | v;
        }
        if (ok && p == eol) {
            /* empty payload: the bare INIT */
        } else if (ok && p < eol && *p == ' ') {
            p++;
            while (p < eol) {
                int hi = hexval(*p++);
                int lo = (p < eol) ? hexval(*p++) : -1;
                if (hi < 0 || lo < 0 || plen >= MSG_CAP) { ok = 0; break; }
                paybuf[plen++] = (unsigned char)((hi << 4) | lo);
            }
        } else {
            ok = 0;
        }
        if (!ok) {
            emit((const unsigned char *)"X parse\n", 8);
            return;
        }
        ctaphid_tx_init(&txs, cid, cmd, paybuf, plen);
        unsigned n = 0;
        while (n < 256 && ctaphid_tx_next(&txs, tframe)) {
            unsigned char *o = out;
            *o++ = 'F'; *o++ = ' ';
            o = hexn(o, tframe, 64);
            *o++ = '\n';
            emit(out, o - out);
            n++;
        }
        if (n == 256) emit((const unsigned char *)"X runaway\n", 10);
        return;
    }

    if (*p == 'I' && p + 1 < eol && *(p + 1) == ' ') {
        p += 2;
        int can_wink, ok = 1;
        if (p < eol && (*p == '0' || *p == '1')) {
            can_wink = (*p == '1');
            p++;
        } else {
            ok = 0;
        }
        if (ok && p < eol && *p == ' ') p++; else ok = 0;
        unsigned char nonce[8];
        for (int i = 0; i < 8 && ok; i++) {
            int hi = (p < eol) ? hexval(*p++) : -1;
            int lo = (p < eol) ? hexval(*p++) : -1;
            if (hi < 0 || lo < 0) ok = 0; else nonce[i] = (unsigned char)((hi << 4) | lo);
        }
        if (ok && p != eol) ok = 0; /* nonce must be exactly 8 bytes */
        if (!ok) {
            emit((const unsigned char *)"X parse\n", 8);
            return;
        }
        unsigned char out17[17];
        ctaphid_init_run(&inis, nonce, 8, can_wink, out17);
        ctaphid_tx_init(&txs, 0xffffffffu, 0x86, out17, 17);
        unsigned n = 0;
        while (n < 256 && ctaphid_tx_next(&txs, tframe)) {
            unsigned char *o = out;
            *o++ = 'F'; *o++ = ' ';
            o = hexn(o, tframe, 64);
            *o++ = '\n';
            emit(out, o - out);
            n++;
        }
        return;
    }

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
        return;
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

int harness_main(void)
{
    st.buf_max = MSG_CAP;
    st.buf = msgbuf;
    ctaphid_init_init(&inis);

    unsigned have = 0;
    for (;;) {
        long n = sys_read(0, inbuf + have, sizeof inbuf - have);
        if (n <= 0) break;
        have += (unsigned)n;

        unsigned char *line = inbuf;
        unsigned char *end = inbuf + have;
        while (line < end) {
            unsigned char *eol = line;
            while (eol < end && *eol != '\n') eol++;
            if (eol == end) break;
            process_line(line, eol);
            line = eol + 1;
        }
        if (line == inbuf) {
            if (have == sizeof inbuf) {
                /* a line with no room to exist: drop it, keep streaming */
                emit((const unsigned char *)"X parse\n", 8);
                have = 0;
            }
            continue;
        }
        have = end - line;
        for (unsigned i = 0; i < have; i++) inbuf[i] = line[i];
    }
    if (have > 0) process_line(inbuf, inbuf + have);
    return 0;
}
