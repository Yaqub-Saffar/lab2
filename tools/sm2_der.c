/*
 * sm2_der.c - minimal ASN.1 DER encoder/decoder for the two structures that
 *             GmSSL uses in its `gmssl sm2sign` / `gmssl sm2encrypt` output.
 *
 * GmSSL 3.2.0 encodes a signature as (src/sm2_sign.c):
 *
 *      SM2Signature ::= SEQUENCE { r INTEGER, s INTEGER }
 *
 * and a ciphertext as (src/sm2_enc.c):
 *
 *      SM2Cipher ::= SEQUENCE {
 *          xCoordinate  INTEGER,
 *          yCoordinate  INTEGER,
 *          hash         OCTET STRING (32),
 *          cipherText   OCTET STRING }
 *
 * The upstream SCCTC code works with raw 32-byte big-endian integers and with
 * the C1||C3||C2 byte string, so this tool is the bridge between the two
 * worlds and lets us verify each other's signatures and ciphertexts.
 *
 * Build:
 *   gcc -o sm2_der sm2_der.c
 *
 * Usage:
 *   sm2_der sig-encode <r_hex> <s_hex> <out.der>
 *   sm2_der sig-decode <in.der>              -> prints "r=<hex> s=<hex>"
 *   sm2_der ct-encode  <x_hex> <y_hex> <c3_hex> <c2_hex> <out.der>
 *   sm2_der ct-decode  <in.der>              -> prints "x=.. y=.. c3=.. c2=.."
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG_INTEGER     0x02
#define TAG_OCTETSTRING 0x04
#define TAG_SEQUENCE    0x30

static int hex2bin(const char *hex, unsigned char *out, int outlen)
{
    int i;
    unsigned int v;

    if ((int)strlen(hex) != outlen * 2)
        return -1;
    for (i = 0; i < outlen; i++) {
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (unsigned char)v;
    }
    return 0;
}

static void print_hex(const unsigned char *b, int n)
{
    int i;
    for (i = 0; i < n; i++)
        printf("%02X", b[i]);
}

/* ---------------- DER writing ---------------- */

static int der_write_len(unsigned char *p, size_t n)
{
    if (n < 0x80) {
        p[0] = (unsigned char)n;
        return 1;
    }
    if (n <= 0xff) {
        p[0] = 0x81;
        p[1] = (unsigned char)n;
        return 2;
    }
    p[0] = 0x82;
    p[1] = (unsigned char)((n >> 8) & 0xff);
    p[2] = (unsigned char)(n & 0xff);
    return 3;
}

/* INTEGER from a 32-byte positive big-endian value.
 * The encoding follows GmSSL's asn1_integer_to_der_ex(): leading zero bytes are
 * removed, and a single 0x00 is prepended when the first significant byte has
 * its high bit set (so that the value stays positive). */
static int der_write_integer(unsigned char *p, const unsigned char *v, int vlen)
{
    int off = 0, pad = 0, len;

    while (vlen - pad > 1 && v[pad] == 0)
        pad++;
    len = vlen - pad;

    p[off++] = TAG_INTEGER;
    if (v[pad] & 0x80) {
        off += der_write_len(p + off, (size_t)(len + 1));
        p[off++] = 0x00;
    } else {
        off += der_write_len(p + off, (size_t)len);
    }
    memcpy(p + off, v + pad, (size_t)len);
    off += len;
    return off;
}

static int der_write_octetstring(unsigned char *p, const unsigned char *v, int vlen)
{
    int off = 0;

    p[off++] = TAG_OCTETSTRING;
    off += der_write_len(p + off, (size_t)vlen);
    memcpy(p + off, v, (size_t)vlen);
    off += vlen;
    return off;
}

static int der_write_sequence(unsigned char *p, const unsigned char *content, int clen)
{
    int off = 0;

    p[off++] = TAG_SEQUENCE;
    off += der_write_len(p + off, (size_t)clen);
    memcpy(p + off, content, (size_t)clen);
    off += clen;
    return off;
}

/* ---------------- DER reading ---------------- */

typedef struct {
    const unsigned char *p;
    int len;
    int off;
} der_cursor;

static int der_read_tlv(der_cursor *c, int *tag, const unsigned char **val, int *vlen)
{
    int l;

    if (c->off + 2 > c->len)
        return -1;
    *tag = c->p[c->off++];
    l = c->p[c->off++];
    if (l & 0x80) {
        int n = l & 0x7f;
        int i;
        if (n == 0 || n > 4 || c->off + n > c->len)
            return -1;
        l = 0;
        for (i = 0; i < n; i++)
            l = (l << 8) | c->p[c->off++];
    }
    if (c->off + l > c->len)
        return -1;
    *val = c->p + c->off;
    *vlen = l;
    c->off += l;
    return 0;
}

/* normalise a DER INTEGER into a fixed 32-byte big-endian buffer */
static int der_int_to_32(const unsigned char *v, int vlen, unsigned char *out)
{
    int i = 0;

    if (vlen > 33)
        return -1;
    while (i < vlen - 1 && v[i] == 0x00)
        i++;
    if (vlen - i > 32)
        return -1;
    memset(out, 0, 32);
    memcpy(out + 32 - (vlen - i), v + i, (size_t)(vlen - i));
    return 0;
}

/* ---------------- commands ---------------- */

static int cmd_sig_encode(int argc, char **argv)
{
    unsigned char r[32], s[32], body[128], out[256];
    int n, total;

    if (argc < 5) {
        fprintf(stderr, "usage: %s sig-encode <r_hex> <s_hex> <out.der>\n", argv[0]);
        return 2;
    }
    if (hex2bin(argv[2], r, 32) != 0 || hex2bin(argv[3], s, 32) != 0) {
        fprintf(stderr, "bad hex\n");
        return 2;
    }
    n = 0;
    n += der_write_integer(body + n, r, 32);
    n += der_write_integer(body + n, s, 32);
    total = der_write_sequence(out, body, n);
    {
        FILE *f = fopen(argv[4], "wb");
        if (!f) {
            perror(argv[4]);
            return 1;
        }
        fwrite(out, 1, (size_t)total, f);
        fclose(f);
    }
    printf("wrote %d bytes to %s\n", total, argv[4]);
    return 0;
}

static int cmd_sig_decode(int argc, char **argv)
{
    unsigned char buf[512], r[32], s[32];
    const unsigned char *v;
    int tag, vlen, n = 0;
    der_cursor c;
    FILE *f;

    if (argc < 3) {
        fprintf(stderr, "usage: %s sig-decode <in.der>\n", argv[0]);
        return 2;
    }
    f = fopen(argv[2], "rb");
    if (!f) {
        perror(argv[2]);
        return 1;
    }
    n = (int)fread(buf, 1, sizeof(buf), f);
    fclose(f);
    c.p = buf;
    c.len = n;
    c.off = 0;
    if (der_read_tlv(&c, &tag, &v, &vlen) != 0 || tag != TAG_SEQUENCE) {
        fprintf(stderr, "not a SEQUENCE\n");
        return 1;
    }
    {
        der_cursor in;
        in.p = v;
        in.len = vlen;
        in.off = 0;
        if (der_read_tlv(&in, &tag, &v, &vlen) != 0 || tag != TAG_INTEGER ||
            der_int_to_32(v, vlen, r) != 0) {
            fprintf(stderr, "bad r\n");
            return 1;
        }
        if (der_read_tlv(&in, &tag, &v, &vlen) != 0 || tag != TAG_INTEGER ||
            der_int_to_32(v, vlen, s) != 0) {
            fprintf(stderr, "bad s\n");
            return 1;
        }
    }
    printf("r=");
    print_hex(r, 32);
    printf("\ns=");
    print_hex(s, 32);
    printf("\n");
    return 0;
}

static int cmd_ct_encode(int argc, char **argv)
{
    unsigned char x[32], y[32], c3[32], c2[256], body[512], out[640];
    int c2len, n = 0, total;

    if (argc < 7) {
        fprintf(stderr, "usage: %s ct-encode <x_hex> <y_hex> <c3_hex> <c2_hex> <out.der>\n", argv[0]);
        return 2;
    }
    if (hex2bin(argv[2], x, 32) != 0 || hex2bin(argv[3], y, 32) != 0 ||
        hex2bin(argv[4], c3, 32) != 0) {
        fprintf(stderr, "bad hex\n");
        return 2;
    }
    c2len = (int)strlen(argv[5]) / 2;
    if (c2len <= 0 || c2len > (int)sizeof(c2)) {
        fprintf(stderr, "bad c2 length\n");
        return 2;
    }
    if (hex2bin(argv[5], c2, c2len) != 0) {
        fprintf(stderr, "bad c2 hex\n");
        return 2;
    }
    n += der_write_integer(body + n, x, 32);
    n += der_write_integer(body + n, y, 32);
    n += der_write_octetstring(body + n, c3, 32);
    n += der_write_octetstring(body + n, c2, c2len);
    total = der_write_sequence(out, body, n);
    {
        FILE *f = fopen(argv[6], "wb");
        if (!f) {
            perror(argv[6]);
            return 1;
        }
        fwrite(out, 1, (size_t)total, f);
        fclose(f);
    }
    printf("wrote %d bytes to %s\n", total, argv[6]);
    return 0;
}

static int cmd_ct_decode(int argc, char **argv)
{
    unsigned char buf[2048], x[32], y[32], c3[32], c2[512];
    const unsigned char *v;
    int tag, vlen, n = 0, c2len;
    der_cursor c, in;
    FILE *f;

    if (argc < 3) {
        fprintf(stderr, "usage: %s ct-decode <in.der>\n", argv[0]);
        return 2;
    }
    f = fopen(argv[2], "rb");
    if (!f) {
        perror(argv[2]);
        return 1;
    }
    n = (int)fread(buf, 1, sizeof(buf), f);
    fclose(f);
    c.p = buf;
    c.len = n;
    c.off = 0;
    if (der_read_tlv(&c, &tag, &v, &vlen) != 0 || tag != TAG_SEQUENCE) {
        fprintf(stderr, "not a SEQUENCE\n");
        return 1;
    }
    in.p = v;
    in.len = vlen;
    in.off = 0;
    if (der_read_tlv(&in, &tag, &v, &vlen) != 0 || tag != TAG_INTEGER ||
        der_int_to_32(v, vlen, x) != 0) {
        fprintf(stderr, "bad x\n");
        return 1;
    }
    if (der_read_tlv(&in, &tag, &v, &vlen) != 0 || tag != TAG_INTEGER ||
        der_int_to_32(v, vlen, y) != 0) {
        fprintf(stderr, "bad y\n");
        return 1;
    }
    if (der_read_tlv(&in, &tag, &v, &vlen) != 0 || tag != TAG_OCTETSTRING || vlen != 32) {
        fprintf(stderr, "bad c3\n");
        return 1;
    }
    memcpy(c3, v, 32);
    if (der_read_tlv(&in, &tag, &v, &vlen) != 0 || tag != TAG_OCTETSTRING || vlen <= 0) {
        fprintf(stderr, "bad c2\n");
        return 1;
    }
    c2len = vlen;
    memcpy(c2, v, (size_t)c2len);
    printf("x=");
    print_hex(x, 32);
    printf("\ny=");
    print_hex(y, 32);
    printf("\nc3=");
    print_hex(c3, 32);
    printf("\nc2=");
    print_hex(c2, c2len);
    printf("\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s sig-encode|sig-decode|ct-encode|ct-decode ...\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "sig-encode") == 0)
        return cmd_sig_encode(argc, argv);
    if (strcmp(argv[1], "sig-decode") == 0)
        return cmd_sig_decode(argc, argv);
    if (strcmp(argv[1], "ct-encode") == 0)
        return cmd_ct_encode(argc, argv);
    if (strcmp(argv[1], "ct-decode") == 0)
        return cmd_ct_decode(argc, argv);
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}
