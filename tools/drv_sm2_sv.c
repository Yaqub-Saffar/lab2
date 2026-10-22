/*
 * drv_sm2_sv.c - SM2 signature/verification driver for the SCCTC (SM2349)
 *                implementation (upstream file src/SM2_sv.c).
 *
 * The upstream header declares the curve parameters as *initialised globals*,
 * so including it in another translation unit would produce duplicate
 * symbols at link time. We therefore declare the upstream functions as
 * extern and carry our own copy of the recommended curve parameters, taken
 * from GB/T 32918.1-2016 Annex A.
 *
 * ZA is computed here, by us, exactly as prescribed by
 * GB/T 32918.2-2016 clause 5.5:
 *
 *      ZA = H(ENTLA || ID || a || b || xG || yG || xA || yA)
 *      ENTLA = bit length of ID, 2 bytes, big endian
 *
 * GmSSL computes the same value internally (sm2_compute_z(), with the
 * default ID "1234567812345678"), so a signature produced here can be
 * verified by `gmssl sm2verify` and vice versa.
 *
 * Build (inside the guest, next to the upstream sources):
 *   gcc -o drv_sm2_sv drv_sm2_sv.c ../SM2349/src/SM2_sv.o ../SM2349/src/SM3.o \
 *       -I../SM2349/miracl/include ../SM2349/miracl.a
 *
 * Usage:
 *   drv_sm2_sv keygen  <d_hex>
 *   drv_sm2_sv sign    <d_hex> <id> <k_hex> <msg_file>
 *   drv_sm2_sv verify  <x_hex> <y_hex> <id> <r_hex> <s_hex> <msg_file>
 *
 * <id> is the user identity string, or "-" for the default
 * "1234567812345678" used by GmSSL.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* MIRACL core - needed because the upstream SM2 code works on the global
 * MIRACL instance; mirsys() must be called once before any SM2 call.
 * (miracl.h is safe to include here: the clash comes from the upstream
 *  SM2_sv.h, which declares the curve parameters as initialised globals.) */
#include "miracl.h"

#define DEFAULT_ID "1234567812345678"


/* Upstream API (SM2349/src/SM2_sv.h) */
extern int SM2_KeyGeneration(unsigned char PriKey[], unsigned char Px[], unsigned char Py[]);
extern int SM2_Sign(unsigned char *message, int len, unsigned char ZA[], unsigned char rand[],
                    unsigned char d[], unsigned char R[], unsigned char S[]);
extern int SM2_Verify(unsigned char *message, int len, unsigned char ZA[], unsigned char Px[],
                      unsigned char Py[], unsigned char R[], unsigned char S[]);
extern void SM3_256(unsigned char buf[], int len, unsigned char hash[]);

/* SM2 recommended curve parameters - GB/T 32918.1-2016 Annex A */
static const unsigned char SM2_a[32] = {
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc};
static const unsigned char SM2_b[32] = {
    0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34, 0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x09,
    0xa7, 0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92, 0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93};
static const unsigned char SM2_Gx[32] = {
    0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9, 0x94,
    0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1, 0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7};
static const unsigned char SM2_Gy[32] = {
    0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53,
    0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40, 0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0};

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

/* ZA = H(ENTLA || ID || a || b || xG || yG || xA || yA)   (GB/T 32918.2-2016 5.5) */
static void compute_ZA(const unsigned char *id, int idlen,
                       const unsigned char *xA, const unsigned char *yA,
                       unsigned char *ZA)
{
    unsigned char msg[2 + 64 + 32 * 6];
    int off = 0;

    memset(msg, 0, sizeof(msg));
    msg[0] = (unsigned char)((idlen * 8) >> 8);   /* ENTLA, 2 bytes big endian */
    msg[1] = (unsigned char)((idlen * 8) & 0xff);
    off = 2;
    memcpy(msg + off, id, idlen);
    off += idlen;
    memcpy(msg + off, SM2_a, 32);
    off += 32;
    memcpy(msg + off, SM2_b, 32);
    off += 32;
    memcpy(msg + off, SM2_Gx, 32);
    off += 32;
    memcpy(msg + off, SM2_Gy, 32);
    off += 32;
    memcpy(msg + off, xA, 32);
    off += 32;
    memcpy(msg + off, yA, 32);
    off += 32;

    SM3_256(msg, off, ZA);
}

static int read_file(const char *path, unsigned char **out, int *outlen)
{
    FILE *f = fopen(path, "rb");
    size_t cap = 65536, len = 0, n;
    unsigned char *buf;

    if (!f) {
        perror(path);
        return -1;
    }
    buf = (unsigned char *)malloc(cap);
    if (!buf) {
        fclose(f);
        return -1;
    }
    for (;;) {
        if (len == cap) {
            unsigned char *nb;
            cap *= 2;
            nb = (unsigned char *)realloc(buf, cap);
            if (!nb) {
                free(buf);
                fclose(f);
                return -1;
            }
            buf = nb;
        }
        n = fread(buf + len, 1, cap - len, f);
        if (n == 0)
            break;
        len += n;
    }
    fclose(f);
    *out = buf;
    *outlen = (int)len;
    return 0;
}

static void resolve_id(const char *arg, unsigned char *id, int *idlen)
{
    if (strcmp(arg, "-") == 0) {
        memcpy(id, DEFAULT_ID, strlen(DEFAULT_ID));
        *idlen = (int)strlen(DEFAULT_ID);
    } else {
        memcpy(id, arg, strlen(arg));
        *idlen = (int)strlen(arg);
    }
}

int main(int argc, char **argv)
{
    unsigned char d[32], xA[32], yA[32], R[32], S[32], ZA[32], k[32];
    unsigned char id[64];
    unsigned char *msg = NULL;
    int idlen = 0, msglen = 0, rc;

    /* initialise the global MIRACL instance (as the upstream self-check does) */
    /* mirsys() also installs the instance as MIRACL's global (mr_mip), which is
     * what the upstream SM2 code uses internally. */
    miracl *mip = mirsys(10000, 16);
    mip->IOBASE = 16;

    if (argc < 2) {
        fprintf(stderr, "usage: %s keygen|sign|verify ...\n", argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "keygen") == 0) {
        if (argc < 3 || hex2bin(argv[2], d, 32) != 0) {
            fprintf(stderr, "usage: %s keygen <d_hex>\n", argv[0]);
            return 2;
        }
        rc = SM2_KeyGeneration(d, xA, yA);
        if (rc) {
            fprintf(stderr, "SM2_KeyGeneration failed: %d\n", rc);
            return 1;
        }
        printf("x=");
        print_hex(xA, 32);
        printf("\ny=");
        print_hex(yA, 32);
        printf("\n");
        return 0;
    }

    if (strcmp(argv[1], "sign") == 0) {
        if (argc < 6 || hex2bin(argv[2], d, 32) != 0) {
            fprintf(stderr, "usage: %s sign <d_hex> <id|-> <k_hex> <msg_file>\n", argv[0]);
            return 2;
        }
        resolve_id(argv[3], id, &idlen);
        if (read_file(argv[5], &msg, &msglen) != 0)
            return 1;
        rc = SM2_KeyGeneration(d, xA, yA);
        if (rc) {
            fprintf(stderr, "SM2_KeyGeneration failed: %d\n", rc);
            return 1;
        }
        compute_ZA(id, idlen, xA, yA, ZA);
        if (hex2bin(argv[4], k, 32) != 0) {
            fprintf(stderr, "bad k hex\n");
            return 2;
        }
        rc = SM2_Sign(msg, msglen, ZA, k, d, R, S);
        if (rc) {
            fprintf(stderr, "SM2_Sign failed: %d\n", rc);
            return 1;
        }
        printf("za=");
        print_hex(ZA, 32);
        printf("\nr=");
        print_hex(R, 32);
        printf("\ns=");
        print_hex(S, 32);
        printf("\n");
        free(msg);
        return 0;
    }

    if (strcmp(argv[1], "verify") == 0) {
        if (argc < 8) {
            fprintf(stderr, "usage: %s verify <x_hex> <y_hex> <id|-> <r_hex> <s_hex> <msg_file>\n", argv[0]);
            return 2;
        }
        if (hex2bin(argv[2], xA, 32) != 0 || hex2bin(argv[3], yA, 32) != 0) {
            fprintf(stderr, "bad public key hex\n");
            return 2;
        }
        resolve_id(argv[4], id, &idlen);
        if (hex2bin(argv[5], R, 32) != 0 || hex2bin(argv[6], S, 32) != 0) {
            fprintf(stderr, "bad signature hex\n");
            return 2;
        }
        if (read_file(argv[7], &msg, &msglen) != 0)
            return 1;
        compute_ZA(id, idlen, xA, yA, ZA);
        rc = SM2_Verify(msg, msglen, ZA, xA, yA, R, S);
        printf("za=");
        print_hex(ZA, 32);
        printf("\nverify=%s\n", rc == 0 ? "OK" : "FAIL");
        free(msg);
        return rc == 0 ? 0 : 1;
    }

    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}
