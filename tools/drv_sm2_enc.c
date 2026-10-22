/*
 * drv_sm2_enc.c - SM2 encryption/decryption driver for the SCCTC (SM2349)
 *                  implementation (upstream file src/SM2_ENC.c).
 *
 * The upstream API works on MIRACL types (big / epoint), so this driver links
 * against miracl.a as well. Like the upstream self test it must set up the
 * MIRACL instance first:
 *
 *      mip = mirsys(1000, 16);  mip->IOBASE = 16;
 *
 * Ciphertext layout produced by the upstream code (and by the standard,
 * GB/T 32918.4-2016 clause 6.1):
 *
 *      C = C1 || C3 || C2 ,  C1 = x1 || y1 (64 bytes), C3 = 32 bytes,
 *      C2 = |M| bytes
 *
 * Build (inside the guest, next to the upstream sources):
 *   gcc -o drv_sm2_enc drv_sm2_enc.c ../SM2349/src/SM2_ENC.o ../SM2349/src/SM3.o \
 *       -I../SM2349/miracl/include ../SM2349/miracl.a
 *
 * Usage:
 *   drv_sm2_enc encrypt <d_hex> <k_hex> <msg_file>   # prints c=<hex>
 *   drv_sm2_enc decrypt <d_hex> <ct_file>            # prints the plaintext hex
 */
#include <miracl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int SM2_Init();
extern int SM2_KeyGeneration(big priKey, epoint *pubKey);
extern int SM2_Encrypt(unsigned char *randK, epoint *pubKey, unsigned char M[], int klen,
                       unsigned char C[]);
extern int SM2_Decrypt(big dB, unsigned char C[], int Clen, unsigned char M[]);

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

int main(int argc, char **argv)
{
    unsigned char d[32], k[32];
    unsigned char *msg = NULL;
    int msglen = 0, rc;

    if (argc < 2) {
        fprintf(stderr, "usage: %s encrypt <d_hex> <k_hex> <msg_file> | decrypt <d_hex> <ct_file>\n", argv[0]);
        return 2;
    }

    /* mirsys() also installs the instance as MIRACL's global (mr_mip), which is
     * what the upstream SM2 code uses internally. */
    miracl *mip = mirsys(10000, 16);
    mip->IOBASE = 16;

    if (strcmp(argv[1], "encrypt") == 0) {
        big pri, x, y;
        epoint *pub;
        unsigned char *C, xy[64];
        int Clen;

        if (argc < 5 || hex2bin(argv[2], d, 32) != 0 || hex2bin(argv[3], k, 32) != 0) {
            fprintf(stderr, "usage: %s encrypt <d_hex> <k_hex> <msg_file>\n", argv[0]);
            return 2;
        }
        if (read_file(argv[4], &msg, &msglen) != 0)
            return 1;

        rc = SM2_Init();
        if (rc) {
            fprintf(stderr, "SM2_Init failed: %d\n", rc);
            return 1;
        }
        pri = mirvar(0);
        x = mirvar(0);
        y = mirvar(0);
        bytes_to_big(32, (char *)d, pri);
        pub = epoint_init();
        rc = SM2_KeyGeneration(pri, pub);
        if (rc) {
            fprintf(stderr, "SM2_KeyGeneration failed: %d\n", rc);
            return 1;
        }
        epoint_get(pub, x, y);
        big_to_bytes(32, x, (char *)xy, 1);
        big_to_bytes(32, y, (char *)(xy + 32), 1);

        Clen = msglen + 32 * 3;
        C = (unsigned char *)malloc(Clen);
        if (!C)
            return 1;
        rc = SM2_Encrypt(k, pub, msg, msglen, C);
        if (rc) {
            fprintf(stderr, "SM2_Encrypt failed: %d\n", rc);
            return 1;
        }
        printf("pubx=");
        print_hex(xy, 32);
        printf("\npuby=");
        print_hex(xy + 32, 32);
        /* the upstream ciphertext layout is C1x || C1y || C3 || C2 */
        printf("\nc1x=");
        print_hex(C, 32);
        printf("\nc1y=");
        print_hex(C + 32, 32);
        printf("\nc3=");
        print_hex(C + 64, 32);
        printf("\nc2=");
        print_hex(C + 96, Clen - 96);
        printf("\n");
        free(C);
        free(msg);
        return 0;
    }

    if (strcmp(argv[1], "decrypt") == 0) {
        big pri;
        unsigned char *C, *M;
        int Clen, Mlen;

        if (argc < 4 || hex2bin(argv[2], d, 32) != 0) {
            fprintf(stderr, "usage: %s decrypt <d_hex> <ct_file>\n", argv[0]);
            return 2;
        }
        if (read_file(argv[3], &C, &Clen) != 0)
            return 1;

        rc = SM2_Init();
        if (rc) {
            fprintf(stderr, "SM2_Init failed: %d\n", rc);
            return 1;
        }
        pri = mirvar(0);
        bytes_to_big(32, (char *)d, pri);

        Mlen = Clen - 32 * 3;
        if (Mlen < 0) {
            fprintf(stderr, "ciphertext too short\n");
            return 2;
        }
        M = (unsigned char *)malloc(Mlen ? Mlen : 1);
        if (!M)
            return 1;
        rc = SM2_Decrypt(pri, C, Clen, M);
        if (rc) {
            fprintf(stderr, "SM2_Decrypt failed: %d\n", rc);
            return 1;
        }
        printf("m=");
        print_hex(M, Mlen);
        printf("\n");
        free(M);
        free(C);
        return 0;
    }

    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}
