/*
 * drv_sm4.c - SM4 (ECB, no padding) driver for the SCCTC (SM2349) implementation.
 *
 * The upstream SM4_Encrypt()/SM4_Decrypt() operate on a single 16-byte block
 * and run the key schedule inside every call, so this driver loops over the
 * blocks of the input itself (raw ECB, i.e. the semantics of
 * GB/T 32907-2016 Appendix A.1).
 *
 * Cross-checked against:
 *   - the GB/T 32907-2016 A.1 test vector,
 *   - `gmssl sm4_ecb -encrypt/-decrypt`,
 *   - `openssl enc -sm4-ecb -nopad`.
 *
 * Build (inside the guest, next to the upstream sources):
 *   gcc -o drv_sm4 drv_sm4.c ../SM2349/src/SM4.o
 *
 * Usage:
 *   drv_sm4 -key <32 hex chars> -in <file>            # encrypt, hex to stdout
 *   drv_sm4 -key <32 hex chars> -in <file> -dec       # decrypt
 *   drv_sm4 -key <32 hex chars> -in_str <text>        # encrypt a string
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void SM4_Encrypt(unsigned char MK[], unsigned char PlainText[], unsigned char CipherText[]);
extern void SM4_Decrypt(unsigned char MK[], unsigned char CipherText[], unsigned char PlainText[]);

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

int main(int argc, char **argv)
{
    unsigned char key[16];
    unsigned char *buf = NULL, *out = NULL;
    long len = 0, cap = 0, n, i, nblocks;
    int dec = 0, have_key = 0;
    const char *in_str = NULL, *in_file = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-key") == 0 && i + 1 < argc) {
            if (hex2bin(argv[++i], key, 16) != 0) {
                fprintf(stderr, "bad -key (need 32 hex chars)\n");
                return 2;
            }
            have_key = 1;
        } else if (strcmp(argv[i], "-dec") == 0) {
            dec = 1;
        } else if (strcmp(argv[i], "-in_str") == 0 && i + 1 < argc) {
            in_str = argv[++i];
        } else if (strcmp(argv[i], "-in") == 0 && i + 1 < argc) {
            in_file = argv[++i];
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            return 2;
        }
    }
    if (!have_key) {
        fprintf(stderr, "usage: %s -key <hex32> [-in file | -in_str text] [-dec]\n", argv[0]);
        return 2;
    }

    if (in_str) {
        len = (long)strlen(in_str);
        buf = (unsigned char *)malloc(len ? len : 1);
        if (!buf)
            return 1;
        memcpy(buf, in_str, len);
    } else if (in_file) {
        FILE *f = fopen(in_file, "rb");
        if (!f) {
            perror(in_file);
            return 1;
        }
        cap = 65536;
        buf = (unsigned char *)malloc(cap);
        for (;;) {
            if (len == cap) {
                unsigned char *nb;
                cap *= 2;
                nb = (unsigned char *)realloc(buf, cap);
                if (!nb) {
                    fclose(f);
                    return 1;
                }
                buf = nb;
            }
            n = (long)fread(buf + len, 1, cap - len, f);
            if (n == 0)
                break;
            len += n;
        }
        fclose(f);
    } else {
        cap = 65536;
        buf = (unsigned char *)malloc(cap);
        for (;;) {
            if (len == cap) {
                unsigned char *nb;
                cap *= 2;
                nb = (unsigned char *)realloc(buf, cap);
                if (!nb)
                    return 1;
                buf = nb;
            }
            n = (long)fread(buf + len, 1, cap - len, stdin);
            if (n == 0)
                break;
            len += n;
        }
    }

    if (len % 16 != 0) {
        fprintf(stderr, "input length %ld is not a multiple of the 16-byte block\n", len);
        free(buf);
        return 2;
    }

    nblocks = len / 16;
    out = (unsigned char *)malloc(len ? len : 1);
    if (!out) {
        free(buf);
        return 1;
    }

    for (i = 0; i < nblocks; i++) {
        if (dec)
            SM4_Decrypt(key, buf + i * 16, out + i * 16);
        else
            SM4_Encrypt(key, buf + i * 16, out + i * 16);
    }

    print_hex(out, (int)len);
    printf("\n");

    free(buf);
    free(out);
    return 0;
}
