/*
 * drv_sm3.c - SM3 driver for the SCCTC (SM2349) implementation.
 *
 * Computes the SM3 digest of a string, a file or stdin and prints it in
 * uppercase hex. Used to cross-check the upstream implementation against
 *   - the GB/T 32905-2016 test vectors, and
 *   - the `gmssl sm3` command.
 *
 * Build (inside the guest, next to the upstream sources):
 *   gcc -o drv_sm3 drv_sm3.c ../SM2349/src/SM3.o
 *
 * Usage:
 *   drv_sm3 -in_str abc
 *   drv_sm3 -in file.bin
 *   cat file.bin | drv_sm3
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Upstream prototype (SM2349/src/SM3.h) - declared here to avoid pulling in
 * the whole header, whose globals would clash with the upstream object file. */
extern void SM3_256(unsigned char buf[], int len, unsigned char hash[]);

static void print_hex(const unsigned char *b, int n)
{
    int i;
    for (i = 0; i < n; i++)
        printf("%02X", b[i]);
}

static int read_all(FILE *f, unsigned char **out, int *outlen)
{
    size_t cap = 65536, len = 0, n;
    unsigned char *buf = (unsigned char *)malloc(cap);

    if (!buf)
        return -1;
    for (;;) {
        if (len == cap) {
            unsigned char *nb;
            cap *= 2;
            nb = (unsigned char *)realloc(buf, cap);
            if (!nb) {
                free(buf);
                return -1;
            }
            buf = nb;
        }
        n = fread(buf + len, 1, cap - len, f);
        if (n == 0)
            break;
        len += n;
    }
    *out = buf;
    *outlen = (int)len;
    return 0;
}

int main(int argc, char **argv)
{
    unsigned char *buf = NULL;
    unsigned char hash[32];
    int len = 0;

    if (argc > 1 && strcmp(argv[1], "-in_str") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: %s -in_str <string> | -in <file> | (stdin)\n", argv[0]);
            return 2;
        }
        len = (int)strlen(argv[2]);
        buf = (unsigned char *)malloc(len ? len : 1);
        if (!buf)
            return 1;
        memcpy(buf, argv[2], len);
    } else if (argc > 1 && strcmp(argv[1], "-in") == 0) {
        FILE *f;
        if (argc < 3) {
            fprintf(stderr, "usage: %s -in_str <string> | -in <file> | (stdin)\n", argv[0]);
            return 2;
        }
        f = fopen(argv[2], "rb");
        if (!f) {
            perror(argv[2]);
            return 1;
        }
        if (read_all(f, &buf, &len) != 0) {
            fclose(f);
            fprintf(stderr, "read error\n");
            return 1;
        }
        fclose(f);
    } else {
        if (read_all(stdin, &buf, &len) != 0) {
            fprintf(stderr, "read error\n");
            return 1;
        }
    }

    SM3_256(buf, len, hash);
    print_hex(hash, 32);
    printf("\n");

    free(buf);
    return 0;
}
