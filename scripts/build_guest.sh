#!/bin/bash
#
# build_guest.sh - build our own verification drivers against the upstream
#                  SCCTC (SM2349) sources, inside the openEuler guest.
#
# The upstream .c files contain their own main() (the self-test programs), so
# they cannot be linked as-is next to our drivers. We recompile the three
# sources we need with -Dmain=scctc_unused_main, which renames the upstream
# entry point instead of colliding with ours.
#
# Prerequisite: the upstream tree is cloned and MIRACL is built:
#   ~/exp2/SM2349/{Makefile,miracl.a} exist  (make miracl.a && make)
#
# Usage: bash build_guest.sh

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
SM="${SM_DIR:-$HOME/exp2/SM2349}"
OUT="${OUT_DIR:-$ROOT/bin}"
OBJ="${OBJ_DIR:-$ROOT/build}"

if [ ! -f "$SM/miracl.a" ]; then
    echo "ERROR: $SM/miracl.a not found - build the upstream sources first" >&2
    exit 1
fi

mkdir -p "$OUT" "$OBJ"
cd "$ROOT" || exit 1

CFLAGS="-O2 -Wall -I$SM/miracl/include"
DMAIN="-Dmain=scctc_unused_main"

echo "=== recompiling the upstream sources we use (main renamed) ==="
gcc $CFLAGS $DMAIN -c -o "$OBJ/SM3.o"     "$SM/src/SM3.c"     || exit 1
gcc $CFLAGS $DMAIN -c -o "$OBJ/SM4.o"     "$SM/src/SM4.c"     || exit 1
gcc $CFLAGS $DMAIN -c -o "$OBJ/SM2_sv.o"  "$SM/src/SM2_sv.c"  || exit 1
gcc $CFLAGS $DMAIN -c -o "$OBJ/SM2_ENC.o" "$SM/src/SM2_ENC.c" || exit 1

echo "=== building our drivers ==="
gcc $CFLAGS -o "$OUT/drv_sm3"     tools/drv_sm3.c     "$OBJ/SM3.o"                          || exit 1
gcc $CFLAGS -o "$OUT/drv_sm4"     tools/drv_sm4.c     "$OBJ/SM4.o"                          || exit 1
gcc $CFLAGS -o "$OUT/drv_sm2_sv"  tools/drv_sm2_sv.c  "$OBJ/SM2_sv.o" "$OBJ/SM3.o" \
                                 "$SM/miracl.a"                                            || exit 1
gcc $CFLAGS -o "$OUT/drv_sm2_enc" tools/drv_sm2_enc.c "$OBJ/SM2_ENC.o" "$OBJ/SM3.o" \
                                 "$SM/miracl.a"                                            || exit 1
gcc $CFLAGS -o "$OUT/sm2_der"     tools/sm2_der.c                                           || exit 1

echo "=== built ==="
ls -la "$OUT"
