#!/bin/bash
#
# verify_all.sh - cross verification of the SCCTC (SM2349) implementation.
#
#   SM3   : GB/T 32905-2016 vectors + `gmssl sm3`
#   SM4   : GB/T 32907-2016 A.1 vector + `gmssl sm4_ecb` + `openssl enc`
#   SM2   : GB/T 32918.5-2017 A.2 key pair, signature and encryption
#           interoperation with `gmssl sm2sign / sm2verify / sm2encrypt /
#           sm2decrypt` in both directions, plus negative tests
#   selftest: the upstream self-check binaries (exit code 0 == pass)
#
# Every line prints PASS or FAIL; the script ends with a summary.
#
# Usage: bash verify_all.sh

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
BIN="${BIN_DIR:-$ROOT/bin}"
SM="${SM_DIR:-$HOME/exp2/SM2349}"
TOOLS="$ROOT/tools"
W=/tmp/exp2_verify
PASS=0
FAIL=0

rm -rf "$W"
mkdir -p "$W"
cd "$W" || exit 1

up() { printf '%s' "$1" | tr 'a-f' 'A-F'; }

check() {   # check <name> <expected> <actual>
    if [ "$(up "$2")" = "$(up "$3")" ]; then
        echo "PASS  $1"
        PASS=$((PASS + 1))
    else
        echo "FAIL  $1"
        echo "        expected: $2"
        echo "        actual  : $3"
        FAIL=$((FAIL + 1))
    fi
}

check_rc() { # check_rc <name> <expected_rc> <actual_rc>
    if [ "$(up "$2")" = "$(up "$3")" ]; then
        echo "PASS  $1"
        PASS=$((PASS + 1))
    else
        echo "FAIL  $1 (expected rc=$2, got rc=$3)"
        FAIL=$((FAIL + 1))
    fi
}

echo "=============================================================="
echo " SCCTC SM2349 cross verification   ($(date '+%F %T'))"
echo "=============================================================="

# ---------------------------------------------------------------- SM3
echo ""
echo "---- SM3 ----"
V3_ABC=66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0
V3_64=DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732

check "SM3 GB/T 32905-2016 vector (abc)" \
      "$V3_ABC" "$(up "$("$BIN/drv_sm3" -in_str abc)")"

printf 'abcd%.0s' $(seq 1 16) > "$W/m64.bin"
check "SM3 GB/T 32905-2016 vector (abcd x16)" \
      "$V3_64" "$(up "$("$BIN/drv_sm3" -in "$W/m64.bin")")"

head -c 1000 /dev/urandom > "$W/rand.bin"
check "SM3 vs gmssl sm3 (1000 random bytes)" \
      "$(up "$("$BIN/drv_sm3" -in "$W/rand.bin")")" \
      "$(up "$(gmssl sm3 -in "$W/rand.bin" < /dev/null | tr -d ' \n')")"

# ---------------------------------------------------------------- SM4
echo ""
echo "---- SM4 ----"
K4=0123456789abcdeffedcba9876543210
V4=681EDF34D206965E86B3E94F536E4246
printf '0123456789abcdeffedcba9876543210' | xxd -r -p > "$W/pt4.bin"

check "SM4 GB/T 32907-2016 A.1 vector" \
      "$V4" "$(up "$("$BIN/drv_sm4" -key $K4 -in "$W/pt4.bin")")"

gmssl sm4_ecb -encrypt -key $K4 -in "$W/pt4.bin" -out "$W/ct4_gm.bin" < /dev/null
check "SM4 vs gmssl sm4_ecb" \
      "$V4" "$(up "$(xxd -p "$W/ct4_gm.bin" | tr -d '\n')")"

openssl enc -sm4-ecb -nopad -K $K4 -in "$W/pt4.bin" -out "$W/ct4_os.bin" < /dev/null
check "SM4 vs openssl enc -sm4-ecb -nopad" \
      "$V4" "$(up "$(xxd -p "$W/ct4_os.bin" | tr -d '\n')")"

check "SM4 cross decrypt: gmssl ciphertext -> drv_sm4" \
      "$(xxd -p "$W/pt4.bin" | tr -d '\n')" \
      "$(up "$("$BIN/drv_sm4" -key $K4 -in "$W/ct4_gm.bin" -dec)")"

"$BIN/drv_sm4" -key $K4 -in "$W/pt4.bin" > "$W/ct4_our.hex"
xxd -r -p "$W/ct4_our.hex" > "$W/ct4_our.bin"
gmssl sm4_ecb -decrypt -key $K4 -in "$W/ct4_our.bin" -out "$W/pt4_back.bin" < /dev/null
check "SM4 cross decrypt: drv_sm4 ciphertext -> gmssl" \
      "$(xxd -p "$W/pt4.bin" | tr -d '\n')" \
      "$(xxd -p "$W/pt4_back.bin" | tr -d '\n')"

# ---------------------------------------------------------------- SM2 keys
echo ""
echo "---- SM2 key generation ----"
DA=3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8
XA=09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020
YA=CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13

OUR_X=$("$BIN/drv_sm2_sv" keygen $DA | grep '^x=' | cut -d= -f2)
OUR_Y=$("$BIN/drv_sm2_sv" keygen $DA | grep '^y=' | cut -d= -f2)
check "SM2 keygen GB/T 32918.5-2017 A.2 (xA)" "$XA" "$(up "$OUR_X")"
check "SM2 keygen GB/T 32918.5-2017 A.2 (yA)" "$YA" "$(up "$OUR_Y")"

# a GmSSL key pair, so that both implementations work on the same key
GMPASS=12345678
gmssl sm2keygen -pass $GMPASS -out "$W/gm.pem" -pubout "$W/gm_pub.pem" < /dev/null
KDUMP=$(python3 "$ROOT/scripts/gmssl_key_dump.py" "$W/gm.pem" $GMPASS)
GD=$(echo "$KDUMP" | grep '^d=' | cut -d= -f2)
GX=$(echo "$KDUMP" | grep '^x=' | cut -d= -f2)
GY=$(echo "$KDUMP" | grep '^y=' | cut -d= -f2)
check "SM2 keygen vs GmSSL keypair (x)" "$GX" "$(up "$("$BIN/drv_sm2_sv" keygen $GD | grep '^x=' | cut -d= -f2)")"
check "SM2 keygen vs GmSSL keypair (y)" "$GY" "$(up "$("$BIN/drv_sm2_sv" keygen $GD | grep '^y=' | cut -d= -f2)")"

# ---------------------------------------------------------------- SM2 sign
echo ""
echo "---- SM2 signature ----"
KS=59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21
printf 'message digest' > "$W/msg.bin"

SIG=$("$BIN/drv_sm2_sv" sign $GD - $KS "$W/msg.bin")
OUR_R=$(echo "$SIG" | grep '^r=' | cut -d= -f2)
OUR_S=$(echo "$SIG" | grep '^s=' | cut -d= -f2)
OUR_ZA=$(echo "$SIG" | grep '^za=' | cut -d= -f2)
"$BIN/sm2_der" sig-encode "$OUR_R" "$OUR_S" "$W/our_sig.der" > /dev/null

gmssl sm2verify -pubkey "$W/gm_pub.pem" -in "$W/msg.bin" -sig "$W/our_sig.der" < /dev/null > "$W/v1.log" 2>&1
check_rc "SM2 signature: drv_sm2_sv -> gmssl sm2verify" 0 $?

gmssl sm2sign -key "$W/gm.pem" -pass $GMPASS -in "$W/msg.bin" -out "$W/gm_sig.der" < /dev/null
GM_SIG=$("$BIN/sm2_der" sig-decode "$W/gm_sig.der")
GM_R=$(echo "$GM_SIG" | grep '^r=' | cut -d= -f2)
GM_S=$(echo "$GM_SIG" | grep '^s=' | cut -d= -f2)
VOUT=$("$BIN/drv_sm2_sv" verify "$GX" "$GY" - "$GM_R" "$GM_S" "$W/msg.bin")
check_rc "SM2 signature: gmssl sm2sign -> drv_sm2_sv verify" 0 $?

check "SM2 ZA: ours vs GmSSL (implied by mutual verify)" \
      "$(up "$OUR_ZA")" "$(up "$(echo "$VOUT" | grep '^za=' | cut -d= -f2)")"

# negative test 1: the message was changed
cp "$W/msg.bin" "$W/msg_bad.bin"
printf 'X' >> "$W/msg_bad.bin"
"$BIN/drv_sm2_sv" verify "$GX" "$GY" - "$GM_R" "$GM_S" "$W/msg_bad.bin" > /dev/null 2>&1
check_rc "SM2 signature: tampered message must NOT verify" 1 $?

# negative test 2: r was changed
BAD_R=$(echo "$OUR_R" | sed 's/^\(..\)/0X/')
"$BIN/sm2_der" sig-encode "$BAD_R" "$OUR_S" "$W/bad_sig.der" > /dev/null
gmssl sm2verify -pubkey "$W/gm_pub.pem" -in "$W/msg.bin" -sig "$W/bad_sig.der" < /dev/null > /dev/null 2>&1
check_rc "SM2 signature: tampered r must NOT verify in GmSSL" 1 $?

# ---------------------------------------------------------------- SM2 encrypt
echo ""
echo "---- SM2 encryption ----"
KE=59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21
ENC=$("$BIN/drv_sm2_enc" encrypt $GD $KE "$W/msg.bin")
EC_X=$(echo "$ENC" | grep '^c1x=' | cut -d= -f2)
EC_Y=$(echo "$ENC" | grep '^c1y=' | cut -d= -f2)
EC_C3=$(echo "$ENC" | grep '^c3=' | cut -d= -f2)
EC_C2=$(echo "$ENC" | grep '^c2=' | cut -d= -f2)
"$BIN/sm2_der" ct-encode "$EC_X" "$EC_Y" "$EC_C3" "$EC_C2" "$W/our_ct.der" > /dev/null

gmssl sm2decrypt -key "$W/gm.pem" -pass $GMPASS -in "$W/our_ct.der" -out "$W/pt_dec.bin" < /dev/null
check "SM2 encryption: drv_sm2_enc -> gmssl sm2decrypt" \
      "$(xxd -p "$W/msg.bin" | tr -d '\n')" \
      "$(xxd -p "$W/pt_dec.bin" | tr -d '\n')"

gmssl sm2encrypt -pubkey "$W/gm_pub.pem" -in "$W/msg.bin" -out "$W/gm_ct.der" < /dev/null
GM_CT=$("$BIN/sm2_der" ct-decode "$W/gm_ct.der")
GC_X=$(echo "$GM_CT" | grep '^x=' | cut -d= -f2)
GC_Y=$(echo "$GM_CT" | grep '^y=' | cut -d= -f2)
GC_C3=$(echo "$GM_CT" | grep '^c3=' | cut -d= -f2)
GC_C2=$(echo "$GM_CT" | grep '^c2=' | cut -d= -f2)
printf '%s%s%s%s' "$GC_X" "$GC_Y" "$GC_C3" "$GC_C2" | xxd -r -p > "$W/gm_ct.bin"
DEC=$("$BIN/drv_sm2_enc" decrypt $GD "$W/gm_ct.bin")
check "SM2 encryption: gmssl sm2encrypt -> drv_sm2_enc decrypt" \
      "$(xxd -p "$W/msg.bin" | tr -d '\n')" \
      "$(up "$(echo "$DEC" | grep '^m=' | cut -d= -f2)")"

# negative test: C3 was changed -> decryption must fail
BAD_C3=$(echo "$GC_C3" | sed 's/^\(..\)/0X/')
printf '%s%s%s%s' "$GC_X" "$GC_Y" "$BAD_C3" "$GC_C2" | xxd -r -p > "$W/bad_ct.bin"
"$BIN/drv_sm2_enc" decrypt $GD "$W/bad_ct.bin" > /dev/null 2>&1
check_rc "SM2 encryption: tampered C3 must NOT decrypt" 1 $?

# ---------------------------------------------------------------- upstream selftest
echo ""
echo "---- upstream self-check programs ----"
for t in SM3 SM4 SM2key SM2sv SM2enc; do
    if [ -x "$SM/$t" ]; then
        "$SM/$t" > /dev/null 2>&1
        check_rc "upstream $t self-test" 0 $?
    fi
done

echo ""
echo "=============================================================="
echo " passed: $PASS   failed: $FAIL"
echo "=============================================================="
[ "$FAIL" -eq 0 ]
