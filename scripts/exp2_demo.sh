#!/bin/bash
#
# exp2_demo.sh - one-shot demo of Experiment 2, made for taking screenshots.
#
# It prints, in order:
#   1. the environment (openEuler / gcc / GmSSL / OpenSSL)
#   2. where the SCCTC (SM2349) sources are and how they were obtained
#   3. the upstream self-check programs (exit code 0 == pass)
#   4. our own drivers on the GB/T test vectors
#   5. cross verification against GmSSL (sign / verify / encrypt / decrypt)
#   6. the summary of the full 25-item verification run
#
# Usage:  bash ~/exp2/our/scripts/exp2_demo.sh

set -u

W=/tmp/exp2_demo
SM="${SM_DIR:-$HOME/exp2/SM2349}"
OUR="${OUR_DIR:-$HOME/exp2/our}"
BIN="$OUR/bin"
mkdir -p "$W"
cd "$W" || exit 1

hdr() {
    echo
    echo "=============================================================="
    echo "  $*"
    echo "=============================================================="
}

hdr "1. Environment"
cat /etc/os-release | head -3
echo "kernel : $(uname -r)"
echo "gcc    : $(gcc --version | head -1)"
echo "gmssl  : $(gmssl version 2>&1 | head -1)"
echo "openssl: $(openssl version)"
echo "user   : $(whoami)   host: $(hostname)"
echo "ip     : $(ip -4 addr show | grep -o 'inet [0-9.]*' | head -2 | tail -1)"

hdr "2. SCCTC sources (SM2349) obtained from https://github.com/Arkq/SM2349"
cd "$SM" || exit 1
git log --oneline -3
echo "--- files ---"
ls src/ | tr '\n' ' '; echo
echo "--- MIRACL submodule commit ---"
(cd miracl && git log --oneline -1)
echo "--- the official package only ships PDF listings, not .c files ---"
echo "    (see docs/01-源码获取与溯源.md : 1353/1420 code lines matched 95.3%)"

hdr "3. Upstream self-check programs (exit code 0 == pass)"
cd "$SM" || exit 1
for p in SM3 SM4 SM2key SM2sv SM2enc; do
    printf '%-8s : ' "./$p"
    if [ -x "./$p" ]; then
        ./"$p" > /dev/null 2>&1
        echo "exit=$?  (pass)"
    else
        echo "not built"
    fi
done

hdr "4. Our drivers against the GB/T test vectors"
K4=0123456789abcdeffedcba9876543210
DA=3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8
KS=59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21
printf '0123456789abcdeffedcba9876543210' | xxd -r -p > pt4.bin
printf 'message digest' > msg.bin

echo "--- SM3  GB/T 32905-2016 appendix A : abc ---"
echo "ours : $("$BIN/drv_sm3" -in_str abc)"
echo "gmssl: $(gmssl sm3 -in <(printf 'abc') < /dev/null 2>/dev/null | tr -d ' \n')"

echo "--- SM4  GB/T 32907-2016 appendix A.1 ---"
echo "ours : $("$BIN/drv_sm4" -key $K4 -in pt4.bin)"
echo "gmssl: $(gmssl sm4_ecb -encrypt -key $K4 -in pt4.bin -out ct4.bin < /dev/null >/dev/null 2>&1; xxd -p ct4.bin | tr -d '\n')"

echo "--- SM2  GB/T 32918.5-2017 appendix A.2 key pair ---"
"$BIN/drv_sm2_sv" keygen $DA

hdr "5. Cross verification with GmSSL (both directions)"
echo "--- 5.1 SM2 signature : ours -> gmssl sm2verify ---"
gmssl sm2keygen -pass 12345678 -out gm.pem -pubout gm_pub.pem < /dev/null
GD=$(python3 "$OUR/scripts/gmssl_key_dump.py" gm.pem 12345678 | grep '^d=' | cut -d= -f2)
GX=$(python3 "$OUR/scripts/gmssl_key_dump.py" gm.pem 12345678 | grep '^x=' | cut -d= -f2)
GY=$(python3 "$OUR/scripts/gmssl_key_dump.py" gm.pem 12345678 | grep '^y=' | cut -d= -f2)
echo "GmSSL private key d = $GD"
SIG=$("$BIN/drv_sm2_sv" sign $GD - $KS msg.bin)
echo "$SIG" | grep -E '^(za|r|s)='
OUR_R=$(echo "$SIG" | grep '^r=' | cut -d= -f2)
OUR_S=$(echo "$SIG" | grep '^s=' | cut -d= -f2)
"$BIN/sm2_der" sig-encode "$OUR_R" "$OUR_S" our_sig.der > /dev/null
gmssl sm2verify -pubkey gm_pub.pem -in msg.bin -sig our_sig.der < /dev/null
echo "gmssl sm2verify exit = $?   (0 == our signature is accepted by GmSSL)"

echo "--- 5.2 SM2 signature : gmssl sm2sign -> ours ---"
gmssl sm2sign -key gm.pem -pass 12345678 -in msg.bin -out gm_sig.der < /dev/null
"$BIN/sm2_der" sig-decode gm_sig.der | grep -E '^(r|s)='
GM_R=$("$BIN/sm2_der" sig-decode gm_sig.der | grep '^r=' | cut -d= -f2)
GM_S=$("$BIN/sm2_der" sig-decode gm_sig.der | grep '^s=' | cut -d= -f2)
"$BIN/drv_sm2_sv" verify "$GX" "$GY" - "$GM_R" "$GM_S" msg.bin
echo "our verify exit = $?   (0 == GmSSL signature is accepted by us)"

echo "--- 5.3 SM2 encryption : ours -> gmssl sm2decrypt ---"
ENC=$("$BIN/drv_sm2_enc" encrypt $GD $KS msg.bin)
echo "$ENC" | grep -E '^(c1x|c1y|c3|c2)=' | cut -c1-70
C1X=$(echo "$ENC" | grep '^c1x=' | cut -d= -f2)
C1Y=$(echo "$ENC" | grep '^c1y=' | cut -d= -f2)
C3H=$(echo "$ENC" | grep '^c3='  | cut -d= -f2)
C2H=$(echo "$ENC" | grep '^c2='  | cut -d= -f2)
"$BIN/sm2_der" ct-encode "$C1X" "$C1Y" "$C3H" "$C2H" our_ct.der > /dev/null
gmssl sm2decrypt -key gm.pem -pass 12345678 -in our_ct.der -out pt.bin < /dev/null
echo "decrypted by GmSSL : $(cat pt.bin)"
echo "original           : $(cat msg.bin)"

hdr "6. Full verification run (25 checks)"
bash "$OUR/scripts/verify_all.sh" | tail -n 22

echo
echo "=============================================================="
echo "  Experiment 2 demo finished.  20241422 Mu Yihan"
echo "=============================================================="
