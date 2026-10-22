#!/usr/bin/env python3
"""
gmssl_key_dump.py - read a GmSSL encrypted PKCS#8 private key and print the
                    raw private key and public key coordinates in hex.

Why this is needed
------------------
GmSSL 3.2.0 writes the SM2 private key as an encrypted PKCS#8 structure:

    EncryptedPrivateKeyInfo ::= SEQUENCE {
        encryptionAlgorithm  AlgorithmIdentifier,   -- PBES2
        encryptedData        OCTET STRING }

    PBES2-params ::= SEQUENCE {
        keyDerivationFunc AlgorithmIdentifier,        -- PBKDF2
        encryptionScheme  AlgorithmIdentifier }       -- sm4-cbc

    PBKDF2-params ::= SEQUENCE {
        salt OCTET STRING, iterationCount INTEGER,
        keyLength INTEGER OPTIONAL,
        prf AlgorithmIdentifier DEFAULT hmacWithSHA1 }   -- GmSSL: hmacWithSM3

OpenSSL cannot decrypt this file: it does not know the PBKDF2 PRF
hmacWithSM3 (OID 1.2.156.10197.1.401.2).  But Python's hashlib can derive the
key (OpenSSL 3.5 provides SM3) and the guest's OpenSSL can run SM4-CBC, so the
file can be opened here.  Having the coordinates in hex lets us check the
SCCTC implementation against GmSSL in both directions (sign and encrypt).

Only the standard library is used.

Usage:
    python3 gmssl_key_dump.py <gm.pem> [password]
"""
import base64
import binascii
import hashlib
import os
import subprocess
import sys
import tempfile


def read_tlv(buf, off):
    """Read one DER TLV. Returns (tag, value_bytes, next_offset)."""
    tag = buf[off]
    off += 1
    length = buf[off]
    off += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[off:off + n], 'big')
        off += n
    return tag, buf[off:off + length], off + length


def children(buf):
    """Split a constructed DER value into its children."""
    out = []
    off = 0
    while off < len(buf):
        tag, val, off = read_tlv(buf, off)
        out.append((tag, val))
    return out


def pem_body(path):
    data = open(path, 'rb').read().decode('ascii')
    lines = [l.strip() for l in data.splitlines()]
    body = ''.join(l for l in lines if l and not l.startswith('-----'))
    return base64.b64decode(body)


def der_oid(value):
    """Decode an OBJECT IDENTIFIER value into dotted notation."""
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(n))
            n = 0
    return '.'.join(parts)


def derive_key(password, salt, iterations, keylen):
    return hashlib.pbkdf2_hmac('sm3', password.encode('utf-8'), salt,
                                iterations, keylen)


def sm4_cbc_decrypt(key, iv, data):
    with tempfile.TemporaryDirectory() as tmp:
        ct = os.path.join(tmp, 'ct.bin')
        pt = os.path.join(tmp, 'pt.bin')
        open(ct, 'wb').write(data)
        cmd = ['openssl', 'enc', '-d', '-sm4-cbc',
               '-K', key.hex(), '-iv', iv.hex(), '-in', ct, '-out', pt]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            raise RuntimeError('openssl sm4-cbc decrypt failed: '
                               + r.stderr.decode('utf-8', 'replace'))
        return open(pt, 'rb').read()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    password = sys.argv[2] if len(sys.argv) > 2 else ''

    der = pem_body(path)

    # EncryptedPrivateKeyInfo
    tag, seq, _ = read_tlv(der, 0)
    assert tag == 0x30, 'not a SEQUENCE'
    algid_tag, algid, off = read_tlv(seq, 0)
    assert algid_tag == 0x30, 'not an AlgorithmIdentifier'
    data_tag, enc_data, _ = read_tlv(seq, off)

    alg = children(algid)
    assert der_oid(alg[0][1]) == '1.2.840.113549.1.5.13', 'not PBES2'
    params = children(alg[1][1])

    # keyDerivationFunc
    kdf = children(params[0][1])
    assert der_oid(kdf[0][1]) == '1.2.840.113549.1.5.12', 'not PBKDF2'
    kdf_params = children(kdf[1][1])
    salt = kdf_params[0][1]
    iterations = int.from_bytes(kdf_params[1][1], 'big')
    keylen = None
    prf = 'hmacWithSHA1'
    for tag_, val_ in kdf_params[2:]:
        if tag_ == 0x02:
            keylen = int.from_bytes(val_, 'big')
        elif tag_ == 0x30:
            prf = der_oid(children(val_)[0][1])
    print('# PBES2 / PBKDF2 salt=%s iterations=%d keylen=%s prf=%s'
          % (salt.hex().upper(), iterations, keylen, prf))
    if prf != '1.2.156.10197.1.401.2':
        print('# WARNING: unexpected PRF %s' % prf, file=sys.stderr)

    # encryptionScheme
    scheme = children(params[1][1])
    cipher_oid = der_oid(scheme[0][1])
    iv = scheme[1][1]
    print('# cipher=%s iv=%s' % (cipher_oid, iv.hex().upper()))

    if keylen is None:
        keylen = 16
    key = derive_key(password, salt, iterations, keylen)

    plain = sm4_cbc_decrypt(key, iv, enc_data)

    # PrivateKeyInfo
    tag, p8, _ = read_tlv(plain, 0)
    items = children(p8)
    ec_tag, ec, _ = read_tlv(items[2][1], 0)
    ec_items = children(ec)
    d = ec_items[1][1]
    point = None
    for tag_, val_ in ec_items[2:]:
        if tag_ == 0xA1:
            bit_tag, bit, _ = read_tlv(val_, 0)
            point = bit[1:]          # strip the unused-bits octet
    print('d=' + d.hex().upper())
    if point and len(point) == 65 and point[0] == 0x04:
        print('x=' + point[1:33].hex().upper())
        print('y=' + point[33:65].hex().upper())
    elif point:
        print('pub=' + point.hex().upper())
    return 0


if __name__ == '__main__':
    sys.exit(main())
