#!/usr/bin/env python3
"""
compare_pdf_code.py - provenance check for the SM2349 sources.

The Commercial Cryptography Testing Center (SCCTC) publishes the SM2/SM3/SM4
source code as PDF listings, not as .c/.h files.  The compilable sources used
in this experiment come from the mirror https://github.com/arkq/SM2349.  This
script checks that the mirror really contains the same code as the official
PDFs: it normalises both to "code lines" (no indentation, no comments) and
reports, per file, how many of the mirror's code lines appear verbatim in the
official PDF text.

Usage:
    python3 compare_pdf_code.py <pdf-text-dir> <mirror-src-dir>
"""
import os
import re
import sys

# official PDF name (stem)  ->  mirror source file
PAIRS = [
    ("SM3_c文件", "SM3.c"),
    ("SM4_c文件", "SM4.c"),
    ("SM2_签名验签_c文件", "SM2_sv.c"),
    ("SM2_加解密_c文件", "SM2_ENC.c"),
    ("SM2_KeyExchange_c文件", "SM2_KEY_EX.c"),
]

SKIP = re.compile(r'^(//|/\*|\*|\}|\{|$)')


def code_lines(text):
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or SKIP.match(s):
            continue
        s = re.sub(r'\s+', '', s)
        if len(s) < 12:          # too short to be a meaningful statement
            continue
        out.append(s)
    return out


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    pdf_dir, src_dir = sys.argv[1], sys.argv[2]

    total_hit = total_all = 0
    for pdf_stem, src_name in PAIRS:
        pdf_path = os.path.join(pdf_dir, pdf_stem + ".txt")
        src_path = os.path.join(src_dir, src_name)
        if not os.path.exists(pdf_path) or not os.path.exists(src_path):
            print("SKIP  %-24s (missing file)" % src_name)
            continue
        pdf_text = open(pdf_path, encoding="utf-8", errors="replace").read()
        # the PDF text has spaces/newlines injected between characters, so
        # compare against a whitespace-free version of the PDF text as well
        pdf_flat = re.sub(r'\s+', '', pdf_text)
        src_lines = code_lines(open(src_path, encoding="utf-8",
                                    errors="replace").read())
        hit = [l for l in src_lines if l in pdf_flat]
        pct = 100.0 * len(hit) / len(src_lines) if src_lines else 0.0
        print("%-16s vs %-24s : %3d/%3d code lines found in the official PDF (%.1f%%)"
              % (src_name, pdf_stem + ".txt", len(hit), len(src_lines), pct))
        total_hit += len(hit)
        total_all += len(src_lines)

    if total_all:
        print("total: %d/%d (%.1f%%)" % (total_hit, total_all,
                                         100.0 * total_hit / total_all))
    return 0


if __name__ == '__main__':
    sys.exit(main())
