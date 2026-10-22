#!/usr/bin/env python3
"""
pdf_text.py - extract the text of the official SCCTC source-code PDFs.

The packages offered by the Commercial Cryptography Testing Center
(https://www.scctc.org.cn/xzzx/sfydm/ydmxz/) do not contain .c/.h files; the
source code is shipped as PDF listings.  This script turns them back into
plain text so that the code can be compared with the compiled sources.

Usage:
    python3 pdf_text.py <input.pdf> [output.txt]
"""
import sys

try:
    from pypdf import PdfReader
except ImportError:
    sys.stderr.write("pypdf is required: pip install pypdf\n")
    sys.exit(2)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    reader = PdfReader(sys.argv[1])
    pages = []
    for i, page in enumerate(reader.pages):
        pages.append("===== page %d =====" % (i + 1))
        pages.append(page.extract_text() or "")
    text = "\n".join(pages)
    if len(sys.argv) > 2:
        with open(sys.argv[2], "w", encoding="utf-8", errors="replace") as f:
            f.write(text)
        print("wrote %d bytes to %s" % (len(text), sys.argv[2]))
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
