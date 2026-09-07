#!/usr/bin/env bash
# Render index.html to the committed PDF with headless Chrome, assert two or three A4
# pages, and rasterise each page to build/page-N.png for visual QA.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PDF="$DIR/tracecat-solution-brief-zero-day-mitigation.pdf"
OUT="$DIR/build"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"

if [[ ! -x "$CHROME" ]]; then
    echo "chrome not found at $CHROME (set CHROME=...)" >&2
    exit 1
fi

mkdir -p "$OUT"
rm -f "$PDF"
PROFILE="$(mktemp -d)"
CHROME_PID=""
cleanup() {
    if [[ -n "$CHROME_PID" ]] && kill -0 "$CHROME_PID" 2>/dev/null; then
        kill "$CHROME_PID" 2>/dev/null || true
        wait "$CHROME_PID" 2>/dev/null || true
    fi
    rm -rf "$PROFILE"
}
trap cleanup EXIT

# Chrome 152 new-headless writes the PDF and then does not exit on its own, so
# run it in the background and stop it once the file has stopped growing.
"$CHROME" --headless=new --disable-gpu --no-first-run \
    --user-data-dir="$PROFILE" \
    --force-color-profile=srgb --hide-scrollbars --allow-file-access-from-files \
    --run-all-compositor-stages-before-draw --virtual-time-budget=10000 \
    --no-pdf-header-footer --print-to-pdf="$PDF" "file://$DIR/index.html" \
    >/dev/null 2>&1 &
CHROME_PID=$!

last=-1
for _ in $(seq 1 120); do
    sleep 0.5
    if [[ -s "$PDF" ]]; then
        size=$(stat -f %z "$PDF")
        if [[ "$size" == "$last" ]]; then
            break
        fi
        last=$size
    fi
    if ! kill -0 "$CHROME_PID" 2>/dev/null; then
        break
    fi
done

if [[ ! -s "$PDF" ]]; then
    echo "chrome did not produce $PDF" >&2
    exit 1
fi

PDF_PATH="$PDF" OUT_DIR="$OUT" uv run --no-project --with pypdfium2 --with pillow python - <<'EOF'
import os

import pypdfium2 as pdfium

pdf = pdfium.PdfDocument(os.environ["PDF_PATH"])
n = len(pdf)
w, h = pdf[0].get_size()
print(f"pages={n} size={w:.1f}x{h:.1f}pt")
for i, page in enumerate(pdf, start=1):
    page.render(scale=2).to_pil().save(os.path.join(os.environ["OUT_DIR"], f"page-{i}.png"))
assert n in (2, 3), f"expected 2 or 3 pages, got {n}"
EOF
