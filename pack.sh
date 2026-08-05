#!/usr/bin/env bash
# Build an extensions.gnome.org-ready zip (UUID directory contents only).
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UUID="secure-clipboard@n0l0g1c.github.io"
SRC="$ROOT/$UUID"
OUT="$ROOT/${UUID}.shell-extension.zip"

REQUIRED=(metadata.json extension.js stylesheet.css LICENSE)
for f in "${REQUIRED[@]}"; do
  if [[ ! -f "$SRC/$f" ]]; then
    echo "error: missing $SRC/$f" >&2
    exit 1
  fi
done

rm -f "$OUT"
(
  cd "$SRC"
  zip -q -r "$OUT" metadata.json extension.js stylesheet.css LICENSE
)

echo "Wrote $OUT"
unzip -l "$OUT"
