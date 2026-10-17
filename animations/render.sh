#!/usr/bin/env bash
# Render the pitch animation and export it as one self-contained HTML slideshow.
#
#   ./animations/render.sh          1080p60 (final)  -> animations/pitch.html + animations/pitch_video.mp4
#   ./animations/render.sh -ql      480p15  (fast preview)
#
# The last section is footage of the real dashboard (record_dashboard.py, run automatically
# the first time; delete animations/footage/ to re-record it).
#
# Present: open animations/pitch.html in a browser, press F for fullscreen, → for the next section.
#
# Needs Manim + manim-slides in their own venv (heavy deps, kept apart from .venv):
#   python3 -m venv .venv-anim && .venv-anim/bin/pip install -r animations/requirements.txt
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${ANIM_BIN:-$HERE/../.venv-anim/bin}"
QUALITY="${1:--qh}"

[[ -x "$BIN/manim-slides" ]] || { echo "manim-slides not found. Run: python3 -m venv .venv-anim && .venv-anim/bin/pip install -r animations/requirements.txt"; exit 1; }
cd "$HERE"   # manim-slides writes its slide data to ./slides
"$BIN/manim" "$QUALITY" --progress_bar none --media_dir "$HERE/media" scenes.py Pitch >/dev/null
"$BIN/manim-slides" convert Pitch pitch.html --one-file >/dev/null
# final section: the real dashboard under a scripted attack (record once; delete footage/ to re-record)
[[ -f footage/dashboard.mp4 ]] || "$BIN/python" record_dashboard.py
"$BIN/python" add_footage.py pitch.html footage/dashboard.mp4
echo "animations/pitch.html ($(du -h pitch.html | cut -f1)) — open it, press F, then → to step through"
"$BIN/python" make_video.py   # the same pitch as one MP4, holding each section for its narration
