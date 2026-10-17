"""One continuous pitch video (no key presses): every animated section, then the dashboard footage.

  python animations/make_video.py        -> animations/pitch_video.mp4

Where the slideshow would wait for →, the video holds the section's last frame for as long
as that section's narration in PITCH_SCRIPT.md takes to say (150 words a minute), so a
voice-over recorded from the script lines up. Needs a render first (slides/Pitch.json).
"""
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "PITCH_SCRIPT.md"
FOOTAGE = HERE / "footage" / "dashboard.mp4"
OUT = HERE / "pitch_video.mp4"
WORDS_PER_SEC = 150 / 60
MIN_HOLD = 1.2     # even a short line gets a beat to read the caption
END_HOLD = 2.0     # after the footage


def duration(path):
    out = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(path)],
                         capture_output=True, text=True, check=True).stdout
    return float(out)


def narration_words():
    """Words spoken in each '### N ·' section of the script (quoted lines only)."""
    sections = re.split(r"^### \d+ · .*$", SCRIPT.read_text(), flags=re.M)[1:]
    sections[-1] = sections[-1].split("\n---")[0]   # drop the presenter notes after the last section
    return [sum(len(l.lstrip("> ").split()) for l in s.splitlines() if l.startswith(">")) for s in sections]


def main():
    slides = json.loads((HERE / "slides" / "Pitch.json").read_text())["slides"]
    clips = [HERE / s["file"] for s in slides] + [FOOTAGE]
    words = narration_words()
    if len(words) != len(clips):
        sys.exit(f"PITCH_SCRIPT.md has {len(words)} sections but the video has {len(clips)}; keep them in step")

    holds = []
    for i, (clip, w) in enumerate(zip(clips, words)):
        if clip == FOOTAGE:
            holds.append(END_HOLD)   # the footage paces itself with its own captions
        else:
            holds.append(max(MIN_HOLD, w / WORDS_PER_SEC - duration(clip)))

    args, chains = ["ffmpeg", "-v", "error", "-y"], []
    for i, (clip, hold) in enumerate(zip(clips, holds)):
        args += ["-i", str(clip)]
        chains.append(f"[{i}:v]fps=60,scale=1920:1080,setsar=1,format=yuv420p,"
                      f"tpad=stop_mode=clone:stop_duration={hold:.2f}[v{i}]")
    graph = ";".join(chains) + ";" + "".join(f"[v{i}]" for i in range(len(clips))) + f"concat=n={len(clips)}:v=1:a=0[out]"
    args += ["-filter_complex", graph, "-map", "[out]", "-c:v", "libx264", "-crf", "20", "-preset", "medium",
             "-movflags", "+faststart", str(OUT)]
    subprocess.run(args, check=True)
    total = duration(OUT)
    print(f"{OUT.name}: {total // 60:.0f}:{total % 60:04.1f}, {OUT.stat().st_size / 1e6:.1f} MB "
          f"({len(clips)} sections, holds {min(holds):.1f}–{max(holds):.1f}s)")


if __name__ == "__main__":
    main()
