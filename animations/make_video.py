"""One continuous pitch video (no key presses): every animated section, then the dashboard footage.

  python animations/make_video.py              -> animations/pitch_video.mp4, sections back to back
  python animations/make_video.py --narrated   -> holds each section's last frame for as long as its
                                                  narration in PITCH_SCRIPT.md takes (150 words/min)
  python animations/make_video.py --length 150 -> slows the animated sections so the whole video runs
                                                  150 s (the dashboard footage keeps its real speed)

Needs a render first (slides/Pitch.json).
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
    argv = sys.argv[1:]
    narrated = "--narrated" in argv
    length = float(argv[argv.index("--length") + 1]) if "--length" in argv else None
    slides = json.loads((HERE / "slides" / "Pitch.json").read_text())["slides"]
    clips = [HERE / s["file"] for s in slides] + [FOOTAGE]
    holds = [0.0] * (len(clips) - 1) + [END_HOLD]
    if narrated:
        words = narration_words()
        if len(words) != len(clips):
            sys.exit(f"PITCH_SCRIPT.md has {len(words)} sections but the video has {len(clips)}; keep them in step")
        # the footage paces itself with its own captions
        holds = [max(MIN_HOLD, w / WORDS_PER_SEC - duration(c)) for c, w in zip(clips[:-1], words)] + [END_HOLD]

    slow = 1.0
    if length:
        anim = sum(duration(c) for c in clips[:-1]) + sum(holds[:-1])
        fixed = duration(clips[-1]) + holds[-1]
        if length <= fixed:
            sys.exit(f"--length must be more than the footage's {fixed:.0f}s")
        slow = (length - fixed) / anim

    args, chains = ["ffmpeg", "-v", "error", "-y"], []
    for i, (clip, hold) in enumerate(zip(clips, holds)):
        args += ["-i", str(clip)]
        stretch = slow if clip != FOOTAGE else 1.0
        chains.append(f"[{i}:v]scale=1920:1080,setsar=1,format=yuv420p,"
                      f"tpad=stop_mode=clone:stop_duration={hold:.2f},setpts={stretch:.4f}*PTS,fps=60[v{i}]")
    graph = ";".join(chains) + ";" + "".join(f"[v{i}]" for i in range(len(clips))) + f"concat=n={len(clips)}:v=1:a=0[out]"
    args += ["-filter_complex", graph, "-map", "[out]", "-c:v", "libx264", "-crf", "20", "-preset", "medium",
             "-movflags", "+faststart", str(OUT)]
    subprocess.run(args, check=True)
    total = duration(OUT)
    print(f"{OUT.name}: {total // 60:.0f}:{total % 60:04.1f}, {OUT.stat().st_size / 1e6:.1f} MB "
          f"({len(clips)} sections{', narration holds' if narrated else ', no pauses'}"
          f"{f', animation at {1 / slow:.2f}x speed' if slow != 1 else ''})")


if __name__ == "__main__":
    main()
