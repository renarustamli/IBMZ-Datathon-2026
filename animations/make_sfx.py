"""Generate the pitch video's sound effects with the ElevenLabs sound-effects API.

  ELEVENLABS_API_KEY=... python animations/make_sfx.py      -> animations/sfx/<name>.mp3

Sounds that already exist are skipped (each generation spends ElevenLabs credits), so delete
a file to regenerate it. The key is read from the environment only; never commit it.
"""
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parent / "sfx"
API = "https://api.elevenlabs.io/v1/sound-generation?output_format=mp3_44100_128"

# One family: every prompt shares STYLE and varies only the gesture, so the sounds match.
STYLE = ("minimal soft synthesized sound, warm clean sine tones, gentle, no harsh noise, no voice, "
         "calm educational explainer video style")

# name: (gesture, seconds). Names are what scenes.py cues and add_sfx.py mixes.
SOUNDS = {
    "whoosh": ("soft airy synth pad swell sweeping past, transition", 1.0),
    "soft_pop": ("single soft round sine blip", 0.5),
    "data_blip": ("three soft quick ascending sine blips", 1.0),
    "rec_beep": ("single soft low sine beep", 0.6),
    "time_warp": ("soft rising synth pad swell with gentle shimmer", 2.0),
    "quantum_zap": ("soft deep synth pulse with a light shimmer tail", 1.0),
    "unlock": ("two soft descending sine tones, gentle release", 1.0),
    "lock_click": ("soft muted click with a short low sine tone", 0.6),
    "denied": ("two soft low descending sine tones, gentle negative", 0.7),
    "alarm": ("two soft pulsing low synth tones, gentle tension", 1.5),
    "marker_strike": ("soft quick downward synth swipe", 0.6),
    "typing": ("soft rapid sequence of tiny sine ticks", 1.0),
    "error_glitch": ("soft low slightly dissonant synth tone with a short stutter", 0.8),
    "success_chime": ("soft warm major chord sine chime", 1.0),
    "scan": ("soft sine sweep upward with faint ticks", 1.2),
    "scramble": ("soft fast shuffle of sine blips", 1.2),
    "riser": ("soft rising sine tone swell", 1.2),
}


def generate(name, prompt, seconds, key):
    body = {"text": f"{prompt}. {STYLE}", "duration_seconds": seconds, "prompt_influence": 0.6}
    req = urllib.request.Request(API, data=json.dumps(body).encode(), method="POST",
                                 headers={"xi-api-key": key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{name}: HTTP {e.code} {e.read()[:300]!r}")


def main():
    key = os.environ.get("ELEVENLABS_API_KEY")
    if not key:
        sys.exit("set ELEVENLABS_API_KEY first")
    OUT.mkdir(exist_ok=True)
    for name, (prompt, seconds) in SOUNDS.items():
        path = OUT / f"{name}.mp3"
        if path.exists():
            continue
        path.write_bytes(generate(name, prompt, seconds, key))
        print(f"  {path.name} ({seconds:g}s)")


if __name__ == "__main__":
    main()
