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

# name: (prompt, seconds). Names are what scenes.py cues and add_sfx.py mixes.
SOUNDS = {
    "whoosh": ("quick soft cinematic whoosh transition, airy, clean, no music", 1.0),
    "soft_pop": ("soft subtle user interface pop, gentle click", 0.5),
    "data_blip": ("three quick soft digital data blips, futuristic interface", 1.0),
    "rec_beep": ("single short electronic recording beep, surveillance device", 0.6),
    "time_warp": ("time passing, ticking clock accelerating into a soft whoosh swell", 2.0),
    "quantum_zap": ("sci-fi energy beam zap with electric hum discharge", 1.0),
    "unlock": ("several metal padlocks clicking open in quick succession", 1.0),
    "lock_click": ("solid metallic lock clicking shut, secure", 0.6),
    "denied": ("short digital access denied buzzer", 0.7),
    "alarm": ("short urgent two-tone digital security alert, not too loud", 1.5),
    "marker_strike": ("marker pen quickly striking through text on paper", 0.6),
    "typing": ("short fast burst of keyboard typing", 1.0),
    "error_glitch": ("digital glitch error stutter, data corruption", 0.8),
    "success_chime": ("bright positive interface success chime", 1.0),
    "scan": ("sci-fi scanner sweep with soft beeps", 1.2),
    "scramble": ("digital data scrambling, encryption computing chatter", 1.2),
    "riser": ("short subtle rising synth tone swell", 1.2),
    "ambient": ("subtle dark ambient technology drone, low warm hum, minimal, no melody, seamless loop", 20.0),
}


def generate(name, prompt, seconds, key):
    body = {"text": prompt, "duration_seconds": seconds, "prompt_influence": 0.4}
    if name == "ambient":
        body["loop"] = True
    req = urllib.request.Request(API, data=json.dumps(body).encode(), method="POST",
                                 headers={"xi-api-key": key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if body.pop("loop", None) and e.code in (400, 422):  # older models have no loop option
            req = urllib.request.Request(API, data=json.dumps(body).encode(), method="POST",
                                         headers={"xi-api-key": key, "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read()
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
