"""Second version of the pitch video with sound effects only (no voice, no background): pitch_video.mp4 -> pitch_video_sfx.mp4

  python animations/add_sfx.py

The picture is copied unchanged from pitch_video.mp4. Sounds come from animations/sfx/ (make_sfx.py)
and are timed from cues.json, which scenes.py writes on every render, so they stay on their frames
when the animation changes. The video plays the animation slowed down (make_video.py --length),
so cue times are stretched by the same factor. Footage cues are listed below.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VIDEO = HERE / "pitch_video.mp4"
OUT = HERE / "pitch_video_sfx.mp4"
SFX = HERE / "sfx"

# Seconds into footage/dashboard.mp4. Found by scene-change detection on the recording
# (caption bar, banner and integrity tile); re-check them if the footage is re-recorded.
FOOTAGE_CUES = [
    (0.0, "whoosh"),          # footage starts
    (4.87, "alarm"),          # banner turns red: PQC downgrade
    (6.07, "whoosh"),         # scroll to the risk table
    (9.17, "whoosh"),         # scroll to the anomaly chart
    (9.4, "data_blip"),       # AI anomalies land
    (13.2, "typing"),         # attacker edits the audit log
    (14.77, "riser"),         # fast-forward while the seal check runs
    (15.77, "error_glitch"),  # integrity tile: TAMPERED
    (16.5, "success_chime"),  # caught
]

# Mix level in dB after every sound is normalised to the same peak.
GAIN = {
    "whoosh": -9, "soft_pop": -10, "data_blip": -12, "rec_beep": -12, "time_warp": -8, "quantum_zap": -8,
    "unlock": -7, "lock_click": -8, "denied": -8, "alarm": -9, "marker_strike": -8, "typing": -9,
    "error_glitch": -9, "success_chime": -9, "scan": -10, "scramble": -10, "riser": -10,
}
PEAK = -1.0  # dBFS every sound is normalised to before its mix gain
MASTER = 7   # dB on the whole mix, before the limiter


def probe(path):
    return float(subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0",
                                 str(path)], capture_output=True, text=True, check=True).stdout)


def peak_db(path):
    err = subprocess.run(["ffmpeg", "-i", str(path), "-af", "volumedetect", "-f", "null", "-"],
                         capture_output=True, text=True).stderr
    return float(re.search(r"max_volume: (-?[\d.]+) dB", err).group(1))


def main():
    cues = json.loads((HERE / "cues.json").read_text())
    slides = json.loads((HERE / "slides" / "Pitch.json").read_text())["slides"]
    anim = sum(probe(HERE / s["file"]) for s in slides)
    footage = probe(HERE / "footage" / "dashboard.mp4")
    total = probe(VIDEO)
    end_hold = 2.0                                   # make_video.py END_HOLD
    slow = (total - footage - end_hold) / anim       # same stretch make_video.py applied
    start = anim * slow                              # where the footage begins in the video

    events = [(t * slow, name) for t, name in cues] + [(start + t, name) for t, name in FOOTAGE_CUES]
    missing = sorted({n for _, n in events if not (SFX / f"{n}.mp3").exists()})
    if missing:
        sys.exit(f"missing sounds {missing}: run make_sfx.py")

    norm = {n: PEAK - peak_db(SFX / f"{n}.mp3") for n in {n for _, n in events}}
    args = ["ffmpeg", "-v", "error", "-y", "-i", str(VIDEO)]
    chains, labels = [], []
    for i, (t, name) in enumerate(events, start=1):
        args += ["-i", str(SFX / f"{name}.mp3")]
        ms = int(round(t * 1000))
        chains.append(f"[{i}:a]aformat=sample_rates=48000:channel_layouts=stereo,"
                      f"volume={norm[name] + GAIN[name]:.1f}dB,lowpass=f=7000,adelay={ms}|{ms}[s{i}]")
        labels.append(f"[s{i}]")
    # every effect shares one bus with the same short echo, so they sound like one family in one room;
    # silence pads the track out to the video's full length
    graph = ";".join(chains) + ";" + "".join(labels) + \
        f"amix=inputs={len(labels)}:normalize=0:duration=longest,aecho=0.8:0.6:90|180:0.18|0.10," \
        f"apad=whole_dur={total:.2f},atrim=0:{total:.2f},volume={MASTER}dB,alimiter=limit=0.9[aout]"
    args += ["-filter_complex", graph, "-map", "0:v", "-map", "[aout]", "-c:v", "copy",
             "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart", str(OUT)]
    subprocess.run(args, check=True)
    print(f"{OUT.name}: {probe(OUT):.1f}s, {len(events)} sound effects "
          f"(animation x{slow:.3f}, footage from {start:.1f}s)")


if __name__ == "__main__":
    main()
