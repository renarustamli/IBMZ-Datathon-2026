"""Record the real dashboard reacting to a scripted attack, for the end of the pitch.

  .venv-anim/bin/python animations/record_dashboard.py      -> animations/footage/dashboard.mp4

Starts its own private dashboard (port 5080) with its own log, keys and sealer, so it never
touches a demo that is already running. Traffic is the detector's simulated feed; the
dashboard, detector, AI model and ML-DSA log sealing are the real code. A caption bar in the
recording says what is being simulated at each step.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
PY = str(ROOT / ".venv" / "bin" / "python")          # project venv: dashboard, feed, crypto
OUT = ROOT / "animations" / "footage" / "dashboard.mp4"
PORT = 5080
FAST = 6                                               # fast-forward factor while waiting on the page
VIEW = {"width": 1440, "height": 810}                  # x 4/3 device scale -> 1920x1080 frames
FEED = ROOT / "demo_tools" / "handshake_feed.py"

CAPTION_JS = """
(text) => {
  let bar = document.getElementById('rec-caption');
  if (!bar) {
    bar = document.createElement('div'); bar.id = 'rec-caption';
    Object.assign(bar.style, {position: 'fixed', left: '50%', bottom: '22px', transform: 'translateX(-50%)',
      background: 'rgba(14,17,23,.92)', color: '#e6e9ee', border: '1px solid #2b313b', borderRadius: '10px',
      padding: '10px 18px', font: '600 17px system-ui, -apple-system, sans-serif', zIndex: 99,
      boxShadow: '0 6px 24px rgba(0,0,0,.4)', transition: 'opacity .3s', whiteSpace: 'nowrap'});
    document.body.appendChild(bar);
  }
  bar.style.opacity = text ? 1 : 0;
  if (text) bar.textContent = text;
}
"""


def wait_http(url, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=1)
            return
        except OSError:
            time.sleep(0.5)
    raise SystemExit(f"{url} did not come up")


def main():
    work = Path(tempfile.mkdtemp(prefix="pitch-rec-"))
    log, keys, frames = work / "connections.jsonl", work / "keys", work / "frames"
    frames.mkdir()
    env = {**os.environ, "QSAFE_KEYS": str(keys), "LOG_FILE": str(log), "PORT": str(PORT)}
    procs = []

    def bg(*args):
        procs.append(subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    try:
        print("setting up: keys, 20 min of background traffic, ML-DSA seals…")
        subprocess.run([PY, str(ROOT / "pqc" / "qsafe_crypto.py"), "keygen"], env=env, check=True,
                       stdout=subprocess.DEVNULL)
        subprocess.run([PY, str(FEED), "backlog", str(log), "20"], env=env, check=True)
        subprocess.run([PY, str(ROOT / "pqc" / "qsafe_crypto.py"), "seal", str(log)], env=env, check=True,
                       stdout=subprocess.DEVNULL)
        bg(PY, str(ROOT / "pqc" / "qsafe_crypto.py"), "follow", str(log))
        bg(PY, str(ROOT / "detector" / "dashboard.py"))
        wait_http(f"http://127.0.0.1:{PORT}/api/state")
        bg(PY, str(FEED), "normal", str(log))

        def inject(kind):
            if kind == "pqc_strip":
                subprocess.run([PY, str(FEED), "attack", str(log)], env=env, check=True, stdout=subprocess.DEVNULL)
                return
            code = ("import json,random,sys; from datetime import timedelta; sys.path.insert(0,'detector');"
                    "import generate_traffic as gt; from schema import FIELDS,parse_ts,read_notes;"
                    f"p={str(log)!r}; ns=read_notes(p); seen={{n['client_id'] for n in ns}};"
                    "cl=[c for c in gt.make_clients(random.Random(7)) if c['id'] in seen and c['kind']=='modern'];"
                    f"out=gt.gen_attack(random.Random(5),{kind!r},cl[3],parse_ts(ns[-1]['ts'])+timedelta(seconds=2));"
                    "f=open(p,'a'); [f.write(json.dumps({k:n[k] for k in FIELDS})+'\\n') for n in out]")
            subprocess.run([PY, "-c", code], cwd=ROOT, env=env, check=True)

        attack_at = {}

        def strip():
            attack_at["offset"] = log.stat().st_size
            inject("pqc_strip")

        def tamper():
            """Same-length edit of the attack line (pin it on another client), so the file
            size and the dashboard's read position stay valid: only the seal check notices."""
            with open(log, "r+b") as f:
                f.seek(attack_at["offset"])
                line = f.readline()
                note = json.loads(line)
                cid = note["client_id"]
                forged = cid[:-2] + ("99" if not cid.endswith("99") else "98")
                f.seek(attack_at["offset"])
                f.write(line.replace(cid.encode(), forged.encode(), 1))

        with sync_playwright() as p:
            browser = p.chromium.launch(channel="chrome", headless=True)
            page = browser.new_page(viewport=VIEW, device_scale_factor=4 / 3)
            page.goto(f"http://127.0.0.1:{PORT}/?theme=dark")
            page.wait_for_function("document.getElementById('t-total').textContent !== '0'")
            # the log lives in a temp folder; show just its name rather than the long temp path
            page.evaluate("document.querySelector('.sub .mono').textContent = 'connections.jsonl'")
            time.sleep(3)

            stamps, speeds = [], []   # speed > 1: frame was captured while waiting, play it faster

            def snap(speed=1):
                path = frames / f"{len(stamps):05d}.jpg"
                page.screenshot(path=str(path), type="jpeg", quality=92)
                stamps.append(time.time())
                speeds.append(speed)

            def caption(text):
                page.evaluate(CAPTION_JS, text)

            def scroll_to(selector, block="start"):
                page.evaluate(f"document.querySelector({selector!r}).scrollIntoView({{behavior:'smooth',block:{block!r}}})")

            def hold(seconds, until=None, timeout=25, text=None):
                """Record for `seconds`; if still waiting for `until` after that, keep recording
                but fast-forward those frames (FAST x) and say so in the caption."""
                start, fast = time.time(), False
                while True:
                    waited = time.time() - start
                    if waited >= seconds and until and not fast:
                        fast = True
                        caption(f"{text}  (sped up ×{FAST})")
                    snap(FAST if fast else 1)
                    if waited >= seconds and (until is None or page.evaluate(until)):
                        if fast:
                            caption(text)
                        return
                    if waited > timeout:
                        print(f"  (gave up waiting for: {until})")
                        return

            red = "document.getElementById('banner').classList.contains('bad')"
            tampered = "document.getElementById('seal').textContent.includes('TAMPERED')"

            steps = [
                ("Live dashboard · simulated bank traffic through the gateway", None, 3, None),
                ("Simulated attack: a client's post-quantum options are stripped", strip, 3, red),
                ("The risk table puts the downgraded client first", lambda: scroll_to("#clients", "center"), 3, None),
                ("Simulated attack: subtler anomalies that no fixed rule catches",
                 lambda: (scroll_to("#c-scores", "center"), inject("forced_classical"), inject("cipher_downgrade")), 4, None),
                ("The attacker edits the audit log to cover their tracks",
                 lambda: (scroll_to("main", "start"), tamper()), 1.5, tampered),
                ("ML-DSA seals catch the edit", None, 2.5, None),
            ]
            for i, (text, action, seconds, until) in enumerate(steps, 1):
                print(f"  step {i}/{len(steps)}: {text}")
                caption(text)
                if action:
                    action()
                hold(seconds, until, text=text)
            caption(None)
            hold(0.5)
            browser.close()

        # one frame per screenshot, shown for as long as it really lasted (÷ FAST while waiting)
        concat = work / "frames.txt"
        with open(concat, "w") as f:
            for i in range(len(stamps)):
                dur = ((stamps[i + 1] - stamps[i]) if i + 1 < len(stamps) else 0.1) / speeds[i]
                f.write(f"file '{frames / f'{i:05d}.jpg'}'\nduration {dur:.4f}\n")
            f.write(f"file '{frames / f'{len(stamps) - 1:05d}.jpg'}'\n")
        OUT.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(concat),
                        "-vf", "fps=30,format=yuv420p", "-c:v", "libx264", "-crf", "20", "-movflags", "+faststart",
                        str(OUT)], check=True)
        played = sum((b - a) / sp for a, b, sp in zip(stamps, stamps[1:], speeds))
        print(f"{OUT.relative_to(ROOT)}: {played:.0f}s of video from {stamps[-1] - stamps[0]:.0f}s recorded")
    finally:
        for pr in procs:
            pr.terminate()
        for pr in procs:
            try:
                pr.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pr.kill()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
