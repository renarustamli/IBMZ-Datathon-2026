"""Append the dashboard recording to pitch.html as its final section.

  python animations/add_footage.py [pitch.html] [footage/dashboard.mp4]

Uses the same markup manim-slides writes for its own sections, so the presenter's → key
moves onto the footage like any other slide. Run after `manim-slides convert`.
"""
import base64
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
html_path = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "pitch.html"
video_path = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "footage" / "dashboard.mp4"

html = html_path.read_text()
marker = "<!-- dashboard footage -->"
if marker in html:
    sys.exit(f"{html_path.name} already has the footage; re-run manim-slides convert first")
last = html.rfind("</section>")
if last < 0:
    sys.exit(f"no <section> found in {html_path}")
data = base64.b64encode(video_path.read_bytes()).decode()
section = f"""
        {marker}
        <section
          data-background-size='contain'
          data-background-color="#0e1117"
          data-background-video="data:video/mp4;base64,{data}"
          >
        </section>"""
cut = last + len("</section>")
html_path.write_text(html[:cut] + section + html[cut:])
print(f"added {video_path.name} ({video_path.stat().st_size / 1e6:.1f} MB) as the last section of {html_path.name}")
