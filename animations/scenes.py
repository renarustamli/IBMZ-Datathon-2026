"""The pitch as one continuous animation, in the style of 3Blue1Brown.

Built with Manim Community Edition + manim-slides: each `self.next_slide()` is a pause,
and the presenter presses → to play the next section.

  ./animations/render.sh                         -> animations/pitch.html (open, press F, then →)
  manim -pql animations/scenes.py Pitch          (quick low-quality preview, no pauses)

Benchmark numbers on the LinuxONE section come from gateway/bench/benchmarks.md.
"""
import json
from pathlib import Path

from manim import *
from manim_slides import Slide

config.background_color = "#0e1117"
FONT = "Avenir Next"
MONO = "Menlo"

# Palette validated with the dataviz validator against the background (dark mode, all checks pass).
OLD = "#E06C2A"     # classical crypto (RSA / X25519 alone)
PQ = "#14A88E"      # post-quantum (ML-KEM / ML-DSA)
BAD = "#E5484D"
GOOD = "#46A758"
INK = GREY_A        # secondary text


def T(s, size=28, color=WHITE, **kw):
    return Text(s, font=FONT, font_size=size, color=color, **kw)


def M(s, size=20, color=WHITE, **kw):
    return Text(s, font=MONO, font_size=size, color=color, **kw)


# ───────────────────────────── icons ─────────────────────────────
class Lock(VGroup):
    def __init__(self, color=OLD, label=None, s=1.0, **kw):
        body = RoundedRectangle(width=0.56, height=0.46, corner_radius=0.08,
                                fill_color=color, fill_opacity=1, stroke_width=0)
        top = body.get_top()
        legs = VGroup(Line(top + LEFT * 0.17, top + LEFT * 0.17 + UP * 0.12),
                      Line(top + RIGHT * 0.17, top + RIGHT * 0.17 + UP * 0.12))
        arc = Arc(radius=0.17, start_angle=0, angle=PI).move_to(top + UP * 0.12, aligned_edge=DOWN)
        self.shackle = VGroup(legs, arc).set_stroke(color, width=6)
        hole = Dot(body.get_center() + UP * 0.03, radius=0.05, color=config.background_color)
        parts = [self.shackle, body, hole]
        if label:
            parts.append(T(label, 14, WHITE, weight=BOLD).next_to(body, DOWN, buff=0.06))
        super().__init__(*parts, **kw)
        self.scale(s)

    def open(self):
        """Animation: the shackle swings open."""
        pivot = self.shackle[0][1].get_bottom()
        return Rotate(self.shackle, angle=-PI / 2.6, about_point=pivot, rate_func=rush_from)


def key_icon(color=YELLOW, s=1.0):
    ring = Circle(radius=0.16, stroke_color=color, stroke_width=6)
    shaft = Line(ring.get_right(), ring.get_right() + RIGHT * 0.5, stroke_color=color, stroke_width=6)
    teeth = VGroup(*[Line(shaft.get_end() + LEFT * x, shaft.get_end() + LEFT * x + DOWN * 0.12,
                          stroke_color=color, stroke_width=6) for x in (0.02, 0.16)])
    return VGroup(ring, shaft, teeth).scale(s)


def laptop(label, color=BLUE_B):
    screen = RoundedRectangle(width=1.0, height=0.66, corner_radius=0.06, stroke_color=color, stroke_width=4)
    inner = Rectangle(width=0.82, height=0.48, stroke_width=0, fill_color=color, fill_opacity=0.25).move_to(screen)
    base = Polygon([-0.62, 0, 0], [0.62, 0, 0], [0.5, 0.1, 0], [-0.5, 0.1, 0],
                   stroke_width=0, fill_color=color, fill_opacity=1).next_to(screen, DOWN, buff=0.02)
    return VGroup(screen, inner, base, T(label, 20, INK).next_to(base, DOWN, buff=0.15))


def server(label, color=GREY_B):
    units = VGroup(*[
        VGroup(RoundedRectangle(width=1.3, height=0.36, corner_radius=0.05, stroke_color=color, stroke_width=3),
               Dot(radius=0.04, color=GOOD).shift(LEFT * 0.45),
               Line(RIGHT * 0.05, RIGHT * 0.5, stroke_color=color, stroke_width=3))
        for _ in range(3)]).arrange(DOWN, buff=0.08)
    return VGroup(units, T(label, 20, INK).next_to(units, DOWN, buff=0.15))


def person(label, color=BAD):
    head = Circle(radius=0.2, fill_color=color, fill_opacity=1, stroke_width=0)
    body = Arc(radius=0.36, start_angle=0, angle=PI, fill_color=color, fill_opacity=1, stroke_width=0)
    body.next_to(head, DOWN, buff=0.06)
    return VGroup(head, body, T(label, 20, color).next_to(body, DOWN, buff=0.15))


def quantum_computer(label="Quantum computer"):
    """The 'golden chandelier' dilution fridge, simplified."""
    discs = VGroup(*[Ellipse(width=w, height=0.16, fill_color=GOLD, fill_opacity=1, stroke_width=0)
                     for w in (1.3, 1.0, 0.7)]).arrange(DOWN, buff=0.36)
    wires = VGroup(*[Line(discs[0].get_center() + RIGHT * x, discs[2].get_center() + RIGHT * x * 0.5,
                          stroke_color=GOLD_A, stroke_width=2) for x in (-0.45, -0.15, 0.15, 0.45)])
    chip = Square(0.18, fill_color=PURPLE_B, fill_opacity=1, stroke_width=0).next_to(discs[2], DOWN, buff=0.08)
    g = VGroup(wires, discs, chip)
    return VGroup(g, T(label, 20, GOLD_A).next_to(g, DOWN, buff=0.15))


def packet(color):
    box = RoundedRectangle(width=0.62, height=0.42, corner_radius=0.07,
                           fill_color=GREY_E, fill_opacity=1, stroke_color=GREY_B, stroke_width=2)
    lines = VGroup(*[Line(LEFT * 0.18, RIGHT * 0.18, stroke_width=2, stroke_color=GREY_B) for _ in range(3)])
    lines.arrange(DOWN, buff=0.07).move_to(box).shift(LEFT * 0.06)
    lk = Lock(color, s=0.42).move_to(box.get_corner(UR) + LEFT * 0.04 + DOWN * 0.02)
    p = VGroup(box, lines, lk)
    p.lock = lk
    return p


def gateway_icon(h=2.2, label=True):
    box = RoundedRectangle(width=1.5, height=h, corner_radius=0.2, stroke_color=PQ, stroke_width=5,
                           fill_color=PQ, fill_opacity=0.12)
    g = VGroup(box, Lock(PQ, "ML-KEM", s=1.1).move_to(box).shift(UP * 0.2))
    if label:
        g.add(T("Gateway", 22, PQ).next_to(box, DOWN, buff=0.15))
    g.box = box
    return g


def caption(s, color=INK):
    return T(s, 26, color).to_edge(DOWN, buff=0.45)


def send(p, line, t=1.4):
    """A packet fades in at the start of a line, travels it, and fades out at the end."""
    p.move_to(line.get_start())
    return Succession(FadeIn(p, run_time=0.2), p.animate(run_time=t, rate_func=linear).move_to(line.get_end()),
                      FadeOut(p, run_time=0.2))


# ───────────────────────────── the pitch ─────────────────────────────
class Pitch(Slide):
    def construct(self):
        self.title = None
        self.cap = None
        self.cues = []
        self.intro()
        self.harvest()
        self.gateway()
        self.at_rest()
        self.downgrade()
        self.tamper()
        self.linuxone()
        self.summary()
        # sound-effect cue sheet for make_video.py --sfx (times in seconds of animation)
        (Path(__file__).resolve().parent / "cues.json").write_text(json.dumps(self.cues, indent=1))

    # helpers -----------------------------------------------------------
    def cue(self, sound):
        """Mark a sound effect to start with the next animation (see make_video.py --sfx)."""
        self.cues.append([round(self.time, 3), sound])

    def set_title(self, s):
        new = T(s, 44).to_edge(UP, buff=0.4)
        self.cue("whoosh")
        if self.title is None:
            self.play(Write(new), run_time=1)
        else:
            self.play(ReplacementTransform(self.title, new), run_time=0.8)
        self.title = new

    def say(self, s, color=INK):
        new = caption(s, color)
        if self.cap is not None:
            self.play(FadeOut(self.cap, shift=UP * 0.25), run_time=0.3)
        self.play(FadeIn(new, shift=UP * 0.25), run_time=0.35)
        self.cap = new

    def clear(self, keep=()):
        """Fade out everything except the title and `keep`."""
        keep = set(keep) | {self.title}
        gone = [m for m in self.mobjects if m not in keep]
        if gone:
            self.play(*[FadeOut(m) for m in gone], run_time=0.6)
        if self.cap in gone:
            self.cap = None

    def pause(self):
        self.wait(0.3)
        self.next_slide()

    # 0 ---------------------------------------------------------------
    def intro(self):
        name = T("Quantum-Safe Gateway", 60)
        sub = T("for legacy systems", 34, INK)
        event = T("IBM Z Datathon 2026  ·  Theme 2: AI Secured", 22, GREY_B)
        VGroup(name, sub, event).arrange(DOWN, buff=0.3).shift(UP * 0.6)
        old, new = Lock(OLD, s=2.0), Lock(PQ, s=2.0)
        for lk in (old, new):
            lk.next_to(event, DOWN, buff=0.7)
        self.cue("whoosh")
        self.play(Write(name), run_time=1.2)
        self.play(FadeIn(sub, shift=UP * 0.2), FadeIn(event), FadeIn(old, scale=0.8), run_time=0.8)
        self.cue("lock_click")
        self.play(Transform(old, new), run_time=1.0)
        self.pause()
        self.play(FadeOut(VGroup(sub, event, old)), run_time=0.5)
        self.title = name
        self.set_title("Harvest now, decrypt later")

    # 1 ---------------------------------------------------------------
    def harvest(self):
        self.client = client = laptop("Bank client").move_to(LEFT * 5 + UP * 1.0)
        self.srv = srv = server("Bank server").move_to(RIGHT * 5 + UP * 1.0)
        self.wire = wire = Line(client[0].get_right() + RIGHT * 0.2, srv[0].get_left() + LEFT * 0.2,
                                stroke_color=GREY_B, stroke_width=3)
        yr = ValueTracker(2026)  # Integer/DecimalNumber need LaTeX, so redraw a Text instead
        year_lbl = T("year", 18, GREY_B).to_corner(UR, buff=0.5).shift(LEFT * 0.25)
        year_num = always_redraw(lambda: T(str(int(round(yr.get_value()))), 40).next_to(year_lbl, DOWN, buff=0.05))
        self.play(FadeIn(client, shift=RIGHT * 0.3), FadeIn(srv, shift=LEFT * 0.3),
                  Create(wire), FadeIn(year_lbl), FadeIn(year_num), run_time=1)
        self.say("Customer records travel encrypted with classical RSA")

        self.spy = spy = person("Eavesdropper").move_to(DOWN * 1.1)
        self.tap = tap = DashedLine(wire.get_center(), spy[0].get_top(), stroke_color=BAD, dash_length=0.08)
        bars = VGroup(*[RoundedRectangle(width=1.6, height=0.22, corner_radius=0.05, stroke_color=BAD,
                                         stroke_width=2) for _ in range(3)]).arrange(DOWN, buff=0.05)
        store_lbl = T("recorded traffic", 18, BAD).next_to(bars, DOWN, buff=0.1)
        VGroup(bars, store_lbl).next_to(spy, RIGHT, buff=0.6).shift(UP * 0.15)
        self.cue("rec_beep")
        self.play(FadeIn(spy, shift=UP * 0.3), Create(tap), FadeIn(bars), FadeIn(store_lbl), run_time=0.9)

        self.cue("data_blip")
        self.play(LaggedStart(*[send(packet(OLD), wire, 1.6) for _ in range(3)], lag_ratio=0.3))
        slots = [bars[i].get_center() for i in range(3)]
        recorded = VGroup(*[packet(OLD).scale(0.7).move_to(wire.get_center()) for _ in range(3)])
        self.play(LaggedStart(*[r.animate.move_to(slots[i] + LEFT * 0.45) for i, r in enumerate(recorded)],
                              lag_ratio=0.2), run_time=1.2)
        self.say("Today: recorded, but still locked")
        self.pause()

        self.say("Years later…")
        self.cue("time_warp")
        self.play(yr.animate.set_value(2036), run_time=2, rate_func=smooth)
        self.qc = qc = quantum_computer().scale(0.8).move_to(RIGHT * 5.7 + DOWN * 1.5)
        self.play(FadeIn(qc, shift=UP * 0.3), run_time=0.8)
        beam = Line(qc[0].get_left(), bars.get_right(), stroke_color=PURPLE_A, stroke_width=6)
        self.cue("quantum_zap")
        self.play(ShowPassingFlash(beam.copy(), time_width=0.6), run_time=0.7)
        self.cue("unlock")
        self.play(ShowPassingFlash(beam.copy(), time_width=0.6), *[r.lock.open() for r in recorded], run_time=0.7)
        names = ["Sofia Shah · 46913810", "Noah Evans · 23756669", "Chloe Patel · 89254563"]
        leaked = VGroup(*[M(n, 18, YELLOW).move_to(slots[i]) for i, n in enumerate(names)])
        self.cue("error_glitch")
        self.play(FadeOut(bars), LaggedStart(*[ReplacementTransform(recorded[i], leaked[i]) for i in range(3)],
                                             lag_ratio=0.15), run_time=1)
        self.say("Data that must stay secret for 10+ years is already at risk", YELLOW)
        note = T("Illustration: quantum computers able to do this do not exist yet.", 19, GREY_C)
        note.next_to(self.cap, DOWN, buff=0.1)
        self.play(FadeIn(note), run_time=0.5)
        self.pause()
        self.play(FadeOut(VGroup(year_lbl, leaked, store_lbl, note)), FadeOut(year_num), run_time=0.6)
        self.remove(year_num)

    # 2 ---------------------------------------------------------------
    def gateway(self):
        self.set_title("A drop-in quantum-safe gateway")
        srv, client, wire, spy, tap, qc = self.srv, self.client, self.wire, self.spy, self.tap, self.qc
        new_srv = server("Legacy bank server").move_to(srv)
        self.play(Transform(srv, new_srv), run_time=0.4)
        old_lock = Lock(OLD, "RSA", s=0.9).next_to(srv[0], LEFT, buff=0.25)
        self.cue("lock_click")
        self.play(FadeIn(old_lock, scale=0.8), run_time=0.5)
        self.say("Rewriting old systems is slow, expensive and risky")
        self.pause()

        gw = gateway_icon().move_to(RIGHT * 1.8 + UP * 0.9)
        self.say("So we put a gateway in front of it instead")
        outer = Line(client[0].get_right() + RIGHT * 0.2, gw.box.get_left(), stroke_color=PQ, stroke_width=5)
        inner = Line(gw.box.get_right(), srv[0].get_left() + LEFT * 0.1, stroke_color=GREY_B, stroke_width=3)
        mid = outer.get_center()
        self.cue("whoosh")
        self.play(FadeIn(gw, shift=LEFT * 1.5), FadeOut(old_lock), ReplacementTransform(wire, outer),
                  FadeIn(inner), spy.animate.move_to([mid[0], -1.1, 0]),
                  Transform(tap, DashedLine(mid, [mid[0], -1.1 + 0.62, 0], stroke_color=BAD, dash_length=0.08)),
                  run_time=1.3)
        inner_lbl = T("same machine", 16, GREY_B).next_to(inner, UP, buff=0.08)
        unchanged = T("unchanged ✓", 20, GOOD).next_to(srv, DOWN, buff=0.15)
        self.play(FadeIn(inner_lbl), FadeIn(unchanged), run_time=0.6)
        self.say("Outside link: hybrid TLS, X25519 + ML-KEM-768 (NIST FIPS 203)", PQ)

        self.cue("data_blip")
        self.play(LaggedStart(*[send(packet(PQ), outer, 1.3) for _ in range(3)], lag_ratio=0.3))
        rec = VGroup(*[packet(PQ).scale(0.7) for _ in range(3)]).arrange(RIGHT, buff=0.15)
        rec.next_to(spy, RIGHT, buff=0.5)
        self.play(LaggedStart(*[FadeIn(r, shift=DOWN * 0.3) for r in rec], lag_ratio=0.2), run_time=0.8)

        self.say("The quantum computer tries again…")
        beam = Line(qc[0].get_left(), rec.get_right(), stroke_color=PURPLE_A, stroke_width=6)
        for _ in range(2):
            self.cue("quantum_zap")
            self.play(ShowPassingFlash(beam.copy(), time_width=0.6),
                      *[Wiggle(r.lock, scale_value=1.15, rotation_angle=0.05 * TAU) for r in rec], run_time=0.8)
        self.say("…and the recordings stay locked", GOOD)
        self.cue("success_chime")
        self.play(Circumscribe(rec, color=GOOD), run_time=1)
        self.pause()

        # strict mode: a connection that offers only the old lock is refused
        self.say("Someone tries to connect with only the old lock…", OLD)
        p = packet(OLD).move_to(outer.get_start())
        self.play(FadeIn(p), run_time=0.2)
        self.play(p.animate.move_to(outer.get_end() + LEFT * 0.45), run_time=1.0, rate_func=linear)
        cross = Cross(p, stroke_color=BAD, stroke_width=6)
        self.cue("denied")
        self.play(Create(cross), Indicate(gw.box, color=BAD), run_time=0.6)
        self.play(VGroup(p, cross).animate.shift(LEFT * 1.5).set_opacity(0), run_time=0.7)
        self.say("Strict mode: no quantum-safe lock, no connection", GOOD)
        self.pause()

    # 3 ---------------------------------------------------------------
    def at_rest(self):
        self.clear()
        self.set_title("Data at rest")
        doc = RoundedRectangle(width=3.0, height=2.2, corner_radius=0.15, stroke_color=GREY_B, stroke_width=3,
                               fill_color=GREY_E, fill_opacity=0.6)
        rows = VGroup(*[M(s, 16, WHITE) for s in ("Sofia Shah   46913810", "Noah Evans   23756669",
                                                   "Chloe Patel  89254563", "Aarav Patel  39345092")])
        rows.arrange(DOWN, aligned_edge=LEFT, buff=0.15).move_to(doc)
        fname = T("bank_records.json", 18, INK).next_to(doc, DOWN, buff=0.15)
        file_ = VGroup(doc, rows, fname).move_to(LEFT * 4.3 + UP * 0.4)
        self.play(FadeIn(file_, shift=RIGHT * 0.3), run_time=0.7)
        self.say("A thief who copies the disk gets everything")
        self.pause()

        aes_key = key_icon(YELLOW, 1.2).move_to(LEFT * 0.6 + UP * 1.6)
        aes_lbl = T("random AES-256 key", 18, YELLOW).next_to(aes_key, UP, buff=0.12)
        arrow = Arrow(doc.get_right(), RIGHT * 2.1 + UP * 0.4, buff=0.2, color=GREY_B, stroke_width=4)
        gcm = T("AES-256-GCM", 18, INK).next_to(arrow, DOWN, buff=0.1)
        rng = __import__("random").Random(3)
        hexrows = VGroup(*[M(" ".join(f"{rng.randrange(256):02x}" for _ in range(6)), 16, GREY_B) for _ in range(4)])
        hexrows.arrange(DOWN, aligned_edge=LEFT, buff=0.15)
        blob_box = RoundedRectangle(width=3.0, height=2.2, corner_radius=0.15, stroke_color=PQ, stroke_width=3,
                                    fill_color=GREY_E, fill_opacity=0.6)
        blob = VGroup(blob_box, hexrows.move_to(blob_box)).move_to(RIGHT * 4.3 + UP * 0.4)
        blob_lbl = T("bank_records.json.locked", 18, INK).next_to(blob_box, DOWN, buff=0.15)
        self.say("Step 1: a fresh AES-256 key scrambles the file")
        self.cue("soft_pop")
        self.play(FadeIn(aes_key, shift=DOWN * 0.3), FadeIn(aes_lbl), run_time=0.6)
        self.play(GrowArrow(arrow), FadeIn(gcm), aes_key.animate.move_to(arrow.get_center() + UP * 0.45),
                  aes_lbl.animate.move_to(arrow.get_center() + UP * 0.95), run_time=0.8)
        self.cue("scramble")
        self.play(TransformFromCopy(file_[:2], blob), FadeIn(blob_lbl), run_time=1.2)
        self.pause()

        env = RoundedRectangle(width=1.6, height=1.0, corner_radius=0.12, stroke_color=PQ, stroke_width=4,
                               fill_color=PQ, fill_opacity=0.15)
        flap = Polygon(env.get_corner(UL), env.get_corner(UR), env.get_center() + DOWN * 0.05,
                       stroke_color=PQ, stroke_width=3)
        envelope = VGroup(env, flap).move_to(DOWN * 1.6)
        env_lbl = T("wrapped with ML-KEM-768", 18, PQ).next_to(envelope, DOWN, buff=0.12)
        self.say("Step 2: the key itself is locked with ML-KEM-768 and stored beside the file", PQ)
        self.play(FadeIn(envelope, shift=UP * 0.3), FadeIn(env_lbl), FadeOut(aes_lbl), run_time=0.6)
        self.cue("lock_click")
        self.play(aes_key.animate.scale(0.7).move_to(env.get_center() + DOWN * 0.15), run_time=0.8)
        self.play(Indicate(envelope, color=PQ), run_time=0.6)
        self.say("Only the private key can unlock it; change one byte and unlock refuses", GOOD)
        self.pause()

    # 4 ---------------------------------------------------------------
    def downgrade(self):
        self.clear()
        self.set_title("Downgrade attack")
        client = laptop("Client").move_to(LEFT * 5.4 + UP * 0.6)
        mitm = person("Attacker in the middle").move_to(UP * 0.6)
        gw = gateway_icon(h=1.8)
        gw[1].scale(0.85)
        gw.move_to(RIGHT * 5.3 + UP * 0.6)
        self.play(FadeIn(client), FadeIn(gw), run_time=0.7)
        self.play(FadeIn(mitm, shift=DOWN * 0.3), run_time=0.6)

        def row(name, kind, color):
            return VGroup(Dot(radius=0.07, color=color), M(name, 18, WHITE), T(kind, 16, GREY_B)).arrange(RIGHT, buff=0.15)
        head = T("“I can use:”", 18, INK)
        r1 = row("X25519MLKEM768", "quantum-safe", PQ)
        r2 = row("X25519", "classical", OLD)
        rows = VGroup(r1, r2).arrange(DOWN, aligned_edge=LEFT, buff=0.12)
        body = VGroup(head, rows).arrange(DOWN, aligned_edge=LEFT, buff=0.15)
        card_bg = SurroundingRectangle(body, buff=0.18, corner_radius=0.1, stroke_color=GREY_B,
                                       fill_color=GREY_E, fill_opacity=1)
        card = VGroup(card_bg, body).scale(0.95).next_to(client, DOWN, buff=0.35).to_edge(LEFT, buff=0.4)
        self.say("The client offers the quantum-safe lock, and the old one as a fallback")
        self.cue("soft_pop")
        self.play(FadeIn(card, shift=UP * 0.2), run_time=0.8)
        self.pause()

        self.play(card.animate.next_to(mitm, DOWN, buff=0.35), run_time=1.2)
        strike = Line(r1.get_left() + LEFT * 0.05, r1.get_right() + RIGHT * 0.05, stroke_color=BAD, stroke_width=5)
        self.say("The attacker deletes the quantum-safe option", BAD)
        self.cue("marker_strike")
        self.play(Create(strike), run_time=0.6)
        self.play(FadeOut(VGroup(r1, strike)), run_time=0.5)
        self.play(r2.animate.next_to(head, DOWN, aligned_edge=LEFT, buff=0.15).align_to(head, LEFT), run_time=0.4)
        new_bg = SurroundingRectangle(VGroup(head, r2), buff=0.18, corner_radius=0.1, stroke_color=GREY_B,
                                      fill_color=GREY_E, fill_opacity=1)
        self.play(Transform(card_bg, new_bg), run_time=0.4)
        card = VGroup(card_bg, head, r2)
        self.play(card.animate.next_to(gw, DOWN, buff=0.3).to_edge(RIGHT, buff=0.4), run_time=1.2)
        self.pause()

        self.say("The AI tripwire checks this client's history", YELLOW)
        hist_dots = VGroup(*[Dot(radius=0.12, color=c) for c in (PQ, PQ, PQ, OLD)]).arrange(RIGHT, buff=0.25)
        hist_lbl = T("this client's handshakes", 16, GREY_B)
        hist = VGroup(hist_lbl, hist_dots).arrange(DOWN, buff=0.15)
        hist_bg = SurroundingRectangle(hist, buff=0.2, corner_radius=0.1, stroke_color=YELLOW)
        trip_lbl = T("AI tripwire", 18, YELLOW).next_to(hist_bg, UP, buff=0.08)
        VGroup(hist_bg, hist, trip_lbl).move_to(RIGHT * 1.6 + DOWN * 1.65)
        self.play(FadeIn(hist_bg), FadeIn(trip_lbl), FadeIn(hist_lbl), run_time=0.5)
        self.cue("data_blip")
        self.play(LaggedStart(*[GrowFromCenter(d) for d in hist_dots[:3]], lag_ratio=0.3), run_time=0.8)
        self.play(GrowFromCenter(hist_dots[3]), run_time=0.4)
        self.cue("error_glitch")
        self.play(Flash(hist_dots[3], color=BAD, flash_radius=0.3), Indicate(hist_dots[3], color=BAD), run_time=0.8)

        banner = VGroup(RoundedRectangle(width=6.2, height=0.7, corner_radius=0.12, fill_color=BAD,
                                         fill_opacity=0.9, stroke_width=0),
                        T("ATTACK DETECTED: PQC downgrade", 24, WHITE, weight=BOLD))
        banner[1].move_to(banner[0])
        banner.next_to(self.title, DOWN, buff=0.25)
        cross = Cross(card, stroke_color=BAD, stroke_width=6)
        self.say("The gateway refuses it, and the AI flags it", GOOD)
        self.cue("alarm")
        self.play(FadeIn(banner, scale=1.1), Create(cross), run_time=0.7)
        for _ in range(2):
            self.play(banner.animate.set_opacity(0.6), rate_func=there_and_back, run_time=0.6)
        self.pause()

    # 5 ---------------------------------------------------------------
    def tamper(self):
        self.clear()
        self.set_title("Tamper-proof audit log")
        entries = [
            ("10:01  branch-1  X25519MLKEM768  strong", PQ),
            ("10:02  branch-2  X25519MLKEM768  strong", PQ),
            ("10:03  branch-2  X25519           weak", OLD),
            ("10:04  branch-3  X25519MLKEM768  strong", PQ),
            ("10:05  branch-1  X25519MLKEM768  strong", PQ),
        ]
        rows = VGroup()
        for text, color in entries:
            bg = RoundedRectangle(width=6.6, height=0.5, corner_radius=0.08, stroke_color=GREY_D,
                                  fill_color=GREY_E, fill_opacity=0.6)
            mark = Dot(radius=0.07, color=color).move_to(bg.get_left() + RIGHT * 0.25)
            t = M(text, 18, WHITE).next_to(mark, RIGHT, buff=0.18)
            rows.add(VGroup(bg, t, mark))
        rows.arrange(DOWN, buff=0.22).move_to(LEFT * 2.3 + UP * 0.1)

        seals = VGroup()
        for r in rows:
            oct_ = RegularPolygon(8, radius=0.25, fill_color=PQ, fill_opacity=1, stroke_width=0)
            seals.add(VGroup(oct_, T("✓", 18, config.background_color, weight=BOLD).move_to(oct_))
                      .next_to(r, RIGHT, buff=0.7))
        links = VGroup(*[Arrow(seals[i].get_bottom(), seals[i + 1].get_top(), buff=0.04, stroke_width=4,
                               max_tip_length_to_length_ratio=0.35, color=TEAL_B) for i in range(len(seals) - 1)])
        legend = VGroup(T("each seal = ML-DSA-65 signature over", 17, INK),
                        T("this line + the seal before it", 17, INK)).arrange(DOWN, aligned_edge=LEFT, buff=0.05)
        legend.next_to(seals, RIGHT, buff=0.4)
        self.play(LaggedStart(*[FadeIn(r, shift=RIGHT * 0.3) for r in rows], lag_ratio=0.15), run_time=1.2)
        self.cue("lock_click")
        self.play(LaggedStart(*[GrowFromCenter(s) for s in seals], lag_ratio=0.15),
                  LaggedStart(*[GrowArrow(a) for a in links], lag_ratio=0.15), run_time=1.2)
        self.play(FadeIn(legend), run_time=0.5)
        self.say("Every connection is written down and sealed")
        self.pause()

        self.say("The attacker edits line 3 to hide the downgrade", BAD)
        spy = person("Attacker").scale(0.8).next_to(rows[2], LEFT, buff=0.4)
        self.play(FadeIn(spy, shift=RIGHT * 0.3), run_time=0.5)
        forged = M("10:03  branch-2  X25519MLKEM768  strong", 18, WHITE).move_to(rows[2][1], aligned_edge=LEFT)
        self.cue("typing")
        self.play(Transform(rows[2][1], forged), rows[2][2].animate.set_color(PQ),
                  rows[2][0].animate.set_stroke(YELLOW, width=3), run_time=0.9)
        self.pause()

        self.say("Verifying: each line is checked against its seal")
        scan = SurroundingRectangle(rows[0], color=YELLOW, buff=0.06, corner_radius=0.1)
        self.cue("scan")
        self.play(Create(scan), run_time=0.3)
        for i in range(3):
            if i:
                self.play(scan.animate.move_to(rows[i]), run_time=0.3)
            if i < 2:
                self.play(Indicate(seals[i], color=GOOD, scale_factor=1.15), run_time=0.35)
        broken = VGroup(seals[2][0].copy().set_fill(BAD), T("✗", 20, WHITE, weight=BOLD).move_to(seals[2]))
        self.cue("error_glitch")
        self.play(Transform(seals[2], broken), Flash(seals[2], color=BAD), run_time=0.6)
        verdict = T("TAMPERED: line 3 changed after it was sealed", 24, BAD, weight=BOLD)
        verdict.next_to(rows, DOWN, buff=0.35).align_to(rows, LEFT)
        self.play(FadeOut(scan), Write(verdict), run_time=0.8)
        self.say("Edits, deletions, insertions and reordering are all caught", GOOD)
        self.pause()

    # 6 ---------------------------------------------------------------
    def linuxone(self):
        """Real numbers from gateway/bench/benchmarks.md (500 handshakes per mode, s390x, 3 CPUs, loopback)."""
        self.clear()
        self.set_title("Running on IBM LinuxONE (s390x)")
        data = [("classical X25519", 0.702, OLD), ("hybrid X25519 + ML-KEM-768", 1.033, PQ)]
        scale_ = 6.0 / 1.2  # scene units per ms
        axis_title = T("TLS handshake time, mean of 500 (lower is better)", 20, INK)
        axis_title.move_to(UP * 1.75)
        baseline_x = -1.4
        bars, labels, values = VGroup(), VGroup(), VGroup()
        for i, (name, ms, color) in enumerate(data):
            y = 0.9 - i * 1.0
            bar = RoundedRectangle(width=ms * scale_, height=0.55, corner_radius=0.06, fill_color=color,
                                   fill_opacity=1, stroke_width=0)
            bar.move_to([baseline_x + bar.width / 2, y, 0])
            bars.add(bar)
            labels.add(T(name, 20, WHITE).next_to([baseline_x, y, 0], LEFT, buff=0.25))
            values.add(T(f"{ms:.2f} ms", 22, WHITE).next_to(bar, RIGHT, buff=0.2))
        base = Line([baseline_x, 1.35, 0], [baseline_x, -0.45, 0], stroke_color=GREY_C, stroke_width=2)
        self.play(FadeIn(axis_title), FadeIn(labels), Create(base), run_time=0.6)
        self.cue("riser")
        self.play(LaggedStart(*[GrowFromEdge(b, LEFT) for b in bars], lag_ratio=0.3), run_time=1.2)
        self.play(FadeIn(values), run_time=0.4)

        delta = T("+0.33 ms per connection to be quantum-safe", 30, WHITE).move_to(DOWN * 1.35)
        thr = T("Throughput: 2,371 → 2,224 MB/s (−6%), same AES bulk cipher", 22, INK).next_to(delta, DOWN, buff=0.2)
        src = T("Measured on the team's LinuxONE VM (3 CPUs, loopback) · gateway/bench/benchmarks.md", 16, GREY_C)
        src.to_edge(DOWN, buff=0.35)
        self.cue("soft_pop")
        self.play(Write(delta), run_time=0.8)
        self.play(FadeIn(thr), FadeIn(src), run_time=0.5)
        self.pause()

    # 7 ---------------------------------------------------------------
    def summary(self):
        self.clear()
        self.set_title("Quantum-safe, without rewriting")
        items = [
            ("Hybrid post-quantum TLS", "X25519 + ML-KEM-768", PQ),
            ("Data at rest", "AES-256-GCM, keys wrapped with ML-KEM", PQ),
            ("AI downgrade tripwire", "rule + kNN anomaly model", YELLOW),
            ("Tamper-proof logs", "ML-DSA-65 signature chain", PQ),
            ("Legacy server", "unchanged", GOOD),
        ]
        rows = VGroup()
        for name, detail, color in items:
            tick = VGroup(Circle(radius=0.17, fill_color=color, fill_opacity=1, stroke_width=0),
                          T("✓", 16, config.background_color, weight=BOLD))
            tick[1].move_to(tick[0])
            rows.add(VGroup(tick, T(name, 26, WHITE), T(detail, 20, GREY_B)).arrange(RIGHT, buff=0.3))
        rows.arrange(DOWN, aligned_edge=LEFT, buff=0.35).move_to(DOWN * 0.2)
        self.cue("success_chime")
        self.play(LaggedStart(*[FadeIn(r, shift=RIGHT * 0.3) for r in rows], lag_ratio=0.2), run_time=1.8)
        self.say("Built and benchmarked on IBM LinuxONE · IBM Z Datathon 2026")
        self.pause()

        # hand-off to the real dashboard recording (appended to pitch.html by add_footage.py)
        self.clear()
        self.set_title("Here it is running")
        sub = T("The real dashboard and detector, with simulated bank traffic", 26, INK).next_to(self.title, DOWN, buff=0.5)
        screen = laptop("", color=BLUE_B).scale(2.6).next_to(sub, DOWN, buff=0.8)
        live = VGroup(Dot(radius=0.09, color=BAD), T("LIVE", 22, WHITE, weight=BOLD)).arrange(RIGHT, buff=0.15)
        live.move_to(screen[1])
        self.play(FadeIn(sub, shift=UP * 0.2), FadeIn(screen, shift=UP * 0.3), run_time=0.8)
        self.cue("rec_beep")
        self.play(FadeIn(live, scale=0.8), run_time=0.4)
        self.play(live[0].animate.set_opacity(0.25), rate_func=there_and_back, run_time=0.8)
        self.wait(0.5)
