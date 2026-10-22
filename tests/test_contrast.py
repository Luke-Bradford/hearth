"""Step 3, part 4: every colour is a token, and both themes meet WCAG contrast.

Text (body, muted, and the status words in tags) needs 4.5:1 on the backgrounds it sits on
(WCAG 1.4.3). Graphics that carry meaning - status shapes, the timeline's slots, "no data",
chart lines, the accent used for focus and selection - need 3:1 (WCAG 1.4.11)."""
import json
import pathlib
import re
import subprocess
import unittest

from tests.helpers import needs_node

PAGE = (pathlib.Path(__file__).resolve().parent.parent / "dashboard.html").read_text(encoding="utf-8")

TEXT = ("text", "muted", "good", "warn", "bad")
GRAPHICS = ("good", "warn", "bad", "none", "accent", "s1", "s2", "s3", "s4", "s5", "s6", "s-other")
BACKGROUNDS = ("bg", "panel")
SERIES = ("s1", "s2", "s3", "s4", "s5", "s6", "s-other")


def tokens(selector):
    block = re.search(re.escape(selector) + r"\{([^}]*)\}", PAGE)
    assert block, f"no {selector} block"
    return dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})\b", block.group(1)))


def luminance(hex_colour):
    def channel(c):
        c = int(c, 16) / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (channel(hex_colour[i:i + 2]) for i in (1, 3, 5))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(a, b):
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


THEMES = {"dark": tokens(":root"), "light": {**tokens(":root"), **tokens(':root[data-theme="light"]')}}


class ContrastTest(unittest.TestCase):
    def test_both_themes_define_every_colour(self):
        light = tokens(':root[data-theme="light"]')
        for name in set(TEXT + GRAPHICS + BACKGROUNDS + ("line", "inset")):
            self.assertIn(name, THEMES["dark"], name)
            self.assertIn(name, light, f"light theme misses --{name}")

    def test_text_is_at_least_4_5_to_1(self):
        for theme, t in THEMES.items():
            for fg in TEXT:
                for bg in BACKGROUNDS:
                    with self.subTest(theme=theme, fg=fg, bg=bg):
                        self.assertGreaterEqual(ratio(t[fg], t[bg]), 4.5)

    def test_meaningful_graphics_are_at_least_3_to_1(self):
        for theme, t in THEMES.items():
            for fg in GRAPHICS:
                for bg in BACKGROUNDS:
                    with self.subTest(theme=theme, fg=fg, bg=bg):
                        self.assertGreaterEqual(ratio(t[fg], t[bg]), 3.0)

    def test_the_series_palette_uses_no_status_colour(self):
        # a chart line never looks like "good", "fair" or "poor"
        for theme, t in THEMES.items():
            status = {t[k].lower() for k in ("good", "warn", "bad")}
            for s in SERIES:
                with self.subTest(theme=theme, series=s):
                    self.assertNotIn(t[s].lower(), status)
                    hue = _hue(t[s])
                    if hue is not None:   # greys have no hue
                        self.assertFalse(70 <= hue <= 160, f"{s} {t[s]} is green ({hue:.0f}°)")
                        self.assertFalse(35 <= hue < 60, f"{s} {t[s]} is amber ({hue:.0f}°)")
                        self.assertFalse(hue < 15 or hue > 350, f"{s} {t[s]} is red ({hue:.0f}°)")

    def test_no_colour_is_hard_coded_outside_the_tokens(self):
        # the tokens are the single source: the stylesheet past them and the script use variables
        style = PAGE[PAGE.index("<style>"):PAGE.index("</style>")]
        after_tokens = style[style.index("}", style.index(':root[data-theme="light"]')) + 1:]
        self.assertEqual(re.findall(r"#[0-9a-fA-F]{3,8}\b", after_tokens), [])
        script = (pathlib.Path(__file__).resolve().parent.parent / "dashboard.js").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"[\"'`]#[0-9a-fA-F]{3,8}[\"'`]", script), [])


@needs_node
class ThemeChoiceTest(unittest.TestCase):
    """The script in <head> picks the theme before the first paint."""

    def theme(self, stored, system_light, blocked=False):
        js = re.search(r"<script>(\{let t=null.*?)</script>", PAGE, re.S).group(1)
        get = "throw new Error('blocked')" if blocked else f"return {json.dumps(stored)}"
        stub = (f"const localStorage={{getItem(){{{get}}}}};const matchMedia=()=>({{matches:{json.dumps(system_light)}}});"
                "const document={documentElement:{dataset:{}}};")
        return subprocess.run(["node", "-e", stub + js + ";console.log(document.documentElement.dataset.theme)"],
                              capture_output=True, text=True, timeout=30, check=True).stdout.strip()

    def test_a_choice_wins_otherwise_the_system(self):
        self.assertEqual(self.theme("dark", True), "dark")
        self.assertEqual(self.theme("light", False), "light")
        self.assertEqual(self.theme(None, True), "light")
        self.assertEqual(self.theme("purple", False), "dark")       # anything else is ignored

    def test_blocked_storage_still_follows_the_system(self):
        # #85 review: a storage error must not skip the system preference
        self.assertEqual(self.theme(None, True, blocked=True), "light")


def _hue(hex_colour):
    r, g, b = (int(hex_colour[i:i + 2], 16) / 255 for i in (1, 3, 5))
    mx, mn = max(r, g, b), min(r, g, b)
    if mx - mn < 0.08:
        return None
    d = mx - mn
    h = ((g - b) / d) % 6 if mx == r else (b - r) / d + 2 if mx == g else (r - g) / d + 4
    return h * 60


if __name__ == "__main__":
    unittest.main()
