"""Generate the placeholder images the README embeds.

The README references two images. Committing nothing left GitHub rendering
two broken links, which is the first thing anyone sees, so a real image is
committed for each and is meant to be replaced rather than kept.

Run with `pip install -e ".[docs]"` available:

    python docs/images/make_placeholders.py
"""
from pathlib import Path

from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent

# The dashboard's own palette, so the placeholders do not look foreign next
# to the screenshots that will replace them.
BACKGROUND = (16, 22, 27)
PANEL = (27, 36, 43)
BORDER = (42, 52, 60)
TEXT = (143, 160, 168)
ACCENT = (127, 231, 196)

PLACEHOLDERS = [
    ("dashboard.png", "Dashboard screenshot", "docs/images/dashboard.png"),
    ("gateway.png", "Gateway photo or diagram", "docs/images/gateway.png"),
]


def draw(name: str, title: str, path_hint: str, size=(1200, 630)) -> None:
    image = Image.new("RGB", size, BACKGROUND)
    canvas = ImageDraw.Draw(image)

    margin = 40
    canvas.rounded_rectangle(
        [margin, margin, size[0] - margin, size[1] - margin],
        radius=14, fill=PANEL, outline=BORDER, width=2)

    centre_x, centre_y = size[0] // 2, size[1] // 2
    canvas.text((centre_x, centre_y - 34), title,
                fill=ACCENT, anchor="mm", font_size=34)
    canvas.text((centre_x, centre_y + 14), "Replace this file:",
                fill=TEXT, anchor="mm", font_size=19)
    canvas.text((centre_x, centre_y + 44), path_hint,
                fill=TEXT, anchor="mm", font_size=19)

    image.save(HERE / name, optimize=True)
    print(f"wrote {name}")


if __name__ == "__main__":
    for name, title, hint in PLACEHOLDERS:
        draw(name, title, hint)
