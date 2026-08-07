"""Generate the gateway topology diagram the README embeds.

The point of the picture is positional, not decorative. A Wi-Fi client
cannot see other devices' traffic, so the only way to measure a household
is to sit in the path of it. Three labels carry that: DHCP off on the
access point, which is what stops traffic routing around the Pi, and the
two interface names, which say which side is which.

Rendered at 2x and downsampled, because Pillow has no antialiasing on
shapes and a straight 1x draw has visibly ragged corners.

    python docs/images/make_gateway_diagram.py
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent / "gateway.png"

SCALE = 2
WIDTH, HEIGHT = 1180 * SCALE, 396 * SCALE

# The runbook PDF's palette, so the project reads as one piece.
INK = "#1B242B"
MUTED = "#5E6A70"
ACCENT = "#1E7A5A"
RULE = "#D8DEE2"
PANEL = "#F4F6F7"
PAPER = "#FFFFFF"
HIGHLIGHT = "#E8F3EE"

FONTS = ["C:/Windows/Fonts/arial.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]
BOLD = ["C:/Windows/Fonts/arialbd.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"]


def font(candidates, size):
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size * SCALE)
    return ImageFont.load_default()


TITLE = font(BOLD, 15)
LABEL = font(BOLD, 12)
SUB = font(FONTS, 10)
NOTE = font(FONTS, 9.5)
TAG = font(BOLD, 9)

image = Image.new("RGB", (WIDTH, HEIGHT), PAPER)
draw = ImageDraw.Draw(image)


def centred(text, box, y, chosen, fill):
    left, right = box
    width = draw.textlength(text, font=chosen)
    draw.text(((left + right) / 2 - width / 2, y * SCALE), text, font=chosen, fill=fill)


def node(x, y, w, h, title, subtitle, *, emphasis=False, note=None):
    """One box in the chain. The Pi is the only emphasised one."""
    box = (x * SCALE, y * SCALE, (x + w) * SCALE, (y + h) * SCALE)
    draw.rounded_rectangle(
        box, radius=7 * SCALE,
        fill=HIGHLIGHT if emphasis else PANEL,
        outline=ACCENT if emphasis else RULE,
        width=(2 if emphasis else 1) * SCALE,
    )
    span = (box[0], box[2])
    centred(title, span, y + (h / 2 - 15 if subtitle else h / 2 - 7), LABEL, INK)
    if subtitle:
        for index, line in enumerate(subtitle.split("\n")):
            centred(line, span, y + h / 2 + 1 + index * 13, SUB, MUTED)
    if note:
        centred(note, span, y + h + 9, NOTE, ACCENT)
    return box


def arrow(x1, x2, y):
    """A connector, drawn as a line with a solid head."""
    y = y * SCALE
    draw.line((x1 * SCALE, y, (x2 - 7) * SCALE, y), fill=MUTED, width=2 * SCALE)
    tip = x2 * SCALE
    draw.polygon(
        [(tip, y), (tip - 8 * SCALE, y - 4 * SCALE), (tip - 8 * SCALE, y + 4 * SCALE)],
        fill=MUTED,
    )


# ---- title -------------------------------------------------------------
draw.text((44 * SCALE, 30 * SCALE),
          "Every packet the household sends crosses the Pi",
          font=TITLE, fill=INK)
draw.text((44 * SCALE, 54 * SCALE),
          "A Wi-Fi client cannot see other devices' traffic, so measuring a "
          "network means sitting in the path of it.",
          font=NOTE, fill=MUTED)

# ---- the chain ---------------------------------------------------------
TOP, BOX_H = 104, 92
WIDE, NARROW = 196, 168
# 168*2 + 196*3 + 42*4 spans exactly the width between the margins, so the
# chain lines up with the rule and the text below it.
GAP = 42
LEFT = 44

x = LEFT
devices = node(x, TOP, NARROW, BOX_H, "Your devices",
               "phones, laptops\nTV, console")
x += NARROW + GAP
arrow(devices[2] / SCALE + 6, x - 6, TOP + BOX_H / 2)

ap = node(x, TOP, WIDE, BOX_H, "Archer VR1600v", "access point",
          note="DHCP off")
x += WIDE + GAP
arrow(ap[2] / SCALE + 6, x - 6, TOP + BOX_H / 2)

pi = node(x, TOP, WIDE, BOX_H, "Raspberry Pi 4B", "gateway: NAT + capture",
          emphasis=True)
# Interface names sit on the box edges they describe, which is the whole
# point of naming them: eth1 is the side you capture, eth0 is the side you
# must not.
draw.text((pi[0] + 12 * SCALE, pi[1] + 8 * SCALE), "eth1", font=TAG, fill=ACCENT)
right = draw.textlength("eth0", font=TAG)
draw.text((pi[2] - 12 * SCALE - right, pi[1] + 8 * SCALE), "eth0", font=TAG, fill=ACCENT)
x += WIDE + GAP
arrow(pi[2] / SCALE + 6, x - 6, TOP + BOX_H / 2)

modem = node(x, TOP, WIDE, BOX_H, "Archer VR1600v", "modem")
x += WIDE + GAP
arrow(modem[2] / SCALE + 6, x - 6, TOP + BOX_H / 2)

node(x, TOP, NARROW, BOX_H, "Internet", None)

# ---- what the two labels mean -----------------------------------------
draw.line((LEFT * SCALE, 236 * SCALE, (WIDTH / SCALE - LEFT) * SCALE, 236 * SCALE),
          fill=RULE, width=1 * SCALE)

FOOT = [
    ("DHCP off on the access point",
     "makes the Pi the only DHCP server and the only default gateway, so no "
     "device can route around it."),
    ("eth1 is the LAN side",
     "and the one to capture on. Capturing eth0 would see the household as a "
     "single NAT'd address."),
    ("Nothing leaves the machine",
     "Only metadata already visible in transit is read: DNS names, the TLS "
     "SNI hostname, flow timing."),
]
for index, (heading, body) in enumerate(FOOT):
    top = 258 + index * 40
    draw.text((LEFT * SCALE, top * SCALE), heading, font=LABEL, fill=INK)
    draw.text((LEFT * SCALE, (top + 17) * SCALE), body, font=NOTE, fill=MUTED)

image.resize((WIDTH // SCALE, HEIGHT // SCALE), Image.LANCZOS).save(OUT)
print(f"wrote {OUT} ({OUT.stat().st_size / 1024:.0f} KB)")
