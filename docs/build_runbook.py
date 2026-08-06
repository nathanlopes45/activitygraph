"""Build the ActivityGraph gateway setup runbook as a printable A4 PDF.

The generated PDF is committed alongside this script, so reading the runbook
needs nothing installed. Regenerate it after editing:

    pip install -e ".[docs]"
    python docs/build_runbook.py

Keep it in step with docs/raspberry-pi-gateway.md, which is the same runbook
in a form that is reviewable in a diff.
"""
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Preformatted, Spacer,
    Table, TableStyle,
)

OUT = str(Path(__file__).resolve().parent / "ActivityGraph-Gateway-Setup.pdf")

INK = colors.HexColor("#1B242B")
MUTED = colors.HexColor("#5E6A70")
ACCENT = colors.HexColor("#1E7A5A")
WARN = colors.HexColor("#B37413")
WARN_BG = colors.HexColor("#FDF5E6")
CODE_BG = colors.HexColor("#F4F6F7")
RULE = colors.HexColor("#D8DEE2")

ss = getSampleStyleSheet()

H1 = ParagraphStyle("H1", parent=ss["Title"], fontName="Helvetica-Bold",
                    fontSize=22, leading=26, textColor=INK, alignment=TA_LEFT,
                    spaceAfter=2)
SUB = ParagraphStyle("SUB", parent=ss["Normal"], fontName="Helvetica",
                     fontSize=10.5, leading=15, textColor=MUTED, spaceAfter=14)
H2 = ParagraphStyle("H2", parent=ss["Heading1"], fontName="Helvetica-Bold",
                    fontSize=13.5, leading=17, textColor=INK,
                    spaceBefore=16, spaceAfter=6)
H3 = ParagraphStyle("H3", parent=ss["Heading2"], fontName="Helvetica-Bold",
                    fontSize=10.5, leading=14, textColor=ACCENT,
                    spaceBefore=10, spaceAfter=4)
BODY = ParagraphStyle("BODY", parent=ss["Normal"], fontName="Helvetica",
                      fontSize=9.8, leading=14.2, textColor=INK, spaceAfter=6)
BULLET = ParagraphStyle("BULLET", parent=BODY, leftIndent=12, bulletIndent=2,
                        spaceAfter=3)
CODE = ParagraphStyle("CODE", parent=ss["Code"], fontName="Courier",
                      fontSize=8.4, leading=11.4, textColor=INK,
                      backColor=CODE_BG, borderPadding=(6, 7, 6, 7),
                      leftIndent=0, spaceBefore=3, spaceAfter=8)
# For the odd command that must stay on one line to be copied correctly.
# Preformatted does not wrap, so an over-wide line is silently clipped and
# the reader loses the end of the command, which is usually the important
# part. Shrinking the type is the lesser evil against rewording it.
CODE_NARROW = ParagraphStyle("CODE_NARROW", parent=ss["Code"], fontName="Courier",
                             fontSize=7.6, leading=10.4, textColor=INK,
                             backColor=CODE_BG, borderPadding=(6, 7, 6, 7),
                             leftIndent=0, spaceBefore=3, spaceAfter=8)
CALLOUT = ParagraphStyle("CALLOUT", parent=BODY, fontSize=9.5, leading=13.5,
                         textColor=INK, spaceAfter=0)
FOOT = ParagraphStyle("FOOT", parent=ss["Normal"], fontName="Helvetica",
                      fontSize=7.5, textColor=MUTED)

story = []


def h2(t):
    story.append(Paragraph(t, H2))


def h3(t):
    story.append(Paragraph(t, H3))


def p(t):
    story.append(Paragraph(t, BODY))


def bullets(items):
    for it in items:
        story.append(Paragraph(it, BULLET, bulletText="\u2022"))
    story.append(Spacer(1, 4))


def code(t, style=CODE):
    story.append(Preformatted(t.strip("\n"), style))


def callout(title, text, colour=WARN, bg=WARN_BG):
    inner = [[Paragraph(f"<b>{title}</b><br/>{text}", CALLOUT)]]
    t = Table(inner, colWidths=[165 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("LINEBEFORE", (0, 0), (0, -1), 2.4, colour),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(t)
    story.append(Spacer(1, 9))


def table(rows, widths, header=True):
    data = [[Paragraph(f"<b>{c}</b>" if header and i == 0 else c, BODY)
             for c in row] for i, row in enumerate(rows)]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), CODE_BG),
                  ("LINEBELOW", (0, 0), (-1, 0), 0.9, INK)]
    t.setStyle(TableStyle(style))
    story.append(t)
    story.append(Spacer(1, 10))


# ---------------------------------------------------------------- cover
story.append(Paragraph("ActivityGraph Gateway Setup", H1))
story.append(Paragraph(
    "Turning a Raspberry Pi 4B into the network gateway, so every device "
    "on the network is measured rather than just the machine doing the "
    "capturing.", SUB))

p("A laptop on Wi-Fi can only ever see its own traffic. In managed mode a "
  "wireless client receives frames addressed to it plus broadcast, and "
  "nothing else, so another device's browsing is invisible no matter how "
  "long you capture. That is a property of 802.11, not a limitation of the "
  "software.")

p("A gateway is different. Every packet from every device must pass through "
  "it to reach the internet. Move the capture there and the blind spot "
  "disappears, with no change to the code.")

h3("What you are building")
code("""
   internet feed
        |
   [ Router 1 ]        modem only, Wi-Fi OFF
        |  ethernet
   [ Raspberry Pi ]    eth0 = WAN      (built-in port)
        |              eth1 = LAN      (USB adapter)  <-- CAPTURE HERE
        |  ethernet
   [ Router 2 ]        access point: DHCP off, static IP
      )  )  )  Wi-Fi
   phone / laptops / TV
""")

p("Traffic path: device, router 2, Pi, router 1, internet. Every packet "
  "crosses the Pi carrying its original source IP, which is what makes "
  "per-device and per-person reporting possible.")

callout("Read this before you start",
        "Three steps in this guide fail <i>silently</i>. They produce a "
        "dashboard that fills in normally while the data underneath is "
        "wrong. They are marked CHECKPOINT. Do not skip the verification "
        "at each one.")

h2("Before you start")

p("Beyond the two routers and the Pi, you need:")
table([
    ["Item", "Notes"],
    ["microSD card, 16 GB+", "For Raspberry Pi OS"],
    ["Pi power supply", "USB-C, 3 A"],
    ["USB Ethernet adapter", "Gives the Pi its second network interface"],
    ["USB-A to USB-C adapter",
     "Only if your Ethernet adapter is USB-C. The Pi's USB-C port is power "
     "input only and cannot host peripherals. This is the piece most often "
     "missing."],
    ["Two Ethernet cables", "Router 1 to Pi, Pi to router 2"],
], [52 * mm, 113 * mm])

p("Time required is roughly 60 to 90 minutes. Your network will be down for "
  "a few minutes during Phase 7.")

# ---------------------------------------------------------------- phase 1
h2("Phase 1: Flash and boot the Pi")

p("On your laptop, open Raspberry Pi Imager and choose "
  "<b>Raspberry Pi OS Lite (64-bit)</b>. Before writing, open the settings "
  "(gear icon) and configure:")
bullets([
    "Hostname: <font face='Courier'>activitygraph</font>",
    "Enable SSH, with a password or your public key",
    "Your username and password",
    "Your Wi-Fi details are not needed, since the Pi uses Ethernet",
])

p("Write the card, put it in the Pi, connect the Pi's <b>built-in</b> "
  "Ethernet port to a LAN port on router 1, and power it on. Wait about a "
  "minute, then from your laptop:")
code("ssh <your-user>@activitygraph.local")

p("If the hostname does not resolve, find the Pi's address in router 1's "
  "DHCP client list and use that instead.")

# ---------------------------------------------------------------- phase 2
h2("Phase 2: The USB adapter  [CHECKPOINT]")

p("Plug the Ethernet adapter into a <b>blue USB 3.0 port</b>, using the "
  "USB-A to USB-C adapter if needed. Black ports are USB 2.0 and cap "
  "throughput around 280 Mbps. Then:")
code("ip -br link")

p("You should see <font face='Courier'>eth0</font>, "
  "<font face='Courier'>eth1</font> and <font face='Courier'>lo</font>. "
  "Most Realtek and ASIX based adapters need no drivers. If "
  "<font face='Courier'>eth1</font> is missing, check "
  "<font face='Courier'>dmesg | tail</font> and confirm the port. "
  "<b>Do not continue until it appears.</b>")

h3("Pin the interface name")
p("Interface names can swap between reboots. Note the adapter's MAC from "
  "the output above, then:")
code("""
echo 'SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="AA:BB:CC:DD:EE:FF", NAME="eth1"' \\
  | sudo tee /etc/udev/rules.d/10-activitygraph-lan.rules
""")

callout("Why this matters",
        "If eth0 and eth1 swap after a reboot, you capture the WAN side "
        "instead of the LAN side. Everything downstream of NAT carries the "
        "Pi's own address, so the dashboard would attribute your entire "
        "household to a single device. Nothing errors. The numbers just "
        "quietly become meaningless.")

# ---------------------------------------------------------------- phase 3
h2("Phase 3: Get the code onto the Pi")

callout("Why copy instead of clone",
        "The Pi cannot clone a private GitHub repo without credentials, and "
        "copying from your laptop avoids setting those up on the Pi. It does "
        "bring the laptop's virtual environment along, which is useless on "
        "the Pi's architecture and has to be deleted and rebuilt: see the "
        "warning further down.",
        colour=ACCENT, bg=colors.HexColor("#EEF7F3"))

p("From your <b>laptop</b>, in PowerShell. Substitute your own project path "
  "and Pi username, and keep the quotes: the path contains a space, and "
  "without them scp reads it as two arguments.")
code(r"""
scp -r "C:\Nathan Daily\Study\Projects\ActivityGraph\activitygraph" nathan@activitygraph.local:~/
""", CODE_NARROW)

p("The destination is <font face='Courier'>~/</font> rather than "
  "<font face='Courier'>~/activitygraph</font>, which makes the result "
  "predictable. <font face='Courier'>scp -r</font> copies <i>into</i> a "
  "destination that already exists, and your home directory always exists, "
  "so the project lands at <font face='Courier'>~/activitygraph</font> every "
  "time. That directory is the project root, and every later path in this "
  "guide is relative to it. It legitimately contains a folder also named "
  "<font face='Courier'>activitygraph</font>, which is the Python package: "
  "that nested name is normal.")

callout("Run the copy once",
        "Running it a second time copies into the project root instead, "
        "leaving the real project at "
        "<font face='Courier'>~/activitygraph/activitygraph</font> and "
        "quietly breaking every path below. To re-copy, delete "
        "<font face='Courier'>~/activitygraph</font> on the Pi first. The "
        "transfer sends about 115 MB and takes a few minutes, almost all of "
        "it the .venv folder you are about to throw away; scp has no exclude "
        "option.")

p("Then on the <b>Pi</b>, install the system packages:")
code("""
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y python3-pip python3-venv tcpdump dnsmasq nftables
""")

callout("rm -rf .venv is required, not optional",
        "The copy brought your laptop's Windows virtualenv, which holds "
        "Windows executables in a <font face='Courier'>Scripts</font> folder "
        "where Linux expects <font face='Courier'>bin</font>. Left in place, "
        "every <font face='Courier'>.venv/bin/...</font> command below fails "
        "with a confusing \"No such file or directory\".")

code("""
cd ~/activitygraph
rm -rf .venv
python3 -m venv .venv
.venv/bin/pip install -e .

.venv/bin/python -m activitygraph.main --demo
""")

p("The demo run needs no root and no network traffic. If it prints the "
  "category and time tables, the software side is working. "
  "<font face='Courier'>tcpdump</font> is installed because it brings in "
  "libpcap and gives you a second tool for checking what an interface is "
  "actually receiving.")

p("If anything above could not find the project, confirm where it landed. "
  "Whatever directory holds <font face='Courier'>pyproject.toml</font> is "
  "the project root, and should be "
  "<font face='Courier'>/home/&lt;you&gt;/activitygraph</font>. If it is one "
  "level deeper, the copy ran twice: use the path it reports for the rest of "
  "this guide, including the systemd unit in Phase 10.")
code("find ~ -name pyproject.toml -not -path '*/.venv/*' 2>/dev/null")

# ---------------------------------------------------------------- phase 4
h2("Phase 4: Make the Pi a gateway")

h3("4.1  LAN address")
p("Give <font face='Courier'>eth1</font> a static address on its own subnet, "
  "kept distinct from router 1's <font face='Courier'>192.168.1.x</font> so "
  "routing is unambiguous. Leave <font face='Courier'>eth0</font> alone: it "
  "takes a DHCP lease from router 1 as normal.")

callout("Check which network manager you have first",
        "Raspberry Pi OS switched from dhcpcd to NetworkManager in Bookworm "
        "(October 2023). <font face='Courier'>/etc/dhcpcd.conf</font> is "
        "often still present on such a system: it exists, looks entirely "
        "editable, and is completely ignored. Its presence is not evidence "
        "that dhcpcd is in use.")

code("systemctl is-active NetworkManager && ls -l /etc/dhcpcd.conf")

p("<b>NetworkManager</b>, which is almost certainly your case on a fresh "
  "install:")
code("""
sudo nmcli connection add \\
  type ethernet ifname eth1 con-name ag-lan \\
  ipv4.method manual ipv4.addresses 192.168.50.1/24 \\
  ipv4.never-default yes ipv6.method disabled

sudo nmcli connection up ag-lan
""")

bullets([
    "<b>No gateway is set.</b> eth1 faces your devices, not the internet. "
    "The default route must stay on eth0.",
    "<b>ipv4.never-default yes</b> guarantees eth1 can never become the "
    "default route, which protects the capture invariant: an interface "
    "carrying the default route is by definition the WAN side.",
    "<b>ipv6.method disabled</b> keeps the LAN single-stack, so devices "
    "cannot pick up IPv6 routes that bypass NAT and therefore bypass "
    "measurement.",
])

p("ActivityGraph does capture IPv6 where it is present, so that last setting "
  "is belt and braces rather than the only defence. It still matters here: "
  "Phase 4.3 sets up forwarding and NAT for IPv4 only, so a device with a "
  "working IPv6 route would be routing around the Pi rather than through it, "
  "and traffic that never crosses the gateway cannot be measured no matter "
  "what the capture layer supports. Expect to see no IPv6 traffic on this "
  "build. That is the intended outcome, not a fault.")

p("<font face='Courier'>sudo nmtui</font> offers the same thing as an "
  "interactive menu if you prefer that to flags.")

p("<b>dhcpcd</b>, older images only, appended to "
  "<font face='Courier'>/etc/dhcpcd.conf</font>:")
code("""
interface eth1
static ip_address=192.168.50.1/24
""")

p("Verify, whichever path you took:")
code("""
ip addr show eth1     # expect inet 192.168.50.1/24
ip route              # default route MUST be on eth0, not eth1
""")

p("On the NetworkManager path, confirm the settings resolved as intended "
  "rather than assuming the command that printed \"successfully added\" did "
  "what you meant. <font face='Courier'>nmcli</font> accepts unambiguous "
  "abbreviations, so a truncated value is accepted silently:")
code("""
nmcli -g ipv4.method,ipv4.addresses,ipv4.never-default,ipv6.method \
  connection show ag-lan
""")

p("Expected, in order:")
code("""
manual
192.168.50.1/24
yes
disabled
""")

p("Correct any that differ, for example:")
code("""
sudo nmcli connection modify ag-lan ipv6.method disabled
sudo nmcli connection up ag-lan
""")

callout("NO-CARRIER here is normal",
        "At this point <font face='Courier'>eth1</font> reports "
        "<font face='Courier'>NO-CARRIER</font> and its route is marked "
        "<font face='Courier'>linkdown</font>, because nothing is plugged "
        "into it yet. That clears when you cable the access point in Phase "
        "7. The address and route are configured regardless.",
        colour=ACCENT, bg=colors.HexColor("#EEF7F3"))

h3("4.2  DHCP and DNS")
p("<font face='Courier'>dnsmasq</font> does two jobs. As a <b>DHCP server</b> "
  "it hands each device an address and tells it to use the Pi as its "
  "gateway, which is what routes traffic through the capture. As a <b>DNS "
  "forwarder</b> it resolves names on their behalf.")

p("<b>Create the config.</b> Copy and paste this entire block, including the "
  "final EOF line. It writes the file in one go, so there is no editor to "
  "learn.")
code("""
sudo tee /etc/dnsmasq.d/activitygraph.conf > /dev/null <<'EOF'
# Serve only on the LAN side, never on eth0 which faces the router.
interface=eth1
bind-interfaces

# Addresses for your devices. .1 to .49 stay free for fixed addresses
# such as the Pi (.1) and the access point (.2).
dhcp-range=192.168.50.50,192.168.50.200,12h

# Tell clients the Pi is their gateway and DNS server.
dhcp-option=option:router,192.168.50.1
dhcp-option=option:dns-server,192.168.50.1

domain=lan
log-queries
log-facility=/var/log/dnsmasq.log
EOF
""")

p("<b>Apply it, then check it actually started.</b> A config error makes "
  "dnsmasq exit rather than run with defaults, so this is worth verifying:")
code("""
sudo systemctl restart dnsmasq
systemctl is-active dnsmasq || sudo journalctl -u dnsmasq -n 20 --no-pager
""")

p("<b>Confirm it is listening on the LAN side only.</b> Use ss's own port "
  "filter rather than grepping the text, which would also match unrelated "
  "ports such as 5353 and 53412:")
code("sudo ss -lnup 'sport = :53'")

p("Expect three lines, all belonging to dnsmasq:")
table([
    ["Address", "Meaning"],
    ["192.168.50.1:53", "The LAN side. This is the one that matters"],
    ["127.0.0.1:53", "Loopback, so the Pi resolves names for itself. Normal"],
    ["[::1]:53", "The IPv6 loopback equivalent. Also normal"],
], [45 * mm, 120 * mm])

p("Two things should <b>not</b> appear. "
  "<font face='Courier'>0.0.0.0:53</font> means bind-interfaces is not "
  "taking effect and the Pi is offering DNS to every network it touches. "
  "Your eth0 address, the 192.168.1.x one, means it is serving the upstream "
  "network, where a second DHCP and DNS server causes real problems.")

p("Anything on port 5353 is <font face='Courier'>avahi-daemon</font> doing "
  "mDNS. It is unrelated to this setup and can be ignored.")

callout("If dnsmasq will not start: address already in use",
        "Another process holds port 53, usually systemd-resolved. Run "
        "<font face='Courier'>sudo systemctl disable --now "
        "systemd-resolved</font> and then "
        "<font face='Courier'>sudo systemctl restart dnsmasq</font>.")

p("Two settings are load-bearing. <font face='Courier'>bind-interfaces</font> "
  "keeps dnsmasq off eth0, so the Pi never offers DHCP upstream where a "
  "second DHCP server would cause real problems. The "
  "<font face='Courier'>option:router</font> line is what makes devices "
  "route through the Pi at all: without it they may receive the wrong "
  "gateway and bypass the capture entirely.")

h3("4.3  Forwarding and NAT")
p("Two separate things are needed, and the Pi does neither by default.")
bullets([
    "<b>Forwarding</b> lets the Pi pass packets between its two interfaces. "
    "Linux refuses by default, because a normal computer should not silently "
    "relay other machines' traffic.",
    "<b>NAT (masquerade)</b> rewrites outgoing packets to appear to come "
    "from the Pi. The upstream router knows nothing about your 192.168.50.x "
    "devices, so without this their replies have nowhere to return to.",
])

p("<b>Enable forwarding</b>, permanently across reboots:")
code("""
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-activitygraph.conf
sudo sysctl -p /etc/sysctl.d/99-activitygraph.conf

cat /proc/sys/net/ipv4/ip_forward     # expect 1
""")

p("<b>Back up any existing firewall rules</b> before overwriting them:")
code("[ -f /etc/nftables.conf ] && sudo cp /etc/nftables.conf /etc/nftables.conf.backup")

p("<b>Write the ruleset.</b> Paste the whole block including the final EOF:")
code("""
sudo tee /etc/nftables.conf > /dev/null <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  # Allow traffic to pass between eth1 (devices) and eth0 (internet).
  chain forward { type filter hook forward priority 0; policy accept; }
}

table ip nat {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    # Rewrite outgoing packets to come from the Pi's WAN address.
    oifname "eth0" masquerade
  }
}
EOF
""")

p("<b>Apply it, make it load on boot, and verify it parsed:</b>")
code("""
sudo systemctl enable --now nftables
systemctl is-active nftables || sudo journalctl -u nftables -n 20 --no-pager
sudo nft list ruleset
""")

p("The last command must show both the <font face='Courier'>forward</font> "
  "chain and the <font face='Courier'>masquerade</font> line. An empty "
  "ruleset means the file did not parse, even though "
  "<font face='Courier'>enable --now</font> reported success.")

p("The printed ruleset will not match your file character for character, and "
  "that is expected:")
table([
    ["You wrote", "nft displays"],
    ["priority 0", "priority filter"],
    ["priority 100", "priority srcnat"],
], [45 * mm, 120 * mm])

p("Those are the symbolic names for those numeric priorities. Your comments "
  "are also absent, because nftables does not retain them in the loaded "
  "ruleset. Neither indicates a problem.")

p("Nothing routes yet, because no devices are connected. You test this for "
  "real at the end of Phase 8.")

# ---------------------------------------------------------------- phase 5
h2("Phase 5: Router 2 as an access point")

callout("Configure this router in isolation",
        "Both routers ship on <font face='Courier'>192.168.1.1</font> with "
        "the same default SSID and admin password. Power router 1 OFF while "
        "you do this. With both live you get an address conflict, and a real "
        "chance of reconfiguring the wrong box without noticing.")

p("Connect your laptop to router 2 and open "
  "<font face='Courier'>http://192.168.1.1</font>.")

h3("The easy path")
p("Look for an <b>Operation Mode</b> setting offering <b>Access Point</b> "
  "alongside <b>Wireless Router</b>. Selecting Access Point does most of the "
  "following in one toggle and is far less error-prone.")

h3("The manual path")
bullets([
    "<b>DHCP server: OFF.</b> The Pi is the DHCP server now. Two DHCP "
    "servers on one segment hand out conflicting leases and cause "
    "intermittent failures that are painful to diagnose.",
    "<b>LAN IP: static 192.168.50.2</b>, subnet 255.255.255.0. This must sit "
    "outside the 192.168.50.50 to .200 DHCP range configured earlier.",
    "<b>SSID: something distinct</b>, for example Home-AG. Do not reuse the "
    "old name.",
    "<b>Wi-Fi: ON.</b> This is the radio your devices will use.",
    "Its DSL and WAN ports stay unused. You are using only its switch and "
    "radio.",
])

callout("Beware the advice you will find online",
        "Searching for how to reuse a router as an access point usually "
        "returns a double-NAT method: connect its <b>WAN</b> port and give it "
        "a different subnet. That works for extending Wi-Fi and is wrong "
        "here. It NATs every device before the traffic reaches the Pi, so the "
        "capture sees one address instead of your actual devices.")

h3("Where these settings live")
p("The DHCP toggle is frequently <b>not</b> on a page of its own. On TP-Link "
  "gateways, and many others, both settings sit on the same page, with the "
  "checkbox below the IP fields:")
code("""
Advanced > Network > LAN Settings

    IP Address      192.168.50.2
    Subnet Mask     255.255.255.0
    DHCP Server     [ ] Enable      <- checkbox, below the IP fields
""")

p("Make sure you are in the <b>Advanced</b> view rather than Basic, which "
  "usually hides LAN settings entirely. Changing both on one page is "
  "convenient: save once and the router drops off the network a single time "
  "rather than twice.")

callout("Saving disconnects you, and that is expected",
        "The admin page is no longer at the address your browser is using. "
        "Reach it again at 192.168.50.2 once the Pi is serving DHCP in Phase "
        "8, or immediately by giving your computer a temporary static address "
        "such as 192.168.50.10, mask 255.255.255.0, no gateway.",
        colour=ACCENT, bg=colors.HexColor("#EEF7F3"))

# ---------------------------------------------------------------- phase 6
h2("Phase 6: Router 1 becomes a modem")

p("Power router 1 back on, open its admin page, and <b>turn off its Wi-Fi</b>, "
  "both the 2.4 GHz and 5 GHz radios. Leave everything else alone: it keeps "
  "the DSL connection and continues handing out addresses on "
  "<font face='Courier'>192.168.1.x</font>, which is how the Pi's "
  "<font face='Courier'>eth0</font> gets its address.")

callout("The single most common failure",
        "Router 1 sits <i>above</i> the Pi. Any device that associates with "
        "its Wi-Fi reaches the internet without the Pi ever seeing it, and "
        "shows no traffic at all. If you also reused its SSID on router 2, "
        "devices may silently reattach to the wrong one.")

# ---------------------------------------------------------------- phase 7
h2("Phase 7: Cabling")

callout("Do not change how router 1 reaches the internet",
        "It is your existing working router, so whatever is plugged into it "
        "now is already correct. Leave that cable exactly as it is. The only "
        "change router 1 needs is its Wi-Fi turned off.",
        colour=ACCENT, bg=colors.HexColor("#EEF7F3"))

table([
    ["From", "To"],
    ["Your internet feed, unchanged",
     "Router 1. A thin phone cable means the <b>DSL</b> port (FTTN or FTTB). "
     "An Ethernet cable from an NBN box or fibre NTD means the <b>WAN</b> "
     "port. Never a LAN port."],
    ["Router 1, any LAN port", "Pi, built-in Ethernet (eth0)"],
    ["Pi, USB adapter (eth1)", "Router 2, any <b>LAN</b> port"],
], [55 * mm, 110 * mm])

p("Only the last two rows are new. The connectors are not interchangeable: "
  "a DSL port is RJ11, narrower with 6 pins, while WAN and LAN ports are "
  "RJ45, wider with 8 pins. An Ethernet plug will not seat properly in a DSL "
  "socket.")

callout("Use router 2's LAN port, never its WAN port",
        "Cabling into the WAN port makes router 2 route and NAT the traffic "
        "before it reaches the Pi. That destroys per-device visibility in "
        "exactly the same way capturing on eth0 would.")

# ---------------------------------------------------------------- phase 8
h2("Phase 8: Verify the plumbing  [CHECKPOINT]")

p("Connect your phone to router 2's Wi-Fi, then look at its IP address in "
  "the Wi-Fi settings.")

table([
    ["Phone shows", "Meaning"],
    ["<font face='Courier'>192.168.50.x</font>, gateway "
     "<font face='Courier'>192.168.50.1</font>",
     "Correct. Traffic is routing through the Pi."],
    ["<font face='Courier'>192.168.1.x</font>",
     "Wrong. It is talking to router 1 and bypassing the Pi. Return to "
     "Phase 6 and confirm that radio is off."],
], [58 * mm, 107 * mm])

p("On the Pi, confirm the lease was issued:")
code("cat /var/lib/misc/dnsmasq.leases")

p("Your phone should appear with its hostname. Confirm it also has working "
  "internet before continuing.")

# ---------------------------------------------------------------- phase 9
h2("Phase 9: Run ActivityGraph")

code("""
cd ~/activitygraph
sudo .venv/bin/python -m activitygraph.main \\
  --serve --serve-source live -i eth1 \\
  --host 0.0.0.0 --no-browser \\
  --capture-mode light --dhcp-leases \\
  --accounts ~/activitygraph/accounts.db \\
  --history-db ~/activitygraph/history.db
""")

table([
    ["Flag", "Why"],
    ["<font face='Courier'>-i eth1</font>",
     "The LAN side. <b>Never eth0.</b> ActivityGraph warns at startup if the "
     "interface you pass carries the default route."],
    ["<font face='Courier'>--dhcp-leases</font>",
     "Learns a name for every device in the Pi's own lease table. Works with "
     "any router, needs no credentials. Names only: a lease records an address "
     "handed out and outlives the connection by hours, so a device appears "
     "once it sends traffic, wearing the name the lease taught."],
    ["<font face='Courier'>--active-within 15</font>",
     "Limits the graph, sessions and services to the last fifteen minutes. A "
     "gateway runs for weeks, and without it the dashboard fills with "
     "everything ever seen. Devices are not removed by it: a phone that has "
     "gone home stays in the Devices panel marked offline, since it is still a "
     "device on this network. What it did earlier is in the History panel."],
    ["<font face='Courier'>--show-background</font>",
     "Puts DNS, DHCP, clock sync, update checks and ad beacons back into the "
     "headline panels. Left out by default because none of it is something a "
     "person did, and DNS appears on every device. The raw flow list under "
     "Stats for Nerds always shows everything."],
    ["<font face='Courier'>--host 0.0.0.0</font>",
     "Needed to reach the dashboard from another machine. It also publishes "
     "it to the whole LAN, which is why the flag below is on the same line."],
    ["<font face='Courier'>--accounts</font>",
     "Requires people to sign in, and shows each of them only the devices "
     "they have claimed. Without it the dashboard is unauthenticated and "
     "anyone who can reach the port can read every device's history."],
    ["<font face='Courier'>--exclude-self</font>",
     "Keeps the Pi out of the device list. It forwards everyone's traffic but "
     "is nobody's device, and otherwise appears more than once: under its LAN "
     "address, and again under its upstream address, which it answers on when "
     "you open the dashboard by that address from the LAN side. Leave it off "
     "on a laptop capturing its own traffic."],
    ["<font face='Courier'>--capture-mode light</font>",
     "Close to mandatory on a Pi. Every packet the capture filter admits is "
     "copied into Python and taken apart by scapy, which costs far more per "
     "packet than the kernel spends forwarding it. On a 110 Mbps line that is "
     "roughly 13,000 packets a second: the CPU saturates, forwarding starves, "
     "and measured throughput falls to about 15 Mbps. The same line measures "
     "about 100 Mbps in light mode, which inspects only "
     "what identifies devices, services and flow timing. Categories and time "
     "stay accurate; byte totals become an undercount."],
    ["<font face='Courier'>--history-db</font>",
     "Records activity over time, and stores hostnames learned from DNS so "
     "the service breakdown survives a reboot. A durable record of what "
     "every device did: treat it as private."],
], [40 * mm, 125 * mm])

p("Open <font face='Courier'>http://192.168.50.1:8420</font> from any device "
  "on the network. Browse something distinctive on your phone, wait roughly "
  "10 seconds for flows to close and classify, then check <b>Where Your Time "
  "Went</b> and <b>Time by Person</b>.")

h3("9.1  Create the admin account first")
callout("Whoever registers first becomes the admin",
        "The first account created can see every device on the network, and "
        "there is no other gate on it. Register yours immediately, before "
        "anyone else opens the dashboard.")

p("Everyone else then registers their own account and starts out seeing "
  "nothing at all. They add a device by opening the dashboard <b>on that "
  "device</b> and pressing <b>Claim this device</b> in the My Devices panel.")

p("Claiming is checked against the connection's own source address, so a "
  "phone can only be added from the phone. That is what makes the dashboard "
  "safe to hand out: nobody can attach a device they are not holding, and "
  "nobody needs to be told anyone else's MAC address. A device belongs to "
  "one person at a time, so shared items such as a TV are usually left "
  "unclaimed, which leaves them visible to the admin only.")

p("The admin cannot claim anything, deliberately. It already sees every "
  "device, so a claim would add nothing to its view, and because a device "
  "belongs to one group at a time it would take that device away from the "
  "person it belongs to, who would then have no way to claim it. Seeing "
  "everything and owning nothing is the whole role. Use a personal account "
  "as well if you want your own devices grouped.")

p("The command above gives the account database an explicit path so that the "
  "service in Phase 10 uses the same one. Left bare, "
  "<font face='Courier'>--accounts</font> defaults to <font face='Courier'>"
  "~/.activitygraph/</font>, which resolves to root's home under "
  "<font face='Courier'>sudo</font>, and you would find yourself registering "
  "all over again once the service took over. The session key sits beside "
  "the database; deleting it signs everyone out. If you forget the admin "
  "password, delete both files and register again: that discards accounts "
  "and claims, but not captured history.")

# ---------------------------------------------------------------- phase 10
h2("Phase 10: Grouping and permanence")

h3("10.1  Grouping devices without accounts")
p("With <font face='Courier'>--accounts</font> on, people build their own "
  "groups by claiming devices and this step is unnecessary. The file-based "
  "alternative still exists for a gateway you administer alone, or if you "
  "would rather assign devices centrally than ask anyone to sign in.")

p("Take the MAC addresses from the Devices panel and create "
  "<font face='Courier'>~/groups.json</font>:")
code("""
{
  "Nathan": ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"],
  "Guest":  ["AA:BB:CC:00:00:03"]
}
""")
p("Add <font face='Courier'>--device-groups ~/groups.json</font> to the "
  "command. Devices you do not list appear under Ungrouped, which is where "
  "shared items such as a TV naturally belong. The two mechanisms can run "
  "together: groups label the Time by Person panel, accounts decide who is "
  "allowed to see what.")

h3("10.2  Run it on boot")
p("Set a variable to your project root first, so the paths are filled in for "
  "you rather than edited by hand:")
code("""
AG=$(dirname "$(find ~ -name pyproject.toml -not -path '*/.venv/*' | head -1)")
echo "$AG"        # sanity check: this is your project root
""")

p("Then paste the whole block, including the final EOF:")
code("""
sudo tee /etc/systemd/system/activitygraph.service > /dev/null <<EOF
[Unit]
Description=ActivityGraph
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$AG
ExecStart=$AG/.venv/bin/python -m activitygraph.main --serve --serve-source live -i eth1 --host 0.0.0.0 --no-browser --capture-mode light --exclude-self --active-within 15 --accounts $AG/accounts.db --dhcp-leases --history-db $AG/history.db
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
""")

p("Two deliberate choices there. The heredoc is unquoted so $AG is replaced "
  "with your real path as the file is written. And ExecStart is one long "
  "line rather than using backslash continuations, because a backslash "
  "inside an unquoted heredoc is consumed by the shell before systemd ever "
  "sees it, producing a mangled command.")

p("<b>Check the result, then enable it:</b>")
code("""
cat /etc/systemd/system/activitygraph.service

sudo systemctl enable --now activitygraph
systemctl is-active activitygraph || journalctl -u activitygraph -n 30
""")

callout("Systemd does not expand the ~ shortcut",
        "Every path in the unit must be absolute. Confirm the file you just "
        "printed contains no $AG and no ~ characters. Note also that "
        "<font face='Courier'>pi</font> is no longer the default username on "
        "current Raspberry Pi OS images.")

# ---------------------------------------------------------------- trouble
h2("Troubleshooting")

table([
    ["Symptom", "Most likely cause"],
    ["Phone gets a 192.168.1.x address",
     "It associated with router 1's Wi-Fi. Turn that radio off."],
    ["Phone absent from dnsmasq.leases",
     "Router 2's DHCP server is still on, or it is cabled by its WAN port "
     "instead of a LAN port."],
    ["Leases fine, but no traffic recorded",
     "Capturing the wrong interface. It must be eth1."],
    ["Everything attributed to one IP address",
     "Capturing eth0 post-NAT, or eth0 and eth1 swapped after a reboot. "
     "Check the udev rule from Phase 2."],
    ["Traffic appears but has no categories",
     "Flows classify when they close. Allow about --idle-timeout seconds."],
    ["Dashboard unreachable",
     "Confirm --host 0.0.0.0 and that you are browsing to 192.168.50.1, not "
     "the old 192.168.1.x address."],
    ["No internet anywhere",
     "Check IP forwarding and the nftables masquerade rule from Phase 4.3."],
    ["Signed in, but every panel is empty",
     "A non-admin account sees only the devices it has claimed. Open the "
     "dashboard on the device itself and claim it."],
    ["A lot of traffic filed as plain HTTPS",
     "Services are identified from DNS, which the Pi only sees once devices "
     "start querying it. It fills in over the first few minutes, and "
     "--history-db carries it across reboots."],
    ["Everyone logged out after a reboot",
     "The session key moved. It lives beside the path given to --accounts, "
     "so keep that path the same between the manual run and the service."],
    ["A phone shows as a bare model name",
     "iOS sends a generic \"iPhone\" as its DHCP hostname, so the name its "
     "owner chose comes from Bonjour instead. That needs mDNS (UDP 5353) "
     "reaching the Pi, which --capture-mode light allows. Check Settings &gt; "
     "General &gt; About &gt; Name, or override it with --device-aliases."],
    ["Time in categories looks too low",
     "Flows are kept alive by a sampled fraction of packets in light mode. "
     "If durations still look short, raise --idle-timeout."],
    ["No IPv6 traffic at all",
     "Expected. The LAN is single-stack by design. See Phase 4.1."],
], [58 * mm, 107 * mm])

h3("Wi-Fi appears, but devices get no internet")

p("The most common failure after the rebuild, and the one that looks worst "
  "while being the smallest fault. Establish which half is broken before "
  "changing anything, because the Pi is usually innocent.")

p("Check the Pi first:")
code("""
ip -br addr
ip route
ping -c 3 1.1.1.1
ping -c 3 google.com
""")

p("You want eth0 holding an address from router 1, eth1 on 192.168.50.1/24, "
  "a default route out of eth0, and both pings succeeding. If all of that "
  "holds, the Pi is fine and nothing on it needs touching: the fault is "
  "between the Pi and your devices. Then check whether anything ever asked "
  "it for an address:")
code("""
cat /var/lib/misc/dnsmasq.leases

ping -c 2 192.168.50.2

sudo tcpdump -i eth1 -n port 67 or port 68
""")

callout("An empty lease file with a healthy Pi means one thing",
        "DHCP requests are not reaching the Pi at all. If 192.168.50.2 also "
        "does not answer, the access point is not on the Pi's LAN, and the "
        "cause is almost always that the cable from the Pi is in its "
        "WAN/Internet port rather than a numbered LAN port. In the WAN port "
        "it routes instead of bridging, so its Wi-Fi becomes a separate "
        "network and DHCP never crosses. With its own DHCP server switched "
        "off by then, clients associate and get no address at all, which "
        "presents as \"connected, no internet\". Run the tcpdump while "
        "connecting a phone: no output confirms it. Also rule out the access "
        "point's own DHCP still being enabled, and its Wi-Fi being a guest "
        "network, which isolates clients from the wired LAN just as "
        "effectively.")

h2("Things to know")

bullets([
    "<b>The Pi becomes a single point of failure.</b> If it is off, the "
    "network is down. Restart=always covers crashes, not power loss or SD "
    "card corruption.",
    "<b>Packet inspection costs more than forwarding.</b> Measured on a Pi "
    "4B on a 110 Mbps line: --capture-mode full gives about 15 Mbps, and "
    "--capture-mode light about 100 Mbps. Python cannot dissect 13,000 "
    "packets a second, and the pegged CPU starves the kernel forwarding "
    "path. Light mode avoids this by not looking at payload, at the cost "
    "of exact byte totals. Time in categories is unaffected.",
    "<b>Device-to-device traffic may bypass the Pi.</b> A phone casting to a "
    "TV, where both sit on router 2, is switched locally and never reaches "
    "the gateway. Only traffic crossing the Pi is visible.",
    "<b>You will lose SSH access briefly</b> during Phase 7, because your "
    "laptop is still on the old network. Move it to router 2's Wi-Fi and "
    "reach the Pi at 192.168.50.1.",
    "<b>The admin account sees everyone's activity.</b> Accounts stop "
    "household members reading each other's browsing; they hide nothing "
    "from whoever holds the admin login, or from anyone with shell access "
    "to the Pi. If you are setting this up for other people, tell them that "
    "rather than letting them assume otherwise.",
])

h3("Rollback")
p("Nothing here is permanent. Turn router 1's Wi-Fi back on, reconnect your "
  "devices to it, and power the Pi off. Neither router was changed in a way "
  "that cannot be undone from its admin page.")


# ---------------------------------------------------------------- build
def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.4)
    canvas.line(22 * mm, 15 * mm, 188 * mm, 15 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(22 * mm, 10 * mm, "ActivityGraph gateway setup")
    canvas.drawRightString(188 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


doc = BaseDocTemplate(OUT, pagesize=A4,
                      leftMargin=22 * mm, rightMargin=22 * mm,
                      topMargin=20 * mm, bottomMargin=22 * mm,
                      title="ActivityGraph Gateway Setup",
                      author="nathanlopes45")
frame = Frame(doc.leftMargin, doc.bottomMargin,
              doc.width, doc.height, id="body")
doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=footer)])
doc.build(story)
print("written:", OUT)
