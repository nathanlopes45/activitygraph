# Running ActivityGraph on a Raspberry Pi gateway

This is the setup that delivers the full vision: **every device on the
network**, with real flows, TLS SNI, byte counts and per-person category
time, not just the machine doing the capturing.

It works because of something a Wi-Fi client fundamentally cannot do. A
laptop on Wi-Fi in managed mode only receives frames addressed to it, so it
can never see your phone's traffic no matter how long it captures. A gateway
is different: every packet from every device has to pass *through* it to
reach the internet. Put the capture there and the blindness disappears.

Your existing code runs unchanged. It is `scapy`-based and portable, and the
one Windows-specific helper (`collector.list_interfaces`) already falls back
cleanly on Linux.

---

## The one thing you must get right

> **Capture on the LAN interface, never the WAN interface.**

The Pi performs NAT. By the time packets leave the WAN side, every one of
them carries the *Pi's* source IP. Capturing there would attribute the whole
household's browsing to a single device and silently destroy the per-device
data this setup exists to provide. It would not look broken: the dashboard
would fill in normally, with everything wrong.

Capture on the LAN side (`eth1` below), where each packet still carries the
real source IP of the phone, laptop or TV that sent it.

ActivityGraph checks this itself and warns at startup if the interface you
pass carries the default route.

---

## Hardware

- Raspberry Pi 4B (any RAM size, 2 GB is plenty)
- SD card, 16 GB or larger
- **USB 3.0 gigabit Ethernet adapter**, giving the Pi a second wired
  interface. If it is a USB-C dongle you also need a **USB-A male to USB-C
  female adapter**, because the Pi's USB-C port is power input only and
  cannot host peripherals. Plug it into a blue USB 3.0 port, not a black
  USB 2.0 one.
- **Your existing modem/router**, which keeps the internet connection
- **A second router or access point** to serve Wi-Fi on the LAN side. An old
  router works: you will run it as a dumb access point.
- Two Ethernet cables

At around 100 Mbps, a Pi 4B running scapy has comfortable headroom.

You can substitute the Pi's onboard Wi-Fi for the access point and skip the
USB adapter, but the Pi's radio is weaker than a dedicated AP for range and
concurrent clients. See [Variants](#variants).

## Topology

The Pi becomes the gateway for everything. The upstream router is demoted to
"the thing that talks to the internet", and the second router becomes a plain
access point downstream of the Pi. No bridge mode is required, which keeps
this entirely reversible.

```
        Internet
           |
   +-------+--------+
   | modem/router   |   Wi-Fi DISABLED   <-- critical, see below
   | (upstream)     |
   +-------+--------+
           | ethernet
   +-------+-----------------+
   | Raspberry Pi 4B         |
   |   eth0 = WAN            |   faces the upstream router
   |   eth1 = LAN (USB)      |   <-- ActivityGraph captures HERE
   +-------+-----------------+
           | ethernet (LAN port to LAN port)
   +-------+--------+
   | access point   |   DHCP OFF, static IP, no routing
   | (old router)   |
   +-------+--------+
        )  )  )  Wi-Fi
   phone, laptops, TV
```

Traffic path: device, access point, Pi, upstream router, internet. Every
packet crosses the Pi with its original source IP intact.

**Turn off the upstream router's Wi-Fi.** It sits above the Pi, so any device
that associates with it reaches the internet without the Pi ever seeing it.
This is the most common cause of an apparently non-functioning setup.

---

## Setup

### 1. OS

Flash **Raspberry Pi OS Lite (64-bit)**. Enable SSH in Imager's advanced
options so you can work headless.

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y python3-pip python3-venv git tcpdump dnsmasq nftables
```

`tcpdump` pulls in `libpcap`. On Linux scapy can also use native `AF_PACKET`
sockets, so libpcap is not strictly required, but having `tcpdump` gives you
a second tool for checking what an interface is actually receiving.

No `hostapd` is needed. The access point is a separate physical device.

### 2. Confirm the USB adapter

Plug it in and check that a second interface appeared:

```bash
ip -br link
```

You should see `eth0`, `eth1` and `lo`. Most Realtek and ASIX based adapters
need no drivers. If `eth1` is missing, check `dmesg | tail` and confirm the
adapter is in a blue USB 3.0 port.

Interface names can swap between boots. Pin them by MAC so `eth1` is always
the USB adapter:

```bash
# replace with the adapter's MAC from `ip -br link`
echo 'SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="aa:bb:cc:dd:ee:ff", NAME="eth1"' \
  | sudo tee /etc/udev/rules.d/10-activitygraph-lan.rules
```

Getting this wrong swaps WAN and LAN after a reboot, which silently produces
the post-NAT capture described above.

### 3. ActivityGraph

```bash
git clone <your-repo> activitygraph && cd activitygraph
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python -m activitygraph.main --demo    # smoke test, no root needed
```

If you copied the project across with `scp -r` instead of cloning, check
where it actually landed before continuing. `scp -r src dest` copies *into*
`dest` when that directory already exists, which nests the project one level
deeper than intended:

```bash
find ~ -name pyproject.toml -not -path '*/.venv/*' 2>/dev/null
```

Whatever directory holds `pyproject.toml` is the project root. Every path in
the rest of this guide is relative to it, including the systemd unit in
step 9. Note that the root legitimately *contains* a folder named
`activitygraph` (the Python package), so seeing that nested name is normal
and not itself a sign of a bad copy.

An scp'd copy also brings the source machine's `.venv`, which is useless on
the Pi's architecture. Delete it before creating a new one:

```bash
rm -rf .venv
```

### 4. LAN interface

Give `eth1` a static address on its own subnet, distinct from the upstream
router's `192.168.1.x` so routing stays unambiguous. Leave `eth0` alone: it
takes a DHCP lease from the upstream router as normal.

Raspberry Pi OS switched from `dhcpcd` to NetworkManager in Bookworm
(October 2023). Check which system you have:

```bash
systemctl is-active NetworkManager && ls -l /etc/dhcpcd.conf
```

If that reports `active`, use the NetworkManager path below. Note that
`/etc/dhcpcd.conf` is often still present on such a system: it exists, looks
entirely editable, and is completely ignored. Its presence is not evidence
that dhcpcd is in use.

**NetworkManager (current images):**

```bash
sudo nmcli connection add \
  type ethernet ifname eth1 con-name ag-lan \
  ipv4.method manual ipv4.addresses 192.168.50.1/24 \
  ipv4.never-default yes ipv6.method disabled

sudo nmcli connection up ag-lan
```

No gateway is set, because `eth1` faces your devices rather than the
internet. `ipv4.never-default yes` guarantees `eth1` can never become the
default route, which protects the capture invariant: an interface carrying
the default route is by definition the WAN side. `ipv6.method disabled`
keeps the LAN single-stack, so devices cannot pick up IPv6 routes that
bypass NAT and therefore bypass measurement.

`sudo nmtui` offers the same thing as an interactive menu.

**dhcpcd (older images only).** Copy and paste this whole block, including
the final `EOF` line. It appends to the file rather than replacing it:

```bash
sudo tee -a /etc/dhcpcd.conf > /dev/null <<'EOF'

interface eth1
static ip_address=192.168.50.1/24
EOF

sudo systemctl restart dhcpcd
```

Verify, whichever path you took:

```bash
ip addr show eth1     # expect inet 192.168.50.1/24
ip route              # default route MUST be on eth0, not eth1
```

On the NetworkManager path, confirm the settings resolved as intended rather
than assuming the command that printed "successfully added" did what you
meant. `nmcli` accepts unambiguous abbreviations, so a truncated value is
accepted silently:

```bash
nmcli -g ipv4.method,ipv4.addresses,ipv4.never-default,ipv6.method \
  connection show ag-lan
```

Expected, in order:

```
manual
192.168.50.1/24
yes
disabled
```

Correct any that differ, for example:

```bash
sudo nmcli connection modify ag-lan ipv6.method disabled
sudo nmcli connection up ag-lan
```

At this point `eth1` will report `NO-CARRIER` and its route will be marked
`linkdown`, because nothing is plugged into it yet. That is expected and
clears when you cable the access point in step 7. The address and the route
are configured regardless.

### 5. DHCP and DNS

`dnsmasq` does two jobs here. As a **DHCP server** it hands each device an
address on the Pi's subnet and tells it to use the Pi as its gateway, which
is what routes traffic through the capture. As a **DNS forwarder** it
resolves names on their behalf.

**Create the config.** Copy and paste this entire block, including the final
`EOF` line. It writes the file in one go, so there is no editor to learn:

```bash
sudo tee /etc/dnsmasq.d/activitygraph.conf > /dev/null <<'EOF'
# Serve only on the LAN side. Never on eth0, which faces the upstream router.
interface=eth1
bind-interfaces

# Addresses handed to your devices. Leave .1 to .49 free for fixed addresses
# such as the Pi itself (.1) and the access point (.2).
dhcp-range=192.168.50.50,192.168.50.200,12h

# Tell clients the Pi is their gateway and DNS server.
dhcp-option=option:router,192.168.50.1
dhcp-option=option:dns-server,192.168.50.1

domain=lan
log-queries
log-facility=/var/log/dnsmasq.log
EOF
```

**Apply it:**

```bash
sudo systemctl restart dnsmasq
```

**Verify it started.** This is worth checking rather than assuming, because
a config error makes dnsmasq exit rather than run with defaults:

```bash
systemctl is-active dnsmasq || sudo journalctl -u dnsmasq -n 20 --no-pager
```

`active` means good. Anything else prints the reason.

**Confirm it is listening on the right interface only.** Use `ss`'s own port
filter rather than grepping the text, which would also match unrelated ports
such as 5353 and 53412:

```bash
sudo ss -lnup 'sport = :53'
```

Expect three lines, all belonging to `dnsmasq`:

| Address | Meaning |
|---|---|
| `192.168.50.1:53` | The LAN side. This is the one that matters |
| `127.0.0.1:53` | Loopback, so the Pi resolves names for itself. Normal |
| `[::1]:53` | The IPv6 loopback equivalent. Also normal |

Two things should **not** appear. `0.0.0.0:53` means `bind-interfaces` is not
taking effect and the Pi is offering DNS to every network it touches. Your
`eth0` address, the `192.168.1.x` one, means it is serving the upstream
network, where a second DHCP and DNS server causes real problems.

Anything on port 5353 is `avahi-daemon` doing mDNS. It is unrelated to this
setup and can be ignored.

<details>
<summary><b>If dnsmasq fails to start with an "address already in use" error</b></summary>

Another process holds port 53, usually `systemd-resolved`. Check and disable
it:

```bash
sudo ss -lnup | grep ':53'
sudo systemctl disable --now systemd-resolved
sudo systemctl restart dnsmasq
```

</details>

Two settings are load-bearing. `bind-interfaces` keeps dnsmasq off `eth0`, so
the Pi never offers DHCP or DNS to the upstream network, where a second DHCP
server would cause real problems. The `option:router` line is what makes
devices route through the Pi at all: without it they may be handed the wrong
gateway and bypass the capture entirely.

**This also solves device naming, on any router.** As the DHCP server, the Pi
receives each device's self-reported hostname (DHCP option 12) in its lease
request, the same source a router's admin page uses. Pass `--dhcp-leases` and
ActivityGraph reads that table directly:

```
[activitygraph] DHCP leases: 4 device(s), 4 with a hostname.

  Alice-Laptop     192.168.50.20   AA:BB:CC:00:00:01   group=Alice
  Alice-Phone      192.168.50.21   AA:BB:CC:00:00:02   group=Alice
  Bob-Phone        192.168.50.22   AA:BB:CC:00:00:03   group=Bob
  Living-Room-TV   192.168.50.23   AA:BB:CC:00:00:04   group=Ungrouped
```

This is why the gateway approach is **router-agnostic**: naming no longer
depends on your router's brand, admin API, or credentials. `--router-devices`
and the vendor login path become unnecessary. Reading a local text file
cannot be rate-limited or locked out, and it covers every device holding a
lease, including ones that ignore mDNS and NBSTAT probes. `--device-aliases`
stays available for renaming, but is no longer required to get names at all.

Leases are re-read on each flush cycle, so devices that join after startup
appear without a restart.

`log-queries` additionally logs every DNS lookup per client IP, which is a
useful cross-check against what ActivityGraph classifies.

### 6. Routing and NAT

Two separate things are needed here, and the Pi does neither by default.

**Forwarding** lets the Pi pass packets between its two interfaces. Linux
refuses to do this out of the box, because a normal computer should not
silently relay other machines' traffic.

**NAT (masquerade)** rewrites outgoing packets to appear to come from the
Pi. The upstream router only knows about the Pi, not the `192.168.50.x`
devices behind it, so without this their replies have nowhere to return to.

**Enable forwarding**, permanently across reboots:

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-activitygraph.conf
sudo sysctl -p /etc/sysctl.d/99-activitygraph.conf
```

That should print `net.ipv4.ip_forward = 1`. Confirm it took effect:

```bash
cat /proc/sys/net/ipv4/ip_forward     # expect 1
```

**Back up any existing firewall rules** before overwriting them:

```bash
[ -f /etc/nftables.conf ] && sudo cp /etc/nftables.conf /etc/nftables.conf.backup
```

**Write the ruleset.** Copy and paste the whole block including the final
`EOF`:

```bash
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
```

**Apply it, and make it load on boot:**

```bash
sudo systemctl enable --now nftables
```

**Verify the rules actually loaded.** `enable --now` reporting success does
not guarantee the file parsed:

```bash
systemctl is-active nftables || sudo journalctl -u nftables -n 20 --no-pager
sudo nft list ruleset
```

The output of the last command should contain both the `forward` chain and
the `masquerade` line. An empty ruleset means the file did not parse.

The printed ruleset will not match your file character for character, and
that is expected:

| You wrote | nft displays |
|---|---|
| `priority 0` | `priority filter` |
| `priority 100` | `priority srcnat` |

Those are the symbolic names for those numeric priorities. Your comments are
also absent, because nftables does not retain them in the loaded ruleset.
Neither indicates a problem.

Nothing will route yet, because no devices are connected. You test this for
real at the end of step 8.

### 7. The access point

This is where this topology usually goes wrong. Three rules, all of which
matter:

**Connect a LAN port to the Pi, never the AP's WAN port.** Using the WAN port
makes it route and NAT, which destroys per-device visibility exactly the way
capturing on `eth0` would. LAN port to LAN port makes it a dumb bridge.

**Turn its DHCP server off.** The Pi is the DHCP server now. Two DHCP servers
on one segment hand out conflicting leases and cause intermittent failures
that are painful to diagnose.

**Give it a static IP on the Pi's subnet**, for example `192.168.50.2`, so
you can still reach its admin page. Make sure it is outside the
`192.168.50.50` to `192.168.50.200` DHCP range above.

Its DSL or WAN port stays unused. You are only using its switch and radio.

Before doing this by hand, check the AP's admin page for an **Operation Mode**
setting. Many consumer gateways offer "Access Point" alongside "Wireless
Router", and selecting it disables DHCP and bridges the LAN and Wi-Fi in a
single toggle, which is far less error-prone than setting each option
individually.

**If your access point is the same model as your upstream router**, configure
it *first, while it is the only one powered on*. Identical units ship with the
same default address, SSID and admin credentials, so having both live at once
means an address conflict and a real chance of reconfiguring the wrong box
without noticing. Set its static IP and give it a distinct SSID before
cabling it to the Pi.

### 8. Run it

```bash
sudo .venv/bin/python -m activitygraph.main \
  --serve --serve-source live -i eth1 \
  --host 0.0.0.0 --no-browser \
  --dhcp-leases \
  --device-groups ~/groups.json \
  --history-db ~/activitygraph/history.db
```

- `-i eth1` is the LAN side. **Not `eth0`.** See the warning at the top.
- `--dhcp-leases` names and registers every device from the lease table. With
  no value it probes the usual dnsmasq locations; pass a path to override.
- `--host 0.0.0.0` is needed to reach the dashboard from another machine, but
  it exposes an unauthenticated dashboard to everyone on the LAN. That is a
  deliberate choice, not a default. ActivityGraph warns when you do it.

Open `http://192.168.50.1:8420` from any device on the network.

### 9. Run it permanently

Set a variable to your project root first, so the paths below are filled in
for you rather than edited by hand:

```bash
AG=$(dirname "$(find ~ -name pyproject.toml -not -path '*/.venv/*' | head -1)")
echo "$AG"        # sanity check: this is your project root
```

Then paste the whole block, including the final `EOF`:

```bash
sudo tee /etc/systemd/system/activitygraph.service > /dev/null <<EOF
[Unit]
Description=ActivityGraph
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$AG
ExecStart=$AG/.venv/bin/python -m activitygraph.main --serve --serve-source live -i eth1 --host 0.0.0.0 --no-browser --dhcp-leases --device-groups $AG/groups.json --history-db $AG/history.db
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

Two deliberate choices in that block. It uses `<<EOF` rather than `<<'EOF'`
so `$AG` is replaced with your real path as the file is written. And
`ExecStart` is one long line rather than using backslash continuations,
because a backslash inside an unquoted heredoc is consumed by the shell
before systemd ever sees it, which produces a mangled command.

Check the result before enabling it:

```bash
cat /etc/systemd/system/activitygraph.service
```

Every path should be absolute and start with `/home/`, with no `$AG` or `~`
left in the file.

For reference, the file it produces looks like this:

```ini
[Unit]
Description=ActivityGraph
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/activitygraph
ExecStart=/opt/activitygraph/.venv/bin/python -m activitygraph.main \
  --serve --serve-source live -i eth1 --host 0.0.0.0 --no-browser \
  --dhcp-leases --device-groups /opt/activitygraph/groups.json \
  --history-db /opt/activitygraph/history.db
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now activitygraph
journalctl -u activitygraph -f
```

The paths assume the project root is `/opt/activitygraph`. Replace them with
the directory containing `pyproject.toml` on your machine, which is what
step 3 had you locate. Two things that commonly break this unit:

- `pi` is no longer the default user on current Raspberry Pi OS images, so a
  unit file hardcoding `/home/pi` fails to start.
- Systemd needs absolute paths. `~` is not expanded, so `~/activitygraph`
  silently resolves to nothing.

Check it started rather than assuming:

```bash
systemctl is-active activitygraph || journalctl -u activitygraph -n 30
```

---

## Verify

1. Connect a phone to the access point's Wi-Fi.
2. `cat /var/lib/misc/dnsmasq.leases` shows the phone with its hostname.
3. `ip route` on the phone, or its Wi-Fi details screen, shows a
   `192.168.50.x` address with `192.168.50.1` as the gateway. If it shows a
   `192.168.1.x` address, it is talking to the upstream router and bypassing
   the Pi entirely.
4. Browse something distinctive on the phone, such as YouTube.
5. Dashboard, **Where Your Time Went**, shows Entertainment, Video, YouTube,
   and the phone appears in **Time by Person** with real minutes.

If the phone shows 0m, work through these in order:

| Symptom | Likely cause |
|---|---|
| Phone gets a `192.168.1.x` address | It associated with the upstream router's Wi-Fi. Turn that radio off |
| Phone not in `dnsmasq.leases` | The AP's DHCP server is still on, or it is cabled by its WAN port |
| Leases fine, no traffic | Capturing the wrong interface. Must be `eth1` |
| Everything attributed to one IP | Capturing `eth0` post-NAT, or `eth0`/`eth1` swapped after a reboot. Check the udev rule in step 2 |
| Traffic but no categories | Flows classify on close, so allow about `--idle-timeout` seconds |

---

## Variants

**No USB adapter.** Use the Pi's onboard Wi-Fi as the access point instead:
install `hostapd`, put `wlan0` on `192.168.50.1/24`, point dnsmasq at `wlan0`
and capture `wlan0`. Costs nothing, but the Pi's radio is weaker than a
dedicated AP for range and concurrent clients, and you must set
`country_code` correctly in `hostapd.conf` because it is a regulatory
setting, not a cosmetic one.

**Wired devices too.** Put an unmanaged switch between the Pi's `eth1` and
the access point. Everything on that switch is downstream of the Pi and is
captured normally.

---

## Things to know before you commit

- **The Pi becomes a single point of failure.** If it is off, the network is
  down. `Restart=always` covers crashes, not power loss or SD card
  corruption.
- **scapy drops packets under sustained load.** At around 100 Mbps this is
  unlikely, but a saturated link can outrun Python packet parsing. Time in
  categories degrades gracefully; precise byte accounting does not.
- **Device-to-device traffic may bypass the Pi.** A phone casting to a TV
  where both sit on the same access point is switched locally and never
  reaches the gateway. Only traffic crossing the Pi is visible.
- **Rollback is easy.** Re-enable the upstream router's Wi-Fi, reconnect
  devices to it, and power the Pi off. Nothing about either router was
  permanently changed.
