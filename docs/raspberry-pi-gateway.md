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

### 4. LAN interface

Give `eth1` a static address on its own subnet, distinct from the upstream
router's `192.168.1.x` so routing stays unambiguous.

`/etc/dhcpcd.conf`:
```
interface eth1
static ip_address=192.168.50.1/24
```

Leave `eth0` alone. It takes a DHCP lease from the upstream router as normal.

### 5. DHCP and DNS

`/etc/dnsmasq.d/activitygraph.conf`:
```
interface=eth1
bind-interfaces
dhcp-range=192.168.50.50,192.168.50.200,12h
domain=lan
log-queries
log-facility=/var/log/dnsmasq.log
```

```bash
sudo systemctl restart dnsmasq
```

`bind-interfaces` keeps dnsmasq off `eth0`, so the Pi never offers DHCP or
DNS to the upstream network.

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

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-activitygraph.conf
sudo sysctl -p /etc/sysctl.d/99-activitygraph.conf
```

`/etc/nftables.conf`:
```
table inet filter {
  chain forward { type filter hook forward priority 0; policy accept; }
}
table ip nat {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    oifname "eth0" masquerade
  }
}
```

```bash
sudo systemctl enable --now nftables
```

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

`/etc/systemd/system/activitygraph.service`:
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

The paths assume the repository lives at `/opt/activitygraph`. Adjust them to
wherever you cloned it. Note that `pi` is no longer the default user on
current Raspberry Pi OS images, so a unit file hardcoding `/home/pi` will
fail to start.

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
