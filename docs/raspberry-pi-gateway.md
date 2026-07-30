# Running ActivityGraph on a Raspberry Pi gateway

This is the setup that delivers the full vision: **every device on the
network**, with real flows, TLS SNI, byte counts and per-person category
time -- not just the machine doing the capturing.

It works because of something a Wi-Fi client fundamentally cannot do. A
laptop on Wi-Fi in managed mode only receives frames addressed to it, so it
can never see your phone's traffic no matter how long it captures. A gateway
is different: every packet from every device has to pass *through* it to
reach the internet. Put the capture there and the blindness disappears.

Your existing code runs unchanged -- it's `scapy`-based and portable, and the
one Windows-specific helper (`collector.list_interfaces`) already falls back
cleanly on Linux.

---

## The one thing you must get right

> **Capture on the LAN interface, never the WAN interface.**

The Pi performs NAT: by the time packets leave the WAN side, every one of
them carries the *Pi's* source IP. Capturing there would attribute the whole
household's browsing to a single device and silently destroy per-device
data -- the exact thing this setup exists to provide.

Capture on the LAN side (`wlan0` below), where each packet still carries the
real source IP of the phone, laptop or TV that sent it.

---

## Hardware

- Raspberry Pi 4B (any RAM size; 2 GB is plenty)
- SD card, 16 GB+
- Ethernet cable to your existing router
- *Optional:* a USB 3.0 gigabit Ethernet adapter, if you want wired devices
  covered or better Wi-Fi throughput (see [Variants](#variants))

At ~100 Mbps, a Pi 4B running scapy has comfortable headroom.

## Topology

The Pi becomes the gateway for everything; the existing router is demoted to
"the thing that talks to the internet". No bridge mode required, which keeps
this entirely reversible.

```
        Internet
           │
     ┌─────┴──────┐
     │ router      │  Wi-Fi DISABLED  ← critical, see below
     │ modem/router│
     └─────┬──────┘
           │ ethernet
     ┌─────┴──────────────────┐
     │ Pi 4B                   │
     │  eth0  = WAN  (DHCP)    │
     │  wlan0 = LAN  (AP)      │  ← ActivityGraph captures HERE
     └─────┬──────────────────┘
           ) ) )  Wi-Fi
      phone, laptops, TV
```

**Turn off the existing router's Wi-Fi.** If it stays on, devices keep
associating with it, bypass the Pi entirely, and appear to have no traffic.
This is the most common cause of an apparently non-functioning setup.

---

## Setup

### 1. OS

Flash **Raspberry Pi OS Lite (64-bit)**. Enable SSH in Imager's advanced
options so you can work headless.

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y python3-pip python3-venv git tcpdump hostapd dnsmasq nftables
```

`tcpdump` pulls in `libpcap`, which `scapy` needs to open an interface --
`pip install scapy` alone is not enough.

### 2. ActivityGraph

```bash
git clone <your-repo> activitygraph && cd activitygraph
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python -m activitygraph.main --demo    # smoke test, no root needed
```

### 3. LAN interface

Give `wlan0` a static address on its own subnet, distinct from the
router's `192.168.1.x` so routing stays unambiguous.

`/etc/dhcpcd.conf`:
```
interface wlan0
static ip_address=192.168.50.1/24
nohook wpa_supplicant
```

### 4. Wi-Fi access point

`/etc/hostapd/hostapd.conf`:
```
interface=wlan0
driver=nl80211
ssid=ActivityGraph
hw_mode=a
channel=36
country_code=XX          # REQUIRED: your ISO 3166-1 country code
wmm_enabled=1
ieee80211n=1
ieee80211ac=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=CHANGE_ME
```

```bash
sudo systemctl unmask hostapd && sudo systemctl enable --now hostapd
```

### 5. DHCP + DNS

`/etc/dnsmasq.d/activitygraph.conf`:
```
interface=wlan0
dhcp-range=192.168.50.50,192.168.50.200,12h
domain=lan
log-queries
log-facility=/var/log/dnsmasq.log
```

```bash
sudo systemctl restart dnsmasq
```

**This also solves device naming, on any router.** As the DHCP server, the Pi
receives each device's self-reported hostname (DHCP option 12) in its lease
request -- the same source a router's admin page uses. Pass `--dhcp-leases`
and ActivityGraph reads that table directly:

```
[activitygraph] DHCP leases: 4 device(s), 4 with a hostname.

  Alice-Laptop     192.168.50.20   AA:BB:CC:00:00:01   group=Alice
  Alice-Phone      192.168.50.21   AA:BB:CC:00:00:02   group=Alice
  Bob-Phone        192.168.50.22   AA:BB:CC:00:00:03   group=Bob
  Living-Room-TV   192.168.50.23   AA:BB:CC:00:00:04   group=Ungrouped
```

This is why the gateway approach is **router-agnostic**: naming no longer
depends on your router's brand, admin API, or credentials. `--router-devices`
and the TP-Link login path become unnecessary -- reading a local text file
can't be rate-limited or locked out, and it covers every device that holds a
lease, including ones that ignore mDNS/NBSTAT probes. `--device-aliases`
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

### 7. Run it

```bash
sudo .venv/bin/python -m activitygraph.main \
  --serve --serve-source live -i wlan0 \
  --host 0.0.0.0 --no-browser \
  --dhcp-leases \
  --device-groups ~/groups.json \
  --history-db ~/activitygraph/history.db
```

- `-i wlan0` -- the LAN side. **Not `eth0`.** See the warning above.
  ActivityGraph now checks this itself: if the interface you pass carries the
  default route, it prints a warning at startup rather than letting you
  collect a week of silently wrong data.
- `--dhcp-leases` -- names and registers every device from the lease table.
  With no value it probes the usual dnsmasq locations; pass a path to override.
- `--host 0.0.0.0` -- needed to reach the dashboard from your laptop, but it
  exposes it to everyone on the LAN with no authentication. That's a
  deliberate choice, not a default; on a home network it's usually fine.

Open `http://192.168.50.1:8420` from any device on the Pi's Wi-Fi.

### 8. Run it permanently

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
  --serve --serve-source live -i wlan0 --host 0.0.0.0 --no-browser \
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

The paths above assume the repository lives at `/opt/activitygraph`. Adjust
them to wherever you cloned it -- note that `pi` is no longer the default user
on current Raspberry Pi OS images, so a unit file hardcoding `/home/pi` will
fail to start.

---

## Verify

1. Connect your phone to the `ActivityGraph` Wi-Fi.
2. `cat /var/lib/misc/dnsmasq.leases` -- the phone appears with its hostname.
3. Browse something distinctive on the phone (YouTube).
4. Dashboard → **Where Your Time Went** shows Entertainment → Video →
   YouTube, and the phone appears in **Time by Person** with real minutes.

If the phone shows 0m, work through these in order:

| Symptom | Likely cause |
|---|---|
| Phone not in `dnsmasq.leases` | It associated with the old router's Wi-Fi instead -- turn that radio off |
| Leases fine, no traffic | Capturing on the wrong interface -- must be `wlan0` |
| Traffic but no categories | Flows not yet classified; they classify on close (~`--idle-timeout`) |
| Everything attributed to one IP | Capturing on `eth0` post-NAT -- switch to `wlan0` |

---

## Variants

**Add a USB Ethernet adapter** if you want wired devices covered or better
Wi-Fi. Use the adapter (`eth1`) as WAN to the router, keep `eth0` for a
wired switch, and bridge `eth0` + `wlan0` as the LAN. Capture the bridge.

**Reuse the existing router as a dumb AP** for stronger Wi-Fi than the Pi's onboard
radio: disable its DHCP server, give it a static address on the Pi's subnet,
and connect its LAN port (not WAN) to the Pi's LAN side.

---

## Things to know before you commit

- **The Pi becomes a single point of failure.** If it's off, the network is
  down. `Restart=always` covers crashes, not power loss or SD corruption.
- **scapy drops packets under sustained load.** At ~100 Mbps this is
  unlikely, but a saturated link can outrun Python packet parsing. Time in
  categories degrades gracefully; precise byte accounting does not.
- **Pi onboard Wi-Fi is modest** -- fine for ~100 Mbps and a handful of
  devices, weaker than a dedicated AP for range and concurrent clients.
- **Rollback is easy:** re-enable the router's Wi-Fi, reconnect devices to it,
  power the Pi off. Nothing about the router was permanently changed.
