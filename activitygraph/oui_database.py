"""A small, offline MAC-address vendor-prefix (OUI) table.

ActivityGraph is privacy-first and local-only by design, so device
identification never phones home to an external vendor-lookup API.
This table covers the vendors most likely to show up on a home/campus
network. It's intentionally compact and easy to extend.
"""

# Prefixes are the first 6 hex digits of the MAC address, uppercase, no separators.
OUI_PREFIXES = {
    "F4F5E8": "Google",
    "3C5AB4": "Google",
    "94EB2C": "Amazon Technologies",
    "68540F": "Amazon Technologies",
    "FCA13E": "Amazon Technologies",
    "001A11": "Google",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Foundation",
    "3C0754": "Apple",
    "A45E60": "Apple",
    "F0DBF8": "Apple",
    "AC87A3": "Apple",
    "BC926B": "Apple",
    "D8961D": "Apple",
    "F45C89": "Apple",
    "88E9FE": "Apple",
    "3C15C2": "Apple",
    "40B395": "Apple",
    "001CB3": "Apple",
    "0050E4": "Apple",
    "F4F951": "Apple",
    "A4C361": "Samsung Electronics",
    "5C0A5B": "Samsung Electronics",
    "8C7712": "Samsung Electronics",
    "F8042E": "Samsung Electronics",
    "D01712": "Samsung Electronics",
    "001E58": "Samsung Electronics",
    "D8551B": "Samsung Electronics",
    "48D355": "Samsung Electronics",
    "3868DD": "Huawei Technologies",
    "00E0FC": "Huawei Technologies",
    "70723C": "Huawei Technologies",
    "F0B429": "Xiaomi",
    "8CBEBE": "Xiaomi",
    "641C67": "Xiaomi",
    "B0BE76": "Xiaomi",
    "18A6F7": "Sonos",
    "5CAAFD": "Sonos",
    "000E58": "Sonos",
    "B8271E": "Nintendo",
    "9C2A70": "Nintendo",
    "0009BF": "Nintendo",
    "7CBB8A": "Microsoft",
    "60453E": "Microsoft",
    "0003FF": "Microsoft",
    "E4B318": "Dell",
    "D4BED9": "Dell",
    "B8CA3A": "Dell",
    "3417EB": "Hewlett Packard",
    "3CD92B": "Hewlett Packard",
    "9C8E99": "Hewlett Packard",
    "D8D385": "TP-Link",
    "50C7BF": "TP-Link",
    "F4F26D": "TP-Link",
    "A0F3C1": "Ubiquiti Networks",
    "24A43C": "Ubiquiti Networks",
    "78452C": "Ubiquiti Networks",
    "001DD8": "Netgear",
    "204E7F": "Netgear",
    "E091F5": "Netgear",
    "6C5997": "Intel",
    "34E6D7": "Intel",
    "A4BF01": "Intel",
    "DC5360": "Intel",
    "000C29": "VMware (virtual)",
    "005056": "VMware (virtual)",
    "080027": "VirtualBox (virtual)",
    "AC220B": "Amazon (Echo/Alexa)",
    "44650D": "Amazon (Echo/Alexa)",
    "F0272D": "Amazon (Fire TV)",
    "6C56F7": "Espressif (IoT/ESP32)",
    "84CCA8": "Espressif (IoT/ESP32)",
    "246F28": "Espressif (IoT/ESP32)",
    "B4E62D": "Espressif (IoT/ESP32)",
}


def lookup_vendor(mac: str) -> str:
    """Return a best-effort vendor name for a MAC address, or 'Unknown'."""
    if not mac:
        return "Unknown"
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    return OUI_PREFIXES.get(prefix, "Unknown")
