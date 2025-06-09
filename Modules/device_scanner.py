from scapy.all import ARP, Ether, srp
import re

def _valid_ip(ip):
    # Regex validácia IPv4 adresy pre kontrolu správnosti formátu
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

def _valid_mac(mac):
    # Regex validácia MAC adresy pre kontrolu správnosti formátu
    pattern = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    return re.match(pattern, mac) is not None

def scan_network(ip_range="10.0.2.0/24"):
    print(f"[INFO] Scanning network {ip_range}...")

    # Vytvor ARP požiadavku pre zadaný IP rozsah
    arp = ARP(pdst=ip_range)

    # Vytvor Ethernet rámec s broadcast MAC adresou (všetky zariadenia v sieti)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Spoj ARP požiadavku a Ethernet rámec do jedného paketu
    packet = ether / arp

    # Odošli paket(y) do siete a čakaj na odpovede počas 2 sekúnd (bez výpisu detailov)
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []

    # Pre každý odpovedaný paket ulož IP a MAC zariadenia
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        # Over, či IP a MAC majú správny formát pred pridaním do zoznamu
        if _valid_ip(ip) and _valid_mac(mac):
            devices.append({
                "ip": ip,     # Zdrojová IP adresa (z odpovede)
                "mac": mac    # Zdrojová MAC adresa (z odpovede)
            })
        else:
            print(f"[WARN] Detected invalid IP or MAC: IP={ip}, MAC={mac}")

    return devices  # Vráť zoznam zariadení v sieti
