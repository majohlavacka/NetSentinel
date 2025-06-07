from scapy.all import ARP, Ether, srp

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
        devices.append({
            "ip": received.psrc,     # Zdrojová IP adresa (z odpovede)
            "mac": received.hwsrc    # Zdrojová MAC adresa (z odpovede)
        })

    return devices  # Vráť zoznam zariadení v sieti
