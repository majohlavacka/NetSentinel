from scapy.all import ARP, sniff, arping
import threading

class ARPSpoofDetector:
    def __init__(self):
        # Mapa legitímnych IP -> MAC adries zo siete
        self.ip_mac_map = {}
        # Callback funkcia pre odoslanie alertu (napr. do hlavného rozhrania)
        self.alert_callback = None

    def preload_known_macs(self, network="10.0.2.0/24"):
        """
        Na začiatku preskenuje celú lokálnu sieť a uloží si aktuálne IP → MAC adresy
        Pomocou arping() získame odpovede od všetkých aktívnych zariadení
        """
        ans, _ = arping(network, verbose=False)
        for snd, rcv in ans:
            ip = rcv.psrc # IP zariadenia, ktoré odpovedalo na ARP požiadavku
            mac = rcv.hwsrc # fyzická adresa (MAC) toho istého zariadenia
            self.ip_mac_map[ip] = mac  # Ukladá mapovanie IP → MAC do slovníka ip_mac_map a slúži ako "biely zoznam" legitímnych párov IP/MAC.

    def packet_callback(self, pkt):
        """
        Táto funkcia sa volá pri každom zachytenom ARP pakete.
        Skontroluje, či je odpoveď legitímna, alebo ide o spoofing.
        """
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # op == 2 → ARP Reply
            ip = pkt[ARP].psrc     # Zdrojová IP adresa
            mac = pkt[ARP].hwsrc   # Zdrojová MAC adresa

            # Ak už túto IP poznáme, porovnáme jej MAC
            if ip in self.ip_mac_map:
                if self.ip_mac_map[ip] != mac:
                    # Ak sa MAC zmenila, je to podozrivé → ARP spoofing
                    alert_msg = f"[ALERT] Possible ARP spoofing detected! IP {ip} is at {mac}, but was previously at {self.ip_mac_map[ip]}"
                    if self.alert_callback:
                        self.alert_callback(alert_msg)  # odovzdáme alert späť do hlavnej aplikácie
                    else:
                        print(alert_msg)
            else:
                # Ak IP ešte nepoznáme, pridáme si ju do mapy
                self.ip_mac_map[ip] = mac

    def start(self, iface=None, network="10.0.2.0/24"):
        """
        Hlavná funkcia – najprv si načítame legitímne IP-MAC adresy a potom počúvame ARP odpovede
        """
        self.preload_known_macs(network)  # naskenujeme sieť na začiatku
        sniff(prn=self.packet_callback, filter="arp", store=False, iface=iface)  # počúvame ARP pakety
