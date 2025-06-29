from scapy.all import AsyncSniffer, TCP, IP
import time
from ipaddress import ip_address, IPv4Address  # Pre validáciu IP adries

class PortScanDetector:
    def __init__(self, threshold=10, interval=5, cooldown=300):
        """
        Inicializácia detektora port scanov.

        :param threshold: počet SYN packetov z jednej IP adresy za interval,
                          po ktorom sa vyhlási alert
        :param interval: časové okno v sekundách, počas ktorého sa počítajú SYN pakety
        :param cooldown: čas v sekundách, počas ktorého sa IP po vyhlásení alertu ignoruje
        """
        self.threshold = threshold
        self.interval = interval
        self.cooldown = cooldown  # Nová premenná pre cooldown čas alertov

        # slovník, kde kľúč je IP adresa a hodnota je zoznam časov prijatia SYN packetov
        self.syn_packets = {}

        # slovník IP adries, ktoré už vyvolali alert, s časom alertu (pre cooldown)
        self.alerted_ips = {}

        # callback funkcia, ktorú môžeme nastaviť, aby sa zavolala pri detekcii alertu
        self.alert_callback = None

        # Flag na kontrolu, či sniffovanie beží
        self.running = False
        self.sniffer = None  # AsyncSniffer inštancia

    def packet_callback(self, pkt):
        """
        Callback funkcia volaná pre každý zachytený paket.
        """
        # Skontrolujeme, či paket má vrstvy TCP a IP
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]

            try:
                src_ip = ip_layer.src
                # Validácia IP adresy
                ip_obj = ip_address(src_ip)
                if not isinstance(ip_obj, IPv4Address):
                    return  # ignoruj ne-IPv4 adresy
                # Ignoruj multicast, broadcast, loopback a iné špeciálne adresy
                if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved or ip_obj.is_loopback:
                    return
            except ValueError:
                # Ak IP adresa nie je platná, ignoruj paket
                return

            # Kontrola, či je TCP flag SYN ('S')
            if tcp_layer.flags == 'S':
                now = time.time()

                # Skontroluj cooldown pre alertované IP
                if src_ip in self.alerted_ips:
                    if now - self.alerted_ips[src_ip] < self.cooldown:
                        return  # stále v cooldown, ignoruj
                    else:
                        # Cooldown vypršal, odstráň IP z alertovaných
                        del self.alerted_ips[src_ip]

                # Ak táto IP ešte nemá záznam, vytvor nový zoznam
                if src_ip not in self.syn_packets:
                    self.syn_packets[src_ip] = []

                self.syn_packets[src_ip].append(now)

                # Vyfiltruj len SYN pakety v rámci intervalového okna
                self.syn_packets[src_ip] = [t for t in self.syn_packets[src_ip] if now - t <= self.interval]

                # Ak je počet SYN packetov za interval väčší ako threshold, spusti alert
                if len(self.syn_packets[src_ip]) > self.threshold:
                    if self.alert_callback:
                        # Zavolaj callback s alert správou
                        self.alert_callback(f"[ALERT] Possible port scan from IP {src_ip}")
                    else:
                        print(f"[ALERT] Possible port scan from IP {src_ip}")

                    # Nastav IP do alertovaných IP s časom alertu (nastav cooldown)
                    self.alerted_ips[src_ip] = now

                    # Vyčisti zoznam SYN packetov pre túto IP (reset)
                    self.syn_packets[src_ip] = []

    def start(self, iface=None):
        """
        Spustí sniffovanie paketov.

        :param iface: názov sieťového rozhrania, napr. 'eth0' alebo 'wlan0';
                      ak None, použije predvolené rozhranie
        """
        self.running = True
        self.sniffer = AsyncSniffer(
            prn=self.packet_callback,
            iface=iface,
            store=False,
            filter="tcp"
        )
        # AsyncSniffer spúšťa zachytávanie paketov na pozadí (v samostatnom vlákne),
        # takže hlavný program môže pokračovať bez blokovania.
        self.sniffer.start()

    def stop(self):
        """
        Bezpečne zastaví sniffovanie nastavením flagu.
        """
        self.running = False
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
