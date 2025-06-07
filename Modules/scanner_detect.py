from scapy.all import sniff, TCP, IP
import time

class PortScanDetector:
    def __init__(self, threshold=10, interval=5):
        """
        Inicializácia detektora port scanov.

        :param threshold: počet SYN packetov z jednej IP adresy za interval,
                          po ktorom sa vyhlási alert
        :param interval: časové okno v sekundách, počas ktorého sa počítajú SYN pakety
        """
        self.threshold = threshold
        self.interval = interval

        # slovník, kde kľúč je IP adresa a hodnota je zoznam časov prijatia SYN packetov
        self.syn_packets = {}

        # množina IP adries, ktoré už vyvolali alert, aby sme ich nehlásili opakovane
        self.alerted_ips = set()

        # callback funkcia, ktorú môžeme nastaviť, aby sa zavolala pri detekcii alertu
        self.alert_callback = None

    def packet_callback(self, pkt):
        """
        Callback funkcia volaná pre každý zachytený paket.

        Kontroluje, či je paket TCP SYN z jednej IP, a ak ich je
        viac než threshold v danom intervale, spustí alert.
        """
        # Skontrolujeme, či paket má vrstvy TCP a IP
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            tcp_layer = pkt[TCP]
            ip_layer = pkt[IP]

            # Kontrola, či je TCP flag SYN ('S')
            if tcp_layer.flags == 'S':
                src_ip = ip_layer.src
                now = time.time()

                # Ak táto IP ešte nemá záznam, vytvor nový zoznam
                if src_ip not in self.syn_packets:
                    self.syn_packets[src_ip] = []

                # Pridaj aktuálny čas k zoznamu SYN packetov od tejto IP
                self.syn_packets[src_ip].append(now)

                # Odstráň všetky záznamy staršie ako interval sekúnd
                self.syn_packets[src_ip] = [
                    t for t in self.syn_packets[src_ip] if now - t <= self.interval
                ]

                # Ak je počet SYN packetov za interval väčší ako threshold
                # a táto IP ešte nebola alertovaná, spusti alert
                if len(self.syn_packets[src_ip]) > self.threshold and src_ip not in self.alerted_ips:
                    if self.alert_callback:
                        # Zavolaj callback s alert správou
                        self.alert_callback(f"[ALERT] Possible port scan from IP {src_ip}")
                    # Pridaj IP do setu alertovaných IP
                    self.alerted_ips.add(src_ip)

                    # Vyčisti zoznam SYN packetov pre túto IP (reset)
                    self.syn_packets[src_ip] = []

    def start(self, iface=None):
        """
        Spustí sniffovanie paketov na danom sieťovom rozhraní.

        :param iface: názov sieťového rozhrania, napr. 'eth0' alebo 'wlan0';
                      ak None, použije predvolené rozhranie
        """
        sniff(prn=self.packet_callback, iface=iface, store=False)
