from scapy.all import ICMP, IP, AsyncSniffer
import time
import re
from collections import deque  # PRE GRAF
from Modules.firewall import block_ip, is_blocked  # IPS firewall

class ICMPFloodDetector:
    def __init__(self, threshold=20, interval=5):
        self.threshold = threshold            # Maximálny počet ICMP paketov za interval
        self.interval = interval              # Časové okno v sekundách
        self.icmp_requests = {}               # Ukladá časové značky ICMP paketov podľa IP
        self.alerted_ips = set()              # IP adresy, pre ktoré už bol alert odoslaný
        self.alert_callback = None            # Callback funkcia pre alerty

        self.running = False                  # Flag pre kontrolu behu
        self.sniffer = None                   # AsyncSniffer inštancia

        # BUFFER PRE REALTIME GRAF
        self.packet_times = deque(maxlen=1000)

        # IPS: sledovanie začiatku útoku
        self.attack_start = {}

        # IPS: po koľkých sekundách blokujeme
        self.block_time = 10   # môžeš neskôr zmeniť späť na 30

    def _valid_ip(self, ip):
        """
        Validuje IPv4 adresu pomocou regexu, aby sa predišlo spracovaniu škodlivých alebo nesprávnych IP.
        """
        pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not pattern.match(ip):
            return False
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)

    def packet_callback(self, pkt):
        """
        Callback funkcia pre každý zachytený paket.
        Detekuje ICMP Echo Request (type 8) a počíta ich počet podľa zdrojovej IP.
        """

        if pkt.haslayer(ICMP) and pkt.haslayer(IP):

            if pkt[ICMP].type == 8:

                src_ip = pkt[IP].src

                # IPS: ak je IP blokovaná firewallom ignorujeme jej pakety
                if is_blocked(src_ip):
                    return

                if not self._valid_ip(src_ip):
                    return

                now = time.time()

                # PRE GRAF
                self.packet_times.append(now)

                if src_ip not in self.icmp_requests:
                    self.icmp_requests[src_ip] = []

                # Uloženie timestampu
                self.icmp_requests[src_ip].append(now)

                # Vyčistenie starých timestampov mimo intervalu
                self.icmp_requests[src_ip] = [
                    t for t in self.icmp_requests[src_ip]
                    if now - t <= self.interval
                ]

                # Kontrola prahu
                if len(self.icmp_requests[src_ip]) > self.threshold:

                    if src_ip not in self.alerted_ips:
                        self._alert(f"[ALERT] Possible ICMP flood from {src_ip}")
                        self.alerted_ips.add(src_ip)

                    # IPS: začiatok sledovania útoku
                    if src_ip not in self.attack_start:
                        self.attack_start[src_ip] = now

                    duration = now - self.attack_start[src_ip]

                    # IPS: blokovanie IP po určitom čase
                    if duration > self.block_time:
                        block_ip(src_ip)

                else:

                    # reset keď útok skončí
                    if src_ip in self.attack_start:
                        del self.attack_start[src_ip]

    def get_rate(self):
        """
        Vráti počet ICMP paketov za poslednú sekundu.
        Používa sa pre realtime graf v termináli.
        """
        now = time.time()
        return len([
            t for t in self.packet_times
            if now - t <= 1
        ])

    def _alert(self, message):
        """
        Odosiela alert cez callback, ak je definovaný, inak vypíše na konzolu.
        """
        if self.alert_callback:
            self.alert_callback(message)
        else:
            print(message)

    def start(self, iface=None):
        """
        Spustí zachytávanie paketov na danom rozhraní pomocou AsyncSniffer.
        """
        self.running = True
        self.sniffer = AsyncSniffer(
            prn=self.packet_callback,
            store=False,
            filter="icmp",
            iface=iface
        )

        # AsyncSniffer spúšťa zachytávanie paketov na pozadí (v samostatnom vlákne),
        # takže hlavný program môže pokračovať bez blokovania.
        self.sniffer.start()

    def stop(self):
        """
        Bezpečne zastaví sniffovanie nastavením flagu a stopnutím AsyncSniffera.
        """
        self.running = False
        if self.sniffer and self.sniffer.running:
            try:
                self.sniffer.stop()
            except:
                pass
