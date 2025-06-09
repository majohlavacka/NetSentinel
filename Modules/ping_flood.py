from scapy.all import ICMP, IP, sniff
import time
import re

class ICMPFloodDetector:
    def __init__(self, threshold=20, interval=5):
        self.threshold = threshold            # Maximálny počet ICMP paketov za interval
        self.interval = interval              # Časové okno v sekundách
        self.icmp_requests = {}               # Ukladá časové značky ICMP paketov podľa IP
        self.alerted_ips = set()              # IP adresy, pre ktoré už bol alert odoslaný
        self.alert_callback = None            # Callback funkcia pre alerty

        # Flag na kontrolu, či sniffovanie beží
        self.running = False

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
                
                # Validácia IP adresy pre bezpečnosť
                if not self._valid_ip(src_ip):
                    return  # Ignoruj pakety s neplatnou IP adresou

                now = time.time()

                if src_ip not in self.icmp_requests:
                    self.icmp_requests[src_ip] = []

                # Uložíme čas prijatia paketu
                self.icmp_requests[src_ip].append(now)

                # Odstránime pakety staršie ako interval
                self.icmp_requests[src_ip] = [t for t in self.icmp_requests[src_ip] if now - t <= self.interval]

                # Ak počet paketov prekročí prah a pre IP ešte nebol alert
                if len(self.icmp_requests[src_ip]) > self.threshold and src_ip not in self.alerted_ips:
                    self._alert(f"[ALERT] Possible ICMP flood from {src_ip}")
                    self.alerted_ips.add(src_ip)

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
        Spustí zachytávanie paketov na danom rozhraní.
        """
        self.running = True

        def stop_filter(pkt):
            # Ak running je False, ukonči sniffovanie
            return not self.running

        sniff(prn=self.packet_callback, iface=iface, store=False, stop_filter=stop_filter)

    def stop(self):
        """
        Bezpečne zastaví sniffovanie nastavením flagu.
        """
        self.running = False
