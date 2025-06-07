from scapy.all import ICMP, IP, sniff
import time

class ICMPFloodDetector:
    def __init__(self, threshold=20, interval=5):
        # Prahová hodnota: koľko ping požiadaviek je považovaných za útok
        self.threshold = threshold  
        # Časový interval v sekundách, v ktorom sa pakety počítajú
        self.interval = interval  
        # Slovník pre sledovanie ping požiadaviek podľa IP adries
        self.icmp_requests = {}  
        # Množina IP adries, z ktorých už bol detekovaný útok (aby sa alert nespúšťal viackrát)
        self.alerted_ips = set()
        # Callback funkcia na odoslanie alertu (nastavuje sa zvonku)
        self.alert_callback = None  

    def packet_callback(self, pkt):
        # Zisťuje, či paket obsahuje ICMP a IP hlavičku
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            # ICMP typ 8 = echo request (klasický ping)
            if pkt[ICMP].type == 8:
                src_ip = pkt[IP].src  # Zdrojová IP adresa
                now = time.time()     # Aktuálny čas

                # Ak IP adresa ešte nie je evidovaná, vytvor pre ňu záznam
                if src_ip not in self.icmp_requests:
                    self.icmp_requests[src_ip] = []

                # Pridaj aktuálny čas ping požiadavky
                self.icmp_requests[src_ip].append(now)

                # Odstráň záznamy staršie ako definovaný interval
                self.icmp_requests[src_ip] = [
                    t for t in self.icmp_requests[src_ip] if now - t <= self.interval
                ]

                # Ak počet požiadaviek prekročí limit a ešte nebola hlásená
                if len(self.icmp_requests[src_ip]) > self.threshold and src_ip not in self.alerted_ips:
                    self._alert(f"[ALERT] Possible ICMP flood from {src_ip}")
                    self.alerted_ips.add(src_ip)

    def _alert(self, message):
        # Ak je definovaný callback, zavolaj ho, inak vypíš alert do konzoly
        if self.alert_callback:
            self.alert_callback(message)
        else:
            print(message)

    def start(self, iface=None):
        # Spustí pasívne odchytávanie paketov na danom rozhraní (alebo všetkých)
        sniff(prn=self.packet_callback, iface=iface, store=False)
