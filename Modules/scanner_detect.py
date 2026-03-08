from scapy.all import AsyncSniffer, TCP, IP
import time
from ipaddress import ip_address, IPv4Address
from collections import deque  # PRE GRAF
from Modules.firewall import block_ip, is_blocked  # IPS firewall


# Trieda pre detekciu port scan útokov
class PortScanDetector:

    # Inicializácia detektora a základných parametrov
    def __init__(self, threshold=10, interval=5, cooldown=300):

        # Počet SYN paketov za časový interval potrebný na vyhlásenie alertu
        self.threshold = threshold

        # Časové okno (v sekundách), v ktorom počítame SYN pakety
        self.interval = interval

        # Cooldown čas medzi alertami pre rovnakú IP
        self.cooldown = cooldown

        # Slovník kde uchovávame timestampy SYN packetov podľa IP
        self.syn_packets = {}

        # IP adresy ktoré už vyvolali alert
        self.alerted_ips = {}

        # Callback funkcia ktorá sa zavolá pri alerte
        self.alert_callback = None

        # Flag ktorý hovorí či detektor beží
        self.running = False

        # AsyncSniffer objekt
        self.sniffer = None

        # BUFFER PRE GRAF
        # Ukladá časy paketov pre realtime graf v UI
        self.packet_times = deque(maxlen=1000)

        # IPS: sledovanie začiatku útoku pre každú IP
        self.attack_start = {}

        # IPS: čas po ktorom blokujeme útočníka firewallom
        self.block_time = 10


    # Callback funkcia ktorá sa spustí pri každom zachytenom pakete
    def packet_callback(self, pkt):

        # Kontrola či paket obsahuje TCP a IP vrstvu
        if pkt.haslayer(TCP) and pkt.haslayer(IP):

            # Aktuálny čas
            now = time.time()

            # Získanie IP a TCP vrstvy
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]

            # Zdrojová IP adresa
            src_ip = ip_layer.src

            # IPS: ak je IP už blokovaná firewallom ignorujeme jej pakety
            if is_blocked(src_ip):
                return

            # Uloženie času paketu do bufferu pre graf
            self.packet_times.append(now)

            try:
                # Overenie či IP adresa je validná
                ip_obj = ip_address(src_ip)

                # Ignorujeme ne IPv4 adresy
                if not isinstance(ip_obj, IPv4Address):
                    return

                # Ignorujeme špeciálne adresy (multicast, loopback atď.)
                if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved or ip_obj.is_loopback:
                    return

            except ValueError:
                # Ak IP nie je validná ignorujeme paket
                return

            # Kontrola či ide o SYN paket (začiatok TCP spojenia)
            if tcp_layer.flags == 'S':

                # Ak IP ešte nemá záznam vytvoríme zoznam
                if src_ip not in self.syn_packets:
                    self.syn_packets[src_ip] = []

                # Uloženie času SYN paketu
                self.syn_packets[src_ip].append(now)

                # Vyfiltrujeme len pakety ktoré sú v časovom intervale
                self.syn_packets[src_ip] = [
                    t for t in self.syn_packets[src_ip]
                    if now - t <= self.interval
                ]

                # Ak počet SYN paketov prekročí threshold ide o možný port scan
                if len(self.syn_packets[src_ip]) > self.threshold:

                    # Ak táto IP ešte nebola alertovaná
                    if src_ip not in self.alerted_ips:

                        # Spustenie alert callbacku
                        if self.alert_callback:
                            self.alert_callback(
                                f"[ALERT] Possible port scan from IP {src_ip}"
                            )
                        else:
                            print(
                                f"[ALERT] Possible port scan from IP {src_ip}"
                            )

                        # Uloženie IP do zoznamu alertovaných
                        self.alerted_ips[src_ip] = now

                    # IPS: uloženie času začiatku útoku
                    if src_ip not in self.attack_start:
                        self.attack_start[src_ip] = now

                    # Vypočítanie ako dlho útok trvá
                    duration = now - self.attack_start[src_ip]

                    # IPS: ak útok trvá dlhšie než block_time zablokujeme IP firewallom
                    if duration > self.block_time:
                        block_ip(src_ip)

                else:

                    # Ak útok prestal vymažeme záznam o začiatku útoku
                    if src_ip in self.attack_start:
                        del self.attack_start[src_ip]


    # Funkcia ktorá vracia počet paketov za poslednú sekundu
    # Používa sa na vykreslenie realtime grafu v termináli
    def get_rate(self):

        now = time.time()

        return len([
            t for t in self.packet_times
            if now - t <= 1
        ])


    # Spustenie sniffovania paketov pomocou AsyncSniffer
    def start(self, iface=None):

        # Nastavenie flagu že detektor beží
        self.running = True

        # Inicializácia AsyncSniffera
        self.sniffer = AsyncSniffer(
            prn=self.packet_callback,
            iface=iface,
            store=False,
            filter="tcp"
        )

        # Spustenie sniffovania v samostatnom vlákne
        self.sniffer.start()


    # Bezpečné zastavenie sniffovania
    def stop(self):

        # Nastavenie flagu že detektor končí
        self.running = False

        # Ak sniffer existuje a beží zastavíme ho
        if self.sniffer and self.sniffer.running:

            try:
                self.sniffer.stop()
            except:
                pass