from scapy.all import ARP, AsyncSniffer, arping
import threading
import time
import re
from collections import deque  # PRE GRAF

class ARPSpoofDetector:
    def __init__(self):
        # Mapa legitímnych IP -> MAC adries zo siete
        self.ip_mac_map = {}
        # Callback funkcia pre odoslanie alertu (napr. do hlavného rozhrania)
        self.alert_callback = None
        # Posledný čas alertu pre každú IP (na rate limiting)
        self.last_alert_time = {}
        # Interval medzi alertami pre tú istú IP v sekundách
        self.alert_cooldown = 10
        # Flag na riadenie behu
        self.running = False
        # AsyncSniffer inštancia
        self.sniffer = None

        # BUFFER PRE GRAF
        self.packet_times = deque(maxlen=1000)

    def _valid_ip(self, ip):
        # Regex validácia IPv4 adresy pre kontrolu správnosti formátu
        pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if not pattern.match(ip):
            return False
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)

    def _valid_mac(self, mac):
        # Regex validácia MAC adresy pre kontrolu správnosti formátu
        pattern = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
        return bool(pattern.match(mac))

    def preload_known_macs(self, network="10.0.2.0/24"):
        """
        Na začiatku preskenuje celú lokálnu sieť a uloží si aktuálne IP → MAC adresy
        Pomocou arping() získame odpovede od všetkých aktívnych zariadení
        """
        ans, _ = arping(network, verbose=False)
        for snd, rcv in ans:
            ip = rcv.psrc
            mac = rcv.hwsrc
            if self._valid_ip(ip) and self._valid_mac(mac):
                self.ip_mac_map[ip] = mac

    def packet_callback(self, pkt):
        """
        Táto funkcia sa volá pri každom zachytenom ARP pakete.
        Skontroluje, či je odpoveď legitímna, alebo ide o spoofing.
        """
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:

            now = time.time()
            self.packet_times.append(now)  # PRE GRAF

            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc

            if not self._valid_ip(ip) or not self._valid_mac(mac):
                return

            if ip in self.ip_mac_map:
                if self.ip_mac_map[ip] != mac:
                    last_time = self.last_alert_time.get(ip, 0)

                    if now - last_time > self.alert_cooldown:
                        alert_msg = f"[ALERT] Possible ARP spoofing detected! IP {ip} is at {mac}, but was previously at {self.ip_mac_map[ip]}"
                        if self.alert_callback:
                            self.alert_callback(alert_msg)
                        else:
                            print(alert_msg)

                        self.last_alert_time[ip] = now
            else:
                self.ip_mac_map[ip] = mac

    def get_rate(self):
        """
        Vráti počet ARP paketov za poslednú sekundu.
        Používa sa pre realtime graf.
        """
        now = time.time()
        return len([t for t in self.packet_times if now - t <= 1])

    def start(self, iface=None, network="10.0.2.0/24"):
        self.running = True
        self.preload_known_macs(network)

        self.sniffer = AsyncSniffer(
            prn=self.packet_callback,
            filter="arp",
            store=False,
            iface=iface
        )

        self.sniffer.start()

    def stop(self):
        self.running = False
        if self.sniffer and self.sniffer.running:
            try:
                self.sniffer.stop()
            except:
                pass
