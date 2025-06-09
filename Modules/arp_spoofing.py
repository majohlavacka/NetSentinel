from scapy.all import ARP, sniff, arping
import threading
import time
import re

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
        # Flag na riadenie behu sniffu
        self.running = False

    def _valid_ip(self, ip):
        # Regex validácia IPv4 adresy pre kontrolu správnosti formátu
        pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if not pattern.match(ip):
            return False
        # kontrola, či každá časť je v rozsahu 0-255
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
            # Validuj IP a MAC pred uložením
            if self._valid_ip(ip) and self._valid_mac(mac):
                self.ip_mac_map[ip] = mac  # uložíme legitímnu MAC pre každú IP

    def packet_callback(self, pkt):
        """
        Táto funkcia sa volá pri každom zachytenom ARP pakete.
        Skontroluje, či je odpoveď legitímna, alebo ide o spoofing.
        """
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # op == 2 → ARP Reply
            ip = pkt[ARP].psrc     # Zdrojová IP adresa
            mac = pkt[ARP].hwsrc   # Zdrojová MAC adresa

            # Validuj IP a MAC, aby sme ignorovali chybné pakety
            if not self._valid_ip(ip) or not self._valid_mac(mac):
                return  # ignoruj paket

            # Ak už túto IP poznáme, porovnáme jej MAC
            if ip in self.ip_mac_map:
                if self.ip_mac_map[ip] != mac:
                    now = time.time()
                    last_time = self.last_alert_time.get(ip, 0)
                    # Rate limiting alertov - aspoň alert_cooldown sekúnd medzi alertami pre rovnakú IP
                    if now - last_time > self.alert_cooldown:
                        alert_msg = f"[ALERT] Possible ARP spoofing detected! IP {ip} is at {mac}, but was previously at {self.ip_mac_map[ip]}"
                        if self.alert_callback:
                            self.alert_callback(alert_msg)  # odovzdáme alert späť do hlavnej aplikácie
                        else:
                            print(alert_msg)
                        self.last_alert_time[ip] = now
            else:
                # Ak IP ešte nepoznáme, pridáme si ju do mapy
                self.ip_mac_map[ip] = mac

    def start(self, iface=None, network="10.0.2.0/24"):
        """
        Hlavná funkcia – najprv si načítame legitímne IP-MAC adresy a potom počúvame ARP odpovede.
        Používame stop_filter na bezpečné ukončenie sniffu.
        """
        self.running = True
        self.preload_known_macs(network)  # naskenujeme sieť na začiatku

        def stop_filter(pkt):
            # Keď self.running je False, sniff skončí
            return not self.running

        sniff(prn=self.packet_callback, filter="arp", store=False, iface=iface, stop_filter=stop_filter)

    def stop(self):
        """
        Funkcia na zastavenie sniffovania.
        Nastaví flag, ktorý spôsobí ukončenie sniffu.
        """
        self.running = False
