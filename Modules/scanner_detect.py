from scapy.all import AsyncSniffer, TCP, IP
import time
from ipaddress import ip_address, IPv4Address  # Pre validáciu IP adries

class PortScanDetector:
    def __init__(self, threshold=10, interval=5, cooldown=300):
        self.threshold = threshold
        self.interval = interval
        self.cooldown = cooldown

        self.syn_packets = {}        # {IP: [časové značky SYN packetov]}
        self.alerted_ips = {}        # {IP: čas posledného alertu}
        self.alert_callback = None   # Callback na alerty

        self.running = False
        self.sniffer = None          # AsyncSniffer inštancia

    def packet_callback(self, pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]

            try:
                src_ip = ip_layer.src
                ip_obj = ip_address(src_ip)
                if not isinstance(ip_obj, IPv4Address):
                    return
                if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved or ip_obj.is_loopback:
                    return
            except ValueError:
                return

            if tcp_layer.flags == 'S':  # SYN flag
                now = time.time()

                # Cooldown kontrola
                if src_ip in self.alerted_ips and (now - self.alerted_ips[src_ip] < self.cooldown):
                    return
                elif src_ip in self.alerted_ips:
                    del self.alerted_ips[src_ip]

                if src_ip not in self.syn_packets:
                    self.syn_packets[src_ip] = []

                self.syn_packets[src_ip].append(now)
                self.syn_packets[src_ip] = [t for t in self.syn_packets[src_ip] if now - t <= self.interval]

                if len(self.syn_packets[src_ip]) > self.threshold:
                    if self.alert_callback:
                        self.alert_callback(f"[ALERT] Possible port scan from IP {src_ip}")
                    else:
                        print(f"[ALERT] Possible port scan from IP {src_ip}")

                    self.alerted_ips[src_ip] = now
                    self.syn_packets[src_ip] = []

    def start(self, iface=None):
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
        self.running = False
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
