import curses           # Knižnica pre tvorbu textového UI v termináli
import threading        # Na spustenie viacerých detektorov súbežne
import time             # Na časové oneskorenia v cykloch
import requests         # Na posielanie alertov cez HTTP (napr. Discord webhook)
from dotenv import load_dotenv  # Na načítanie environment premenných z .env súboru
import os               # Na prístup k environment premenným

# Import vlastných modulov detekcie útokov
from Modules.scanner_detect import PortScanDetector
from Modules.device_scanner import scan_network
from Modules.arp_spoofing import ARPSpoofDetector
from Modules.ping_flood import ICMPFloodDetector

# Import firewall modulu aby IPS vedel posielať správy do UI
from Modules.firewall import set_alert_callback


# Načítanie premenných z .env súboru (napr. Discord webhook)
load_dotenv()


# Zámok pre bezpečný prístup k zdieľaným premenným medzi vláknami
alert_lock = threading.Lock()


# Premenná ktorá uchováva posledný alert (správa + typ modulu)
alert_message = None


# Riadiaca premenná hlavného cyklu programu
running = True


# Načítanie Discord webhook URL z environment premenných
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

# Ak webhook nie je nastavený program sa ukončí
if not DISCORD_WEBHOOK_URL:
    print("[ERROR] DISCORD_WEBHOOK_URL not set in environment variables.")
    exit(1)


# Funkcia ktorá pošle alert správu na Discord server
def send_discord_alert(message: str):
    """
    Pošle správu na Discord pomocou webhooku.
    V prípade chyby vypíše stavový kód a odpoveď.
    """

    data = {"content": message}

    try:

        response = requests.post(DISCORD_WEBHOOK_URL, json=data)

        if response.status_code not in (200, 204):

            print(f"Chyba pri posielaní Discord alertu: {response.status_code} {response.text}")

    except Exception as e:

        print(f"Výnimka pri posielaní Discord alertu: {e}")


# =========================================
# Centrálny alert callback pre všetky moduly
# =========================================
# Ukladá alert do UI a zároveň ho posiela na Discord
def alert_callback(msg, module):

    global alert_message

    with alert_lock:

        alert_message = (msg, module)

    send_discord_alert(msg)


# =========================================
# Nastavenie callbacku pre firewall (IPS)
# =========================================
# Firewall môže poslať správu do UI keď zablokuje IP
set_alert_callback(lambda msg: alert_callback(msg, "IPS"))


# =========================================
# Callback funkcie pre jednotlivé detektory
# =========================================

# Port scan detektor
def portscan_alert(msg):
    alert_callback(msg, "PORTSCAN")


# ARP spoofing detektor
def arp_spoof_alert(msg):
    alert_callback(msg, "ARP")


# ICMP flood detektor
def icmp_flood_alert(msg):
    alert_callback(msg, "ICMP")


# Funkcia ktorá spustí detektor
def run_detector(detector):

    """
    Spustí detektor (jeho metódu start).
    """

    detector.start()


# =========================================
# Funkcia na vykreslenie ASCII grafu
# =========================================
# Graf zobrazuje počet paketov za sekundu
def draw_graph(stdscr, values, y, x, height=6, width=50):

    """
    Vykreslí jednoduchý ASCII graf do terminálu pomocou blokových znakov.

    Ak nie je žiadny traffic (packets/sec = 0),
    zobrazí baseline čiarkovanie aby bolo vidieť,
    že monitoring stále beží.
    """

    if not values:
        return

    max_val = max(values)

    if max_val == 0:
        max_val = 1

    values = values[-width:]

    for i, val in enumerate(values):

        bar_height = int((val / max_val) * height)

        stdscr.addstr(y + height, x + i, "─")

        for h in range(bar_height):
            stdscr.addstr(y + height - h - 1, x + i, "█")


# =========================================
# Hlavné terminálové UI (curses)
# =========================================
def main_interface(stdscr, detectors):

    """
    Terminálové rozhranie pomocou curses.
    Zobrazuje monitoring, alerty a umožňuje vypísať zariadenia.
    """

    global alert_message, running

    curses.curs_set(0)   # skryje kurzor
    stdscr.nodelay(True) # getch nebude blokovať
    stdscr.clear()


    # História hodnôt pre grafy
    history = {
        "ICMP": [],
        "ARP": [],
        "PORTSCAN": []
    }


    # ASCII splash screen pri štarte aplikácie
    splash_screen = [
        "##############################################################################",
        "#                                                                            #",
        "#   ######*@**@@%##**##%#                          #%%#**##%%%@**#%**#*###   #",
        "#    ##*####%@%%%#####%%@%###*                 ####%@%#####%###@@@%######    #",
        "#     #####**           ##%%%#               #**#%%*#         #****####      #",
        "#       ##***%           ##**#%#            #%#**##          %#*****#        #",
        "#         #*#%           %#****##          ##****##          %#**#           #",
        "#          ##%%@        @#******#%        #%******#%        %%*@             #",
        "#              #@@@@@@@%%##%%#                #%##%%%@@@@@@@#                #",
        "#                                                                            #",
        "#                                                                            #",
        "#                                                          NETSENTINEL v1.0  #",
        "#                                                                            #",
        "##############################################################################",
    ]


    height, width = stdscr.getmaxyx()

    start_y = max(0, height//2 - len(splash_screen)//2)


    # Vykreslenie splash screen
    for i, line in enumerate(splash_screen):

        x = max(0, width//2 - len(line)//2)

        stdscr.addstr(start_y + i, x, line)


    stdscr.refresh()
    time.sleep(3)


    dot_count = 0


    # =========================================
    # Hlavný cyklus UI
    # =========================================
    while running:

        stdscr.clear()

        with alert_lock:
            msg = alert_message


        # Získanie detektorov
        portscan = detectors[0]
        arp = detectors[1]
        icmp = detectors[2]


        # Získanie aktuálneho trafficu
        ps_rate = portscan.get_rate()
        arp_rate = arp.get_rate()
        icmp_rate = icmp.get_rate()


        # Uloženie do histórie pre graf
        history["PORTSCAN"].append(ps_rate)
        history["ARP"].append(arp_rate)
        history["ICMP"].append(icmp_rate)

        for k in history:
            history[k] = history[k][-60:]


        # =========================================
        # ALERT OBRAZOVKA
        # =========================================
        if msg:

            alert_text, module = msg

            stdscr.addstr(0, 0, alert_text)


            if module == "ICMP":

                stdscr.addstr(2, 0, "Attack realtime activity:")
                stdscr.addstr(4, 0, f"ICMP packets/sec: {icmp_rate}")
                draw_graph(stdscr, history["ICMP"], 5, 0)


            elif module == "ARP":

                stdscr.addstr(2, 0, "Attack realtime activity:")
                stdscr.addstr(4, 0, f"ARP packets/sec: {arp_rate}")
                draw_graph(stdscr, history["ARP"], 5, 0)


            elif module == "PORTSCAN":

                stdscr.addstr(2, 0, "Attack realtime activity:")
                stdscr.addstr(4, 0, f"SYN packets/sec: {ps_rate}")
                draw_graph(stdscr, history["PORTSCAN"], 5, 0)


            # IPS obrazovka keď firewall zablokuje útočníka
            elif module == "IPS":

                stdscr.addstr(2, 0, "Firewall response:")
                stdscr.addstr(4, 0, "Attacker blocked by UFW firewall.")
                stdscr.addstr(6, 0, f"Attack attempts/sec: {icmp_rate}")
                draw_graph(stdscr, history["ICMP"], 7, 0)


            stdscr.addstr(15, 0, "Press 'b' to return to monitoring...")


        # =========================================
        # HLAVNÝ MONITORING SCREEN
        # =========================================
        else:

            dot_count = (dot_count + 1) % 4
            dots = '.' * dot_count

            stdscr.addstr(0, 0, "Monitoring" + dots)

            controls = "Controls: [d] Scan network | [b] Back | [x] Exit"
            stdscr.addstr(2, 0, controls)


            stdscr.addstr(4, 0, f"ICMP packets/sec: {icmp_rate}")
            draw_graph(stdscr, history["ICMP"], 5, 0)


            stdscr.addstr(12, 0, f"ARP packets/sec: {arp_rate}")
            draw_graph(stdscr, history["ARP"], 13, 0)


            stdscr.addstr(20, 0, f"TCP SYN packets/sec: {ps_rate}")
            draw_graph(stdscr, history["PORTSCAN"], 21, 0)


        stdscr.refresh()


        # =========================================
        # Spracovanie vstupu z klávesnice
        # =========================================
        try:

            key = stdscr.getch()

            if key != -1:

                if msg:

                    if key == ord('b'):

                        with alert_lock:
                            alert_message = None

                else:

                    # Spustenie skenu siete
                    if key == ord('d'):

                        stdscr.clear()

                        info_msg = f"[INFO] Scanning network 10.0.2.0/24..."

                        stdscr.addstr(0, 0, info_msg)

                        stdscr.refresh()

                        devices = scan_network("10.0.2.0/24")

                        stdscr.clear()

                        stdscr.addstr(0, 0, "Connected Devices on Network (10.0.2.0/24):")

                        if not devices:
                            stdscr.addstr(2, 0, "No devices found.")

                        else:
                            for idx, dev in enumerate(devices):
                                stdscr.addstr(2 + idx, 0, f"{dev['ip']} - {dev['mac']}")

                        stdscr.addstr(2 + len(devices) + 1, 0, "Press 'b' to return...")

                        stdscr.refresh()

                        stdscr.nodelay(False)

                        while True:
                            k = stdscr.getch()
                            if k == ord('b'):
                                break

                        stdscr.nodelay(True)


                    # Ukončenie programu
                    elif key == ord('x'):

                        stdscr.clear()

                        stdscr.addstr(height//2, max(0, width//2 - len("NetSentinel is ending")//2), "NetSentinel is ending")

                        stdscr.refresh()

                        time.sleep(3)

                        running = False

        except Exception as e:

            print(f"Error in main interface loop: {e}")

        time.sleep(0.5)


# =========================================
# HLAVNÝ ENTRY POINT PROGRAMU
# =========================================
if __name__ == "__main__":

    threads = []
    detectors_instances = []


    # Zoznam detektorov ktoré sa spustia
    detectors = [
        (PortScanDetector, portscan_alert, ()),
        (ARPSpoofDetector, arp_spoof_alert, ()),
        (ICMPFloodDetector, icmp_flood_alert, ()),
    ]


    # Spustenie každého detektora v samostatnom vlákne
    for det in detectors:

        cls = det[0]
        alert_func = det[1]

        args = det[2] if len(det) > 2 else ()
        kwargs = det[3] if len(det) > 3 else {}

        detector_instance = cls(*args, **kwargs)

        detector_instance.alert_callback = alert_func

        detectors_instances.append(detector_instance)

        t = threading.Thread(target=run_detector, args=(detector_instance,), daemon=False)

        t.start()

        threads.append(t)


    # Spustenie terminálového UI
    curses.wrapper(main_interface, detectors_instances)


    # Po ukončení UI zastavíme všetky detektory
    for det in detectors_instances:
        det.stop()


    # Počkáme na ukončenie všetkých vlákien
    for t in threads:
        t.join()