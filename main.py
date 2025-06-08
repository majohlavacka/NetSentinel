import curses           # Knižnica pre tvorbu textového UI v termináli
import threading        # Na spustenie viacerých detektorov súbežne
import time             # Na časové oneskorenia v cykloch
import requests         # Na posielanie alertov cez HTTP (napr. Discord webhook)
from dotenv import load_dotenv  # Na načítanie environment premenných z .env súboru
import os               # Na prístup k environment premenným

# Import vlastných modulov detekcie
from Modules.scanner_detect import PortScanDetector
from Modules.device_scanner import scan_network
from Modules.arp_spoofing import ARPSpoofDetector
from Modules.ping_flood import ICMPFloodDetector

# Načítanie premenných z .env súboru
load_dotenv()

# Zámok na bezpečný prístup k zdieľanej premennej medzi vláknami
alert_lock = threading.Lock()

# Premenná na uchovanie poslednej alert správy
alert_message = None

# Riadiaca premenná pre hlavný cyklus
running = True

# Načítanie Discord webhook URL z .env súboru
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")


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


def alert_callback(msg):
    """
    Nastaví alert správu a zároveň ju pošle na Discord.
    """
    global alert_message
    with alert_lock:
        alert_message = msg
    send_discord_alert(msg)


# Funkcie pre jednotlivé typy útokov
def portscan_alert(msg):
    alert_callback(msg)

def arp_spoof_alert(msg):
    alert_callback(msg)

def icmp_flood_alert(msg):
    alert_callback(msg)


def run_detector(detector_class, alert_func, *args, **kwargs):
    """
    Spustí detektor v samostatnom vlákne.
    """
    detector = detector_class(*args, **kwargs)
    detector.alert_callback = alert_func
    detector.start()


def main_interface(stdscr):
    """
    Terminálové rozhranie pomocou curses.
    Zobrazuje monitoring, alerty a umožňuje vypísať zariadenia.
    """
    global alert_message, running

    curses.curs_set(0)  # Skryje kurzor
    stdscr.nodelay(True)  # getch() nebude blokovať
    stdscr.clear()

    # Úvodná obrazovka
    stdscr.addstr(0, 0, "Welcome in NetSentinel...")
    stdscr.addstr(10, 0, "Version 1.0")
    stdscr.refresh()
    time.sleep(4)

    while running:
        stdscr.clear()

        # Načítaj správu ak existuje
        with alert_lock:
            msg = alert_message

        if msg:
            # Zobraz alert správu
            stdscr.addstr(0, 0, msg)
            stdscr.addstr(2, 0, "Press any key to return to monitoring...")
        else:
            # Monitoring beží
            stdscr.addstr(0, 0, "Monitoring...")
            stdscr.addstr(2, 0, "Press 'd' to list devices | Press 'x' to exit")

        stdscr.refresh()

        try:
            key = stdscr.getch()

            if key != -1:
                if msg:
                    # Ak bol zobrazený alert, vymaž ho
                    with alert_lock:
                        alert_message = None
                elif key == ord('d'):
                    # Zobraz zoznam zariadení
                    stdscr.clear()
                    stdscr.addstr(0, 0, "Connected Devices on Network (10.0.2.0/24):")
                    devices = scan_network("10.0.2.0/24")

                    if not devices:
                        stdscr.addstr(2, 0, "No devices found.")
                    else:
                        for idx, dev in enumerate(devices):
                            stdscr.addstr(2 + idx, 0, f"{dev['ip']} - {dev['mac']}")

                    stdscr.addstr(2 + len(devices) + 1, 0, "Press any key to return...")
                    stdscr.refresh()
                    stdscr.nodelay(False)
                    stdscr.getch()
                    stdscr.nodelay(True)

                elif key == ord('x'):
                    # Ukončenie programu
                    running = False

        except Exception as e:
            print(f"Error in main interface loop: {e}")

        time.sleep(0.5)  # Malá pauza v cykle


if __name__ == "__main__":
    threads = []

    # Zoznam detektorov a ich callback funkcií
    detectors = [
        (PortScanDetector, portscan_alert, ()),
        (ARPSpoofDetector, arp_spoof_alert, ()),
        (ICMPFloodDetector, icmp_flood_alert, (), {'threshold': 20, 'interval': 5}),
    ]

    # Spustenie každého detektora v samostatnom vlákne
    for det in detectors:
        cls = det[0]
        alert_func = det[1]
        args = det[2] if len(det) > 2 else ()
        kwargs = det[3] if len(det) > 3 else {}
        t = threading.Thread(target=run_detector, args=(cls, alert_func) + args, kwargs=kwargs, daemon=True)
        t.start()
        threads.append(t)

    # Spustenie UI
    curses.wrapper(main_interface)
