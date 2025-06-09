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
if not DISCORD_WEBHOOK_URL:
    print("[ERROR] DISCORD_WEBHOOK_URL not set in environment variables.")  # Kontrola existence webhooku
    exit(1)  # Ukončí program ak webhook nie je definovaný


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


def run_detector(detector):
    """
    Spustí detektor (jeho metódu start).
    """
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

    # ASCII obrazok pri štarte
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

    # Vypíš splash_screen na stred obrazovky
    height, width = stdscr.getmaxyx()
    start_y = max(0, height//2 - len(splash_screen)//2)
    for i, line in enumerate(splash_screen):
        x = max(0, width//2 - len(line)//2)
        stdscr.addstr(start_y + i, x, line)
    stdscr.refresh()
    time.sleep(4)

    dot_count = 0  # Pridane pre animaciu bodiek za Monitoring

    while running:
        stdscr.clear()

        # Načítaj správu ak existuje
        with alert_lock:
            msg = alert_message

        if msg:
            # Zobraz alert správu
            stdscr.addstr(0, 0, msg)
            stdscr.addstr(2, 0, "Press 'b' to return to monitoring...")
        else:
            # Monitoring beží
            dot_count = (dot_count + 1) % 4  # 0,1,2,3 cyklus pre bodky
            dots = '.' * dot_count
            stdscr.addstr(0, 0, "Monitoring" + dots)

            # Čitateľné ovládanie (usporiadané)
            controls = "Controls: [d] Scan network | [b] Back | [x] Exit"
            stdscr.addstr(2, 0, controls)

        stdscr.refresh()

        try:
            key = stdscr.getch()

            if key != -1:
                if msg:
                    # Ak bol zobrazený alert alebo v inej obrazovke, len "b" vracia späť
                    if key == ord('b'):
                        with alert_lock:
                            alert_message = None
                else:
                    if key == ord('d'):
                        stdscr.clear()
                        info_msg = f"[INFO] Scanning network 10.0.2.0/24..."
                        stdscr.addstr(0, 0, info_msg)
                        stdscr.refresh()

                        # Volanie scan_network priamo, čaká synchronne na výsledok
                        devices = scan_network("10.0.2.0/24")  # UPRAVA: synchronný scan, môže spomaliť UI

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

                        # Čakáme, kým používateľ stlačí 'b' na návrat
                        while True:
                            k = stdscr.getch()
                            if k == ord('b'):
                                break

                        stdscr.nodelay(True)

                    elif key == ord('x'):
                        # Zobraz hlášku a ukonči program po 3 sekundách
                        stdscr.clear()
                        stdscr.addstr(height//2, max(0, width//2 - len("NetSentinel is ending")//2), "NetSentinel is ending")
                        stdscr.refresh()
                        time.sleep(3)

                        # Ukončíme hlavný cyklus
                        running = False

                    elif key == ord('b'):
                        # Ak sme na hlavnej obrazovke a stlačíme b, nič sa nestane, len ignorujeme
                        pass

        except Exception as e:
            print(f"Error in main interface loop: {e}")

        time.sleep(0.5)  # Spomalí sa reakcia používateľského rozhrania (napr. bodky budú pomalšie), zároveň sa ušetrí CPU záťaž


if __name__ == "__main__":
    threads = []
    detectors_instances = []  # Ukladáme inštancie detektorov pre stop

    # Zoznam detektorov a ich callback funkcií
    detectors = [
        (PortScanDetector, portscan_alert, ()), 
        (ARPSpoofDetector, arp_spoof_alert, ()),
        (ICMPFloodDetector, icmp_flood_alert, ()),
    ]

    # Spustenie každého detektora v samostatnom bežnom vlákne (nie daemon)
    for det in detectors:
        cls = det[0] # Zober triedu detektora (napr. ICMPFloodDetector)
        alert_func = det[1] # Zober funkciu, ktorá sa má zavolať pri alerte
        args = det[2] if len(det) > 2 else () # Ak sú špeciálne argumenty, zober ich
        kwargs = det[3] if len(det) > 3 else {} # Ak sú kľúčové argumenty, zober ich tiež

        detector_instance = cls(*args, **kwargs) # Vytvorenie inštancie detektora s parametrami (args a kwargs)
        detector_instance.alert_callback = alert_func # Nastavenie callback funkcie, ktorá sa zavolá pri detekcii útoku (alert)
        detectors_instances.append(detector_instance) # Uloženie inštancie detektora do zoznamu, aby sme s ňou mohli neskôr pracovať (napr. zastaviť ho)

	# Vytvorenie a spustenie nového vlákna, ktoré spustí metódu start detektora
	# run_detector() zavolá detektor_instance.start() (spustí detekciu)	
        t = threading.Thread(target=run_detector, args=(detector_instance,), daemon=False)
        t.start() # Štart vlákna, ktoré beží súbežne s hlavným programom
        threads.append(t) # Toto nám umožní neskôr na všetky tieto vlákna počkať (join), aby sa správne ukončili pred ukončením celého programu.

    # Spustenie UI
    curses.wrapper(main_interface)

    # Po ukončení UI (napr. po stlačení 'x') - korektné zastavenie detektorov
    for det in detectors_instances:
        det.stop()  # DOPLNENIE: zavolanie metódy stop pre každého detektora

    # Počkajte na dokončenie všetkých vlákien
    for t in threads:
        t.join()
