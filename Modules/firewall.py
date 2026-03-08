import subprocess

# IP adresy ktoré nikdy nechceme blokovať
WHITELIST = {
    "127.0.0.1",
    "10.0.2.1"
}

# zoznam už blokovaných IP
blocked_ips = set()

# CALLBACK DO UI
alert_callback = None


def set_alert_callback(callback):
    """
    Nastaví callback aby firewall vedel poslať alert do UI.
    """
    global alert_callback
    alert_callback = callback


def block_ip(ip):
    """
    Zablokuje IP adresu pomocou UFW firewallu.
    """

    if ip in WHITELIST:
        return

    if ip in blocked_ips:
        return

    try:

        subprocess.run(
            ["sudo", "ufw", "deny", "from", ip],
            check=True
        )

        blocked_ips.add(ip)

        message = f"[IPS] IP {ip} blocked by firewall"

        print(message)

        # POŠLI ALERT DO UI
        if alert_callback:
            alert_callback(message)

    except Exception as e:
        print(f"[IPS ERROR] {e}")


def is_blocked(ip):
    """
    Kontrola či je IP blokovaná.
    """
    return ip in blocked_ips
import subprocess

# IP adresy ktoré nikdy nechceme blokovať
WHITELIST = {
    "127.0.0.1",
    "10.0.2.1"
}

# zoznam už blokovaných IP
blocked_ips = set()

# CALLBACK DO UI
alert_callback = None


def set_alert_callback(callback):
    """
    Nastaví callback aby firewall vedel poslať alert do UI.
    """
    global alert_callback
    alert_callback = callback


def block_ip(ip):
    """
    Zablokuje IP adresu pomocou UFW firewallu.
    """

    if ip in WHITELIST:
        return

    if ip in blocked_ips:
        return

    try:

        subprocess.run(
            ["sudo", "ufw", "deny", "from", ip],
            check=True
        )

        blocked_ips.add(ip)

        message = f"[IPS] IP {ip} blocked by firewall"

        print(message)

        # POŠLI ALERT DO UI
        if alert_callback:
            alert_callback(message)

    except Exception as e:
        print(f"[IPS ERROR] {e}")


def is_blocked(ip):
    """
    Kontrola či je IP blokovaná.
    """
    return ip in blocked_ips
