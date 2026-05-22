import socket
import requests
import os

UDP_IP = "0.0.0.0"
UDP_PORT = 514

# VictoriaLogs URL из переменной окружения
VICTORIA_URL = os.environ.get("VICTORIA_URL", "http://victorialogs:9428")

DEVICE_NAMES = {
    "10.204.7.7": "CONT 2.3.1",
    "10.204.1.200": "eti-serv3",
    "10.204.6.2": "2.2 калитка",
    "10.204.7.6": "2.3 Вх Гр Д",
    "10.204.7.4": "2.3 Вх Гр У",
    "10.204.7.2": "2.3 Калитка",
    "10.204.6.6": "CONT 2.2.1",
    "10.204.6.5": "CONT 2.2.2",
    "10.204.6.4": "2.2 Вх Гр",
    "10.204.5.5": "CONT 2.1.2",
    "10.204.5.4": "CONT 2.1.1",
    "10.204.5.3": "CONT 2.1.3",
    "10.204.5.2": "2.1 Вх Гр",
    "10.204.4.104": "CONT 1.4.4",
    "10.204.4.103": "CONT 1.4.3",
    "10.204.4.102": "CONT 1.4.2",
    "10.204.4.101": "CONT 1.4.1",
    "10.204.4.51": "1.4 Вх Гр Д",
    "10.204.4.50": "1.4 Вх Гр У",
    "10.204.3.104": "CONT 1.3.4",
    "10.204.3.103": "CONT 1.3.3",
    "10.204.3.102": "CONT 1.3.2",
    "10.204.3.101": "CONT 1.3.1",
    "10.204.3.52": "Сосед ц.",
    "10.204.3.51": "1.3 Вх Гр Д",
    "10.204.3.50": "1.3 Вх Гр У",
    "10.204.2.103": "CONT 1.2.3",
    "10.204.2.102": "CONT 1.2.2",
    "10.204.2.101": "CONT 1.2.1",
    "10.204.2.50": "1.2 Вх Гр У",
    "10.204.1.104": "CONT 1.1.4",
    "10.204.1.103": "CONT 1.1.3",
    "10.204.1.102": "CONT 1.1.2",
    "10.204.1.101": "CONT 1.1.1",
    "10.204.1.50": "1.1 Вх Гр Д",
    "10.204.1.49": "1.1 спуск в P",
    "10.204.1.45": "1.1 Калитка",
}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))
sock.settimeout(1)

print(f"UDP server listening on {UDP_IP}:{UDP_PORT}", flush=True)
print(f"Sending to VictoriaLogs at {VICTORIA_URL}", flush=True)

while True:
    try:
        data, addr = sock.recvfrom(65535)
        message = data.decode('utf-8', errors='ignore').strip()
        if message:
            source_ip = addr[0]
            device_name = DEVICE_NAMES.get(source_ip, source_ip)

            print(f"Received from {source_ip} ({device_name}): {message[:80]}...", flush=True)

            payload = {
                "_msg": message,
                "device": device_name,
                "source_ip": source_ip
            }
            try:
                resp = requests.post(
                    f"{VICTORIA_URL}/insert/jsonline?_stream_fields=device,source_ip",
                    headers={"Content-Type": "application/json"},
                    json=payload,
                    timeout=2
                )
                if resp.status_code != 204:
                    print(f"HTTP error: {resp.status_code}", flush=True)
            except Exception as e:
                print(f"Request error: {e}", flush=True)
    except socket.timeout:
        pass
    except Exception as e:
        print(f"Error: {e}", flush=True)