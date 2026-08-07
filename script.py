import socket
import requests
import os
from datetime import datetime
import time

UDP_IP = "0.0.0.0"
UDP_PORT = 514

# VictoriaLogs URL из переменной окружения
VICTORIA_URL = os.environ.get("VICTORIA_URL", "http://victorialogs:9428")

# Файл для сохранения всех логов (будет смонтирован наружу)
LOG_FILE = "/logs/access.log"

DEVICE_NAMES = {
    "10.204.7.7": "CONT 2.3.1",
    "192.168.5.100": "eti-serv3-new",
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

HEX_CHARS = set('0123456789abcdefABCDEF')

def extract_hex_code(message):
    """Извлекает 16-значный hex-код из сообщения в любом формате"""
    # Ищем в кавычках
    start = message.find("'")
    while start != -1:
        end = start + 17
        if end < len(message) and message[end] == "'":
            code = message[start+1:end]
            if len(code) == 16 and all(c in HEX_CHARS for c in code):
                return code
        start = message.find("'", start + 1)
    
    # Ищем без кавычек
    i = 0
    while i < len(message) - 15:
        if message[i] in HEX_CHARS:
            code = message[i:i+16]
            if len(code) == 16 and all(c in HEX_CHARS for c in code):
                before_ok = (i == 0 or message[i-1] not in HEX_CHARS)
                after_ok = (i+16 == len(message) or message[i+16] not in HEX_CHARS)
                if before_ok and after_ok:
                    return code
        i += 1
    return None

def is_relevant_log(message):
    """Проверяет, содержит ли сообщение 16-значный hex-код"""
    if "ca_module_arm" not in message and "net_module_arm" not in message:
        return False
    return extract_hex_code(message) is not None

def extract_key_info(message):
    """Извлекает информацию из сообщения"""
    result = {
        "code": extract_hex_code(message),
        "user": None,
        "room": None,
        "status": "UNKNOWN"
    }
    
    mr_pos = message.find("Mr. '")
    if mr_pos != -1:
        end_quote = message.find("'", mr_pos + 5)
        if end_quote != -1:
            content = message[mr_pos + 5:end_quote]
            parts = content.split()
            for part in parts:
                if part.startswith("Room_"):
                    result["room"] = part[5:]
                elif part.isdigit() and not result["user"]:
                    result["user"] = part
    
    if "ACCESS APPROVED" in message:
        result["status"] = "APPROVED"
    elif "ACCESS_DENIED" in message or "ACCESS DENIED" in message:
        result["status"] = "DENIED"
    
    return result

def write_log(timestamp, device_name, info):
    """Записывает лог в файл и выводит в консоль"""
    log_line = f"{timestamp} | {device_name} | {info['user'] or '?'} | Room {info['room'] or '?'} | {info['status']} | {info['code']}\n"
    
    # Пишем в консоль
    print(log_line.strip(), flush=True)
    
    # Пишем в файл
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line)
            f.flush()  # Принудительно записываем на диск
    except Exception as e:
        print(f"Error writing to log file: {e}", flush=True)

# Создаем директорию для логов если её нет
try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
except:
    pass

# Создаем сокет
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
sock.bind((UDP_IP, UDP_PORT))
sock.settimeout(1)

print(f"UDP server listening on {UDP_IP}:{UDP_PORT}", flush=True)
print(f"Sending to VictoriaLogs at {VICTORIA_URL}", flush=True)
print(f"Logging to {LOG_FILE}", flush=True)

counter = 0

while True:
    try:
        data, addr = sock.recvfrom(65535)
        
        try:
            message = data.decode('utf-8', errors='ignore').strip()
        except:
            continue
            
        if not message:
            continue

        if not is_relevant_log(message):
            continue

        source_ip = addr[0]
        device_name = DEVICE_NAMES.get(source_ip, source_ip)
        info = extract_key_info(message)

        if info["code"]:
            counter += 1
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Сохраняем лог в файл и выводим в консоль
            write_log(timestamp, device_name, info)

            # Отправляем в VictoriaLogs
            payload = {
                "_msg": message,
                "device": device_name,
                "source_ip": source_ip,
                "key_code": info["code"],
                "user": info["user"] or "",
                "room": info["room"] or "",
                "access_status": info["status"],
                "timestamp": timestamp
            }

            try:
                resp = requests.post(
                    f"{VICTORIA_URL}/insert/jsonline?_stream_fields=device,source_ip",
                    headers={"Content-Type": "application/json"},
                    json=payload,
                    timeout=2
                )
                if resp.status_code != 204:
                    print(f"HTTP error: {resp.status_code} for {info['code']}", flush=True)
            except Exception as e:
                print(f"Request error: {e}", flush=True)

    except socket.timeout:
        pass
    except Exception as e:
        print(f"Error: {e}", flush=True)