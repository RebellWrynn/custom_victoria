#!/usr/bin/env python3
"""
Скрипт для сбора событий доступа в реальном времени.
Запуск: python3 collect_events.py
Остановка: Ctrl+C

Все события записываются в файл access_events.log в формате:
время | L3-адрес | CONT | ключ | статус | пользователь
"""

import socket
import os
import re
import signal
import sys
from datetime import datetime

UDP_IP = "0.0.0.0"
UDP_PORT = 514

# Файл для записи событий
LOG_FILE = "access_events.log"

# --- СОПОСТАВЛЕНИЕ IP УСТРОЙСТВ С ИМЕНАМИ ---
DEVICE_NAMES = {
    "10.204.7.7": "CONT 2.3.1",
    "10.204.7.6": "CONT 2.3 Вх Гр Д",
    "10.204.7.4": "CONT 2.3 Вх Гр У",
    "10.204.7.2": "CONT 2.3 Калитка",
    "10.204.6.6": "CONT 2.2.1",
    "10.204.6.5": "CONT 2.2.2",
    "10.204.6.4": "CONT 2.2 Вх Гр",
    "10.204.5.5": "CONT 2.1.2",
    "10.204.5.4": "CONT 2.1.1",
    "10.204.5.3": "CONT 2.1.3",
    "10.204.5.2": "CONT 2.1 Вх Гр",
    "10.204.4.104": "CONT 1.4.4",
    "10.204.4.103": "CONT 1.4.3",
    "10.204.4.102": "CONT 1.4.2",
    "10.204.4.101": "CONT 1.4.1",
    "10.204.4.51": "CONT 1.4 Вх Гр Д",
    "10.204.4.50": "CONT 1.4 Вх Гр У",
    "10.204.3.104": "CONT 1.3.4",
    "10.204.3.103": "CONT 1.3.3",
    "10.204.3.102": "CONT 1.3.2",
    "10.204.3.101": "CONT 1.3.1",
    "10.204.3.51": "CONT 1.3 Вх Гр Д",
    "10.204.3.50": "CONT 1.3 Вх Гр У",
    "10.204.2.103": "CONT 1.2.3",
    "10.204.2.102": "CONT 1.2.2",
    "10.204.2.101": "CONT 1.2.1",
    "10.204.2.50": "CONT 1.2 Вх Гр У",
    "10.204.1.104": "CONT 1.1.4",
    "10.204.1.103": "CONT 1.1.3",
    "10.204.1.102": "CONT 1.1.2",
    "10.204.1.101": "CONT 1.1.1",
    "10.204.1.50": "CONT 1.1 Вх Гр Д",
    "10.204.1.45": "CONT 1.1 Калитка",
    "10.204.1.200": "eti-serv3",
}

HEX_CHARS = set('0123456789abcdefABCDEF')


def signal_handler(sig, frame):
    print("\n👋 Stopping collector...", flush=True)
    sys.exit(0)


def extract_hex_code(message):
    """Извлекает 16-значный hex-код из сообщения."""
    start = message.find("'")
    while start != -1:
        end = start + 17
        if end < len(message) and message[end] == "'":
            code = message[start+1:end]
            if len(code) == 16 and all(c in HEX_CHARS for c in code):
                return code
        start = message.find("'", start + 1)

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


def extract_l3_address(message):
    """Извлекает L3 адрес (8 символов, начинается с 00)."""
    match = re.search(r'"dstaddr":\s*"([0-9A-Fa-f]{8})"', message, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    
    match = re.search(r'"srcaddr":\s*"([0-9A-Fa-f]{8})"', message, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    
    match = re.search(r'(00[0-9A-Fa-f]{6})', message)
    if match:
        return match.group(1).upper()
    
    return None


def extract_user_id(message):
    """Извлекает ID пользователя."""
    match = re.search(r'auth_requested.*username=([0-9]+)', message)
    if match:
        return match.group(1)
    match = re.search(r"Mr\. '([0-9]+)", message)
    if match:
        return match.group(1)
    return None


def extract_timestamp(message):
    """Извлекает время из сообщения syslog."""
    # Формат: Aug 11 13:29:37
    match = re.search(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', message)
    if match:
        return match.group(1)
    return datetime.now().strftime("%b %d %H:%M:%S")


def is_access_event(message):
    """Проверяет, является ли сообщение событием доступа."""
    if "ACCESS APPROVED" in message or "ACCESS_DENIED" in message or "ACCESS DENIED" in message:
        return True
    if "ca_module_arm" in message and "access_decision" in message:
        return True
    if "net_module_arm" in message and "access_decision" in message:
        return True
    return False


def get_access_status(message):
    """Определяет статус доступа."""
    if "ACCESS APPROVED" in message:
        return "APPROVED"
    elif "ACCESS_DENIED" in message or "ACCESS DENIED" in message:
        return "DENIED"
    return "UNKNOWN"


def main():
    # Обработчик Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    print("=" * 80)
    print("🔑 ACCESS EVENT COLLECTOR")
    print("=" * 80)
    print(f"📡 Listening on UDP {UDP_IP}:{UDP_PORT}")
    print(f"📁 Writing to: {LOG_FILE}")
    print("⏹️  Press Ctrl+C to stop")
    print("=" * 80)
    print()

    # Проверяем, существует ли файл, и добавляем заголовок если новый
    file_exists = os.path.exists(LOG_FILE)
    
    # Открываем файл для записи (в режиме append)
    f = open(LOG_FILE, 'a', buffering=1)  # line buffering
    
    if not file_exists:
        f.write("# " + "=" * 100 + "\n")
        f.write("# ACCESS EVENTS LOG\n")
        f.write(f"# Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("# " + "=" * 100 + "\n")
        f.write("# TIME | L3_ADDRESS | CONT | KEY | STATUS | USER\n")
        f.write("#" + "-" * 100 + "\n")

    # Создаем сокет
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind((UDP_IP, UDP_PORT))
    sock.settimeout(1)

    event_count = 0

    while True:
        try:
            data, addr = sock.recvfrom(65535)

            try:
                message = data.decode('utf-8', errors='ignore').strip()
            except:
                continue

            if not message:
                continue

            # Фильтруем только события доступа
            if not is_access_event(message):
                continue

            # Извлекаем данные
            code = extract_hex_code(message)
            l3_addr = extract_l3_address(message)
            user_id = extract_user_id(message)
            status = get_access_status(message)
            timestamp = extract_timestamp(message)
            
            source_ip = addr[0]
            device_name = DEVICE_NAMES.get(source_ip, source_ip)

            # Если нет кода или L3-адреса — пропускаем
            if not code or not l3_addr:
                continue

            event_count += 1

            # Формируем строку для записи
            # TIME | L3_ADDRESS | CONT | KEY | STATUS | USER
            log_line = f"{timestamp} | {l3_addr} | {device_name} | {code} | {status} | {user_id or ''}\n"
            
            # Пишем в файл
            f.write(log_line)
            f.flush()

            # Выводим в консоль
            print(f"[{event_count:4d}] {timestamp} | {l3_addr} | {device_name[:20]:<20} | {code[:8]}... | {status}", flush=True)

        except socket.timeout:
            pass
        except Exception as e:
            print(f"Error: {e}", flush=True)

    f.close()


if __name__ == "__main__":
    main()