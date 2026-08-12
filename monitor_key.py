#!/usr/bin/env python3
"""
Скрипт для мониторинга конкретного ключа доступа.
Отслеживает все события с ключом 00E00691 в реальном времени.
Запуск: python3 monitor_key.py
Остановка: Ctrl+C
"""

import socket
import re
import signal
import sys
from datetime import datetime
import json
import os

# Конфигурация
UDP_IP = "0.0.0.0"
UDP_PORT = 514

# Ключ для мониторинга (можно изменить)
TARGET_KEY = "00E00691"
# Полный формат ключа с нулями
TARGET_KEY_FULL = "00E0069100000000"

# Файлы для записи
MONITOR_LOG = f"key_{TARGET_KEY}_events.log"
SUMMARY_LOG = f"key_{TARGET_KEY}_summary.log"

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
    print("\n\n👋 Stopping monitor...", flush=True)
    print(f"📊 Summary saved to: {SUMMARY_LOG}", flush=True)
    sys.exit(0)


def extract_hex_code(message):
    """Извлекает 16-значный hex-код из сообщения."""
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


def extract_l3_address(message):
    """Извлекает L3 адрес из сообщения."""
    # Ищем в JSON полях
    match = re.search(r'"dstaddr":\s*"([0-9A-Fa-f]{8})"', message, re.IGNORECASE)
    if match:
        return match.group(1).upper()

    match = re.search(r'"srcaddr":\s*"([0-9A-Fa-f]{8})"', message, re.IGNORECASE)
    if match:
        return match.group(1).upper()

    # Ищем текстовые форматы
    match = re.search(r'(?:reader|dst|src)\s+0x([0-9a-fA-F]{8})', message)
    if match:
        return match.group(1).upper()

    # Ищем как отдельный L3 адрес
    match = re.search(r'(00[0-9A-Fa-f]{6})', message)
    if match:
        addr = match.group(1).upper()
        if addr != "00000000":
            return addr

    return None


def extract_user_id(message):
    """Извлекает ID пользователя."""
    match = re.search(r'auth_requested.*username=([0-9]+)', message)
    if match:
        return match.group(1)

    match = re.search(r"Mr\. '([0-9]+)", message)
    if match:
        return match.group(1)

    match = re.search(r'"asterisk"/0*([0-9]{8,})', message)
    if match:
        return match.group(1)

    return None


def extract_timestamp(message):
    """Извлекает время из сообщения syslog."""
    match = re.search(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', message)
    if match:
        return match.group(1)
    return datetime.now().strftime("%b %d %H:%M:%S")


def get_access_status(message):
    """Определяет статус доступа."""
    if "ACCESS APPROVED" in message:
        return "APPROVED"
    elif "ACCESS_DENIED" in message or "ACCESS DENIED" in message:
        return "DENIED"
    elif "REGISTRATION_SUCCEEDED_IND" in message:
        return "REGISTERED"
    elif "REGISTRATION_FAILED_IND" in message:
        return "REG_FAILED"
    elif "auth_requested" in message:
        return "AUTH_REQUEST"
    return "UNKNOWN"


def check_key_in_message(message, target_key):
    """Проверяет, содержит ли сообщение целевой ключ."""
    # Проверяем полный 16-значный ключ
    if target_key in message:
        return True
    
    # Проверяем 8-значный ключ (без нулей)
    key_short = target_key[:8]
    if key_short in message:
        return True
    
    # Проверяем через extract_hex_code
    hex_code = extract_hex_code(message)
    if hex_code and (hex_code == target_key or hex_code.startswith(key_short)):
        return True
    
    return False


def main():
    # Обработчик Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    print("=" * 80)
    print("🔑 KEY MONITOR")
    print("=" * 80)
    print(f"🎯 Monitoring key: {TARGET_KEY}")
    print(f"📡 Listening on UDP {UDP_IP}:{UDP_PORT}")
    print(f"📁 Events log: {MONITOR_LOG}")
    print(f"📊 Summary log: {SUMMARY_LOG}")
    print("⏹️  Press Ctrl+C to stop")
    print("=" * 80)
    print()

    # Открываем файлы для записи
    f_events = open(MONITOR_LOG, 'w', buffering=1)
    f_events.write("#" + "=" * 100 + "\n")
    f_events.write(f"# MONITOR FOR KEY: {TARGET_KEY}\n")
    f_events.write(f"# Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f_events.write("#" + "=" * 100 + "\n")
    f_events.write("# TIME | L3_ADDRESS | CONT | STATUS | USER | RAW_MESSAGE\n")
    f_events.write("#" + "-" * 100 + "\n")

    f_summary = open(SUMMARY_LOG, 'w', buffering=1)
    f_summary.write("#" + "=" * 100 + "\n")
    f_summary.write(f"# SUMMARY FOR KEY: {TARGET_KEY}\n")
    f_summary.write(f"# Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f_summary.write("#" + "=" * 100 + "\n\n")

    # Создаем сокет
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind((UDP_IP, UDP_PORT))
    sock.settimeout(1)

    event_count = 0
    approved_count = 0
    denied_count = 0
    doors = {}
    users = set()

    print(f"🎯 Waiting for key {TARGET_KEY}...\n")

    while True:
        try:
            data, addr = sock.recvfrom(65535)

            try:
                message = data.decode('utf-8', errors='ignore').strip()
            except:
                continue

            if not message:
                continue

            # Проверяем, есть ли наш ключ в сообщении
            if not check_key_in_message(message, TARGET_KEY_FULL):
                continue

            # Извлекаем данные
            hex_code = extract_hex_code(message)
            l3_addr = extract_l3_address(message)
            user_id = extract_user_id(message)
            status = get_access_status(message)
            timestamp = extract_timestamp(message)

            source_ip = addr[0]
            device_name = DEVICE_NAMES.get(source_ip, source_ip)

            event_count += 1

            # Статистика
            if status == "APPROVED":
                approved_count += 1
            elif status == "DENIED":
                denied_count += 1

            # Запоминаем двери
            door_key = f"{device_name}|{l3_addr}"
            if door_key not in doors:
                doors[door_key] = 0
            doors[door_key] += 1

            if user_id:
                users.add(user_id)

            # Формируем строку для записи
            log_line = f"{timestamp} | {l3_addr or 'N/A'} | {device_name} | {status} | {user_id or ''} | {message[:200]}\n"
            f_events.write(log_line)
            f_events.flush()

            # Вывод в консоль с цветом
            status_symbol = "✅" if status == "APPROVED" else "❌" if status == "DENIED" else "📌" if status == "AUTH_REQUEST" else "🔍"
            
            print(f"{status_symbol} [{event_count:3d}] {timestamp} | {device_name[:25]:<25} | {status:<12} | User: {user_id or 'N/A'}")
            
            # Если APPROVED - показываем ярче
            if status == "APPROVED":
                print(f"   🟢 ACCESS GRANTED at {device_name}")
            elif status == "DENIED":
                print(f"   🔴 ACCESS DENIED at {device_name}")

            # Обновляем сводку каждые 10 событий
            if event_count % 10 == 0:
                f_summary.write("=" * 80 + "\n")
                f_summary.write(f"📊 STATISTICS (Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')})\n")
                f_summary.write("=" * 80 + "\n")
                f_summary.write(f"Total events: {event_count}\n")
                f_summary.write(f"✅ APPROVED: {approved_count}\n")
                f_summary.write(f"❌ DENIED: {denied_count}\n")
                f_summary.write(f"\n🚪 Doors accessed:\n")
                for door, count in sorted(doors.items(), key=lambda x: x[1], reverse=True):
                    f_summary.write(f"   {door}: {count} times\n")
                if users:
                    f_summary.write(f"\n👤 Users: {', '.join(users)}\n")
                f_summary.write("\n")
                f_summary.flush()

        except socket.timeout:
            pass
        except Exception as e:
            print(f"Error: {e}", flush=True)

    f_events.close()
    f_summary.close()


if __name__ == "__main__":
    main()