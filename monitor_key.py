#!/usr/bin/env python3
"""
Скрипт для мониторинга ключа e596849b
Показывает ВСЕ события с ключом (включая access_decision)
Запуск: python3 monitor_key_v3.py
Остановка: Ctrl+C
"""

import socket
import re
import signal
import sys
from datetime import datetime
from collections import defaultdict

UDP_IP = "0.0.0.0"
UDP_PORT = 514

# ВАШ КЛЮЧ
TARGET_KEY = "e596849b"
TARGET_KEY_FULL = "e596849b00000000"

# Файл для записи
LOG_FILE = f"key_{TARGET_KEY}_all_events.log"
SUMMARY_FILE = f"key_{TARGET_KEY}_summary.txt"

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


def signal_handler(sig, frame):
    print("\n\n" + "=" * 80)
    print("📊 FINAL STATISTICS")
    print("=" * 80)
    print_summary()
    print("\n👋 Stopping monitor...")
    sys.exit(0)


def extract_hex_code(message):
    """Извлекает 16-значный hex-код из сообщения."""
    # Ищем в кавычках
    start = message.find("'")
    while start != -1:
        end = start + 17
        if end < len(message) and message[end] == "'":
            code = message[start+1:end]
            if len(code) == 16 and all(c in '0123456789abcdefABCDEF' for c in code):
                return code.lower()
        start = message.find("'", start + 1)

    # Ищем без кавычек
    matches = re.findall(r'[0-9A-Fa-f]{16}', message)
    for code in matches:
        if code.lower() == TARGET_KEY_FULL:
            return code.lower()
    
    # Ищем 8-значный
    matches_8 = re.findall(r'[0-9A-Fa-f]{8}', message)
    for code in matches_8:
        if code.lower() == TARGET_KEY:
            return TARGET_KEY_FULL
    
    return None


def extract_timestamp(message):
    """Извлекает время из сообщения syslog."""
    match = re.search(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', message)
    if match:
        return match.group(1)
    return datetime.now().strftime("%b %d %H:%M:%S")


def get_event_type(message):
    """Определяет тип события."""
    if "ACCESS APPROVED" in message:
        return "APPROVED"
    elif "ACCESS_DENIED" in message or "ACCESS DENIED" in message:
        return "DENIED"
    elif "access_decision" in message:
        return "ACCESS_DECISION"
    elif "auth_requested" in message:
        return "AUTH_REQUEST"
    elif "OPEN_DOOR_IND" in message:
        return "DOOR_OPEN"
    elif "OPEN_DOOR_REQ" in message:
        return "DOOR_REQUEST"
    else:
        return "UNKNOWN"


def get_door_info(message, source_ip):
    """Определяет информацию о двери из сообщения"""
    device_name = DEVICE_NAMES.get(source_ip, source_ip)
    
    # Пытаемся найти номер двери
    door_match = re.search(r'door[=:]\s*(\d+)', message, re.IGNORECASE)
    if door_match:
        door_num = door_match.group(1)
        return f"{device_name} (door {door_num})"
    
    # Пытаемся найти reader ID
    reader_match = re.search(r'reader\s+([0-9a-fA-Fx]+)', message)
    if reader_match:
        reader_id = reader_match.group(1)
        return f"{device_name} (reader {reader_id})"
    
    # Пытаемся найти L3 адрес
    l3_match = re.search(r'(00[0-9A-Fa-f]{6})', message)
    if l3_match:
        l3 = l3_match.group(1).upper()
        return f"{device_name} (L3:{l3})"
    
    return device_name


def print_summary():
    """Выводит сводку по всем событиям"""
    if not events_by_door:
        print("❌ No events recorded yet.")
        return
    
    print("\n" + "=" * 80)
    print("🚪 EVENTS WITH YOUR KEY")
    print("=" * 80)
    print(f"Total events: {total_events}")
    print(f"By type:")
    for event_type, count in event_types.items():
        print(f"  {event_type}: {count}")
    
    print("\n📋 Doors:")
    print("-" * 80)
    
    # Сортируем по количеству
    sorted_doors = sorted(events_by_door.items(), key=lambda x: x[1]['total'], reverse=True)
    
    for i, (door, stats) in enumerate(sorted_doors, 1):
        print(f"{i:2}. {door}")
        print(f"    Total: {stats['total']} events")
        for event_type, count in stats['types'].items():
            print(f"      {event_type}: {count}")
        if stats['last_time']:
            print(f"    Last: {stats['last_time']}")
        print()
    
    # Сохраняем в файл
    with open(SUMMARY_FILE, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write(f"SUMMARY FOR KEY: {TARGET_KEY}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Total events: {total_events}\n")
        for event_type, count in event_types.items():
            f.write(f"  {event_type}: {count}\n")
        f.write("\nDoors:\n")
        for door, stats in sorted_doors:
            f.write(f"  {door}: {stats['total']} events\n")
            for event_type, count in stats['types'].items():
                f.write(f"    {event_type}: {count}\n")


# Глобальные переменные для статистики
events_by_door = defaultdict(lambda: {'total': 0, 'types': defaultdict(int), 'last_time': None})
event_types = defaultdict(int)
total_events = 0


def main():
    global total_events
    
    signal.signal(signal.SIGINT, signal_handler)
    
    print("=" * 80)
    print("🔑 KEY MONITOR V3 - ALL EVENTS")
    print("=" * 80)
    print(f"🎯 Monitoring key: {TARGET_KEY}")
    print(f"📡 Listening on UDP {UDP_IP}:{UDP_PORT}")
    print(f"📁 Events log: {LOG_FILE}")
    print(f"📊 Summary: {SUMMARY_FILE}")
    print("⏹️  Press Ctrl+C to stop")
    print("=" * 80)
    print("\n🔄 Waiting for your key...")
    print("💡 Showing ALL events with your key\n")

    # Открываем файл для записи событий
    f = open(LOG_FILE, 'w', buffering=1)
    f.write("#" + "=" * 100 + "\n")
    f.write(f"# KEY MONITOR: {TARGET_KEY}\n")
    f.write(f"# Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write("#" + "=" * 100 + "\n")
    f.write("# TIME | DOOR | EVENT_TYPE\n")
    f.write("#" + "-" * 100 + "\n")

    # Создаем сокет
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind((UDP_IP, UDP_PORT))
    sock.settimeout(1)

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            
            try:
                message = data.decode('utf-8', errors='ignore').strip()
            except:
                continue
            
            if not message:
                continue
            
            # Проверяем наличие ключа
            if TARGET_KEY not in message and TARGET_KEY_FULL not in message:
                continue
            
            # Извлекаем данные
            timestamp = extract_timestamp(message)
            source_ip = addr[0]
            event_type = get_event_type(message)
            
            # Определяем дверь
            door_name = get_door_info(message, source_ip)
            
            total_events += 1
            
            # Обновляем статистику
            events_by_door[door_name]['total'] += 1
            events_by_door[door_name]['types'][event_type] += 1
            events_by_door[door_name]['last_time'] = timestamp
            event_types[event_type] += 1
            
            # Иконка для типа события
            icons = {
                "APPROVED": "✅",
                "DENIED": "❌",
                "ACCESS_DECISION": "🔍",
                "AUTH_REQUEST": "📌",
                "DOOR_OPEN": "🚪",
                "DOOR_REQUEST": "🔑",
                "UNKNOWN": "❓"
            }
            icon = icons.get(event_type, "📌")
            
            # Выводим в консоль
            print(f"{icon} [{total_events:3d}] {timestamp} | {door_name[:50]:<50} | {event_type}")
            
            # Если это ACCESS_DECISION - показываем дополнительную информацию
            if event_type == "ACCESS_DECISION":
                # Ищем L3 адрес
                l3_match = re.search(r'(00[0-9A-Fa-f]{6})', message)
                if l3_match:
                    print(f"   🔢 L3: {l3_match.group(1).upper()}")
            
            # Записываем в файл
            log_line = f"{timestamp} | {door_name} | {event_type}\n"
            f.write(log_line)
            f.flush()
            
        except socket.timeout:
            pass
        except Exception as e:
            print(f"Error: {e}", flush=True)
    
    f.close()


if __name__ == "__main__":
    main()