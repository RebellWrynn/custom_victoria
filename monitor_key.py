#!/usr/bin/env python3
"""
Скрипт для мониторинга ключа e596849b
Отслеживает все события с этим ключом и показывает, какие двери открываются.
Запуск: python3 monitor_my_key.py
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
TARGET_KEY = "e596849b00000000"
TARGET_KEY_SHORT = "e596849b"

# Файл для записи
LOG_FILE = f"key_{TARGET_KEY_SHORT}_access.log"
SUMMARY_FILE = f"key_{TARGET_KEY_SHORT}_summary.txt"

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
    "10.204.1.46": "CONT 1.1 Калитка",
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
    import re
    matches = re.findall(r'[0-9A-Fa-f]{16}', message)
    for code in matches:
        if code.lower() == TARGET_KEY:
            return code.lower()
    
    # Ищем 8-значный
    matches_8 = re.findall(r'[0-9A-Fa-f]{8}', message)
    for code in matches_8:
        if code.lower() == TARGET_KEY_SHORT:
            return TARGET_KEY  # Возвращаем полный
    
    return None


def extract_l3_address(message):
    """Извлекает L3 адрес из сообщения."""
    import re
    match = re.search(r'"dstaddr":\s*"([0-9A-Fa-f]{8})"', message, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    
    match = re.search(r'"srcaddr":\s*"([0-9A-Fa-f]{8})"', message, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    
    match = re.search(r'(?:reader|dst|src)\s+0x([0-9a-fA-F]{8})', message)
    if match:
        return match.group(1).upper()
    
    match = re.search(r'(00[0-9A-Fa-f]{6})', message)
    if match:
        addr = match.group(1).upper()
        if addr != "00000000":
            return addr
    
    return None


def extract_timestamp(message):
    """Извлекает время из сообщения syslog."""
    import re
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


def print_summary():
    """Выводит сводку по всем дверям"""
    if not doors_stats:
        print("❌ No events recorded yet.")
        return
    
    print("\n" + "=" * 80)
    print("🚪 DOORS ACCESSED BY YOUR KEY")
    print("=" * 80)
    print(f"Total events: {total_events}")
    print(f"✅ Approved: {approved_count}")
    print(f"❌ Denied: {denied_count}")
    print("\n📋 Doors list:")
    print("-" * 80)
    
    # Сортируем по количеству
    sorted_doors = sorted(doors_stats.items(), key=lambda x: x[1]['total'], reverse=True)
    
    for i, (door, stats) in enumerate(sorted_doors, 1):
        status_icon = "🟢" if stats['approved'] > 0 else "🔴" if stats['denied'] > 0 else "⚪"
        print(f"{i:2}. {status_icon} {door}")
        print(f"    Total: {stats['total']} | ✅ {stats['approved']} | ❌ {stats['denied']}")
        if stats['last_time']:
            print(f"    Last: {stats['last_time']}")
        print()
    
    # Сохраняем в файл
    with open(SUMMARY_FILE, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write(f"SUMMARY FOR KEY: {TARGET_KEY_SHORT}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Total events: {total_events}\n")
        f.write(f"✅ Approved: {approved_count}\n")
        f.write(f"❌ Denied: {denied_count}\n\n")
        f.write("Doors:\n")
        for door, stats in sorted_doors:
            f.write(f"  {door}: {stats['total']} times (✅{stats['approved']} ❌{stats['denied']})\n")


# Глобальные переменные для статистики
doors_stats = defaultdict(lambda: {'total': 0, 'approved': 0, 'denied': 0, 'last_time': None})
total_events = 0
approved_count = 0
denied_count = 0


def main():
    global total_events, approved_count, denied_count
    
    signal.signal(signal.SIGINT, signal_handler)
    
    print("=" * 80)
    print("🔑 KEY MONITOR")
    print("=" * 80)
    print(f"🎯 Monitoring key: {TARGET_KEY_SHORT}")
    print(f"📡 Listening on UDP {UDP_IP}:{UDP_PORT}")
    print(f"📁 Events log: {LOG_FILE}")
    print(f"📊 Summary: {SUMMARY_FILE}")
    print("⏹️  Press Ctrl+C to stop")
    print("=" * 80)
    print("\n🔄 Waiting for your key...\n")

    # Открываем файл для записи событий
    f = open(LOG_FILE, 'w', buffering=1)
    f.write("#" + "=" * 100 + "\n")
    f.write(f"# KEY MONITOR: {TARGET_KEY_SHORT}\n")
    f.write(f"# Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write("#" + "=" * 100 + "\n")
    f.write("# TIME | DOOR | L3_ADDRESS | STATUS | USER\n")
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
            
            # Проверяем наличие нашего ключа
            hex_code = extract_hex_code(message)
            if not hex_code:
                continue
            
            # Извлекаем данные
            l3_addr = extract_l3_address(message)
            status = get_access_status(message)
            timestamp = extract_timestamp(message)
            
            source_ip = addr[0]
            device_name = DEVICE_NAMES.get(source_ip, source_ip)
            
            # Если L3 адрес найден, используем его для определения двери
            if l3_addr:
                door_name = f"{device_name} (L3:{l3_addr})"
            else:
                door_name = device_name
            
            total_events += 1
            
            # Обновляем статистику
            doors_stats[door_name]['total'] += 1
            doors_stats[door_name]['last_time'] = timestamp
            
            if status == "APPROVED":
                approved_count += 1
                doors_stats[door_name]['approved'] += 1
                status_icon = "✅"
                status_text = "APPROVED"
            elif status == "DENIED":
                denied_count += 1
                doors_stats[door_name]['denied'] += 1
                status_icon = "❌"
                status_text = "DENIED"
            elif status == "AUTH_REQUEST":
                status_icon = "📌"
                status_text = "AUTH_REQ"
            else:
                status_icon = "🔍"
                status_text = "UNKNOWN"
            
            # Выводим в консоль
            print(f"{status_icon} [{total_events:3d}] {timestamp} | {door_name[:40]:<40} | {status_text:<10}")
            
            # Если APPROVED - делаем акцент
            if status == "APPROVED":
                print(f"   🟢 ✅ ACCESS GRANTED at {door_name}")
            elif status == "DENIED":
                print(f"   🔴 ❌ ACCESS DENIED at {door_name}")
            
            # Записываем в файл
            log_line = f"{timestamp} | {door_name} | {l3_addr or 'N/A'} | {status} | \n"
            f.write(log_line)
            f.flush()
            
        except socket.timeout:
            pass
        except Exception as e:
            print(f"Error: {e}", flush=True)
    
    f.close()


if __name__ == "__main__":
    main()