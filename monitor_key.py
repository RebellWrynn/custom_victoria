#!/usr/bin/env python3
"""
Скрипт для мониторинга ключа e596849b
Отслеживает ВСЕ сообщения и показывает информацию о двери из callmanager
Запуск: python3 monitor_key_full.py
"""

import socket
import re
import signal
import sys
from datetime import datetime
from collections import defaultdict

UDP_IP = "0.0.0.0"
UDP_PORT = 514

TARGET_KEY = "e596849b"
TARGET_KEY_FULL = "e596849b00000000"

LOG_FILE = f"key_{TARGET_KEY}_full.log"
SUMMARY_FILE = f"key_{TARGET_KEY}_full_summary.txt"

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
    match = re.search(r"'([0-9A-Fa-f]{16})'", message)
    if match:
        return match.group(1).lower()
    return None


def extract_timestamp(message):
    """Извлекает время из сообщения syslog."""
    match = re.search(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', message)
    if match:
        return match.group(1)
    return datetime.now().strftime("%b %d %H:%M:%S")


def get_message_type(message):
    """Определяет тип сообщения."""
    if "callmanager" in message:
        return "CALLMANAGER"
    elif "ca_module_arm" in message:
        if "access_decision" in message:
            return "ACCESS_DECISION"
        return "CA_MODULE"
    elif "net_module_arm" in message:
        return "NET_MODULE"
    return "OTHER"


def extract_door_info(message):
    """Извлекает информацию о двери из сообщения callmanager."""
    info = {}
    
    # Ищем номер двери
    door_match = re.search(r'"door":\s*(\d+)', message)
    if door_match:
        info['door'] = door_match.group(1)
    
    # Ищем L3 адрес
    l3_match = re.search(r'"dstaddr":\s*"([0-9A-Fa-f]{8})"', message, re.IGNORECASE)
    if l3_match:
        info['l3'] = l3_match.group(1).upper()
    
    # Ищем статус
    if "ACCESS APPROVED" in message:
        info['status'] = "APPROVED"
    elif "ACCESS_DENIED" in message or "ACCESS DENIED" in message:
        info['status'] = "DENIED"
    elif "auth_requested" in message:
        info['status'] = "AUTH_REQUEST"
    
    # Ищем пользователя
    user_match = re.search(r'"username":\s*"([^"]+)"', message)
    if user_match:
        info['user'] = user_match.group(1)
    
    # Ищем reader
    reader_match = re.search(r'"reader":\s*(\d+)', message)
    if reader_match:
        info['reader'] = reader_match.group(1)
    
    return info


def print_summary():
    """Выводит сводку по всем событиям"""
    if not events:
        print("❌ No events recorded yet.")
        return
    
    print("\n" + "=" * 80)
    print("📊 EVENTS SUMMARY")
    print("=" * 80)
    print(f"Total events: {len(events)}")
    
    # Статистика по типам
    types = defaultdict(int)
    for event in events:
        types[event['type']] += 1
    
    print("\nBy type:")
    for t, count in types.items():
        print(f"  {t}: {count}")
    
    # Статистика по дверям
    doors = defaultdict(int)
    for event in events:
        if event.get('door'):
            doors[event['door']] += 1
    
    if doors:
        print("\n🚪 Doors:")
        for door, count in sorted(doors.items(), key=lambda x: x[1], reverse=True):
            print(f"  {door}: {count} events")
    
    # Сохраняем в файл
    with open(SUMMARY_FILE, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write(f"SUMMARY FOR KEY: {TARGET_KEY}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Total events: {len(events)}\n")
        for t, count in types.items():
            f.write(f"  {t}: {count}\n")
        if doors:
            f.write("\nDoors:\n")
            for door, count in sorted(doors.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {door}: {count}\n")


# Глобальные переменные
events = []
last_decision = None


def main():
    global last_decision
    
    signal.signal(signal.SIGINT, signal_handler)
    
    print("=" * 80)
    print("🔑 KEY MONITOR - FULL VIEW")
    print("=" * 80)
    print(f"🎯 Monitoring key: {TARGET_KEY}")
    print(f"📡 Listening on UDP {UDP_IP}:{UDP_PORT}")
    print(f"📁 Events log: {LOG_FILE}")
    print(f"📊 Summary: {SUMMARY_FILE}")
    print("⏹️  Press Ctrl+C to stop")
    print("=" * 80)
    print("\n🔄 Waiting for your key...")
    print("💡 Showing ALL messages with your key\n")

    f = open(LOG_FILE, 'w', buffering=1)
    f.write("#" + "=" * 100 + "\n")
    f.write(f"# KEY MONITOR: {TARGET_KEY}\n")
    f.write(f"# Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write("#" + "=" * 100 + "\n\n")

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
            
            timestamp = extract_timestamp(message)
            source_ip = addr[0]
            msg_type = get_message_type(message)
            device_name = DEVICE_NAMES.get(source_ip, source_ip)
            
            # Извлекаем информацию
            door_info = extract_door_info(message)
            hex_code = extract_hex_code(message)
            
            # Сохраняем событие
            event = {
                'timestamp': timestamp,
                'source_ip': source_ip,
                'device': device_name,
                'type': msg_type,
                'door_info': door_info,
                'hex_code': hex_code,
                'message': message[:200]
            }
            events.append(event)
            
            # Определяем, что показывать
            if msg_type == "CALLMANAGER":
                # Это сообщение от callmanager - здесь есть информация о двери
                door = door_info.get('door', 'unknown')
                l3 = door_info.get('l3', 'N/A')
                status = door_info.get('status', 'UNKNOWN')
                user = door_info.get('user', 'N/A')
                
                status_icon = "✅" if status == "APPROVED" else "❌" if status == "DENIED" else "📌"
                
                print("=" * 60)
                print(f"🚪 DOOR EVENT from {device_name}")
                print(f"   Time: {timestamp}")
                print(f"   Door: {door}")
                print(f"   L3: {l3}")
                print(f"   Status: {status_icon} {status}")
                if user != 'N/A':
                    print(f"   User: {user}")
                print("=" * 60)
                print()
                
                # Записываем в файл
                f.write(f"DOOR EVENT: {timestamp} | {device_name} | door:{door} | L3:{l3} | {status}\n")
                f.flush()
                
            elif msg_type == "ACCESS_DECISION":
                # Сообщение access_decision - просто показываем
                print(f"🔍 ACCESS_DECISION from {device_name} | {timestamp}")
                if hex_code:
                    print(f"   Key: {hex_code}")
                print()
                
                f.write(f"ACCESS_DECISION: {timestamp} | {device_name} | key:{hex_code}\n")
                f.flush()
            
            else:
                # Другие сообщения
                print(f"📌 {msg_type} from {device_name} | {timestamp}")
                print(f"   {message[:100]}...")
                print()
                
                f.write(f"{msg_type}: {timestamp} | {device_name} | {message[:100]}\n")
                f.flush()
            
        except socket.timeout:
            pass
        except Exception as e:
            print(f"Error: {e}", flush=True)
    
    f.close()


if __name__ == "__main__":
    main()