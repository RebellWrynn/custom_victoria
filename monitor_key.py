#!/usr/bin/env python3
"""
Отладочный скрипт - показывает ВСЕ сообщения с ключом e596849b
и анализирует их статус
Запуск: python3 debug_key.py
"""

import socket
import re
import signal
import sys
from datetime import datetime

UDP_IP = "0.0.0.0"
UDP_PORT = 514

TARGET_KEY = "e596849b"
TARGET_KEY_FULL = "e596849b00000000"

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
    print("\n\n👋 Stopping debug...")
    sys.exit(0)


def analyze_message(message, source_ip):
    """Анализирует сообщение и показывает все найденные данные"""
    results = {}
    
    # 1. Проверяем наличие ключа
    results['has_key'] = TARGET_KEY in message or TARGET_KEY_FULL in message
    
    # 2. Ищем статус
    if "ACCESS APPROVED" in message:
        results['status'] = "APPROVED"
    elif "ACCESS_DENIED" in message or "ACCESS DENIED" in message:
        results['status'] = "DENIED"
    elif "auth_requested" in message:
        results['status'] = "AUTH_REQUEST"
    elif "REGISTRATION_SUCCEEDED_IND" in message:
        results['status'] = "REGISTERED"
    elif "REGISTRATION_FAILED_IND" in message:
        results['status'] = "REG_FAILED"
    elif "OPEN_DOOR_IND" in message:
        results['status'] = "OPEN_DOOR"
    elif "OPEN_DOOR_REQ" in message:
        results['status'] = "OPEN_DOOR_REQ"
    elif "access_decision" in message:
        results['status'] = "ACCESS_DECISION"
    else:
        results['status'] = "UNKNOWN"
    
    # 3. Ищем L3 адрес
    l3_match = re.search(r'"dstaddr":\s*"([0-9A-Fa-f]{8})"', message, re.IGNORECASE)
    if l3_match:
        results['l3'] = l3_match.group(1)
    else:
        l3_match = re.search(r'"srcaddr":\s*"([0-9A-Fa-f]{8})"', message, re.IGNORECASE)
        if l3_match:
            results['l3'] = l3_match.group(1)
        else:
            l3_match = re.search(r'(?:reader|dst|src)\s+0x([0-9a-fA-F]{8})', message)
            if l3_match:
                results['l3'] = l3_match.group(1)
            else:
                results['l3'] = None
    
    # 4. Ищем пользователя
    user_match = re.search(r'username=([0-9]+)', message)
    if user_match:
        results['user'] = user_match.group(1)
    else:
        user_match = re.search(r"Mr\. '([0-9]+)", message)
        if user_match:
            results['user'] = user_match.group(1)
        else:
            results['user'] = None
    
    # 5. Ищем номер двери
    door_match = re.search(r'door=(\d+)', message)
    results['door_num'] = door_match.group(1) if door_match else None
    
    # 6. Ищем hex код
    hex_match = re.search(r"'([0-9A-Fa-f]{16})'", message, re.IGNORECASE)
    results['hex_code'] = hex_match.group(1) if hex_match else None
    
    # 7. Проверяем ключевые слова
    keywords = ["ACCESS", "auth_requested", "reader", "dstaddr", "srcaddr", "OPEN_DOOR", "access_decision"]
    results['keywords_found'] = [kw for kw in keywords if kw in message]
    
    # 8. Дверь по IP
    results['device'] = DEVICE_NAMES.get(source_ip, source_ip)
    
    return results


def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    print("=" * 80)
    print("🔍 DEBUG - ALL MESSAGES WITH YOUR KEY")
    print("=" * 80)
    print(f"🎯 Looking for key: {TARGET_KEY}")
    print(f"📡 Listening on UDP {UDP_IP}:{UDP_PORT}")
    print("⏹️  Press Ctrl+C to stop")
    print("=" * 80)
    print("\n🔄 Waiting for messages with your key...")
    print("💡 Now go and use your key on different doors!\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind((UDP_IP, UDP_PORT))
    sock.settimeout(1)

    found_count = 0
    status_counts = {}
    doors = {}

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            
            try:
                message = data.decode('utf-8', errors='ignore').strip()
            except:
                continue
            
            if not message:
                continue
            
            source_ip = addr[0]
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            # Пропускаем, если нет ключа
            if TARGET_KEY not in message and TARGET_KEY_FULL not in message:
                continue
            
            found_count += 1
            
            # Анализируем сообщение
            analysis = analyze_message(message, source_ip)
            
            # Статистика
            status = analysis['status']
            status_counts[status] = status_counts.get(status, 0) + 1
            
            device = analysis['device']
            doors[device] = doors.get(device, 0) + 1
            
            # Выводим результат
            print("=" * 80)
            print(f"🔔 [#{found_count}] {timestamp} | From: {source_ip}")
            print(f"📱 Device: {device}")
            print(f"📊 Status: {analysis['status']}")
            
            if analysis['l3']:
                print(f"🔢 L3 Address: {analysis['l3']}")
            
            if analysis['user']:
                print(f"👤 User: {analysis['user']}")
            
            if analysis['door_num']:
                print(f"🚪 Door number: {analysis['door_num']}")
            
            if analysis['hex_code']:
                print(f"🔑 Hex code: {analysis['hex_code']}")
            
            if analysis['keywords_found']:
                print(f"🏷️  Keywords: {', '.join(analysis['keywords_found'])}")
            
            # Показываем первые 300 символов сообщения
            print(f"\n📨 Message preview:")
            print(f"   {message[:300]}...")
            
            # Если статус APPROVED - выделяем
            if status == "APPROVED":
                print("   🟢 ✅ ACCESS APPROVED!")
            elif status == "DENIED":
                print("   🔴 ❌ ACCESS DENIED!")
            
            print("=" * 80)
            print()
            
            # Сохраняем полное сообщение в файл
            with open(f"debug_key_{TARGET_KEY}.log", 'a') as f:
                f.write("=" * 80 + "\n")
                f.write(f"#{found_count} {timestamp} From: {source_ip}\n")
                f.write(f"Status: {status}\n")
                f.write(f"Device: {device}\n")
                if analysis['l3']:
                    f.write(f"L3: {analysis['l3']}\n")
                f.write(f"Full message:\n{message}\n")
                f.write("=" * 80 + "\n\n")
            
            # Каждые 5 сообщений показываем статистику
            if found_count % 5 == 0:
                print("\n📊 QUICK STATS:")
                print(f"   Total found: {found_count}")
                print(f"   Statuses:")
                for s, count in status_counts.items():
                    print(f"     {s}: {count}")
                print(f"   Doors:")
                for d, count in list(doors.items())[-5:]:  # Показываем последние 5
                    print(f"     {d}: {count}")
                print()
            
        except socket.timeout:
            pass
        except Exception as e:
            print(f"Error: {e}", flush=True)


if __name__ == "__main__":
    main()