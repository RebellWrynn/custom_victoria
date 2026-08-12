#!/usr/bin/env python3
"""
Отладочный скрипт - показывает ПОЛНОЕ сообщение с ключом
Запуск: python3 debug_full_message.py
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
    "10.204.1.101": "CONT 1.1.1",
    "10.204.1.102": "CONT 1.1.2",
    "10.204.1.103": "CONT 1.1.3",
    "10.204.1.104": "CONT 1.1.4",
    "10.204.2.101": "CONT 1.2.1",
    "10.204.3.101": "CONT 1.3.1",
    "10.204.4.101": "CONT 1.4.1",
    "10.204.5.2": "CONT 2.1 Вх Гр",
    "10.204.6.6": "CONT 2.2.1",
    "10.204.7.7": "CONT 2.3.1",
}


def signal_handler(sig, frame):
    print("\n\n👋 Stopping debug...")
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    print("=" * 80)
    print("🔍 DEBUG - FULL MESSAGE VIEW")
    print("=" * 80)
    print(f"🎯 Looking for key: {TARGET_KEY}")
    print(f"📡 Listening on UDP {UDP_IP}:{UDP_PORT}")
    print("⏹️  Press Ctrl+C to stop")
    print("=" * 80)
    print("\n🔄 Waiting for messages with your key...\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind((UDP_IP, UDP_PORT))
    sock.settimeout(1)

    found_count = 0

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
            
            # Пропускаем, если нет ключа
            if TARGET_KEY not in message and TARGET_KEY_FULL not in message:
                continue
            
            found_count += 1
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            print("=" * 80)
            print(f"🔔 [#{found_count}] {timestamp} | From: {source_ip}")
            print(f"📱 Device: {DEVICE_NAMES.get(source_ip, source_ip)}")
            print("=" * 80)
            print("\n📨 FULL MESSAGE:")
            print("-" * 80)
            print(message)
            print("-" * 80)
            
            # Ищем все возможные идентификаторы двери
            print("\n🔍 SEARCHING FOR DOOR IDENTIFIERS:")
            print("-" * 40)
            
            # 1. Ищем номер двери
            door_matches = re.findall(r'door[=:]\s*(\d+)', message, re.IGNORECASE)
            if door_matches:
                print(f"  🚪 Door numbers found: {', '.join(door_matches)}")
            else:
                print("  🚪 No door number found")
            
            # 2. Ищем L3 адрес (разные форматы)
            l3_matches = re.findall(r'(?:dstaddr|srcaddr)[=:]\s*"([0-9A-Fa-f]{8})"', message, re.IGNORECASE)
            if l3_matches:
                print(f"  🔢 L3 in JSON: {', '.join(l3_matches)}")
            
            l3_matches2 = re.findall(r'(?:reader|dst|src)\s+0x([0-9a-fA-F]{8})', message)
            if l3_matches2:
                print(f"  🔢 L3 with 0x: {', '.join(l3_matches2)}")
            
            l3_matches3 = re.findall(r'(00[0-9A-Fa-f]{6})', message)
            if l3_matches3:
                # Фильтруем 00000000
                valid = [x for x in l3_matches3 if x.upper() != "00000000"]
                if valid:
                    print(f"  🔢 L3 as hex: {', '.join(valid)}")
            
            # 3. Ищем reader ID
            reader_matches = re.findall(r'reader\s+([0-9a-fA-Fx]+)', message)
            if reader_matches:
                print(f"  📖 Reader IDs: {', '.join(reader_matches)}")
            
            # 4. Ищем что-то похожее на ID двери
            id_matches = re.findall(r'"([0-9a-fA-F]{6,8})"', message)
            if id_matches:
                print(f"  🏷️  Hex in quotes: {', '.join(id_matches[:5])}")
            
            # 5. Ищем KEY (ваш ключ)
            key_match = re.search(r"'([0-9a-fA-F]{16})'", message)
            if key_match:
                print(f"  🔑 Key found: {key_match.group(1)}")
            
            print("\n" + "=" * 80)
            print()
            
            # Сохраняем в файл
            with open(f"debug_full_{TARGET_KEY}.log", 'a') as f:
                f.write("=" * 80 + "\n")
                f.write(f"#{found_count} {timestamp} From: {source_ip}\n")
                f.write("FULL MESSAGE:\n")
                f.write(message + "\n")
                f.write("=" * 80 + "\n\n")
            
        except socket.timeout:
            pass
        except Exception as e:
            print(f"Error: {e}", flush=True)


if __name__ == "__main__":
    main()