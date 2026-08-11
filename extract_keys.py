#!/usr/bin/env python3
"""
Скрипт для поиска событий по ключу в файле access_events.log.
Запуск: python3 extract_keys.py <ключ>

Пример: python3 extract_keys.py 6b30859600000000
"""

import sys
import os
from datetime import datetime

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 extract_keys.py <key>")
        print("Example: python3 extract_keys.py 6b30859600000000")
        sys.exit(1)

    search_key = sys.argv[1].upper()
    log_file = "access_events.log"

    if not os.path.exists(log_file):
        print(f"❌ File '{log_file}' not found!")
        print("   Run 'python3 collect_events.py' first to collect data.")
        sys.exit(1)

    print("=" * 100)
    print(f"🔑 SEARCHING FOR KEY: {search_key}")
    print("=" * 100)
    print()

    # Читаем файл и ищем совпадения
    found = []
    total_lines = 0

    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                total_lines += 1
                line = line.strip()
                
                # Пропускаем заголовки и пустые строки
                if line.startswith('#') or not line:
                    continue
                
                # Ищем ключ в строке (формат: TIME | L3 | CONT | KEY | STATUS | USER)
                if search_key in line:
                    found.append(line)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    if not found:
        print(f"❌ Key {search_key} not found in {log_file}")
        print(f"   Total lines scanned: {total_lines}")
        sys.exit(0)

    # Выводим результаты
    print(f"✅ Found {len(found)} event(s) for key {search_key}")
    print()
    print("-" * 100)
    print(f"{'#':<4} {'TIME':<20} {'L3':<12} {'CONT':<25} {'STATUS':<10} {'USER':<12}")
    print("-" * 100)

    for i, line in enumerate(found, 1):
        parts = line.split(' | ')
        if len(parts) >= 5:
            timestamp = parts[0].strip()
            l3 = parts[1].strip()
            cont = parts[2].strip()
            status = parts[4].strip()
            user = parts[5].strip() if len(parts) > 5 else ""
            
            # Укорачиваем CONT если длинный
            if len(cont) > 25:
                cont = cont[:22] + "..."
            
            print(f"{i:<4} {timestamp:<20} {l3:<12} {cont:<25} {status:<10} {user:<12}")
        else:
            print(f"{i:<4} {line}")

    print("-" * 100)
    print()

    # Группировка по дверям (L3-адресам)
    print("📊 SUMMARY BY DOOR:")
    print("-" * 40)
    
    door_stats = {}
    for line in found:
        parts = line.split(' | ')
        if len(parts) >= 3:
            l3 = parts[1].strip()
            if l3 not in door_stats:
                door_stats[l3] = 0
            door_stats[l3] += 1
    
    for l3, count in sorted(door_stats.items()):
        print(f"  {l3}: {count} time(s)")

    print()
    print(f"💾 Full output saved to: key_search_results.txt")
    
    # Сохраняем результаты в файл
    with open("key_search_results.txt", 'w') as f:
        f.write("=" * 100 + "\n")
        f.write(f"SEARCH RESULTS FOR KEY: {search_key}\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 100 + "\n\n")
        for line in found:
            f.write(line + "\n")
        f.write("\n" + "-" * 40 + "\n")
        f.write("SUMMARY BY DOOR:\n")
        for l3, count in sorted(door_stats.items()):
            f.write(f"  {l3}: {count} time(s)\n")


if __name__ == "__main__":
    main()