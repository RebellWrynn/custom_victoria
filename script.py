import socket
import requests
import os

UDP_IP = "0.0.0.0"
UDP_PORT = 514

# VictoriaLogs URL из переменной окружения
VICTORIA_URL = os.environ.get("VICTORIA_URL", "http://victorialogs:9428")

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

# Префиксы модулей, которые генерируют логи о ключах
RELEVANT_MODULES = ("ca_module_arm", "net_module_arm")

# Ключевые слова для быстрой фильтрации (все lowercase для ускорения)
FILTER_KEYWORDS = (
    "badge_code_ind",
    "ca_send_code",
    "access approved",
    "access_approved",
    "analyze code",
    "room_",
)

def is_relevant_log_fast(message):
    """
    Максимально быстрая фильтрация через простые проверки.
    Никаких регулярных выражений!
    """
    # 1. Быстрая проверка модуля
    if "ca_module_arm" not in message and "net_module_arm" not in message:
        return False

    # 2. Переводим в lowercase один раз для проверки ключевых слов
    msg_lower = message.lower()

    # 3. Проверяем наличие ключевых слов
    for keyword in FILTER_KEYWORDS:
        if keyword in msg_lower:
            return True

    # 4. Проверяем наличие 16-значного hex-кода (без регулярки!)
    #    Ищем "'xxxxxxxxxxxxxxxx'" - кавычка, 16 hex символов, кавычка
    #    Это быстрое сканирование строки без компиляции regex
    if "'" in message:
        # Ищем позицию кавычки
        start = message.find("'")
        while start != -1:
            # Проверяем, что после кавычки 16 hex символов и закрывающая кавычка
            end = start + 17  # 1 кавычка + 16 символов
            if end < len(message) and message[end] == "'":
                # Проверяем, что между кавычками 16 hex символов
                code = message[start+1:end]
                if len(code) == 16:
                    # Проверяем, что все символы hex (0-9, a-f, A-F)
                    # Используем set для быстрой проверки
                    if all(c in '0123456789abcdefABCDEF' for c in code):
                        return True
            # Ищем следующую кавычку
            start = message.find("'", start + 1)

    return False

def extract_key_info_fast(message):
    """
    Быстрое извлечение информации из сообщения без регулярных выражений.
    """
    result = {
        "code": None,
        "user": None,
        "room": None,
        "status": "UNKNOWN"
    }

    # 1. Извлекаем код (16 hex символов в кавычках)
    if "'" in message:
        start = message.find("'")
        while start != -1:
            end = start + 17
            if end < len(message) and message[end] == "'":
                code = message[start+1:end]
                if len(code) == 16:
                    if all(c in '0123456789abcdefABCDEF' for c in code):
                        result["code"] = code
                        break
            start = message.find("'", start + 1)

    # 2. Извлекаем имя пользователя и комнату
    #    Ищем "Mr. 'XXX  Room_YYY'"
    mr_pos = message.find("Mr. '")
    if mr_pos != -1:
        # Ищем закрывающую кавычку после Mr.
        end_quote = message.find("'", mr_pos + 5)
        if end_quote != -1:
            # Извлекаем часть между кавычками
            content = message[mr_pos + 5:end_quote]
            # Разделяем по пробелам
            parts = content.split()
            if len(parts) >= 2:
                # Ищем часть с "Room_"
                for part in parts:
                    if part.startswith("Room_"):
                        result["room"] = part[5:]  # Убираем "Room_"
                    elif part.isdigit() and not result["user"]:
                        result["user"] = part

    # 3. Определяем статус
    if "ACCESS APPROVED" in message:
        result["status"] = "APPROVED"
    elif "ACCESS_DENIED" in message or "ACCESS DENIED" in message:
        result["status"] = "DENIED"

    return result

# Создаем сокет с оптимизированными параметрами
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)  # Увеличиваем буфер
sock.bind((UDP_IP, UDP_PORT))
sock.settimeout(1)

print(f"UDP server listening on {UDP_IP}:{UDP_PORT}", flush=True)
print(f"Sending to VictoriaLogs at {VICTORIA_URL}", flush=True)
print("Optimized: fast filtering without regex", flush=True)

# Счетчики для мониторинга
total_messages = 0
filtered_messages = 0

while True:
    try:
        data, addr = sock.recvfrom(65535)
        total_messages += 1

        # Быстрое декодирование
        try:
            message = data.decode('utf-8', errors='ignore').strip()
        except:
            continue

        if not message:
            continue

        # Быстрая фильтрация
        if not is_relevant_log_fast(message):
            continue

        filtered_messages += 1
        source_ip = addr[0]
        device_name = DEVICE_NAMES.get(source_ip, source_ip)

        # Быстрое извлечение информации
        info = extract_key_info_fast(message)

        # Логируем только если есть код
        if info["code"]:
            print(f"[ACCESS] {device_name} | {info['user'] or '?'} @ Room {info['room'] or '?'} | {info['status']} | {info['code']}", flush=True)

            # Минимальный payload для VictoriaLogs
            payload = {
                "_msg": message,
                "device": device_name,
                "source_ip": source_ip,
                "key_code": info["code"],
                "user": info["user"] or "",
                "room": info["room"] or "",
                "access_status": info["status"]
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

        # Логируем статистику каждые 10000 сообщений
        if total_messages % 10000 == 0:
            print(f"Stats: {total_messages} total, {filtered_messages} filtered "
                  f"({filtered_messages*100//total_messages if total_messages else 0}%)", flush=True)

    except socket.timeout:
        pass
    except Exception as e:
        print(f"Error: {e}", flush=True)
