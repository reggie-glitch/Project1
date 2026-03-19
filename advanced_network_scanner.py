#!/usr/bin/env python3
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Словарь с известными сервисами по умолчанию
COMMON_PORTS = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    88: "Kerberos",  # То, что ты нашла!
    110: "POP3",
    111: "RPC",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    27017: "MongoDB",
}

def get_banner(ip, port, timeout=2):
    """Пытается получить баннер от сервиса"""
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Отправляем простой запрос в зависимости от порта
        if port in [80, 8080, 443]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port in [21, 25, 110, 143]:
            sock.send(b"\r\n")
        else:
            sock.send(b"\n")
        
        banner = sock.recv(1024).decode().strip()[:50]  # Первые 50 символов
        sock.close()
        return banner if banner else None
    except:
        return None

def scan_port(ip, port, timeout=1.0, get_banner_flag=False):
    """Сканирует один порт и опционально получает баннер"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            if get_banner_flag:
                banner = get_banner(ip, port, timeout)
                return port, banner
            return port, None
        return None, None
    except socket.error:
        return None, None

def scan_ports(ip, start_port, end_port, threads=100, timeout=1.0, get_banner=False):
    """Многопоточное сканирование диапазона портов"""
    print(f"🔍 Сканирование {ip} на порты {start_port}-{end_port}")
    print(f"⚙️  Использую {threads} потоков, таймаут {timeout} сек")
    if get_banner:
        print("📋 Режим определения сервисов: ВКЛ")
    print("-" * 50)
    
    open_ports = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Создаем словарь задач
        futures = {}
        for port in range(start_port, end_port + 1):
            future = executor.submit(scan_port, ip, port, timeout, get_banner)
            futures[future] = port
        
        # Обрабатываем результаты
        count = 0
        total = end_port - start_port + 1
        
        for future in as_completed(futures):
            count += 1
            port = futures[future]
            result, banner = future.result()
            
            if result:
                service = COMMON_PORTS.get(port, "Unknown")
                if banner:
                    print(f"  ✅ Порт {port:5} | {service:12} | {banner}")
                else:
                    print(f"  ✅ Порт {port:5} | {service}")
                open_ports.append(port)
            
            # Показываем прогресс каждые 100 портов
            if count % 100 == 0:
                print(f"  ⏳ Прогресс: {count}/{total} портов проверено...")

    print("-" * 50)
    print(f"✅ Сканирование завершено!")
    if open_ports:
        print(f"📊 Найдено открытых портов: {len(open_ports)}")
        print(f"📋 Список: {sorted(open_ports)}")
    else:
        print("📊 Открытых портов не найдено")

def scan_common_ports(ip, threads=100, timeout=1.0, get_banner=False):
    """Сканирует только самые популярные порты"""
    ports = sorted(COMMON_PORTS.keys())
    print(f"🔍 Быстрое сканирование популярных портов на {ip}")
    return scan_ports(ip, min(ports), max(ports), threads, timeout, get_banner)

def main():
    parser = argparse.ArgumentParser(description="Продвинутый сканер портов", 
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog="""
Примеры запуска:
  python3 network_scanner.py 127.0.0.1 1-1000
  python3 network_scanner.py 127.0.0.1 1-1000 -b         # с определением сервисов
  python3 network_scanner.py scanme.nmap.org --common    # только популярные порты
  python3 network_scanner.py 192.168.1.1 1-1024 -t 200 --timeout 0.5
""")
    
    parser.add_argument("ip", help="IP-адрес цели (например 127.0.0.1)")
    
    # Группа для выбора режима сканирования
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("ports", nargs="?", help="Диапазон портов (например 20-100)")
    group.add_argument("--common", action="store_true", help="Сканировать только популярные порты")
    
    parser.add_argument("-t", "--threads", type=int, default=100, 
                       help="Количество потоков (по умолчанию 100)")
    parser.add_argument("--timeout", type=float, default=1.0, 
                       help="Таймаут подключения в секундах (по умолчанию 1.0)")
    parser.add_argument("-b", "--banner", action="store_true", 
                       help="Пытаться получить баннер сервиса")
    
    args = parser.parse_args()
    
    try:
        if args.common:
            scan_common_ports(args.ip, args.threads, args.timeout, args.banner)
        else:
            if not args.ports:
                parser.error("Укажите диапазон портов или используйте --common")
            
            start_p, end_p = map(int, args.ports.split('-'))
            if start_p < 1 or end_p > 65535:
                print("❌ Ошибка: Порты должны быть в диапазоне 1-65535")
                return
            if start_p > end_p:
                print("❌ Ошибка: Начальный порт должен быть меньше конечного")
                return
                
            scan_ports(args.ip, start_p, end_p, args.threads, args.timeout, args.banner)
        
    except ValueError:
        print("❌ Ошибка: Диапазон портов должен быть в формате 'начало-конец'")
        print("   Например: 20-100 или 1-1024")
        exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Сканирование прервано пользователем")
        exit(0)
    except Exception as e:
        print(f"❌ Неожиданная ошибка: {e}")
        exit(1)

if __name__ == "__main__":
    main()