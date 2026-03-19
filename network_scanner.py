import socket #работа с сетью
import argparse 
from concurrent.futures import ThreadPoolExecutor, as_completed #многопоточность

def scan_port(ip, port, timeout=1.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
        return None
    except socket.error:
        return None

def scan_ports(ip, start_port, end_port, threads=100, timeout=1.0):
    print(f"Сканирование {ip} на порты {start_port}-{end_port}")
    print(f"Использую {threads} потоков, таймаут {timeout} сек")
    open_ports = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {} # Создаем словарь задач
        for port in range(start_port, end_port + 1):
            future = executor.submit(scan_port, ip, port, timeout)
            futures[future] = port
        
        # Обрабатываем результаты по мере готовности
        for future in as_completed(futures):
            port = futures[future]
            result = future.result()
            if result:
                print(f"Найден открытый порт: {port}")
                open_ports.append(port)

    print(f"\nСканирование завершено!")
    if open_ports:
        print(f" Открытые порты: {sorted(open_ports)}")
    else:
        print("Открытых портов не найдено")
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="Сканер портов", 
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog="""
Примеры запуска:
  python3 network_scanner.py 127.0.0.1 20-100
  python3 network_scanner.py scanme.nmap.org 22-100 -t 200
  python3 network_scanner.py 192.168.1.1 1-1024 --timeout 0.5
""")
    
    parser.add_argument("ip", help="IP-адрес цели (например 127.0.0.1)")
    parser.add_argument("ports", help="Диапазон портов (например 20-100 или 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100, 
                       help="Количество потоков (по умолчанию 100)")
    parser.add_argument("--timeout", type=float, default=1.0, 
                       help="Таймаут подключения в секундах (по умолчанию 1.0)")
    
    args = parser.parse_args()
    
    try:
        start_p, end_p = map(int, args.ports.split('-'))
        if start_p < 1 or end_p > 65535:
            print(" Ошибка: Порты должны быть в диапазоне 1-65535")
            return
        if start_p > end_p:
            print(" Ошибка: Начальный порт должен быть меньше конечного")
            return
            
        scan_ports(args.ip, start_p, end_p, args.threads, args.timeout)
        
    except ValueError:
        print(" Ошибка: Диапазон портов должен быть в формате 'начало-конец'")
        print(" Например: 20-100 или 1-1024")
        exit(1)
    except KeyboardInterrupt:
        print("\n\n Сканирование прервано пользователем")
        exit(0)

if __name__ == "__main__":
    main()