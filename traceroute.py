# Запуск: sudo python3 traceroute.py google.com

import socket, struct, time, sys
# работа с сетью, числа в байты, замер времени, чтение аргументов в ком.строке

def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
    s = (s >> 16) + (s & 0xFFFF)
    return ~s & 0xFFFF

def ping(dst, ttl, seq): # IP назначения, значение TTL, порядковый номер пакета.
    # Echo Request  (8 байт)
    pkt = struct.pack("!BBHHH", 8, 0, 0, 1, seq) # (big-endian, тип, код, временная контрольная сумма, id пакета, порядковый номер)
    pkt = struct.pack("!BBHHH", 8, 0, checksum(pkt), 1, seq)  # пересобираем с реальной суммой

    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)# отправка (IPv4, сокет, протокол ICMP)
    rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)# приём
    rx.settimeout(2)

    tx.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    tx.sendto(pkt, (dst, 0))# отправка пакета (адрес и порт)
    t = time.time()#время отправки в сек.

    try:
        while True:
            raw, addr = rx.recvfrom(1024)
            icmp = raw[(raw[0] & 0xF) * 4:]   # младшие 4 бита первого байта, это длина IP-заголовка. * на 4 — получаем длину в байтах
            typ  = icmp[0] #первый байт ICMP — тип пакета

            check_icmp = icmp[28:] if typ == 11 else icmp
            if struct.unpack("!H", check_icmp[6:8])[0] == seq:
                return (time.time() - t) * 1000, addr[0]# время в миллисекундах и IP ответившего узла
    except socket.timeout:
        return None, None
    finally:
        tx.close(); rx.close()

dst  = sys.argv[1] # sys.argv — список аргументов из командной строки. [0] = имя файла, [1] = первый аргумент
ip   = socket.gethostbyname(dst) # превращает в IP
print(f"\ntraceroute to {dst} ({ip})\n")

seq = 1
for ttl in range(1, 31):
    results = []
    for i in range(3): # 3 пакета на каждый хоп
       results.append(ping(ip, ttl, seq))
       seq += 1  
    hop_ip  = next((r[1] for r in results if r[1]), None)
    times   = ["*" if r[0] is None else f"{r[0]:.1f} ms" for r in results]
    print(f"{ttl:2}.  {hop_ip or '*':<20}  {'  '.join(times)}")
    if hop_ip == ip:
        break