# Запуск: sudo python3 traceroute.py google.com

import socket, struct, time, sys

def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
    s = (s >> 16) + (s & 0xFFFF)
    return ~s & 0xFFFF

def ping(dst, ttl, seq):
    # Собираем ICMP Echo Request пакет (8 байт)
    pkt = struct.pack("!BBHHH", 8, 0, 0, 1, seq) # (тип, код, временная контрольная сумма, идентификатор пакета, порядковый номер)
    pkt = struct.pack("!BBHHH", 8, 0, checksum(pkt), 1, seq)  # пересобираем с реальной суммой

    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    rx.settimeout(2)

    tx.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    tx.sendto(pkt, (dst, 0))# отправка сокета
    t = time.time()

    try:
        while True:
            raw, addr = rx.recvfrom(1024)
            icmp = raw[(raw[0] & 0xF) * 4:]   # срезаем IP-заголовок
            typ  = icmp[0]

            # Тип 11 = TTL Exceeded (от роутера), тип 0 = Echo Reply (от цели)
            check_icmp = icmp[28:] if typ == 11 else icmp
            if struct.unpack("!H", check_icmp[6:8])[0] == seq:
                return (time.time() - t) * 1000, addr[0]
    except socket.timeout:
        return None, None
    finally:
        tx.close(); rx.close()

dst  = sys.argv[1]
ip   = socket.gethostbyname(dst)
print(f"\ntraceroute to {dst} ({ip})\n")

seq = 1
for ttl in range(1, 31):
    results = []
    for i in range(3):
       results.append(ping(ip, ttl, seq))
       seq += 1  
    hop_ip  = next((r[1] for r in results if r[1]), None)
    times   = ["*" if r[0] is None else f"{r[0]:.1f} ms" for r in results]
    print(f"{ttl:2}.  {hop_ip or '*':<20}  {'  '.join(times)}")
    if hop_ip == ip:
        break