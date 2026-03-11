# Запуск: sudo python3 traceroute.py 8.8.8.8
"""
Необходимо разработать простейший аналог утилиты traceroute / tracert, изученной в рамках первой лабораторной работы. В качестве протокола 
передачи данных можно использовать ICMP или UDP (на выбор). При реализации использовать программный интерфейс сокетов 
(готовые реализации отправки/получения echo запросов использовать запрещено). 
Утилита должна принимать в качестве параметра IP-адрес целевого узла и выводить узлы маршрута аналогично системному 
traceroute / tracert (порядковый номер, время ожидания ответа для каждого отправленного пакета и адрес узла). 
Следует отправлять более одного пакета. 
Проверьте, что разработанная программа дает такие же результаты, как и системная. Проанализируйте трафик, генерируемый вашей программой в 
процессе работы, с помощью Wireshark. Также Wireshark можно использовать при отладке, в случае проблем с получением эхо-ответов. 
Обратите внимание на значение контрольной суммы (Wireshark показывает, верно ли оно подсчитано) и обновление значения sequence number 
между отправками (изучите, как оно изменяется в системной утилите traceroute / tracert). 
"""
import socket, time, sys
# работа с сетью, числа в байты, замер времени, чтение аргументов в ком.строке

def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
    s = (s >> 16) + (s & 0xFFFF)
    return ~s & 0xFFFF

def ping(dst, ttl, seq): # IP назначения, значение TTL, порядковый номер пакета.
    # Echo Request  (8 байт)
    header = bytearray(8)
    header[0] = 8
    header[1] = 0

    #байт 2 и 3 оставляем под контрольную сумму

    header[4] = 0 #4 и 5 бвйты это ID(5 байт младший поэтому будет запоняться он)
    header[5] = 1

#6 и 7 байты - номер последовательности
    header[6] = (seq >> 8) & 0xFF #выполняем побитовый сдвиг на 8 позиций и применяем маску, чтобы взять только старшие 8 бит
    header[7] = seq & 0xFF #берём младшие 8 бит числа 

    check_sum = checksum(header) #контрольная сумма(для проверки)

    #посчитаную сумму кладём во 2 и 3 байты
    header[2] = (check_sum >> 8) & 0xFF # Старшие 8 бит контрольной суммы
    header[3] = check_sum & 0xFF # Младшие 8 бит контрольной суммы
    
    pkt = bytes(header)# Превращаем bytearray обратно в неизменяемые байты для отправки

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
            if ((check_icmp[6] << 8) + check_icmp[7]) == seq:
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