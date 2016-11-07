import socket
import errno
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Thread
import time


socket.setdefaulttimeout(3)


def scan_single_socket(ip_addr, port, queue):
        '''return value is one of following string:
            OPEN, TIMEOUT, REFUSED, UNDEFINED'''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # s.settimeout(3)
        try:
            s.connect((ip_addr, port))
            res = 'OPEN'
        except socket.timeout:
            res = 'TIMEOUT'
        except socket.error as sock_error:
            if sock_error.errno == errno.ECONNREFUSED:
                res = 'REFUSED'
            else:
                res = 'UNDEFINED'
        finally:
            s.close()
        queue.put((ip_addr, port, res))
        #return res


def scan_multiple_sockets_multithreaded(nets, ports):
    count_open = 0
    with ThreadPoolExecutor(250) as pool:
        futures = []
        for net in nets:
            for ip in net.hosts():
                for port in ports:
                    futures.append((ip, port,
                        pool.submit(scan_single_socket, str(ip), port)))
        for ip_addr, p, future in futures:
            res = future.result()
            if res == 'OPEN':
                count_open += 1
            print(ip_addr, p, future.result())
        print(count_open)


def scan_multi(nets, ports):
    q = Queue()
    threads = []
    for net in nets:
        for ip in net.hosts():
            for port in ports:
                t = Thread(target=scan_single_socket, args=(str(ip), port, q))
                t.start()
                threads.append(t)
    count_open = 0
    time.sleep(5)
    for thread in threads:
        thread.join()
        res = q.get()
        if res[2] == 'OPEN':
            count_open += 1
        print(res)
    print(count_open)


if __name__ == '__main__':
    # net = ipaddress.IPv4Network('85.14.4.0/24')
    net = ipaddress.IPv4Network('85.14.4.128/25')
    scan_multi([net], [80])
