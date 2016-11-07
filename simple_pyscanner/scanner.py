#!/usr/bin/python3

import socket
import errno
import ipaddress
import argparse
import re
import csv
import sys
from concurrent.futures import ThreadPoolExecutor


class Scanner():

    def __init__(self, list_nets, list_ports,
                 socket_timeout, max_theads, list_port_states):
        self.nets = list_nets
        self.ports = list_ports
        self.timeout = socket_timeout
        self.theads = max_theads
        self.port_states = list_port_states

    def _scan_single_socket(self, ip_addr, port):
        '''return value is one of following string:
            OPEN, TIMEOUT, REFUSED, UNDEFINED'''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((ip_addr, port))
            return 'open'
        except socket.timeout:
            return 'noanswer'
        except socket.error as sock_error:
            if sock_error.errno == errno.ECONNREFUSED:
                return 'closed'
            else:
                return "undefined({})".format(sock_error)
        finally:
            s.close()

    def _get_next_ip_port(self):
        for net in self.nets:
            hosts = net.hosts()
            if net.prefixlen == 32:
                hosts = net
            for ip in hosts:
                for port in self.ports:
                    yield str(ip), port

    def _match_port_state(self, state):
        for searched_port_state in self.port_states:
            if state.startswith(searched_port_state):
                return True
        return False

    def _scan_multiple_sockets_singlethreaded(self):
        '''retrurn generator with tuple of ip, port, state
        '''
        for ip, port in self._get_next_ip_port():
            state = self._scan_single_socket(ip, port)
            if self._match_port_state(state):
                yield ip, port, state

    def _scan_multiple_sockets_multithreaded(self):
        with ThreadPoolExecutor(self.theads) as pool:
            futures = [
                (ip, port, pool.submit(self._scan_single_socket, ip, port))
                for ip, port in self._get_next_ip_port()
            ]
            for ip_addr, p, future in futures:
                state = future.result()
                if self._match_port_state(state):
                    yield ip_addr, p, state

    def start(self):
        '''return generator object'''
        if self.theads is None or self.theads <= 1:
            return self._scan_multiple_sockets_singlethreaded()
        else:
            return self._scan_multiple_sockets_multithreaded()


def range_or_int(string):
    m = re.match(r'(\d+)-(\d+)$', string)
    if m:
        start = int(m.group(1))
        end = int(m.group(2))
        return range(start, end)
    try:
        return int(string)
    except:
        pass
    raise argparse.ArgumentTypeError(
        "'%s' is not integer or range" % (string,))


def remove_nested_list(l):
    res = []
    for elem in l:
        if type(elem) is int:
            res.append(elem)
        else:
            res.extend(elem)
    return sorted(res)


parser = argparse.ArgumentParser(
    description='Simple TCP Three-way Handshake Port Scanner')
parser.add_argument('networks', nargs='+', type=ipaddress.IPv4Network,
                    metavar='networks/hosts')
parser.add_argument('-p', metavar='ports/ports range',
                    nargs='+', type=range_or_int, default=range(1, 1025),
                    help='port args also can be range like 11-102, default = 1-1024')
parser.add_argument('-o', metavar='output', default=sys.stdout,
                    type=argparse.FileType('w'), dest='out',
                    help='where to write output, default is stdout')

predefined_port_states = ['open', 'closed', 'noanswer', 'undefined']

parser.add_argument('--states', nargs='+',
                    default=predefined_port_states[0],
                    choices=predefined_port_states + ['all'],
                    help='results with selected port state will be shown')
parser.add_argument('--max-threads', type=int, default=250,
                    help='select 0 or 1 for single threaded, default = 250')
parser.add_argument('--socket-timeout', type=int, default=5,
                    help='set socket timeout, default = 5')
parser.add_argument('--delimiter', default='\t',
                    help='output word separator (delimiter) default is \\t')

args = parser.parse_args()

port_states = args.states
if port_states == ['all']:
    port_states = predefined_port_states.copy()


scanner = Scanner(list_nets=args.networks,
                  list_ports=remove_nested_list(args.p),
                  socket_timeout=args.socket_timeout,
                  max_theads=args.max_threads,
                  list_port_states=port_states)

res = scanner.start()

csv_w = csv.writer(args.out, delimiter=args.delimiter)
csv_w.writerows(res)
args.out.close()
