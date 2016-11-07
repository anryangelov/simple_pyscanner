import unittest
from ..scanner import Scanner


class TestScan(unittest.TestCase):

        def setUp(self):

            self.scanner = Scanner(timeout=2)

        def test_single_socket_that_port_is_open(self):
            res = self.scanner.scan_single_socket('192.168.0.1', 80)
            self.assertEqual(res, 'OPEN')

        def test_single_socket_timeout(self):
            res = self.scanner.scan_single_socket('8.8.8.8', 443)
            self.assertEqual(res, 'TIMEOUT')

        def test_single_socket_refused(self):
            res = self.scanner.scan_single_socket('127.0.0.1', 9000)
            self.assertEqual(res, 'REFUSED')


if __name__ == '__main__':
    unittest.main()