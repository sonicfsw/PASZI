import unittest
from unittest.mock import patch, MagicMock

from monitor import NetworkMonitor

class MockAddr:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

class MockConnection:
    def __init__(self, laddr, raddr, status, pid, type_):
        self.laddr = laddr
        self.raddr = raddr
        self.status = status
        self.pid = pid
        self.type = type_

class TestNetworkMonitor(unittest.TestCase):
    @patch("monitor.psutil.net_connections")
    @patch("monitor.psutil.Process")
    @patch.object(NetworkMonitor, "_resolve_remote_domain", return_value="")
    def test_detects_suspicious_ip_connection(self, mock_resolve_domain, mock_process, mock_net_connections):
        monitor = NetworkMonitor()
        monitor.update_rules(ports=[], ips=["50.7.157.234"])

        # Псевдосоединение с удалённым IP 50.7.157.234
        conn = MockConnection(
            laddr=MockAddr("192.168.1.10", 52345),
            raddr=MockAddr("50.7.157.234", 443),
            status="ESTABLISHED",
            pid=1234,
            type_="socket"
        )

        mock_net_connections.return_value = [conn]
        mock_proc = MagicMock()
        mock_proc.name.return_value = "vpn-client"
        mock_process.return_value = mock_proc

        suspicious = monitor.get_suspicious_connections()

        self.assertEqual(len(suspicious), 1)
        self.assertEqual(suspicious[0]["remote_addr"], "50.7.157.234:443")
        self.assertIn("Подозрительный IP", suspicious[0]["reason"])

    @patch("monitor.psutil.net_connections")
    @patch("monitor.psutil.Process")
    @patch.object(NetworkMonitor, "_resolve_remote_domain", return_value="")
    def test_ignores_non_suspicious_connection(self, mock_resolve_domain, mock_process, mock_net_connections):
        monitor = NetworkMonitor()
        monitor.update_rules(ports=[], ips=["50.7.157.234"])

        conn = MockConnection(
            laddr=MockAddr("192.168.1.10", 52345),
            raddr=MockAddr("93.184.216.34", 443),
            status="ESTABLISHED",
            pid=1234,
            type_="socket"
        )

        mock_net_connections.return_value = [conn]
        mock_proc = MagicMock()
        mock_proc.name.return_value = "browser"
        mock_process.return_value = mock_proc

        suspicious = monitor.get_suspicious_connections()

        self.assertEqual(len(suspicious), 0)

if __name__ == "__main__":
    unittest.main()
