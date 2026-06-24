import unittest
from unittest.mock import patch

from blocker import ConnectionBlocker


class TestConnectionBlocker(unittest.TestCase):
    @patch("blocker.shutil.which", return_value="/usr/sbin/pfctl")
    @patch("blocker.os.geteuid", return_value=0)
    @patch.object(ConnectionBlocker, "_ensure_pf_enabled")
    @patch.object(ConnectionBlocker, "_load_anchor_rules")
    @patch.object(ConnectionBlocker, "_is_anchor_referenced", return_value=True)
    def test_block_connection_adds_rule(
        self, mock_anchor_referenced, mock_load_anchor, mock_ensure_pf, mock_geteuid, mock_which
    ):
        blocker = ConnectionBlocker()
        blocker.can_block = False
        blocker.anchor_loaded = False

        blocker.block_connection({"remote_addr": "50.7.157.234:443"})

        self.assertIn(
            "block from any to 50.7.157.234 port 443",
            blocker.get_blocked_rules()
        )

    @patch("blocker.shutil.which", return_value="/usr/sbin/pfctl")
    @patch("blocker.os.geteuid", return_value=0)
    @patch.object(ConnectionBlocker, "_ensure_pf_enabled")
    @patch.object(ConnectionBlocker, "_load_anchor_rules")
    @patch.object(ConnectionBlocker, "_is_anchor_referenced", return_value=True)
    def test_unblock_connection_removes_rule(
        self, mock_anchor_referenced, mock_load_anchor, mock_ensure_pf, mock_geteuid, mock_which
    ):
        blocker = ConnectionBlocker()
        blocker.can_block = False
        blocker.anchor_loaded = False

        conn = {"remote_addr": "50.7.157.234:443"}
        blocker.block_connection(conn)
        blocker.unblock_connection(conn)

        self.assertNotIn(
            "block from any to 50.7.157.234 port 443",
            blocker.get_blocked_rules()
        )

    @patch("blocker.shutil.which", return_value=None)
    @patch("blocker.os.geteuid", return_value=1000)
    @patch("blocker.socket.getaddrinfo")
    def test_block_url_adds_entries(self, mock_getaddrinfo, mock_geteuid, mock_which):
        mock_getaddrinfo.return_value = [
            (None, None, None, None, ("93.184.216.34", 0)),
            (None, None, None, None, ("2606:2800:220:1:248:1893:25c8:1946", 0)),
        ]

        blocker = ConnectionBlocker()
        entries, error = blocker.block_url("https://example.com")

        self.assertEqual(error, "")
        self.assertEqual(len(entries), 2)
        self.assertEqual(blocker.get_blocked_entries()[0]["source"], "url")

    @patch("blocker.shutil.which", return_value=None)
    @patch("blocker.os.geteuid", return_value=1000)
    def test_unblock_by_id_removes_entry(self, mock_geteuid, mock_which):
        blocker = ConnectionBlocker()
        entry = blocker.block_connection({"remote_addr": "50.7.157.234:443"})

        ok, error = blocker.unblock_by_id(entry["id"])

        self.assertTrue(ok)
        self.assertEqual(error, "")
        self.assertEqual(blocker.get_blocked_entries(), [])

    @patch("blocker.shutil.which", return_value="/usr/sbin/pfctl")
    @patch("blocker.os.geteuid", return_value=0)
    @patch.object(ConnectionBlocker, "_run_command")
    @patch.object(ConnectionBlocker, "_get_local_interface_ips", return_value=[])
    def test_real_block_kills_existing_states_in_both_directions(
        self, mock_local_ips, mock_run_command, mock_geteuid, mock_which
    ):
        mock_run_command.side_effect = lambda command, input_text=None, timeout=5: (
            "Status: Enabled" if command == ["/usr/sbin/pfctl", "-s", "info"]
            else 'anchor "com.network_monitor"' if command == ["/usr/sbin/pfctl", "-s", "rules"]
            else ""
        )

        blocker = ConnectionBlocker()
        blocker.block_connection({"local_addr": "192.168.1.10:52133", "remote_addr": "50.7.157.234:443"})

        commands = [call.args[0] for call in mock_run_command.call_args_list]
        self.assertIn(
            ["/usr/sbin/pfctl", "-a", "com.network_monitor", "-t", "nm_blocked_hosts", "-T", "add", "50.7.157.234"],
            commands,
        )
        self.assertIn(["/usr/sbin/pfctl", "-k", "50.7.157.234"], commands)
        self.assertIn(["/usr/sbin/pfctl", "-k", "192.168.1.10", "-k", "50.7.157.234"], commands)
        self.assertIn(["/usr/sbin/pfctl", "-k", "50.7.157.234", "-k", "192.168.1.10"], commands)
        self.assertIn(["/usr/sbin/pfctl", "-k", "0.0.0.0/0", "-k", "50.7.157.234"], commands)

    @patch("blocker.shutil.which", return_value="/usr/sbin/pfctl")
    @patch("blocker.os.geteuid", return_value=0)
    @patch.object(ConnectionBlocker, "_run_command")
    @patch.object(ConnectionBlocker, "_get_local_interface_ips", return_value=["192.168.1.10"])
    def test_real_block_uses_interface_ips_when_connection_has_no_local_addr(
        self, mock_local_ips, mock_run_command, mock_geteuid, mock_which
    ):
        mock_run_command.side_effect = lambda command, input_text=None, timeout=5: (
            "Status: Enabled" if command == ["/usr/sbin/pfctl", "-s", "info"]
            else 'anchor "com.network_monitor"' if command == ["/usr/sbin/pfctl", "-s", "rules"]
            else ""
        )

        blocker = ConnectionBlocker()
        blocker.block_connection({"remote_addr": "50.7.157.234:443"})

        commands = [call.args[0] for call in mock_run_command.call_args_list]
        self.assertIn(["/usr/sbin/pfctl", "-k", "192.168.1.10", "-k", "50.7.157.234"], commands)

if __name__ == "__main__":
    unittest.main()
