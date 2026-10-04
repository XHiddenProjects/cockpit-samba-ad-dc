"""Unit tests for sharing_diag.py's pure parsers. Needs only the Python standard library."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sharing_diag as d  # noqa: E402


class FirewallParsing(unittest.TestCase):
    UFW = """Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
445/tcp                    ALLOW       Anywhere
3702/udp                   ALLOW       Anywhere
Samba                      ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
5000:5002/tcp              ALLOW       192.168.1.0/24
"""

    def test_ufw_ports_and_ranges(self):
        active, allowed = d.parse_ufw(self.UFW)
        self.assertTrue(active)
        self.assertTrue(d.ufw_allows(allowed, "tcp", 445))
        self.assertTrue(d.ufw_allows(allowed, "udp", 3702))
        self.assertTrue(d.ufw_allows(allowed, "tcp", 5001))
        self.assertFalse(d.ufw_allows(allowed, "tcp", 5357))
        self.assertFalse(d.ufw_allows(allowed, "udp", 5355))

    def test_ufw_samba_profile_does_not_imply_ws_discovery(self):
        _, allowed = d.parse_ufw("Status: active\n\nTo Action From\n-- ------ ----\nSamba ALLOW Anywhere\n")
        self.assertTrue(d.ufw_allows(allowed, "tcp", 445))
        self.assertFalse(d.ufw_allows(allowed, "udp", 3702))

    def test_ufw_inactive(self):
        self.assertFalse(d.parse_ufw("Status: inactive\n")[0])

    def test_nftables(self):
        nft = """table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;
    tcp dport { 22, 445 } accept
    udp dport 3702 accept
  }
}"""
        restrictive, ports = d.parse_nft(nft)
        self.assertTrue(restrictive)
        self.assertIn(445, ports)
        self.assertNotIn(5357, ports)
        self.assertFalse(d.parse_nft("table inet filter { chain input { type filter hook input priority filter; policy accept; } }")[0])

    def test_firewalld(self):
        svcs, ports = d.parse_firewalld("", "ssh samba dhcpv6-client", "5357/tcp 3702/udp 8000-8002/tcp")
        self.assertIn("samba", svcs)
        self.assertIn(("tcp", 5357), ports)
        self.assertIn(("tcp", 8001), ports)


class ActiveDirectoryPorts(unittest.TestCase):
    """gpupdate 'lack of network connectivity to a domain controller' (event 1129) is usually a blocked AD port."""

    def missing(self, ufw_text, impl="wsdd-server"):
        _, allowed = d.parse_ufw(ufw_text)
        return [x for x in d._need(impl) if not all(d.ufw_allows(allowed, x[0], q) for q in set(d._probe(x[1])))]

    def test_file_sharing_only_firewall_blocks_the_domain(self):
        miss = self.missing("Status: active\n\nTo Action From\n-- ------ ----\n22/tcp ALLOW Anywhere\n445/tcp ALLOW Anywhere\n3702/udp ALLOW Anywhere\n5357/tcp ALLOW Anywhere\n")
        ports = {(p, n) for p, n, k, dd in miss}
        for need in [("tcp", 53), ("tcp", 88), ("tcp", 135), ("tcp", 389), ("udp", 389), ("tcp", "49152-65535")]:
            self.assertIn(need, ports)
        self.assertNotIn(("tcp", 445), ports)

    def test_fully_open(self):
        text = ("Status: active\n\nTo Action From\n-- ------ ----\n53 ALLOW Anywhere\n88 ALLOW Anywhere\n135/tcp ALLOW Anywhere\n137:138/udp ALLOW Anywhere\n"
                "139/tcp ALLOW Anywhere\n389 ALLOW Anywhere\n445/tcp ALLOW Anywhere\n464 ALLOW Anywhere\n636/tcp ALLOW Anywhere\n3268:3269/tcp ALLOW Anywhere\n49152:65535/tcp ALLOW Anywhere\n")
        self.assertEqual(self.missing(text, None), [])

    def test_partial_rpc_range_is_not_enough(self):
        _, allowed = d.parse_ufw("Status: active\n\nTo Action From\n-- ------ ----\n49152:50000/tcp ALLOW Anywhere\n")
        self.assertTrue(d.ufw_allows(allowed, "tcp", 49500))
        self.assertFalse(d.ufw_allows(allowed, "tcp", 60000))

    def test_nftables_and_firewalld_ranges(self):
        nft = "table inet filter { chain input { type filter hook input priority filter; policy drop; tcp dport { 22, 445, 49152-65535 } accept } }"
        self.assertTrue(d.nft_allows(nft, 60000))
        self.assertFalse(d.nft_allows(nft, 389))
        svcs, ports = d.parse_firewalld("", "ssh samba-dc", "")
        self.assertTrue(d.firewalld_allows(svcs, ports, "tcp", 389, "ldap"))
        svcs, ports = d.parse_firewalld("", "ssh samba", "49152-65535/tcp")
        self.assertTrue(d.firewalld_allows(svcs, ports, "tcp", 60000, "rpc"))
        self.assertFalse(d.firewalld_allows(svcs, ports, "tcp", 389, "ldap"))


class ProcNet(unittest.TestCase):
    def test_listener_parsing(self):
        t = tempfile.mkdtemp()
        hdr = "  sl  local_address rem_address   st\n"
        open(t + "/tcp", "w").write(hdr + "   0: 00000000:01BD 00000000:0000 0A 0\n   1: 0100007F:0035 00000000:0000 0A 0\n   2: 0201A8C0:1F90 0100007F:9999 01 0\n")
        open(t + "/tcp6", "w").write(hdr + "   0: 00000000000000000000000000000000:0185 00000000000000000000000000000000:0000 0A 0\n")
        open(t + "/udp", "w").write(hdr + "   0: 0201A8C0:0E76 00000000:0000 07 0\n")
        self.assertEqual(d.listening_on("tcp", 445, root=t), ["0.0.0.0"])
        self.assertEqual(d.listening_on("tcp", 53, root=t), ["127.0.0.1"])
        self.assertEqual(d.listening_on("tcp", 389, root=t), ["::"])
        self.assertEqual(d.listening_on("tcp", 8080, root=t), [])  # ESTABLISHED is not a listener
        self.assertEqual(d.listening_on("udp", 3702, root=t), ["192.168.1.2"])
        self.assertTrue(d.is_wildcard(["::"]))
        self.assertFalse(d.is_wildcard(["127.0.0.1"]))


class DnsNames(unittest.TestCase):
    def test_compressed_name(self):
        # "dc1.test.lan" at offset 0, then a pointer to offset 4 ("test.lan")
        data = b"\x03dc1\x04test\x03lan\x00" + b"\x03ldc\xc0\x04"
        name, end = d._read_name(data, 0)
        self.assertEqual((name, end), ("dc1.test.lan", 14))
        name2, end2 = d._read_name(data, 14)
        self.assertEqual(name2, "ldc.test.lan")
        self.assertEqual(end2, len(data))


class SmbHints(unittest.TestCase):
    def test_every_hint_has_a_layer_and_message(self):
        for code, (layer, msg) in d.NT_HINTS.items():
            self.assertTrue(code.startswith("NT_STATUS_"))
            self.assertIn(layer, {"auth", "acl", "share", "network", "protocol"})
            self.assertTrue(msg)

    def test_rejects_bad_names(self):
        # the helper validates share/user before shelling out
        import json, subprocess
        p = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "..", "sharing_diag.py")],
                           input=json.dumps({"cmd": "smb_test", "share": "x; rm -rf /", "user": "a"}), capture_output=True, text=True)
        self.assertFalse(json.loads(p.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
