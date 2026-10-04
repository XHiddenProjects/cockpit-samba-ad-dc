"""Registry.pol (PReg) writer/parser tests. Skipped automatically when Samba's Python modules are absent
(e.g. on a plain CI runner); on a DC they also check byte-for-byte equality with Samba's own serialiser."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
try:
    import gpo_backend as gb
    HAVE_SAMBA = True
except Exception:  # noqa: BLE001
    HAVE_SAMBA = False

ENTRIES = [
    {"key": "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", "name": "NoAutoUpdate", "type": 4, "data": 0},
    {"key": "Software\\Policies\\Test", "name": "Txt", "type": 1, "data": "h\u00e9llo w\u00f6rld"},
    {"key": "Software\\Policies\\Test", "name": "Exp", "type": 2, "data": "%SystemRoot%\\x"},
    {"key": "Software\\Policies\\Test", "name": "Multi", "type": 7, "data": ["a", "bb", "c c"]},
    {"key": "Software\\Policies\\Test", "name": "**del.Gone", "type": 1, "data": " "},
    {"key": "Software\\Policies\\Test", "name": "Big", "type": 11, "data": 2 ** 40 + 5},
    {"key": "Software\\Policies\\Test", "name": "Bin", "type": 3, "data": "deadbeef00"},
]


@unittest.skipUnless(HAVE_SAMBA, "Samba python modules not installed")
class Preg(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(gb.pol_parse(gb.pol_build(ENTRIES)), ENTRIES)

    def test_identical_to_samba_ndr(self):
        from samba.dcerpc import preg
        from samba.ndr import ndr_pack, ndr_unpack
        blob = gb.pol_build(ENTRIES)
        self.assertEqual(ndr_pack(ndr_unpack(preg.file, blob)), blob)

    def test_extension_name_helpers(self):
        s = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}]"
        d = gb.parse_exts(s)
        self.assertEqual(gb.build_exts(d), "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}]")


if __name__ == "__main__":
    unittest.main()
