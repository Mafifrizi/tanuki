import struct
import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
from kcm_parser import scan_for_ccache_blobs


class TestKCMParser(unittest.TestCase):
    def test_scan_for_ccache_blobs(self):
        fake_db = bytearray(b"RANDOM_LDB_RECORDS_DATA_PADDING")
        
        valid_ccache = bytearray(b"\x05\x04")
        valid_ccache += struct.pack(">H", 12)
        valid_ccache += b"A" * 50
        
        fake_db += valid_ccache
        fake_db += b"MORE_PADDING_DATA"
        
        blobs = scan_for_ccache_blobs(bytes(fake_db))
        self.assertGreaterEqual(len(blobs), 1)
        pos, payload = blobs[0]
        self.assertTrue(payload.startswith(b"\x05\x04"))


if __name__ == "__main__":
    unittest.main()
