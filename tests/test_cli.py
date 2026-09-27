import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from dnsprobe.cli import format_rr  # noqa: E402
from dnsprobe.packet import hexdump  # noqa: E402


def run_cli(args):
    proc = subprocess.run(
        [sys.executable, "-m", "dnsprobe.cli"] + args,
        capture_output=True, text=True, cwd=REPO,
        env={**os.environ, "PYTHONPATH": REPO})
    return proc


class LocalDnsServer(threading.Thread):
    """UDP server answering A queries for test.example. with 192.0.2.7."""

    daemon = True

    def __init__(self):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]

    def run(self):
        from dnsprobe.packet import decode_name, build_response
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                return
            qid = struct.unpack(">H", data[:2])[0]
            qname, off = decode_name(data, 12)
            if qname == "test.example.":
                answer = [{"name": "test.example.", "type": 1,
                           "type_name": "A", "class": 1, "ttl": 120,
                           "rdata": "192.0.2.7"}]
                self.sock.sendto(build_response(qid, qname, "A", answers=answer),
                                 addr)


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = LocalDnsServer()
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.sock.close()

    def test_direct_query_human_output(self):
        proc = run_cli(["test.example", "A", "--server",
                        f"127.0.0.1:{self.server.port}", "--retries", "0"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("192.0.2.7", proc.stdout)
        self.assertIn("Cached: no", proc.stdout)

    def test_cache_file_makes_second_run_cached(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = os.path.join(tmp, "cache.json")
            addr = f"127.0.0.1:{self.server.port}"
            first = run_cli(["test.example", "A", "--server", addr,
                             "--retries", "0", "--cache-file", cache_path])
            second = run_cli(["test.example", "A", "--server", addr,
                              "--retries", "0", "--cache-file", cache_path])
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("Cached: no", first.stdout)
        self.assertIn("Cached: yes", second.stdout)

    def test_json_output(self):
        proc = run_cli(["test.example", "A", "--server",
                        f"127.0.0.1:{self.server.port}", "--retries", "0",
                        "--json"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["answers"][0]["rdata"], "192.0.2.7")
        self.assertIn("_query_ms", payload)

    def test_unreachable_server_exit_1(self):
        dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()
        proc = run_cli(["test.example", "A", "--server", f"127.0.0.1:{dead_port}",
                        "--timeout", "0.2", "--retries", "0"])
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no usable response", proc.stderr)

    def test_invalid_name_exit_2(self):
        proc = run_cli(["exa mple..com", "A", "--server", "127.0.0.1"])
        self.assertEqual(proc.returncode, 2)
        self.assertIn("invalid name", proc.stderr)

    def test_unknown_type_rejected_by_argparse(self):
        proc = run_cli(["test.example", "BOGUS", "--server", "127.0.0.1"])
        self.assertEqual(proc.returncode, 2)

    def test_dump_flag_prints_note(self):
        proc = run_cli(["test.example", "A", "--server",
                        f"127.0.0.1:{self.server.port}", "--retries", "0",
                        "--dump"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("QUERY PACKET", proc.stdout)

    def test_format_rr_alignment(self):
        rr = {"name": "a.test.", "type": 1, "type_name": "A", "class": 1,
              "ttl": 60, "rdata": "1.2.3.4"}
        line = format_rr(rr)
        self.assertIn("A", line)
        self.assertIn("60", line)
        self.assertIn("1.2.3.4", line)

    def test_format_rr_soa_and_mx_and_txt(self):
        soa = {"name": "test.", "type": 6, "type_name": "SOA", "class": 1,
               "ttl": 60, "rdata": {"mname": "ns.test.", "rname": "root.test.",
                                    "serial": 1, "refresh": 2, "retry": 3,
                                    "expire": 4, "minimum": 5}}
        self.assertIn("serial 1", format_rr(soa))
        mx = {"name": "test.", "type": 15, "type_name": "MX", "class": 1,
              "ttl": 60, "rdata": {"preference": 5, "exchange": "mx.test."}}
        self.assertIn("5 mx.test.", format_rr(mx))
        txt = {"name": "test.", "type": 16, "type_name": "TXT", "class": 1,
               "ttl": 60, "rdata": ["a", "b"]}
        self.assertIn('"a" "b"', format_rr(txt))

    def test_hexdump_basic(self):
        out = hexdump(b"GET / HTTP/1.1\r\n")
        self.assertEqual(out[0][:4], "0000")
        self.assertIn("G", out[0])


if __name__ == "__main__":
    unittest.main()
