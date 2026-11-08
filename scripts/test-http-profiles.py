#!/usr/bin/env python3
"""Loopback TLS integration: production d2sfetch, no Internet or router required."""
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

FETCH = Path(__file__).resolve().parents[1] / "core" / "d2sfetch"


class Profiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cert, key = [str(Path(cls.tmp.name) / n) for n in ("cert.pem", "key.pem")]
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj",
                        "/CN=fixture.test", "-keyout", key, "-out", cert],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(cert, key)
        cls.context.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def compare(self, tls12=False):
        requests, errors = [], []
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(2)
            server.settimeout(5)
            def serve():
                try:
                    for _ in range(2):
                        conn, _ = server.accept()
                        with self.context.wrap_socket(conn, server_side=True) as peer:
                            peer.settimeout(3)
                            data = b""
                            while b"\r\n\r\n" not in data:
                                data += peer.recv(4096)
                            requests.append(data)
                            legacy = b"Accept: */*\r\n" in data
                            body = b"waf" if legacy else b"x" * 65536
                            code = b"403 Forbidden" if legacy else b"200 OK"
                            peer.sendall(b"HTTP/1.1 " + code + b"\r\nContent-Type: text/html\r\n"
                                         b"Connection: close\r\nContent-Length: " + str(len(body)).encode()
                                         + b"\r\n\r\n" + body)
                except Exception as exc:
                    errors.append(str(exc))
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            command = [str(FETCH), "--compare-http", "--name", "fixture.test", "--ip",
                       "127.0.0.1", "--port", str(server.getsockname()[1]), "--deadline", "1500"]
            if tls12:
                command.append("--tls12")
            result = subprocess.run(command, capture_output=True, text=True, timeout=8)
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        old, nav = data["comparison"]
        self.assertEqual([old["profile"], nav["profile"]], ["legacy", "navigation"])
        self.assertEqual([old["http"], nav["http"]], [403, 200])
        self.assertEqual([old["body"], nav["body"]], [3, 65536])
        self.assertEqual([old["level"], nav["level"]], [2, 3])
        self.assertTrue(all(row["complete"] for row in (old, nav)))
        self.assertTrue(all(row["tls"] == (0x303 if tls12 else 0x304) for row in (old, nav)))
        self.assertTrue(data["profiles_differ"])
        self.assertEqual(old["failure"], "http_denial_or_error")
        self.assertEqual(nav["failure"], "none")
        self.assertIn(b"Connection: close", requests[1])
        self.assertIn(b"Sec-Fetch-Mode: navigate", requests[1])
        self.assertIn(b"Accept-Encoding: identity", requests[1])

    def test_tls13(self):
        self.compare()

    def test_tls12(self):
        self.compare(tls12=True)

    def test_failed_tls_keeps_two_results(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            result = subprocess.run([str(FETCH), "--compare-http", "--name", "fixture.test",
                                     "--ip", "127.0.0.1", "--port", str(sock.getsockname()[1])],
                                    capture_output=True, text=True, timeout=3)
        data = json.loads(result.stdout)
        self.assertEqual(len(data["comparison"]), 2)
        self.assertTrue(all(row["failure"] == "connection_or_tls" and row["tls"] == 0
                            for row in data["comparison"]))

    def test_incompatible_modes_rejected_before_network(self):
        for args in (["--quic"], ["--ladder"], ["--path", "/resource"]):
            result = subprocess.run([str(FETCH), "--compare-http", "--name", "invalid.test", *args],
                                    capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 2)
            self.assertIn("root navigation", result.stderr)


if __name__ == "__main__":
    unittest.main()
