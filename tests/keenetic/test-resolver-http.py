import http.client,json,socket,subprocess,sys,time,unittest

binary=sys.argv[1]
sys.argv=sys.argv[:1]
class LocalHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with socket.socket() as s:
            s.bind(('127.0.0.1',0));cls.port=s.getsockname()[1]
        cls.proc=subprocess.Popen([binary,'--port',str(cls.port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                with socket.create_connection(('127.0.0.1',cls.port),.1): pass
                break
            except OSError: time.sleep(.05)
        else: raise RuntimeError('server did not start')
    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate();cls.proc.wait(timeout=3)
    def request(self,method,path,body=None,headers=None):
        c=http.client.HTTPConnection('127.0.0.1',self.port,timeout=6)
        c.request(method,path,body=body,headers=headers or {})
        r=c.getresponse(); data=r.read();c.close();return r.status,data
    def raw(self,data):
        with socket.create_connection(('127.0.0.1',self.port),2) as s:
            s.settimeout(6);s.sendall(data);out=b''
            while b'\r\n\r\n' not in out:
                chunk=s.recv(4096)
                if not chunk: break
                out+=chunk
        return int(out.split(b' ',2)[1])
    def test_health(self):
        status,body=self.request('GET','/health');self.assertEqual(status,200);self.assertTrue(json.loads(body)['ok'])
    def test_no_registration(self):
        self.assertEqual(self.request('POST','/register',b'x'*120)[0],404)
    def test_arbitrary_domains_refused(self):
        self.assertEqual(self.request('POST','/resolve',b'{"hosts":["example.com"]}')[0],400)
    def test_missing_body_refused(self):
        self.assertEqual(self.request('POST','/resolve',b'')[0],400)
    def test_nul_json_refused(self):
        self.assertEqual(self.request('POST','/resolve',b'{"hosts":["web.whatsapp.com"]}\0')[0],400)
    def test_extra_json_refused(self):
        self.assertEqual(self.request('POST','/resolve',b'{"hosts":["web.whatsapp.com"],"other":1}')[0],400)
    def test_duplicate_length_refused(self):
        data=b'POST /resolve HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n{} '
        self.assertEqual(self.raw(data),400)
    def test_transfer_encoding_refused(self):
        self.assertEqual(self.raw(b'POST /resolve HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n'),400)
    def test_oversized_body_refused(self):
        self.assertEqual(self.raw(b'POST /resolve HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2049\r\n\r\n'),400)
    def test_oversized_headers_refused(self):
        self.assertEqual(self.raw(b'GET /health HTTP/1.1\r\nX: '+b'x'*4096),431)
    def test_unknown_path_refused(self):
        self.assertEqual(self.request('GET','/anything')[0],404)
    def test_z_bounded_children_and_recovery(self):
        peers=[socket.create_connection(('127.0.0.1',self.port),2) for _ in range(2)]
        try:
            for s in peers: s.sendall(b'POST /resolve HTTP/1.1\r\n')
            time.sleep(.2)
            self.assertEqual(self.request('GET','/health')[0],503)
            time.sleep(4.2)
            self.assertEqual(self.request('GET','/health')[0],200)
        finally:
            for s in peers: s.close()

unittest.main(verbosity=2)
