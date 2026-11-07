"""Production Gateway helpers against independent Python JSON/SHA-1 oracles."""
from pathlib import Path
import base64
import ctypes
import hashlib
import json
import os
import random
import shlex
import subprocess
import tempfile

source = (Path(__file__).parent / "verify.c").read_text()
start = source.index("typedef struct {\n    const uint8_t *p,*end;\n    unsigned op_count")
end = source.index("static int gateway_fill(", start)
nonce_start = source.index("static uint32_t gateway_rol(")
nonce_end = source.index("static int (*gateway_random_hook)", nonce_start)
code = "#include <stdint.h>\n#include <string.h>\n"
code += source[start:end] + source[nonce_start:nonce_end]
code += "int actual_json(const void *p,size_t n){return gateway_json_hello(p,n,0);}\n"
code += "void actual_accept(const char *key,char *out){gateway_accept(key,out);}\n"


class Object(dict):
    def __init__(self, pairs):
        super().__init__()
        self.duplicates = set()
        for key, value in pairs:
            if key in self:
                self.duplicates.add(key)
            self[key] = value


def reject_constant(value):
    raise ValueError(value)


def expected(raw):
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=Object,
                           parse_constant=reject_constant)
    except (ValueError, UnicodeError):
        return False
    if not isinstance(value, Object) or value.duplicates & {"op", "d"}:
        return False
    data = value.get("d")
    if not isinstance(data, Object) or "heartbeat_interval" in data.duplicates:
        return False
    op, interval = value.get("op"), data.get("heartbeat_interval")
    return type(op) is int and op == 10 and type(interval) is int and 0 < interval <= 0xffffffff


rng = random.Random(0x9b74cdb)
leaves = [None, True, False, 0, 1, 10, 45000, -1, 0xffffffff, 0x100000000,
          10.0, 1e100, "op", "hello ☺", "line\n\u0000"]


def nested(depth):
    if not depth or rng.randrange(3) == 0:
        return rng.choice(leaves)
    if rng.randrange(2):
        return [nested(depth - 1) for _ in range(rng.randrange(4))]
    return {key: nested(depth - 1) for key in rng.sample(
        ["x", "op", "d", "heartbeat_interval", "long" * 40], rng.randrange(4))}


with tempfile.TemporaryDirectory(prefix="d2s-gateway-") as temp:
    root = Path(temp)
    cfile, library = root / "actual.c", root / "actual.so"
    cfile.write_text(code)
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) + ["-std=c99", "-O1", "-Wall",
        "-Wextra", "-Werror", "-shared", "-fPIC", str(cfile), "-o", str(library)], check=True)
    lib = ctypes.CDLL(str(library))
    lib.actual_json.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.actual_json.restype = ctypes.c_int
    lib.actual_accept.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    for number in range(8000):
        value = {"op": rng.choice([10, 10, 9, True, 10.0, None]),
                 "d": {"heartbeat_interval": rng.choice([45000, 1, 0, -1, "45000", 0x100000000])},
                 "extra": nested(4)}
        if number % 7 == 0:
            value = nested(4)
        raw = json.dumps(value, ensure_ascii=bool(number % 2)).encode()
        if number % 3 == 0 and raw:
            pos = rng.randrange(len(raw))
            raw = raw[:pos] + (rng.choice([b"", b"}", b"\x00", b"\xff", b"10"])) + raw[pos + 1:]
        actual = lib.actual_json(raw, len(raw))
        assert (actual > 0) == expected(raw), (number, raw, actual)
    for raw in [b'{"op":10,"op":9,"d":{"heartbeat_interval":1}}',
                b'{"op":9,"op":10,"d":{"heartbeat_interval":1}}',
                b'{"op":10,"d":{"heartbeat_interval":1,"heartbeat_interval":2}}',
                b'{"\\u006fp":10,"d":{"heartbeat_interval":1}}']:
        assert (lib.actual_json(raw, len(raw)) > 0) == expected(raw)
    for number in range(300):
        key = base64.b64encode(bytes(rng.randrange(256) for _ in range(16)))
        answer = ctypes.create_string_buffer(29)
        lib.actual_accept(key, answer)
        reference = base64.b64encode(hashlib.sha1(
            key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
        assert answer.value == reference
print("Gateway: 8004 production JSON cases + 300 independent nonce/accept vectors PASS")
