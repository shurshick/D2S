import hashlib,json,sys,re
from pathlib import Path
root=Path(__file__).resolve().parents[2]
if len(sys.argv)>1: root=Path(sys.argv[1])
manifest=json.loads((Path(__file__).with_name("upstream-network.json")).read_text())
def original_namespace(data):
    data=data.replace(b"d2s",b"d2k").replace(b"D2S",b"D2K")
    data=data.replace(b"buf[*pos + 2] = 'S'",b"buf[*pos + 2] = 'K'")
    data=data.replace(b"b[n++]='S';",b"b[n++]='K';")
    data=data.replace(b"'D''2''S''P'",b"'D''2''K''P'")
    data=data.replace(b"cpath[o++] = 's';",b"cpath[o++] = 'k';")
    return re.sub(rb"('D',\s*'2',\s*)'S'",rb"\1'K'",data)
for name,expected in manifest.items():
    assert hashlib.sha256(original_namespace((root/name).read_bytes().replace(b"bb5131a8",b"680fbe00") if name == "core/test_probe_plan.c" else (root/name).read_bytes())).hexdigest()==expected,name+" differs from t0fox/d2o fd4e262"
s=(root/"files/S99d2s").read_text()
assert "lan_scope_rules" not in s and "d2s_lan_sync" not in s
print(str(len(manifest))+" upstream network files match after namespace normalization; no LAN scope hook")
