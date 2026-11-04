import hashlib,json,sys
from pathlib import Path
root=Path(__file__).resolve().parents[2]
if len(sys.argv)>1: root=Path(sys.argv[1])
manifest=json.loads((Path(__file__).with_name("upstream-network.json")).read_text())
for name,expected in manifest.items():
    assert hashlib.sha256((root/name).read_bytes().replace(b"d2s",b"d2k").replace(b"D2S",b"D2K")).hexdigest()==expected,name+" differs from t0fox/d2o fd4e262"
s=(root/"files/S99d2s").read_text()
assert "lan_scope_rules" not in s and "d2s_lan_sync" not in s
print(str(len(manifest))+" upstream network files match after namespace normalization; no LAN scope hook")
