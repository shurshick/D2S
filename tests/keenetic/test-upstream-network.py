import hashlib,json,sys,re
from pathlib import Path
root=Path(__file__).resolve().parents[2]
if len(sys.argv)>1: root=Path(sys.argv[1])
manifest=json.loads((Path(__file__).with_name("upstream-network.json")).read_text())
audited=json.loads((Path(__file__).with_name("audited-engine-changes.json")).read_text())
assert set(audited)<=set(manifest),"audited changes must refer to pinned base files"
def original_namespace(data):
    data=data.replace(b"d2s",b"d2k").replace(b"D2S",b"D2K")
    data=data.replace(b"buf[*pos + 2] = 'S'",b"buf[*pos + 2] = 'K'")
    data=data.replace(b"b[n++]='S';",b"b[n++]='K';")
    data=data.replace(b"'D''2''S''P'",b"'D''2''K''P'")
    data=data.replace(b"cpath[o++] = 's';",b"cpath[o++] = 'k';")
    return re.sub(rb"('D',\s*'2',\s*)'S'",rb"\1'K'",data)
for name,expected in manifest.items():
    data=(root/name).read_bytes()
    if name in audited:
        record=audited[name]
        explanation=record["reason"].split("#",1)[0]
        assert explanation in ("docs/performance-stage1.md","docs/performance-stage2.md","docs/performance-stage3.md","docs/telegram-web.md","docs/diagnostics-8e2c981.md","docs/algorithm-optimizations.md") and (root/explanation).is_file(),name+" has no audit explanation"
        assert hashlib.sha256(data).hexdigest()==record["sha256"],name+" differs from its reviewed D2S change"
    else:
        assert hashlib.sha256(original_namespace(data.replace(b"bb5131a8",b"680fbe00") if name == "core/test_probe_plan.c" else data)).hexdigest()==expected,name+" differs from t0fox/d2o fd4e262"
s=(root/"files/S99d2s").read_text()
assert "lan_scope_rules" not in s and "d2s_lan_sync" not in s
print(f"{len(manifest)-len(audited)} base files match; {len(audited)} reviewed D2S changes match pinned hashes; no LAN scope hook")
