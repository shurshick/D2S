from pathlib import Path
import re
root=Path(__file__).resolve().parents[1]
for directory in ("core","datapath","detect","runtime","panel","telegram","internal/web/assets","files"):
    for p in (root/directory).rglob("*"):
        if not p.is_file() or p.suffix not in (".c",".h",".js",".html",".sh") and p.name != "S99d2s": continue
        if any(x in p.parts for x in ("build",".git")): continue
        text=p.read_text(encoding="utf8")
        text=re.sub(r"https?://[^\s]+","",text)
        assert not re.search(r"d2k|D2K",text),str(p)
print("D2S runtime namespace: PASS")
