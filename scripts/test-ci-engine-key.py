"""Docs/UI reuse the engine proof; code, recipes and CLI fixtures invalidate it."""
from pathlib import Path
import os,subprocess,tempfile
root=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp:
    repo=Path(temp)
    def git(*args): return subprocess.check_output(["git","-C",str(repo),*args],stderr=subprocess.STDOUT,text=True)
    git("init","-q");git("config","user.email","test@example.invalid");git("config","user.name","CI test")
    paths=["core/input.c","datapath/input.c","detect/input.c","runtime/input.h","scripts/test-d2sfetch-cli.py",".github/workflows/check.yml"]
    for rel in paths:
        p=repo/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text("fixture\n")
    keyscript=repo/"scripts/ci-engine-key.sh";keyscript.write_bytes((root/"scripts/ci-engine-key.sh").read_bytes())
    def commit(): git("add",".");git("commit","-qm","fixture")
    def key():return subprocess.check_output(["sh",str(keyscript)],text=True).strip()
    commit();first=key();assert len(first)==64
    (repo/"README.md").write_text("docs change\n");commit();assert key()==first
    css=repo/"internal/web/assets/panel.css";css.parent.mkdir(parents=True);css.write_text(".card {}\n");commit();assert key()==first
    p=repo/"core/input.c";p.write_text("changed engine\n")
    assert subprocess.run(["sh",str(keyscript)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
    commit();second=key();assert second!=first
    (repo/"scripts/test-d2sfetch-cli.py").write_text("changed fixture\n");commit();third=key();assert third!=second
    (repo/".github/workflows/check.yml").write_text("changed workflow\n");commit();assert key()!=third
print("Engine proof key: docs/UI reuse, source/fixture/workflow invalidation, dirty-source rejection PASS")
