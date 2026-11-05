import importlib.util
from pathlib import Path
p=Path(__file__).with_name("require-ci.py")
spec=importlib.util.spec_from_file_location("gate",p);gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
sha="a"*40;repo="shurshick/D2S"
base={"head_sha":sha,"status":"completed","conclusion":"success","event":"push","head_repository":{"full_name":repo},"html_url":"https://example.invalid/run"}
assert gate.approved_run({"workflow_runs":[base]},sha,repo)==base
for changed in ({"head_sha":"b"*40},{"status":"in_progress"},{"conclusion":"failure"},{"event":"pull_request"},{"head_repository":{"full_name":"someone/fork"}},{"head_repository":None}):
    assert gate.approved_run({"workflow_runs":[dict(base,**changed)]},sha,repo) is None
assert gate.approved_run({"workflow_runs":[]},sha,repo) is None
print("Release gate: exact successful push SHA and repository required PASS")
