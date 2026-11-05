"""A release may use only a successful push CI for the exact selected commit."""
import json,os,re,subprocess,sys

def approved_run(data,sha,repo):
    for run in data.get("workflow_runs",[]):
        owner=(run.get("head_repository") or {}).get("full_name","")
        if (run.get("head_sha")==sha and run.get("status")=="completed"
            and run.get("conclusion")=="success" and run.get("event")=="push"
            and owner.casefold()==repo.casefold()):
            return run
    return None

def main():
    repo=os.environ["GITHUB_REPOSITORY"]
    sha=os.environ["GITHUB_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}",sha): raise SystemExit("Invalid release commit")
    url=f"repos/{repo}/actions/workflows/check.yml/runs?head_sha={sha}&status=success&event=push&per_page=100"
    data=json.loads(subprocess.check_output(["gh","api",url],text=True))
    run=approved_run(data,sha,repo)
    if not run: raise SystemExit("This commit has no successful D2S checks run. Wait for CI; release will not repeat or bypass tests.")
    print(f"CI approved {sha}: {run['html_url']}")

if __name__=="__main__": main()
