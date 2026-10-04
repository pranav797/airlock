"""Run: python test_airlock.py (or pytest). The sandbox test needs Docker and internet access."""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

AIRLOCK = str(Path(__file__).with_name("airlock.py"))
AGENT = "open('a.txt','w').write('changed\\n'); open('new.txt','w').write('hi\\n')"

# Runs inside the sandbox and records what a hostile agent could reach.
PROBE = b"""\
node -e 'fetch("https://example.com").then(()=>console.log("EGRESS_OPEN"),()=>console.log("egress_blocked"))' > net.txt
node -e 'require("http").request({host:new URL(process.env.HTTPS_PROXY).hostname,port:8080,method:"CONNECT",path:"example.com:443"}).on("connect",r=>{console.log(r.statusCode);process.exit()}).on("error",()=>console.log("err")).end()' > connect.txt
node -e 'require("http").request({host:new URL(process.env.HTTPS_PROXY).hostname,port:8080,method:"CONNECT",path:"pypi.org:443"}).on("connect",r=>{console.log(r.statusCode);process.exit()}).on("error",()=>console.log("err")).end()' > connect_allowed.txt
node -e 'fetch(process.env.ANTHROPIC_BASE_URL+"/v1/models",{headers:{"anthropic-version":"2023-06-01"}}).then(r=>console.log(r.status),()=>console.log("proxy_unreachable"))' > api.txt
env > env.txt
ls -a > ls.txt
mkdir -p .git/hooks && echo 'echo PWNED' > .git/hooks/post-checkout
ln -s /etc/passwd passwd-link
"""


def make_repo(extra=None):
    repo = Path(tempfile.mkdtemp())
    g = lambda *a: subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True)
    g("init", "-q")
    (repo / "a.txt").write_bytes(b"original\n")
    for name, data in (extra or {}).items():
        (repo / name).write_bytes(data)
    g("add", ".")
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
    return repo


def airlock(repo, answer, *args, env=None):
    return subprocess.run([sys.executable, AIRLOCK, "run", "-C", str(repo), *args],
                          input=answer, capture_output=True, text=True, env=env)


def unsandboxed(repo, answer):
    return airlock(repo, answer, "--no-sandbox", "--", sys.executable, "-c", AGENT)


def test_reject_leaves_tree_untouched():
    repo = make_repo()
    r = unsandboxed(repo, "n\n")
    assert r.returncode == 0, r.stderr
    assert (repo / "a.txt").read_bytes() == b"original\n"
    assert not (repo / "new.txt").exists()


def test_accept_applies():
    repo = make_repo()
    r = unsandboxed(repo, "y\n")
    assert r.returncode == 0, r.stderr
    assert (repo / "a.txt").read_text() == "changed\n"
    assert (repo / "new.txt").read_text() == "hi\n"


def test_agent_sees_uncommitted_edits():
    repo = make_repo()
    (repo / "a.txt").write_bytes(b"original\nuncommitted\n")
    agent = "s = open('a.txt').read(); assert 'uncommitted' in s; open('a.txt','w').write(s + 'agent\\n')"
    r = airlock(repo, "y\n", "--no-sandbox", "--", sys.executable, "-c", agent)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (repo / "a.txt").read_text() == "original\nuncommitted\nagent\n"


def test_conflict_saves_patch_and_changes_nothing():
    repo = make_repo()
    # you edit a.txt while the agent is running
    agent = f"open(r'{repo / 'a.txt'}','w').write('your edit\\n'); " + AGENT
    r = airlock(repo, "y\n", "--no-sandbox", "--", sys.executable, "-c", agent)
    assert r.returncode == 1
    assert (repo / "a.txt").read_text() == "your edit\n"
    assert not (repo / "new.txt").exists()  # atomic: no partial apply
    assert list((repo / ".git" / "airlock" / "runs").glob("*.patch"))


def test_log_undo_and_tamper_detection():
    repo = make_repo()
    assert unsandboxed(repo, "y\n").returncode == 0
    assert unsandboxed(repo, "n\n").returncode == 0
    log = lambda *a: subprocess.run([sys.executable, AIRLOCK, *a, "-C", str(repo)], capture_output=True, text=True)
    out = log("log")
    assert out.returncode == 0 and "applied" in out.stdout and "discarded" in out.stdout
    assert "hash chain intact" in out.stdout

    assert log("undo").returncode == 0  # most recent applied run
    assert (repo / "a.txt").read_text() == "original\n" and not (repo / "new.txt").exists()  # CRLF ok under autocrlf
    assert "applied (undone)" in log("log").stdout
    assert log("undo").returncode != 0  # nothing left to undo

    audit = repo / ".git" / "airlock" / "audit.jsonl"
    audit.write_bytes(audit.read_bytes().replace(b'"applied"', b'"discarded"', 1))
    out = log("log")
    assert out.returncode == 1 and "TAMPERED" in out.stdout


def test_policy_allow_applies_without_prompt():
    repo = make_repo({".airlock.toml": b'[policy]\nallow = ["*.txt"]\n'})
    r = unsandboxed(repo, "")  # no answer given: must not need one
    assert r.returncode == 0, r.stdout + r.stderr
    assert (repo / "a.txt").read_text() == "changed\n" and (repo / "new.txt").exists()


def test_policy_deny_and_confirm():
    repo = make_repo({".airlock.toml": b'[policy]\ndeny = ["new.txt"]\n'})
    agent = (AGENT + "; import os; os.makedirs('.github'); open('.github/ci.yml','w').write('evil\\n')"
             "; open('.airlock.toml','w').write('[policy]\\nallow = [\"*\"]\\n')")
    r = airlock(repo, "y\nn\n", "--no-sandbox", "--", sys.executable, "-c", agent)  # yes to normal, no to flagged
    assert r.returncode == 0, r.stdout + r.stderr
    assert "BLOCKED (will not be applied) new.txt" in r.stdout
    assert (repo / "a.txt").read_text() == "changed\n"   # ordinary change applied
    assert not (repo / "new.txt").exists()                # denied
    assert not (repo / ".github").exists()                # flagged by default rules, declined
    assert "deny" in (repo / ".airlock.toml").read_text()  # agent's policy rewrite flagged, declined


def test_partial_hunks_apply():
    import airlock
    lines = [f"line {n}\n" for n in range(1, 41)]
    repo = make_repo({"f.txt": "".join(lines).encode()})
    edited = lines[:]
    edited[2], edited[35] = "TOP\n", "BOTTOM\n"
    (repo / "f.txt").write_bytes("".join(edited).encode())
    (repo / "g.txt").write_bytes(b"new\n")
    subprocess.run(["git", "add", "-N", "g.txt"], cwd=repo, check=True)
    patch = subprocess.run(["git", "-c", "core.autocrlf=false", "diff", "--binary"], cwd=repo, capture_output=True).stdout
    subprocess.run(["git", "reset", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "checkout", "-q", "--", "f.txt"], cwd=repo, check=True)
    (repo / "g.txt").unlink()

    files = airlock.split_patch(patch)
    assert [airlock.path_of(f) for f in files] == ["f.txt", "g.txt"]
    assert len(files[0]["hunks"]) == 2
    # only the bottom hunk of f.txt, skip g.txt: line numbers of the kept hunk no longer line up, git copes
    assert airlock.apply(airlock.assemble(files, {(0, 1)}), repo)
    text = (repo / "f.txt").read_text()
    assert "BOTTOM" in text and "TOP" not in text and not (repo / "g.txt").exists()


def test_review_ui_requires_token():
    import json
    import threading
    import urllib.error
    import urllib.request
    import airlock_ui
    seen = {}

    def browser(url):
        def go():
            base, token = url.split("/?t=")
            seen["page"] = urllib.request.urlopen(url).read().decode()
            for bad in (base + "/?t=wrong", base + "/"):
                try:
                    urllib.request.urlopen(bad)
                except urllib.error.HTTPError as e:
                    seen.setdefault("denied", []).append(e.code)
            post = lambda tok: urllib.request.Request(base + "/decision", json.dumps({"accept": [[0, 1]]}).encode(),
                                                      {"X-Airlock-Token": tok}, method="POST")
            try:
                urllib.request.urlopen(post("wrong"))
            except urllib.error.HTTPError as e:
                seen["denied"].append(e.code)
            urllib.request.urlopen(post(token))
        threading.Thread(target=go, daemon=True).start()

    files = [{"path": "x", "action": "ask", "reasons": [], "header": "diff --git a/x b/x\n",
              "hunks": ["@@ -1 +1 @@\n-</script><b>\n+y\n"]}]
    assert airlock_ui.review(files, open_browser=browser) == {(0, 1)}
    assert seen["denied"] == [404, 404, 403]
    assert "</script><b>" not in seen["page"]  # untrusted diff can't break out of the data block


def test_sandbox_blocks_egress_and_hides_key():
    if not shutil.which("docker"):
        print("skip: docker not installed")
        return
    home = Path(tempfile.mkdtemp())
    (home / ".airlock").mkdir()
    fake_key = "fake-key-for-airlock-sandbox-test"
    (home / ".airlock" / "anthropic_api_key").write_text(fake_key)
    repo = make_repo({"probe.sh": PROBE, ".airlock.toml": b'[network]\nallow = ["pypi.org"]\n'})
    r = airlock(repo, "y\n", "--", "sh", "probe.sh", env={**os.environ, "USERPROFILE": str(home), "HOME": str(home)})
    assert r.returncode == 0, r.stdout + r.stderr
    out = lambda f: (repo / f).read_text().strip()
    assert out("net.txt") == "egress_blocked"   # no direct internet
    assert out("connect.txt") == "403"          # proxy refuses non-allowlisted tunnels
    assert out("connect_allowed.txt") == "200"  # ...but opens one to a host .airlock.toml allows
    assert out("api.txt") == "401"              # model API reachable via proxy; fake key rejected upstream
    assert fake_key not in out("env.txt")       # real key never enters the sandbox
    assert "ANTHROPIC_MODEL=haiku" in out("env.txt")  # cheap model by default
    assert ".git" not in out("ls.txt").split()  # no git dir to plant hooks/config in
    assert not (repo / ".git" / "hooks" / "post-checkout").exists()  # a planted .git never reaches the host
    assert not (repo / "passwd-link").exists() and not (repo / "passwd-link").is_symlink()  # left out or declined


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
