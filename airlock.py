"""Airlock: run an AI coding agent in a sandboxed copy of your repo, review the diff, apply or discard."""
import argparse
import contextlib
import fnmatch
import functools
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

import airlock_ui

PROXY_IMAGE = "python:3.13-alpine"
KEY_FILE = Path.home() / ".airlock" / "anthropic_api_key"
DEFAULT_MODEL = os.environ.get("AIRLOCK_MODEL", "haiku")  # cheapest; claude's own --model still wins
DOCKERFILE = """\
FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates python3 \\
 && rm -rf /var/lib/apt/lists/*
RUN npm install -g @anthropic-ai/claude-code
ENV PYTHONDONTWRITEBYTECODE=1
USER node
WORKDIR /work
"""
# Tag by recipe hash, so editing DOCKERFILE rebuilds automatically.
AGENT_IMAGE = "airlock-agent:" + hashlib.sha256(DOCKERFILE.encode()).hexdigest()[:12]
HARDEN = ["--cap-drop=ALL", "--security-opt", "no-new-privileges", "--read-only", "--pids-limit", "512"]


def git(*args, cwd, text=True, check=True, **kw):
    return subprocess.run(["git", *args], cwd=cwd, check=check, capture_output=True, text=text, **kw)


def docker(*args, check=True, **kw):
    return subprocess.run(["docker", *args], check=check, capture_output=True, text=True, **kw)


def split_patch(patch):
    """Split a git patch into files: [{"header": [lines], "hunks": [[lines], ...]}] (lines are bytes)."""
    files = []
    for line in patch.splitlines(keepends=True):
        if line.startswith(b"diff --git "):
            files.append({"header": [line], "hunks": []})
        elif line.startswith(b"@@"):  # content lines are prefixed, so this is always a hunk header
            files[-1]["hunks"].append([line])
        elif files[-1]["hunks"]:
            files[-1]["hunks"][-1].append(line)
        else:
            files[-1]["header"].append(line)
    return files


def assemble(files, accept):
    """Rebuild a patch from the accepted (file, hunk) ids; (i, None) selects a file without hunks."""
    out = []
    for i, f in enumerate(files):
        picked = [h for j, h in enumerate(f["hunks"]) if (i, j) in accept]
        if picked or (not f["hunks"] and (i, None) in accept):
            out += f["header"] + [line for h in picked for line in h]
    return b"".join(out)


def path_of(f):
    for prefix in (b"+++ b/", b"--- a/"):
        for line in f["header"]:
            if line.startswith(prefix):
                return line[len(prefix):].rstrip(b"\r\n").decode(errors="replace")
    return f["header"][0][11:].rstrip(b"\r\n").decode(errors="replace")


def file_warnings(f):
    """Flag changes that are easy to miss in review."""
    out = []
    for line in (l.decode(errors="replace").strip() for l in f["header"]):
        if line.endswith(" 120000"):
            out.append("symlink")
        elif "160000" in line:
            out.append("nested git repo (will not be applied)")
        elif line.startswith("new mode"):
            out.append(f"permission change ({line})")
        elif line.startswith("deleted file mode"):
            out.append("file deleted")
        elif line.startswith(('diff --git "', '--- "', '+++ "', 'rename from "', 'rename to "')):
            out.append("unusual file name (policy rules may not match it)")
    return sorted(set(out))


def paths_of(f):
    """Every path a file diff touches (both sides of a rename), so rules can't be dodged by moving files."""
    paths = set()
    for line in (l.rstrip(b"\r\n").decode(errors="replace") for l in f["header"]):
        for prefix in ("--- a/", "+++ b/", "rename from ", "rename to ", "copy from ", "copy to "):
            if line.startswith(prefix):
                paths.add(line[len(prefix):])
    if not paths:  # e.g. binary files have no ---/+++ lines
        a, _, b = f["header"][0][len(b"diff --git a/"):].rstrip(b"\r\n").decode(errors="replace").partition(" b/")
        paths = {a, b}
    return paths


# Built-in rules; a repo's .airlock.toml adds to these. Patterns without "/" match the file name anywhere,
# patterns with "/" match the full path. `*` also matches across directories.
DEFAULT_POLICY = {
    "confirm": [
        ".airlock.toml",
        ".github/*", ".gitlab-ci.yml", ".circleci/*", "Jenkinsfile", ".pre-commit-config.yaml", ".husky/*",
        ".gitattributes", ".gitmodules", ".gitignore",
        ".vscode/*", ".idea/*", ".devcontainer/*", "*Dockerfile*", "docker-compose*", "Makefile",
        "package.json", "requirements*.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile",
        "Cargo.toml", "go.mod", "go.sum", "Gemfile", "*.lock", "*-lock.json", "*-lock.yaml",
    ],
}
ACTIONS = ("allow", "confirm", "deny")


def load_policy(root):
    """File rules plus "hosts": extra HTTPS egress the repo always needs ([network] allow)."""
    policy = {a: list(DEFAULT_POLICY.get(a, [])) for a in ACTIONS}
    policy["hosts"] = []
    path = Path(root, ".airlock.toml")
    if path.is_file():
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as e:
            sys.exit(f"airlock: invalid {path}: {e}")
        for a in ACTIONS:
            policy[a] += data.get("policy", {}).get(a, [])
        policy["hosts"] += data.get("network", {}).get("allow", [])
    return policy


def matches(pattern, path):
    return fnmatch.fnmatchcase(path if "/" in pattern else path.rsplit("/", 1)[-1], pattern)


def decide(f, policy):
    """Return (action, reasons) for one file diff. Strictest wins: deny > confirm > allow > ask."""
    hits = {a: [f"{a} rule '{pat}' ({p})" for pat in policy[a] for p in sorted(paths_of(f)) if matches(pat, p)]
            for a in ("deny", "confirm")}
    warnings = file_warnings(f)
    if hits["deny"]:
        return "deny", hits["deny"]
    if hits["confirm"] or warnings:
        return "confirm", hits["confirm"] + warnings
    if all(any(matches(pat, p) for pat in policy["allow"]) for p in paths_of(f)):
        return "allow", []
    return "ask", []


def ask(question):
    try:
        return input(question).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def apply(patch, root, reverse=False):
    """git apply is all-or-nothing: on a conflict the tree is untouched and this returns False."""
    res = subprocess.run(["git", "apply", *(["-R"] if reverse else []), "-"], cwd=root, input=patch, capture_output=True)
    print(res.stderr.decode(errors="replace"), end="")
    return res.returncode == 0


def repo_paths(repo):
    try:
        root = git("rev-parse", "--show-toplevel", cwd=repo).stdout.strip()
        git("rev-parse", "HEAD", cwd=root)
    except subprocess.CalledProcessError:
        sys.exit("airlock: needs a git repository with at least one commit")
    return root, git("rev-parse", "--absolute-git-dir", cwd=root).stdout.strip()


# Audit log: .git/airlock/audit.jsonl, outside anything the agent can reach. Each line carries the SHA-256
# of the previous line, so editing or deleting history breaks the chain (tamper-evident, not tamper-proof:
# someone with write access to .git could rewrite the whole chain).
def audit_path(gitdir):
    return Path(gitdir, "airlock", "audit.jsonl")


def audit(gitdir, event):
    log = audit_path(gitdir)
    log.parent.mkdir(exist_ok=True)
    lines = log.read_bytes().splitlines() if log.exists() else []  # ponytail: rereads the log; fine for thousands of runs
    event = {**event, "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
             "prev": hashlib.sha256(lines[-1]).hexdigest() if lines else None}
    with log.open("ab") as fh:
        fh.write(json.dumps(event, sort_keys=True).encode() + b"\n")


def read_audit(gitdir):
    """Return (events, line number where the hash chain breaks or None)."""
    log = audit_path(gitdir)
    lines = log.read_bytes().splitlines() if log.exists() else []
    events, broken = [], None
    for n, line in enumerate(lines):
        try:
            e = json.loads(line)
        except ValueError:
            e = {}
        if broken is None and e.get("prev") != (hashlib.sha256(lines[n - 1]).hexdigest() if n else None):
            broken = n + 1
        events.append(e)
    return events, broken


def show_log(repo):
    _, gitdir = repo_paths(repo)
    events, broken = read_audit(gitdir)
    if broken:  # first, so it can't scroll away; entries from that line on may be forged
        print(f"airlock: AUDIT LOG TAMPERED: hash chain breaks at line {broken} of {audit_path(gitdir)}")
    runs = {}
    for e in events:
        runs.setdefault(str(e.get("run")), {}).setdefault(e.get("event"), e)
    print(f"{'RUN':<22} {'OUTCOME':<18} {'FILES':<6} COMMAND")
    for run_id, ev in runs.items():  # .get everywhere: a tampered log must still display, not crash
        res = ev.get("result", {})
        files = [f for f in res.get("files", []) if isinstance(f, dict)]
        outcome = str(res.get("outcome", "incomplete")) + (" (undone)" if "undo" in ev else "")
        applied = f"{sum(bool(f.get('applied')) for f in files)}/{len(files)}" if files else "-"
        cmd = " ".join(map(str, ev.get("start", {}).get("cmd", [])))
        print(f"{run_id:<22} {outcome:<18} {applied:<6} {cmd[:70]}")
    if broken:
        return 1
    print(f"airlock: {len(events)} events, hash chain intact")
    return 0


def undo(repo, run_id=None):
    root, gitdir = repo_paths(repo)
    events, broken = read_audit(gitdir)
    if broken:
        sys.exit(f"airlock: audit log hash chain breaks at line {broken}; refusing to undo from it")
    undone = {e["run"] for e in events if e.get("event") == "undo"}
    applied = [e for e in events if e.get("event") == "result" and e.get("outcome") == "applied"
               and e["run"] not in undone and (run_id is None or e["run"] == run_id)]
    if not applied:
        sys.exit(f"airlock: no applied, not-yet-undone run {run_id or ''}".rstrip())
    res = applied[-1]
    patch = Path(gitdir, "airlock", res["patch"]).read_bytes()
    if hashlib.sha256(patch).hexdigest() != res["sha256"]:
        sys.exit(f"airlock: {res['patch']} doesn't match the hash in the audit log; refusing to undo")
    if not apply(patch, root, reverse=True):
        print(f"airlock: run {res['run']} can't be undone cleanly (later edits touch the same lines); nothing changed")
        return 1
    audit(gitdir, {"run": res["run"], "event": "undo"})
    print(f"airlock: undid run {res['run']}")
    return 0


@contextlib.contextmanager
def sandbox(allow_hosts):
    """Internal-only network + credential-injecting proxy. Yields the `docker run` prefix for the agent."""
    if not shutil.which("docker"):
        sys.exit("airlock: docker not found (install Docker, or use --no-sandbox)")
    if docker("info", check=False).returncode:
        sys.exit("airlock: Docker isn't running (start Docker Desktop, or use --no-sandbox)")
    if not KEY_FILE.is_file():
        sys.exit(f"airlock: put your Anthropic API key in {KEY_FILE}")
    if docker("image", "inspect", AGENT_IMAGE, check=False).returncode:
        print(f"airlock: building {AGENT_IMAGE} image (first run only)")
        subprocess.run(["docker", "build", "-t", AGENT_IMAGE, "-"], input=DOCKERFILE, text=True, check=True)

    name = f"airlock-{secrets.token_hex(4)}"
    proxy = f"{name}-proxy"
    docker("network", "create", "--internal", name)  # no route to the internet or the host
    try:
        # `-e NAME` with no value copies it from our env: the key never appears on a command line.
        docker("run", "-d", "--rm", "--name", proxy, *HARDEN, "--user", "65534:65534",
               "-e", "ANTHROPIC_API_KEY", "-e", f"AIRLOCK_ALLOW_HOSTS={','.join(allow_hosts)}",
               PROXY_IMAGE, "python", "-c", Path(__file__).with_name("airlock_proxy.py").read_text(),
               env={**os.environ, "ANTHROPIC_API_KEY": KEY_FILE.read_text().strip()})
        docker("network", "connect", name, proxy)
        for _ in range(100):
            if "ready" in docker("logs", proxy, check=False).stdout:
                break
            time.sleep(0.1)
        else:
            sys.exit("airlock: egress proxy did not start")

        url = f"http://{proxy}:8080"
        # Run as the host user where there is one (Linux/macOS), so the private temp dir is readable and new
        # files come back owned by you. Windows has no uids; Docker Desktop maps ownership itself.
        uid, gid = (os.getuid(), os.getgid()) if hasattr(os, "getuid") else (1000, 1000)
        # Attach stdin only for a real terminal; piped stdin is reserved for the approval prompt. Check stdout
        # too: Windows reports the NUL device as a tty, and docker then refuses -t.
        tty = sys.stdin.isatty() and sys.stdout.isatty()
        yield ["docker", "run", "--rm", *(["-it"] if tty else []), "--name", name,
               "--user", f"{uid}:{gid}", "-e", "HOME=/home/node",
               "--network", name, *HARDEN, "--tmpfs", "/tmp", "--tmpfs", f"/home/node:uid={uid},gid={gid}",
               "-e", f"ANTHROPIC_BASE_URL={url}", "-e", "ANTHROPIC_API_KEY=airlock-placeholder",
               "-e", f"HTTPS_PROXY={url}", "-e", f"HTTP_PROXY={url}", "-e", f"NO_PROXY={proxy}",
               "-e", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"]
    finally:
        docker("rm", "-f", name, proxy, check=False)
        docker("network", "rm", name, check=False)


def run(cmd, repo, use_sandbox=True, allow_hosts=(), model=DEFAULT_MODEL, ui=False):
    root, gitdir = repo_paths(repo)
    policy = load_policy(root)  # read before the agent runs, from your tree, so the agent can't rewrite it
    allow_hosts = sorted({*allow_hosts, *policy["hosts"]})
    if any(l.startswith("??") for l in git("status", "--porcelain", cwd=root).stdout.splitlines()):
        print("airlock: note: untracked files are not visible to the agent (git add them to include them)")

    tmp = tempfile.mkdtemp(prefix="airlock-")
    work = os.path.join(tmp, "work")
    os.mkdir(work)
    # The agent gets a plain export of your tracked files as they are now, uncommitted edits included:
    # no .git, so no hooks or config it could plant for the host. Untracked files (stray secrets) stay out.
    # The host tracks it with a throwaway index in the real repo's object store.
    env = {**os.environ, "GIT_INDEX_FILE": os.path.join(tmp, "index")}
    # A Linux sandbox wants LF, whatever the host's core.autocrlf says.
    eol = ["-c", "core.autocrlf=false", "-c", "core.eol=lf"] if use_sandbox else []
    wgit = functools.partial(git, *eol, f"--git-dir={gitdir}", f"--work-tree={work}", cwd=work, env=env)
    run_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2)}"
    result = {"run": run_id, "event": "result", "outcome": "aborted"}
    started = False
    try:
        git("read-tree", "HEAD", cwd=root, env=env)
        git("add", "-u", cwd=root, env=env)
        base = git("write-tree", cwd=root, env=env).stdout.strip()  # snapshot the diff is taken against
        wgit("checkout-index", "-a")
        audit(gitdir, {"run": run_id, "event": "start", "cmd": cmd, "model": model, "sandbox": use_sandbox,
                       "allow_hosts": list(allow_hosts), "base_tree": base, "policy": policy})
        started = True
        print(f"airlock: run {run_id}")

        with sandbox(allow_hosts) if use_sandbox else contextlib.nullcontext() as prefix:
            if prefix:
                print("airlock: running agent in sandbox (no network except the model API"
                      + (f" and {', '.join(allow_hosts)})" if allow_hosts else ")"))
                argv = [*prefix, "-e", f"ANTHROPIC_MODEL={model}",
                        "--mount", f"type=bind,src={work},dst=/work", "-w", "/work", AGENT_IMAGE, *cmd]
            else:
                print(f"airlock: running agent UNSANDBOXED in {work}")
                argv = [shutil.which(cmd[0]) or cmd[0], *cmd[1:]]  # resolves .cmd shims on Windows
            rc = subprocess.run(argv, cwd=work, env={**os.environ, "ANTHROPIC_MODEL": model}).returncode
        result["agent_exit"] = rc
        if rc:
            print(f"airlock: agent exited with code {rc}; its changes are still shown for review")

        # The agent's files are untrusted input: one git can't read (e.g. a symlink made in the container shows
        # up on a Windows bind mount as a reparse point) must not crash the review. Leave it out, loudly.
        added = wgit("add", "-A", "--ignore-errors", check=False)
        unreadable = re.findall(r"unable to index file '(.+)'", added.stderr)
        if added.returncode and not unreadable:
            raise subprocess.CalledProcessError(added.returncode, added.args, added.stdout, added.stderr)
        for path in unreadable:
            print(f"airlock: WARNING {path}: git can't read this file (e.g. a symlink on Windows); left out, never applied")
        result["unreadable"] = unreadable
        # Plumbing, so user config (color.diff, diff.noprefix, renames) can't change the patch format.
        patch = wgit("-c", "core.quotepath=false", "diff-index", "--cached", "-p", "--binary", base, text=False).stdout
        if not patch:
            print("airlock: no changes.")
            result["outcome"] = "no_changes"
            return 0

        files = split_patch(patch)
        verdicts = [decide(f, policy) for f in files]
        subprocess.run(["git", *eol, f"--git-dir={gitdir}", f"--work-tree={work}", "--no-pager",
                        "diff", "--cached", "--stat", *([] if ui else ["--patch"]), base], cwd=work, env=env)
        for f, (action, reasons) in zip(files, verdicts):
            label = {"deny": "BLOCKED (will not be applied)", "confirm": "NEEDS CONFIRMATION"}.get(action)
            if label:
                print(f"airlock: {label} {path_of(f)}: {'; '.join(reasons)}")

        def pick(idx):  # every hunk of these files; a file without hunks is (i, None)
            return {(i, j) for i in idx for j in (range(len(files[i]["hunks"])) or [None])}

        by = lambda *actions: [i for i, (a, _) in enumerate(verdicts) if a in actions]
        if len(by("allow")) == len(files):
            print("airlock: every change is allowed by policy; applying without review")
            accept = pick(by("allow"))
        elif ui:
            text = lambda lines: b"".join(lines).decode(errors="replace")
            accept = airlock_ui.review([{"path": path_of(f), "action": a, "reasons": r, "header": text(f["header"]),
                                         "hunks": [text(h) for h in f["hunks"]]} for f, (a, r) in zip(files, verdicts)])
            accept = {(i, j) for i, j in accept or () if i not in by("deny")}  # don't trust the page with deny
        else:
            accept = set()
            if by("allow", "ask") and ask(f"Apply {len(by('allow', 'ask'))} file(s) to your working tree? [y/N] "):
                accept |= pick(by("allow", "ask"))
            flagged = by("confirm")
            if flagged and ask(f"Also apply the {len(flagged)} flagged file(s): "
                               f"{', '.join(path_of(files[i]) for i in flagged)}? [y/N] "):
                accept |= pick(flagged)
        chosen = {i for i, _ in accept}
        result["files"] = [{"path": path_of(f), "verdict": a, "reasons": r, "applied": i in chosen}
                           for i, (f, (a, r)) in enumerate(zip(files, verdicts))]
        patch = assemble(files, accept)
        if not patch:
            print("airlock: discarded. Your working tree was not touched.")
            result["outcome"] = "discarded"
            return 0
        saved = Path(gitdir, "airlock", "runs", f"{run_id}.patch")
        saved.parent.mkdir(parents=True, exist_ok=True)
        saved.write_bytes(patch)
        result.update(patch=f"runs/{run_id}.patch", sha256=hashlib.sha256(patch).hexdigest())
        if not apply(patch, root):
            print(f"airlock: patch did not apply cleanly; nothing changed. Saved to {saved}")
            result["outcome"] = "conflict"
            return 1
        print(f"airlock: applied. Review with `git diff`, commit when ready. Undo with `airlock undo {run_id}`.")
        result["outcome"] = "applied"
        return 0
    finally:
        if started:  # also records Ctrl+C / crashes as "aborted"
            audit(gitdir, result)
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    p = argparse.ArgumentParser(prog="airlock", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="run an agent command on a sandboxed copy of the repo")
    r.add_argument("-C", dest="repo", default=".", help="repository path (default: .)")
    r.add_argument("--no-sandbox", action="store_true", help="run the agent directly on the host (v1 mode)")
    r.add_argument("--allow-host", action="append", default=[], metavar="HOST",
                   help="also allow HTTPS to HOST, e.g. registry.npmjs.org (repeatable)")
    r.add_argument("--model", default=DEFAULT_MODEL,
                   help=f"default model for the agent (ANTHROPIC_MODEL; default: {DEFAULT_MODEL}, set AIRLOCK_MODEL to change)")
    r.add_argument("--ui", action="store_true", help="review in the browser, with per-file and per-hunk selection")
    r.add_argument("cmd", nargs=argparse.REMAINDER, help="agent command, after --")
    lg = sub.add_parser("log", help="list past runs and verify the audit log's hash chain")
    lg.add_argument("-C", dest="repo", default=".", help="repository path (default: .)")
    u = sub.add_parser("undo", help="revert an applied run (default: the most recent one)")
    u.add_argument("-C", dest="repo", default=".", help="repository path (default: .)")
    u.add_argument("run_id", nargs="?", help="run id from `airlock log`")
    a = p.parse_args()
    if a.command == "log":
        sys.exit(show_log(a.repo))
    if a.command == "undo":
        sys.exit(undo(a.repo, a.run_id))
    cmd = a.cmd[1:] if a.cmd[:1] == ["--"] else a.cmd
    if not cmd:
        p.error("missing agent command, e.g. airlock run -- claude -p 'fix the tests'")
    sys.stdout.reconfigure(line_buffering=True)  # keep our lines ordered with git/agent output when piped
    sys.exit(run(cmd, a.repo, not a.no_sandbox, a.allow_host, a.model, a.ui))


if __name__ == "__main__":
    main()
