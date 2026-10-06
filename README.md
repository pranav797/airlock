# Airlock

Run an AI coding agent in a sandboxed copy of your repo, then review its diff before anything touches your working tree.

## The problem

AI coding agents like Claude Code, Codex and Cursor are most useful when they work on their own. But letting one run unattended means giving it everything you have:

- **Your secrets.** It can read `~/.ssh`, cloud credentials and gitignored `.env` files.
- **The network.** Anything it reads can be sent anywhere.
- **Your working tree.** It edits your real files as it goes, so a bad run leaves a mess.

The agent also takes instructions from what it reads. A malicious comment in a dependency or a doc page can turn into a command running as you (prompt injection).

So today the choice is to babysit every action, or to trust the agent completely.

## How Airlock solves it

Airlock lets you use an agent without trusting it.

| Risk | What Airlock does |
|---|---|
| Agent reads your secrets | It works on a copy of your tracked files only, inside a container. Your home directory, keys and untracked files aren't there. |
| Agent leaks your code or data | The container has no internet. Its only route out is a proxy to the model API, plus any hosts you explicitly allow. |
| Agent steals your API key | The key never enters the container. The proxy adds it to requests on the way out. |
| Agent plants git hooks or config that run later | The copy has no `.git` folder, so there's nothing to plant. Only a reviewed patch comes back. |
| Agent changes something it shouldn't | Path rules mark files as allowed, needing explicit confirmation, or never applied. CI config, dependency files and the rules file itself are always flagged. |
| A bad change lands | Nothing touches your repo until you approve the diff, in the terminal or file by file and hunk by hunk in a browser view. Every run is logged, and `airlock undo` reverts one. |

Safety doesn't depend on the model behaving. Everything that enforces it (the container, the network proxy, the rules and the review step) is ordinary code you can read and test.

## Quick start

```bash
pip install -e .
airlock run -- claude -p "add type hints to utils.py" --dangerously-skip-permissions
```

The agent gets a plain copy of your tracked files as they are now, uncommitted edits included. The copy has no `.git`, and untracked files stay out. It runs inside a Docker container:

- **No internet.** Its only route out is a proxy that forwards to `api.anthropic.com`.
- **No real API key.** The proxy adds your key, so the agent never sees it.
- **Locked down.** It runs non-root, with no capabilities and a read-only root filesystem.

Skipping Claude Code's permission prompts is reasonable here because the container is the boundary.

When the agent exits you get the diff, with warnings for deletions, symlinks and permission changes.

- **y** applies it atomically with `git apply`.
- Anything else discards it.
- If the patch conflicts with your uncommitted edits, nothing changes and the patch is saved under `.git/airlock/runs/`.

## Setup

1. Install Docker. The agent image builds itself on first run. To pick up a newer Claude Code, delete it with `docker image rm $(docker images -q airlock-agent)`, and the next run rebuilds it.
2. Put your Anthropic API key in `~/.airlock/anthropic_api_key` (one line). Airlock reads it only to hand it to the proxy. It stays out of your environment and out of every repo.

## Policy

Every changed file gets a verdict before you review it:

| Verdict | Meaning |
|---|---|
| `deny` | Never applied. Shown as blocked. |
| `confirm` | Asked about separately in the terminal. Starts unticked in `--ui`. |
| `allow` | If *every* changed file is allowed, the patch is applied with no prompt. |
| (no match) | Normal review. |

The strictest matching rule wins.

Some things are always flagged for confirmation:
- CI config, dependency and lock files.
- `.gitignore`, `.gitattributes`, `.gitmodules`.
- Editor and devcontainer configs (some can run code when you open the folder).
- `Dockerfile`, `Makefile`.
- `.airlock.toml` itself.
- Deletions, symlinks and permission changes.

Add your own rules in `.airlock.toml` at the repo root:

```toml
[policy]
allow = ["src/*", "tests/*"]      # routine edits here apply without a prompt
confirm = ["migrations/*"]
deny = [".env*", "secrets/*"]

[network]
allow = ["pypi.org", "files.pythonhosted.org"]   # HTTPS the agent always gets in this repo
```

`[network] allow` adds to any `--allow-host` flags. Each allowed host is a possible exfiltration channel, so list only what the repo needs.

How patterns match:
- A pattern without a `/` matches the file name in any directory.
- A pattern with a `/` matches the full path, and `*` also crosses directories.

Airlock reads `.airlock.toml` from your working tree *before* the agent runs. An agent that edits it can't change the rules for its own run, and the edit itself is flagged.

## History and undo

Every run is recorded in `.git/airlock/audit.jsonl`, where the agent can't reach it. The record includes the command, model, policy, each file's verdict, what you applied and the outcome. Applied patches are kept in `.git/airlock/runs/`.

```bash
airlock log              # list runs, and check the log hasn't been edited
airlock undo             # revert the most recent applied run
airlock undo <run-id>    # revert a specific one
```

How tampering is caught:
- Each log entry carries the hash of the one before it, so editing or deleting history breaks the chain. `airlock log` then reports `TAMPERED`, and `airlock undo` refuses to run.
- Before undoing, Airlock checks the saved patch against the hash recorded in the log.

Undo is all-or-nothing. If you've since edited the same lines, it changes nothing and tells you so.

## Options

- `--ui`: review in your browser instead of the terminal. You get a side-by-side diff and can tick individual files and hunks; only the ticked ones are applied.
- `--model NAME`: the model the agent uses by default. The default is `haiku`, the cheapest. To change the default permanently, set `AIRLOCK_MODEL` (e.g. `export AIRLOCK_MODEL=sonnet` in `~/.bashrc`). A `--model` flag passed to `claude` itself still wins.
- `--allow-host HOST`: allow HTTPS to `HOST` for this run, e.g. `--allow-host registry.npmjs.org` for `npm install`. PyPI needs both `pypi.org` and `files.pythonhosted.org`. Every allowed host is a possible exfiltration channel, so add only what the run needs.
- `--no-sandbox`: run the agent directly on the host, without Docker. The diff review still applies, but the agent can read anything you can.

Tests: `python test_airlock.py`. The sandbox test needs Docker and internet access.
