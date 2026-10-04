"""Airlock review UI: a one-shot local web page for per-file / per-hunk accept or reject."""
import hmac
import http.server
import json
import secrets
import threading
import urllib.parse
import webbrowser

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Airlock Review</title>
<style>
:root{--bg:#fafaf9;--fg:#1c1917;--muted:#78716c;--card:#fff;--line:#e7e5e4;--add:#dcfce7;--del:#fee2e2;
--warn:#b45309;--accent:#2563eb;--empty:#f5f5f4}
@media (prefers-color-scheme:dark){:root{--bg:#0c0a09;--fg:#e7e5e4;--muted:#a8a29e;--card:#1c1917;--line:#292524;
--add:#14532d66;--del:#7f1d1d66;--warn:#fbbf24;--accent:#60a5fa;--empty:#171412}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif}
header{position:sticky;top:0;z-index:1;display:flex;flex-wrap:wrap;gap:12px;align-items:center;padding:12px 16px;
background:var(--card);border-bottom:1px solid var(--line)}
h1{font-size:16px;margin:0 auto 0 0}#count{color:var(--muted)}
button{font:inherit;padding:6px 14px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
main{padding:16px;max-width:1400px;margin:auto}
.file{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:16px;overflow:hidden}
.fhead{display:flex;gap:8px;align-items:center;padding:8px 12px;border-bottom:1px solid var(--line);font-weight:600;word-break:break-all}
.warn{color:var(--warn);font-weight:500;padding:4px 12px 0}
.hhead{display:flex;gap:8px;align-items:center;padding:4px 12px;color:var(--muted);font:12px ui-monospace,monospace;background:var(--empty)}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font:12px/1.5 ui-monospace,monospace}
td{padding:0 8px;white-space:pre;vertical-align:top}td.n{color:var(--muted);text-align:right;width:1%;user-select:none}
td.t{width:50%}.del{background:var(--del)}.add{background:var(--add)}.none{background:var(--empty)}
.off{opacity:.4}pre{margin:0;padding:8px 12px;font:12px ui-monospace,monospace;white-space:pre-wrap}
.done{text-align:center;padding:80px 16px;font-size:18px}
</style></head><body>
<header><h1>Airlock review</h1><span id="count"></span>
<button id="none">Discard everything</button><button id="apply" class="primary">Apply selected</button></header>
<main id="main"></main>
<script id="data" type="application/json">__DATA__</script>
<script>
const files = JSON.parse(document.getElementById('data').textContent);
const token = new URLSearchParams(location.search).get('t');
const main = document.getElementById('main'), boxes = [];
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls;
  if (text != null) e.textContent = text; return e; };  // textContent only: the diff is untrusted

function rows(hunk) {
  const lines = hunk.split('\\n'), m = /^@@ -(\\d+)(?:,\\d+)? \\+(\\d+)/.exec(lines[0]);
  let l = +m[1], r = +m[2], del = [], add = [];
  const out = [], flush = () => {
    for (let k = 0; k < Math.max(del.length, add.length); k++)
      out.push([k < del.length ? l++ : '', del[k], k < add.length ? r++ : '', add[k], false]);
    del = []; add = [];
  };
  for (const s of lines.slice(1)) {
    if (s[0] === '-') del.push(s.slice(1));
    else if (s[0] === '+') add.push(s.slice(1));
    else if (s[0] === ' ') { flush(); out.push([l++, s.slice(1), r++, s.slice(1), true]); }
  }
  flush();
  return out;
}

function box(id, wrap, on, denied) {
  const b = el('input'); b.type = 'checkbox'; b.checked = on; b.disabled = denied; b.dataset.id = JSON.stringify(id);
  b.onchange = () => { wrap.classList.toggle('off', !b.checked); update(); };
  wrap.classList.toggle('off', !on);
  if (!denied) boxes.push(b);
  return b;
}

files.forEach((f, i) => {
  // policy: deny = never applied, confirm = starts unticked and must be ticked on purpose
  const denied = f.action === 'deny', on = f.action !== 'deny' && f.action !== 'confirm';
  const card = el('section', 'file'), head = el('label', 'fhead'), fileBox = el('input');
  fileBox.type = 'checkbox'; fileBox.checked = on; fileBox.disabled = denied;
  head.append(fileBox, el('span', null, f.path)); card.append(head);
  const label = {deny: 'Blocked by policy, will not be applied: ', confirm: 'Needs your explicit approval: '}[f.action];
  if (label) card.append(el('div', 'warn', '\\u26a0 ' + label + f.reasons.join('; ')));
  const mine = [];
  if (!f.hunks.length) {
    const body = el('div'); body.append(el('pre', null, f.header));
    fileBox.dataset.id = JSON.stringify([i, null]); if (!denied) boxes.push(fileBox); mine.push(fileBox);
    fileBox.onchange = () => { body.classList.toggle('off', !fileBox.checked); update(); };
    body.classList.toggle('off', !on);
    card.append(body);
  } else f.hunks.forEach((h, j) => {
    const wrap = el('div'), hh = el('label', 'hhead'), b = box([i, j], wrap, on, denied);
    hh.append(b, el('span', null, h.split('\\n')[0])); wrap.append(hh);
    const sc = el('div', 'scroll'), t = el('table');
    for (const [ln, lt, rn, rt, same] of rows(h)) {
      const tr = el('tr');
      tr.append(el('td', 'n', ln), el('td', 't ' + (lt == null ? 'none' : same ? '' : 'del'), lt ?? ''),
                el('td', 'n', rn), el('td', 't ' + (rt == null ? 'none' : same ? '' : 'add'), rt ?? ''));
      t.append(tr);
    }
    sc.append(t); wrap.append(sc); card.append(wrap); mine.push(b);
  });
  // read once: each hunk's onchange re-syncs fileBox from its hunks
  if (f.hunks.length) fileBox.onchange = () => { const on = fileBox.checked; for (const b of mine) { b.checked = on; b.onchange(); } };
  card.syncFile = () => { if (f.hunks.length) { fileBox.checked = mine.some(b => b.checked);
    fileBox.indeterminate = fileBox.checked && !mine.every(b => b.checked); } };
  main.append(card);
});

function update() {
  for (const c of main.children) c.syncFile && c.syncFile();
  const n = boxes.filter(b => b.checked).length;
  document.getElementById('count').textContent = n + ' of ' + boxes.length + ' changes selected';
}
update();

async function decide(accept) {
  const r = await fetch('/decision', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Airlock-Token': token},
                                     body: JSON.stringify({accept})});
  document.body.replaceChildren(el('div', 'done', r.ok
    ? (accept && accept.length ? 'Sent ' + accept.length + ' change(s) to Airlock. Check your terminal.' : 'Discarded. Your working tree was not touched.')
      + ' You can close this tab.'
    : 'Error: ' + r.status));
}
document.getElementById('apply').onclick = () => decide(boxes.filter(b => b.checked).map(b => JSON.parse(b.dataset.id)));
document.getElementById('none').onclick = () => decide(null);
</script></body></html>"""

CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
       "connect-src 'self'; frame-ancestors 'none'")


def review(files, open_browser=webbrowser.open):
    """Serve the review page until the user decides. Returns a set of (file, hunk) ids to apply, or None.

    files: [{"path", "action", "reasons", "header", "hunks": [text, ...]}]; a file with no hunks is id (i, None).
    action is the policy verdict: allow / ask / confirm (starts unticked) / deny (not selectable).
    """
    token = secrets.token_urlsafe(24)
    data = json.dumps(files).replace("</", "<\\/").encode()
    page = PAGE.encode().replace(b"__DATA__", data)
    result, done = {}, threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def send(self, code, body=b"", ctype="text/plain"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            if hmac.compare_digest(q.get("t", [""])[0], token):
                self.send(200, page, "text/html; charset=utf-8")
            else:
                self.send(404)

        def do_POST(self):
            if self.path != "/decision" or not hmac.compare_digest(self.headers.get("X-Airlock-Token", ""), token):
                return self.send(403)
            if done.is_set():
                return self.send(409)
            try:
                accept = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))["accept"]
                result["accept"] = None if accept is None else {(int(i), None if j is None else int(j)) for i, j in accept}
            except (ValueError, KeyError, TypeError):
                return self.send(400)
            self.send(200)
            done.set()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/?t={token}"
    print(f"airlock: review the changes at {url}")
    try:
        open_browser(url)
        while not done.wait(0.5):  # short waits keep Ctrl+C working on Windows
            pass
    finally:
        server.shutdown()
    return result["accept"] or None
