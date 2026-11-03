"""Replay qemu-vnc/tests/mock.rs from the opencode session record.

Three changes over the previous attempt, each aimed at a measured failure:

  * every event is guarded by a delimiter-balance check, so an edit that splices
    two test bodies together is rejected and rolled back rather than kept;
  * an event that exits non-zero *and* left the file untouched is retried with
    the other working directory, because 28 of the original scripts were run
    from qemu-vnc/ rather than the project root;
  * stderr is captured per event, so the events that still fail can be read
    instead of counted.
"""
import difflib, json, os, re, shutil, sqlite3, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from balance import balance

R = '/tmp/opencode/replayroot'
TARGET = f'{R}/qemu-vnc/tests/mock.rs'
DB = '/home/opencode/.local/share/opencode'
CUT = 1790930000000
PAT = re.compile(r'/home/opencode/projects/qemu-display|/tmp/opencode/')

def rewrite(s):
    return PAT.sub(lambda m: R if m.group(0).endswith('qemu-display') else R + '/tmp/', s)

def read():
    return open(TARGET, errors='replace').read() if os.path.exists(TARGET) else ''

def apply_edit(cur, old, new):
    """Apply old -> new. Exact, then anchored on a unique run of old's lines.
    Returns (text, how)."""
    if old in cur:
        return cur.replace(old, new, 1), 'exact'
    ol, nl = old.split('\n'), new.split('\n')
    cl = cur.split('\n')
    idx, best = None, 0
    for a in range(len(ol)):
        for b in range(len(ol), a + 1, -1):
            if b - a < best:
                continue
            block = ol[a:b]
            if len(block) < 2:
                continue
            hits = [k for k in range(len(cl) - len(block) + 1) if cl[k:k + len(block)] == block]
            if len(hits) == 1:
                idx, best = (hits[0], a), b - a
                break
        if best >= 2:
            break
    if idx is None:
        return cur, 'unmatched'
    base, anchor = idx
    edits = [(base + (i1 - anchor), base + (i2 - anchor), nl[j1:j2])
             for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, ol, nl, autojunk=False).get_opcodes()
             if tag != 'equal']
    for s, e, rep in reversed(edits):
        cl[s:e] = rep
    return '\n'.join(cl), f'hunks({len(edits)})'

c = sqlite3.connect(f'file:{DB}/opencode.db?mode=ro', uri=True)
HEREDOC = re.compile(r"cat\s+(?:>>|-?\s*>)\s*(?P<path>[^\s<>|;&]+)\s*<<'(?P<mark>[A-Za-z_]{2,20})'(?P<pre>.*?)\n(?P<body>.*?)\n?(?P=mark)(?=\n|$)", re.S)
PYBODY = re.compile(r"python3 - <<'([A-Za-z_]+)'\n(.*?)\n\1(?=\n|$)", re.S)

events = []
for mid, sid, tm, data in c.execute(
        "select id,session_id,time_created,data from session_message order by time_created"):
    if not data or 'mock' not in data or tm >= CUT:
        continue
    try:
        o = json.loads(data)
    except Exception:
        continue
    cont = o.get('content')
    if not isinstance(cont, list):
        continue
    for item in cont:
        if not isinstance(item, dict) or item.get('type') != 'tool':
            continue
        st = item.get('state') or {}
        inp = st.get('input') if isinstance(st.get('input'), dict) else {}
        cmd = inp.get('command') or ''
        p = str(inp.get('path') or inp.get('filePath') or '')
        ct = inp.get('content')
        if isinstance(ct, str) and p.endswith('tests/mock.rs') and len(ct) > 200:
            events.append((tm, 0, 'write', ct, None))
        elif isinstance(ct, str) and p.endswith('.py'):
            events.append((tm, 0, 'write-py', ct, os.path.basename(p)))
        elif p.endswith('tests/mock.rs') and 'oldString' in inp:
            events.append((tm, 1, 'edit', inp['newString'], inp['oldString']))
        elif not cmd or 'tests/mock.rs' not in cmd:
            continue
        pieces = []
        for m in HEREDOC.finditer(cmd):
            pieces.append((m.start(), 'append' if m.group('path').endswith('tests/mock.rs') else 'file',
                           m.group('body'), m.group('path')))
        for m in PYBODY.finditer(cmd):
            if re.search(r'tests/mock\.rs', m.group(2)):
                pieces.append((m.start(), 'py', m.group(2), None))
        for m in re.finditer(r"sed -i\s+('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")\s+(\S*tests/mock\.rs)", cmd):
            pieces.append((m.start(), 'shell', None, cmd))
        if re.search(r'python3 -c\s+', cmd) and 'tests/mock.rs' in cmd and not re.search(r'python3 - <<', cmd):
            pieces.append((cmd.index('python3 -c'), 'shell', None, cmd))
        for m in re.finditer(r'python3\s+(/tmp/opencode/\S+\.py)', cmd):
            pieces.append((m.start(), 'shell', None, cmd))
        for pos, kind, body, raw in sorted(pieces, key=lambda x: x[0]):
            events.append((tm, 2, kind, body, raw))

events.sort(key=lambda e: (e[0], e[1]))
os.makedirs(f'{R}/tmp', exist_ok=True)
for f in os.listdir(os.path.dirname(os.path.abspath(__file__))):
    if f.startswith('ext-'):
        shutil.copy(os.path.join(os.path.dirname(os.path.abspath(__file__)), f), f"{R}/tmp/{f[4:]}")

open(TARGET, 'w').write('')
log, rolled, retried = [], 0, 0

def snapshot():
    os.makedirs('/tmp/opencode/snaps6', exist_ok=True)
    return read()

for i, (tm, _, kind, body, raw) in enumerate(events, 1):
    before_txt = read()
    before_bal, _ = balance(before_txt)
    act, err = '', ''
    def commit(text, label):
        global rolled
        new_bal, ln = balance(text)
        if before_bal == 0 and new_bal != 0:
            rolled += 1
            return f'{label} REJECTED(splice depth {new_bal} at line {ln})'
        open(TARGET, 'w').write(text)
        return label

    if kind == 'write':
        act = commit(body, 'write')
    elif kind == 'write-py':
        open(f'{R}/{raw}', 'w').write(body); act = f'wrote {raw}'
    elif kind == 'edit':
        s = read()
        s2, how = apply_edit(s, raw or '', body)
        act = commit(s2, how) if how != 'unmatched' else 'unmatched'
    elif kind == 'append':
        act = commit(before_txt.rstrip('\n') + '\n' + body.rstrip('\n') + '\n', 'append')
    elif kind == 'file':
        open(f"{R}/tmp/{os.path.basename(raw)}", 'w').write(body)
        act = f'file {os.path.basename(raw)}'
    elif kind == 'py':
        # every path form resolves from the project root now (see the union
        # symlinks in the README), so there is one cwd and no retry to get wrong
        open(f'{R}/.step.py', 'w').write(body)
        try:
            p = subprocess.run(['python3', f'{R}/.step.py'], cwd=R, stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=25)
            act = 'ok' if p.returncode == 0 else f'rc={p.returncode}'
            err = '' if p.returncode == 0 else (p.stderr.strip().splitlines() or [''])[-1][:130]
        except subprocess.TimeoutExpired:
            act, err = 'TIMEOUT', ''
    elif kind == 'shell':
        open(f'{R}/.cmd.sh', 'w').write(rewrite(raw))
        try:
            p = subprocess.run(['bash', f'{R}/.cmd.sh'], cwd=R, stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=25)
            act = f'rc={p.returncode}'
            err = (p.stderr.strip().splitlines() or [''])[-1][:130] if p.returncode else ''
        except subprocess.TimeoutExpired:
            act, err = 'TIMEOUT', ''

    txt = read()
    log.append({'step': i, 'tm': tm, 'kind': kind, 'lines': txt.count('\n') + 1,
                'bal': balance(txt)[0], 'act': act, 'err': err})
    if i % 50 == 0:
        print(f"  step {i}/{len(events)}  {txt.count(chr(10))+1} lines  {rolled} rejected", flush=True)

txt = read()
names = [l.strip() for l in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'known-test-names.txt')) if l.strip()]
hit = [n for n in names if f'fn {n}(' in txt]
print(f"\n{len(events)} events")
print(f"FINAL {txt.count(chr(10))+1} lines, {len(txt)} bytes, delimiter balance {balance(txt)[0]}")
print(f"splices rejected: {rolled}   cwd retries that worked: {retried}")
print(f"known definitions present: {len(hit)} of {len(names)}")
print("missing:", ', '.join(n for n in names if f'fn {n}(' not in txt) or 'NONE')
json.dump(log, open('/tmp/opencode/replay/log6.json', 'w'), indent=1)
shutil.copy(TARGET, '/tmp/opencode/mock_replay_v6.rs')
print("wrote /tmp/opencode/mock_replay_v6.rs")