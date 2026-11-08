#!/usr/bin/env python3
"""FALLBACK: one-pass index of every EVM bytecode artefact in the 228 cloned
repos, then map each LIVE deployed-bytecode sha256 to repo + exact HEAD commit.

Usage: python3 scripts/audit/map_bytecodes_to_repos.py \
         /home/user/audit-work/repos \
         audit-live/evm-codes-acala.json audit-live/evm-codes-karura.json \
         audit-live/bytecode-repo-map.json
"""
import json, sys, os, glob, hashlib, subprocess, collections

MAX_FILE = 40_000_000

def sha(s):
    if not isinstance(s, str) or not s.startswith('0x') or len(s) < 100: return None
    try: return '0x' + hashlib.sha256(bytes.fromhex(s[2:])).hexdigest()
    except Exception: return None

def variants(s):
    """full creation code + plausible runtime suffixes after RETURN/INVALID."""
    out = [s]
    body = s[2:]
    for marker in ('f3fe', 'f3', 'fe'):
        i = body.find(marker)
        while i != -1:
            tail = body[i + len(marker):]
            if len(tail) > 100: out.append('0x' + tail)
            i = body.find(marker, i + 1)
            if len(out) > 6: break
        if len(out) > 1: break
    return out

def hex_strings(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ('deployedBytecode', 'bytecode', 'object', 'code', 'runtimeBytecode',
                     'creationBytecode') and isinstance(v, str) and v.startswith('0x'):
                yield v, str(k)
            elif isinstance(v, (dict, list)):
                for x, t in hex_strings(v): yield x, str(k) + '/' + t
            elif isinstance(v, str) and v.startswith('0x') and len(v) > 100:
                yield v, str(k)
    elif isinstance(obj, list):
        for v in obj:
            for x, t in hex_strings(v): yield x, t
    elif isinstance(obj, str) and obj.startswith('0x') and len(obj) > 100:
        yield obj, ''

def head_commit(repos, org_repo):
    gd = os.path.join(repos, org_repo, '.git')
    try:
        return subprocess.check_output(['git', '--git-dir', gd, 'rev-parse', 'HEAD'],
                                      stderr=subprocess.DEVNULL, timeout=5).decode().strip()
    except Exception: return None

def main(repos, live_paths, out_path):
    live = {}
    for p in live_paths:
        d = json.load(open(p))
        for c in d['codes']:
            live.setdefault(c['sha256'], []).append({'chain': d['chain'],
                                                     'code_hash': c['storage_key'],
                                                     'bytes': c['code_bytes']})
    print('live unique bytecodes:', len(live), flush=True)
    index = collections.defaultdict(list)
    files = 0
    for path in glob.iglob(os.path.join(repos, '**', '*.json'), recursive=True):
        if '.git/' in path: continue
        files += 1
        try:
            if os.path.getsize(path) > MAX_FILE: continue
            with open(path, 'rb') as f: raw = f.read()
            if b'0x6080604052' not in raw and b'deployedBytecode' not in raw: continue
            data = json.loads(raw)
        except Exception: continue
        for s, trail in hex_strings(data):
            for v in variants(s):
                h = sha(v)
                if h in live and len(index[h]) < 4:
                    rel = os.path.relpath(path, repos)
                    index[h].append({'file': rel, 'trail': trail, 'kind':
                                     'full' if v == s else 'runtime'})
    print('json files scanned:', files, 'live hashes indexed:', len(index), flush=True)
    res = {'repos_root': repos, 'json_files_scanned': files,
           'live_unique_bytecodes': len(live), 'matched': 0, 'unmatched': [], 'entries': []}
    for h, seen in live.items():
        rec = {'sha256': h, 'seen_on': seen, 'artefacts': index.get(h, [])}
        if rec['artefacts']:
            res['matched'] += 1
            for a in rec['artefacts']:
                a['repo'] = '/'.join(a['file'].split('/')[:2])
                a['commit'] = head_commit(repos, a['repo'])
        else:
            res['unmatched'].append(h)
        res['entries'].append(rec)
    res['matched_pct'] = round(100.0 * res['matched'] / max(1, len(live)), 2)
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w') as f: json.dump(res, f, indent=1)
    print('wrote', out_path, 'matched', res['matched'], '/', len(live),
          f"({res['matched_pct']}%)", flush=True)
    for e in res['entries'][:8]:
        print(' ', e['sha256'][:20], '->', e['artefacts'][0]['file'] if e['artefacts'] else 'UNMAPPED')

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2:-1], sys.argv[-1])
