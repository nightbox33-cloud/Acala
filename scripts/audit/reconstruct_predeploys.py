#!/usr/bin/env python3
"""Map LIVE deployed-bytecode sha256 values back to an exact commit + artefact
in the cloned AcalaNetwork/predeploy-contracts repository (full history).

Usage: python3 scripts/audit/reconstruct_predeploys.py \
         audit-live/evm-codes-acala.json audit-live/evm-codes-karura.json \
         /home/user/audit-work/repos/AcalaNetwork/predeploy-contracts \
         audit-live/predeploy-reconstruction.json
"""
import json, sys, os, glob, hashlib, subprocess, collections

def sha_hex(s):
    if not isinstance(s, str) or not s.startswith('0x') or len(s) <= 2: return None
    try: return '0x' + hashlib.sha256(bytes.fromhex(s[2:])).hexdigest()
    except Exception: return None

def git_show(repo, commit, path):
    try:
        return subprocess.check_output(['git', '-C', repo, 'show', f'{commit}:{path}'],
                                      stderr=subprocess.DEVNULL, timeout=15)
    except Exception: return None

def register(s, trail, out, kind):
    h = sha_hex(s)
    if not h: return
    out.setdefault(h, []).append((trail + '/' + kind, len(s)))

def runtime_variants(hexcode):
    """solc creation code = initcode + RETURN(f3) + INVALID(fe) + runtime code.
    Return the plausible runtime-code suffixes so creation-bytecode artefacts
    can be matched against live eth_getCode output."""
    body = hexcode[2:]
    out = []
    for marker in ('f3fe', 'f3', 'fe'):
        i = body.find(marker)
        while i != -1:
            tail = body[i + len(marker):]
            if len(tail) > 100 and (tail.startswith('6080604052') or True):
                out.append('0x' + tail)
            i = body.find(marker, i + 1)
            if len(out) > 8: break
        if out: break
    return out

def collect(obj, trail, out):
    """Recursively collect every hex string that looks like deployed bytecode."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ('deployedBytecode', 'bytecode', 'object', 'code') and isinstance(v, str) and v.startswith('0x'):
                register(v, trail + '/' + k, out, 'full')
                for r in runtime_variants(v): register(r, trail + '/' + k, out, 'runtime')
            elif k == 'deployedBytecode' and isinstance(v, dict):
                collect(v, trail + '/' + k, out)
            else:
                collect(v, trail + '/' + str(k), out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj): collect(v, trail + '/' + str(i), out)
    elif isinstance(obj, str) and obj.startswith('0x') and len(obj) > 100:
        register(obj, trail, out, 'full')
        for r in runtime_variants(obj): register(r, trail, out, 'runtime')

def main(live_paths, repo, out_path):
    live = {}
    for p in live_paths:
        try: d = json.load(open(p))
        except Exception: continue
        for c in d.get('codes', []):
            live.setdefault(c['sha256'], {'chain': d['chain'], 'code_bytes': c['code_bytes'],
                                          'sources': []})['sources'].append(
                {'chain': d['chain'], 'file': c['file'], 'matches_predeploy': c.get('matches_predeploy')})
    print('live unique bytecodes:', len(live), flush=True)

    commits = subprocess.check_output(['git', '-C', repo, 'rev-list', '--all'], timeout=120).decode().split()
    print('predeploy-contracts commits in full clone:', len(commits), flush=True)
    paths = ['resources/bytecodes.json', 'resources/deployedBytecodes.json',
             'resources/deployed-bytecodes.json', 'resources/karura_tokens.json',
             'resources/acala_tokens.json']
    index = collections.defaultdict(list)
    for i, c in enumerate(commits):
        for path in paths:
            raw = git_show(repo, c, path)
            if not raw: continue
            try: data = json.loads(raw)
            except Exception: continue
            tmp = {}
            collect(data, '', tmp)
            for h, hits in tmp.items():
                if h in live and len(index[h]) < 6:
                    index[h].append({'commit': c, 'path': path, 'trails': [x[0] for x in hits[:4]]})
        if i % 100 == 0: print('  scanned', i, 'commits, mapped', len(index), flush=True)
    res = {'repo': 'AcalaNetwork/predeploy-contracts', 'commits_scanned': len(commits),
           'live_unique_bytecodes': len(live), 'matched': 0, 'unmatched': [],
           'entries': []}
    for h, info in live.items():
        rec = {'sha256': h, 'code_bytes': info['code_bytes'], 'seen_on': info['sources'],
               'source_commits': index.get(h, [])}
        if index.get(h): res['matched'] += 1
        else: res['unmatched'].append(h)
        res['entries'].append(rec)
    res['matched_pct'] = round(100.0 * res['matched'] / max(1, len(live)), 2)
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w') as f: json.dump(res, f, indent=1)
    print('wrote', out_path, 'matched', res['matched'], '/', len(live),
          f"({res['matched_pct']}%)", flush=True)

if __name__ == '__main__':
    main(sys.argv[1:-2], sys.argv[-2], sys.argv[-1])
