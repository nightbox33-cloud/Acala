#!/usr/bin/env python3
"""Build selector -> canonical signature -> repo/path/commit index from every
ABI artefact in the 228 cloned repos, then name the selectors found in the LIVE
EVM.Codes disassembly. Closes part of the address -> repo/commit/artefact map
for third-party deployed contracts.
"""
import json, sys, os, glob, hashlib, subprocess, collections
from Crypto.Hash import keccak

def sel4(sig):
    k = keccak.new(digest_bits=256); k.update(sig.encode()); return k.hexdigest()[:8]

def canon(e):
    if not isinstance(e, dict) or e.get('type') != 'function': return None
    n = e.get('name'); ins = e.get('inputs') or []
    def t(x):
        z = x.get('type', '')
        if z.startswith('tuple'):
            inner = ','.join(t(y) for y in x.get('components', []))
            return '(' + inner + ')' + z[5:]
        return z
    return f"{n}({','.join(t(i) for i in ins)})"

def walk(o, out):
    if isinstance(o, dict):
        if 'abi' in o and isinstance(o['abi'], list): out.extend(o['abi'])
        for v in o.values(): walk(v, out)
    elif isinstance(o, list):
        for v in o: walk(v, out)

def main(repos, analysis_paths, out):
    idx = collections.defaultdict(list)
    nfiles = 0
    for p in glob.iglob(os.path.join(repos, '**', '*.json'), recursive=True):
        if '.git/' in p: continue
        nfiles += 1
        try:
            if os.path.getsize(p) > 3_000_000: continue
            raw = open(p, 'rb').read()
            if b'"abi"' not in raw and b'"name"' not in raw: continue
            abis = []; walk(json.loads(raw), abis)
        except Exception: continue
        rel = os.path.relpath(p, repos)
        repo = '/'.join(rel.split('/')[:2])
        for e in abis:
            sig = canon(e)
            if not sig: continue
            s = sel4(sig)
            if len(idx[s]) < 6: idx[s].append({'sig': sig, 'repo': repo, 'file': rel})
    print('json scanned', nfiles, 'distinct selectors', len(idx), flush=True)
    live = collections.Counter(); examples = collections.defaultdict(set)
    for p in analysis_paths:
        d = json.load(open(p))
        rows = d['contracts'] if isinstance(d, dict) and 'contracts' in d else d
        for r in rows:
            for s in r.get('selectors', []):
                s = str(s).replace('0x', '').lower(); live[s] += 1
                examples[s].add(r.get('sha256', '')[:18])
    print('live selectors', len(live), flush=True)
    named = {s: idx[s][0]['sig'] for s in live if s in idx}
    print('named', len(named), '/', len(live), flush=True)
    res = {'repos_root': repos, 'json_files_scanned': nfiles,
           'distinct_selectors_in_repos': len(idx), 'live_selectors': len(live),
           'named_live_selectors': len(named), 'selectors': []}
    for s, c in live.most_common():
        rec = {'selector': s, 'contracts_with_it': c, 'names': idx.get(s, []),
               'example_bytecodes': sorted(examples[s])[:3]}
        res['selectors'].append(rec)
    # commits for the repos that actually matched
    repos_hit = {n['repo'] for s in live for n in idx.get(s, [])[:1]}
    res['matched_repos'] = {}
    for r in sorted(repos_hit):
        gd = os.path.join(repos, r, '.git')
        try:
            res['matched_repos'][r] = subprocess.check_output(
                ['git', '--git-dir', gd, 'rev-parse', 'HEAD'],
                stderr=subprocess.DEVNULL, timeout=5).decode().strip()
        except Exception: pass
    with open(out, 'w') as f: json.dump(res, f, indent=1)
    print('wrote', out, flush=True)
    print('\n=== top live selectors named from cloned ABIs ===')
    for s, c in live.most_common(28):
        if s in idx: print(f'  0x{s} {c:4d} {idx[s][0]["sig"][:76]}')
    print('\n=== most common UNNAMED live selectors (need decompilation) ===')
    for s, c in [x for x in live.most_common() if x[0] not in idx][:18]:
        print(f'  0x{s} {c:4d}')

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2:-1], sys.argv[-1])
