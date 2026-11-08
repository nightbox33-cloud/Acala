#!/usr/bin/env python3
"""FALLBACK: identify the 390 bytecodes with no exact artefact match by
intersecting their dispatcher selectors with every Solidity ABI present in the
228 cloned repos. Gives repo + contract + commit candidates for reconstruction.
"""
import json, sys, os, glob, collections, hashlib
try: from Crypto.Hash import keccak
except ImportError: keccak = None

MAX_FILE = 25_000_000

def sel(sig):
    if keccak is None: return None
    k = keccak.new(digest_bits=256); k.update(sig.encode())
    return k.hexdigest()[:8]

def canon(t):
    return {'uint': 'uint256', 'int': 'int256'}.get(t, t)

def abi_sigs(abi):
    out = set()
    for e in abi or []:
        if not isinstance(e, dict) or e.get('type') != 'function': continue
        s = e.get('name', '') + '(' + ','.join(canon(i.get('type', '')) for i in e.get('inputs', [])) + ')'
        h = sel(s)
        if h: out.add(h)
    return out

def main(repos, chain, out):
    analysis = json.load(open(f'audit-live/evm-codes-analysis-{chain}.json'))
    exact = json.load(open('audit-live/bytecode-repo-map.json'))
    mapped = {e['sha256'] for e in exact['entries'] if e['artefacts']}
    # index ABIs: selector -> list of (sig, repo/path)
    sidx = collections.defaultdict(list)
    files = 0
    for path in glob.iglob(os.path.join(repos, '**', '*.json'), recursive=True):
        if '.git/' in path: continue
        files += 1
        try:
            if os.path.getsize(path) > MAX_FILE: continue
            raw = open(path, 'rb').read()
            if b'"abi"' not in raw and b'"inputs"' not in raw: continue
            d = json.loads(raw)
        except Exception: continue
        abi = d.get('abi') if isinstance(d, dict) else (d if isinstance(d, list) else None)
        if not abi: continue
        rel = os.path.relpath(path, repos)
        for h in abi_sigs(abi):
            if len(sidx[h]) < 6: sidx[h].append(rel)
    print('abi selectors indexed from', files, 'json files:', len(sidx), flush=True)
    res = {'chain': chain, 'abi_json_files': files, 'selectors_indexed': len(sidx),
           'exact_mapped': len(mapped), 'candidates': []}
    for c in analysis.get('contracts', analysis if isinstance(analysis, list) else []):
        sh = c.get('sha256')
        if sh in mapped: continue
        sels = set()
        for k in ('selectors', 'known_selectors', 'dispatcher_selectors'):
            v = c.get(k)
            if isinstance(v, list):
                for x in v: sels.add((x if isinstance(x, str) else str(x)).lower().replace('0x', ''))
            elif isinstance(v, dict): sels |= {str(k2).lower().replace('0x', '') for k2 in v}
        if not sels: continue
        hits = collections.Counter()
        for h in sels:
            for f in sidx.get(h, []): hits[f] += 1
        top = [(f, n, round(n / max(1, len(sels)) * 100, 1)) for f, n in hits.most_common(4)]
        if top and top[0][1] >= 3:
            res['candidates'].append({'sha256': sh, 'code_hash': c.get('code_hash'),
                                     'bytes': c.get('code_bytes'), 'selectors': len(sels),
                                     'top': top})
    res['identified'] = len(res['candidates'])
    with open(out, 'w') as f: json.dump(res, f, indent=1)
    print('wrote', out, 'candidates', res['identified'], flush=True)
    for c in res['candidates'][:12]:
        print(' ', str(c['sha256'])[:18], c['selectors'], '->', c['top'][0] if c['top'] else '')

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3])
