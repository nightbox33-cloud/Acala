#!/usr/bin/env python3
"""Prerequisite: enumerate + clone every accessible repository of the Acala foundation
spaces (and the dependency orgs whose code is compiled into the runtime).

Usage: python3 clone_foundation_repos.py <manifest.json> <dest-dir>
Writes: <dest-dir>/clone-results.jsonl (one line per repo, with exact HEAD sha, refs)
"""
import json, os, subprocess, sys, concurrent.futures, pathlib

manifest, dest = sys.argv[1], sys.argv[2]
data = json.load(open(manifest))
repos = []
for org, rs in data['orgs'].items():
    for r in rs:
        repos.append((org, r['name'], r['clone_url']))
# the checkout itself is the fork of AcalaNetwork/Acala; also clone the canonical repo
FULL = {
    'AcalaNetwork/Acala',
    'AcalaNetwork/predeploy-contracts',
    'AcalaNetwork/evm-tests',
    'AcalaNetwork/evm-bench',
    'AcalaNetwork/acala-node',
    'AcalaNetwork/runtime-overrides',
    'open-web3-stack/open-runtime-module-library',
    'nutsfinance/stable-asset',
}

def sh(cmd, cwd=None, timeout=900):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                       env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'})
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def one(item):
    org, name, url = item
    full = f'{org}/{name}'
    d = os.path.join(dest, 'repos', org, name)
    os.makedirs(os.path.dirname(d), exist_ok=True)
    rec = {'repo': full, 'url': url, 'path': d, 'full_history': full in FULL}
    if os.path.isdir(os.path.join(d, '.git')):
        rec['status'] = 'already-cloned'
    else:
        cmd = ['git', 'clone', '--quiet']
        if full not in FULL:
            cmd += ['--depth', '1', '--no-single-branch', '--no-tags']
        cmd += [url, d]
        rc, out, err = sh(cmd)
        rec['status'] = 'ok' if rc == 0 else 'FAILED'
        rec['clone_stderr'] = err[-400:]
        if rc != 0:
            return rec
    rc, head, _ = sh(['git', 'rev-parse', 'HEAD'], d)
    rec['head'] = head if rc == 0 else None
    rc, refs, _ = sh(['git', 'ls-remote', '--heads', '--tags', url], timeout=120)
    rec['refs'] = refs.splitlines() if rc == 0 else []
    rec['n_heads'] = sum(1 for l in rec['refs'] if 'refs/heads/' in l)
    rec['n_tags'] = sum(1 for l in rec['refs'] if 'refs/tags/' in l)
    # fetch tags reachable at shallow depth; record any tag whose object is present
    if full not in FULL:
        sh(['git', 'fetch', '--quiet', '--depth', '1', '--tags', 'origin'], d, timeout=300)
    rc, tags, _ = sh(['git', 'tag', '--list'], d)
    rec['local_tags'] = tags.splitlines() if rc == 0 else []
    rc, branches, _ = sh(['git', 'branch', '-r'], d)
    rec['local_remote_branches'] = [b.strip() for b in branches.splitlines() if b.strip()] if rc == 0 else []
    # Git LFS pointers in the checked-out tree
    ga = os.path.join(d, '.gitattributes')
    rec['lfs_tracked'] = 'filter=lfs' in open(ga, errors='ignore').read() if os.path.isfile(ga) else False
    rec['submodules'] = []
    gm = os.path.join(d, '.gitmodules')
    if os.path.isfile(gm):
        rc, sm, _ = sh(['git', 'submodule', 'status'], d)
        rec['submodules'] = sm.splitlines() if rc == 0 else []
    return rec

results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    futs = {ex.submit(one, r): r for r in repos}
    for i, f in enumerate(concurrent.futures.as_completed(futs), 1):
        rec = f.result()
        results.append(rec)
        print(f"[{i}/{len(repos)}] {rec['status']:14s} {rec['repo']:60s} {str(rec.get('head'))[:12]}", flush=True)

out = os.path.join(dest, 'clone-results.jsonl')
with open(out, 'w') as f:
    for r in sorted(results, key=lambda x: x['repo']):
        f.write(json.dumps(r) + '\n')
print('DONE', len(results), 'repos ->', out, flush=True)
print('failed:', [r['repo'] for r in results if r['status'] == 'FAILED'], flush=True)
