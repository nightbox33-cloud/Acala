#!/usr/bin/env python3
"""FALLBACK: disassemble deployed EVM bytecode with pyevmasm, extract the
function dispatcher, flag dangerous opcodes, and map each address to a cloned
repo artefact by exact deployed-bytecode sha256.

Usage: PYTHONPATH=/tmp/evmtools python3 scripts/audit/analyze_evm_bytecode.py \
         audit-live/evm-inventory-acala.json audit-live/evm-code-acala \
         /home/user/audit-work/repos audit-live/evm-bytecode-map-acala.json
"""
import json, sys, os, glob, hashlib, subprocess

DANGER = {'CALL', 'CALLCODE', 'DELEGATECALL', 'CREATE', 'CREATE2', 'SELFDESTRUCT',
          'SSTORE', 'CALLVALUE', 'ORIGIN', 'SUICIDE'}


def disassemble(hexcode):
    from pyevmasm import disassemble_all
    code = hexcode[2:] if hexcode.startswith('0x') else hexcode
    try:
        ins = list(disassemble_all(bytes.fromhex(code)))
    except Exception as e:
        return None, str(e)
    return ins, None


def selectors(ins):
    """Find PUSH4 <selector> ... EQ in the dispatcher."""
    out = []
    for i, o in enumerate(ins):
        if o.name == 'PUSH4':
            for nxt in ins[i + 1:i + 12]:
                if nxt.name in ('EQ', 'XOR', 'SUB', 'GT', 'LT'):
                    out.append('0x' + format(o.operand, '08x')); break
    return sorted(set(out))


def opcounts(ins):
    c = {}
    for o in ins: c[o.name] = c.get(o.name, 0) + 1
    return c


def find_artifact_sha(repos_root, target_sha, limit_files=40000):
    """Scan JSON artifact files in the cloned repos for an exact deployed bytecode sha256."""
    hits = []
    roots = [os.path.join(repos_root, 'AcalaNetwork'), os.path.join(repos_root, 'nutsfinance'),
             os.path.join(repos_root, 'laminar-protocol'), os.path.join(repos_root, 'open-web3-stack')]
    seen = 0
    for root in roots:
        for path in glob.iglob(os.path.join(root, '**', '*.json'), recursive=True):
            seen += 1
            if seen > limit_files: break
            if os.path.getsize(path) > 60_000_000: continue
            try:
                with open(path, 'rb') as f: raw = f.read()
            except Exception: continue
            # fast prefilter: only inspect files containing a deployedBytecode/bytecode key
            if b'deployedBytecode' not in raw and b'"bytecode"' not in raw and b'bytecodes' not in raw:
                continue
            try: data = json.loads(raw)
            except Exception: continue
            def walk(v, trail=''):
                if isinstance(v, dict):
                    for k, x in v.items():
                        if k in ('deployedBytecode', 'bytecode', 'object') and isinstance(x, str) and x.startswith('0x') and len(x) > 8:
                            h = '0x' + hashlib.sha256(bytes.fromhex(x[2:])).hexdigest()
                            if h == target_sha:
                                hits.append({'file': path, 'trail': trail + '/' + k})
                        elif k == 'deployedBytecode' and isinstance(x, dict):
                            walk(x, trail + '/' + k)
                        else:
                            walk(x, trail + '/' + str(k))
                elif isinstance(v, list):
                    for idx, x in enumerate(v): walk(x, trail + '/' + str(idx))
                elif isinstance(v, str) and v.startswith('0x') and len(v) > 100:
                    if '0x' + hashlib.sha256(bytes.fromhex(v[2:])).hexdigest() == target_sha:
                        hits.append({'file': path, 'trail': trail})
            walk(data)
            if hits: break
        if hits: break
    return hits, seen


def repo_commit(repos_root, file_path):
    rel = os.path.relpath(file_path, repos_root)
    org_repo = '/'.join(rel.split('/')[:2])
    gd = os.path.join(repos_root, org_repo, '.git')
    try:
        out = subprocess.check_output(['git', '--git-dir', gd, 'rev-parse', 'HEAD'],
                                      stderr=subprocess.DEVNULL, timeout=10).decode().strip()
    except Exception: out = None
    return org_repo, out


def main(inv_path, code_dir, repos_root, out_path):
    inv = json.load(open(inv_path))
    files = glob.glob(os.path.join(code_dir, '*.hex'))
    res = {'chain': inv['chain'], 'block_number': inv['block_number'],
           'finalized_hash': inv['finalized_hash'],
           'source': inv_path, 'dumped_contracts': len(files),
           'contracts': [], 'unmapped': 0, 'errors': []}
    for p in sorted(files):
        addr = os.path.basename(p)[:-4]
        hexcode = open(p).read().strip()
        rec = inv['accounts'].get(addr) or inv['accounts'].get('0x' + addr[2:]) or {}
        entry = {'address': addr,
                 'native_balance_wei': rec.get('native_balance_wei'),
                 'code_bytes': (len(hexcode) - 2) // 2,
                 'sha256': '0x' + hashlib.sha256(bytes.fromhex(hexcode[2:])).hexdigest()}
        ins, err = disassemble(hexcode)
        if err:
            entry['disasm_error'] = err
        else:
            entry['selectors'] = selectors(ins)
            c = opcounts(ins)
            entry['danger_ops'] = {k: c[k] for k in DANGER if c.get(k)}
            entry['has_origin_auth'] = c.get('ORIGIN', 0) > 0
            entry['has_delegatecall'] = c.get('DELEGATECALL', 0) > 0
            entry['has_selfdestruct'] = c.get('SELFDESTRUCT', 0) > 0
        hits, seen = find_artifact_sha(repos_root, entry['sha256'])
        if hits:
            org_repo, commit = repo_commit(repos_root, hits[0]['file'])
            entry['repo'] = org_repo; entry['commit'] = commit
            entry['artifact'] = os.path.relpath(hits[0]['file'], repos_root)
            entry['artifact_trail'] = hits[0]['trail']
        else:
            res['unmapped'] += 1
        res['contracts'].append(entry)
    res['files_scanned_for_artifacts'] = None
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w') as f: json.dump(res, f, indent=1)
    print('wrote', out_path, 'contracts', len(res['contracts']), 'unmapped', res['unmapped'])
    for c in res['contracts'][:12]:
        print(' ', c['address'], 'bal', c.get('native_balance_wei'), 'bytes', c['code_bytes'],
              'selectors', len(c.get('selectors', [])), 'repo', c.get('repo'), c.get('commit'))


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
