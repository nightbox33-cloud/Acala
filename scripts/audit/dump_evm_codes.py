#!/usr/bin/env python3
"""FALLBACK: dump EVERY deployed EVM bytecode from live storage (EVM.Codes),
not just the predeploy addresses. One query_map per chain, no per-address RPC.

Closes the gap left by predeploy_map.json (only 79 addresses) and by the
per-account inventory: every code hash actually present in `:code` storage.
"""
import json, sys, os, hashlib, datetime, traceback
import urllib.request

CHAINS = {
    'acala': ('https://acala-rpc.aca-api.network', 10),
    'karura': ('https://karura-rpc.aca-api.network', 8),
}

def rpc(url, method, params, timeout=60):
    req = urllib.request.Request(url, data=json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r: return json.load(r)

def tohex(x):
    if isinstance(x, str):
        return x if x.startswith('0x') else '0x' + x
    if isinstance(x, (bytes, bytearray)): return '0x' + bytes(x).hex()
    if isinstance(x, (list, tuple)):
        try: return '0x' + bytes(x).hex()
        except Exception: pass
    if hasattr(x, 'value'): return tohex(x.value)
    return None

def j(x):
    if hasattr(x, 'value') and not isinstance(x, (dict, list, str, int, float, bytes)):
        try: return j(x.value)
        except Exception: return str(x)[:200]
    if isinstance(x, bytes): return '0x' + x.hex()
    if isinstance(x, dict): return {str(k): j(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)): return [j(v) for v in x]
    if isinstance(x, (str, int, float, bool)) or x is None: return x
    return str(x)[:200]

def main(chain, out, dump_dir):
    from substrateinterface import SubstrateInterface
    rpc_url, ss58 = CHAINS[chain]
    sub = SubstrateInterface(url=rpc_url, ss58_format=ss58)
    fin = rpc(rpc_url, 'chain_getFinalizedHead', []).get('result')
    hdr = rpc(rpc_url, 'chain_getHeader', [fin]).get('result')
    sub.init_runtime(block_hash=fin)
    res = {'chain': chain, 'generated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'finalized_hash': fin, 'block_number': int(hdr['number'], 16),
           'rpc': rpc_url, 'codes': [], 'errors': []}
    os.makedirs(dump_dir, exist_ok=True)
    try:
        rows = list(sub.query_map('EVM', 'Codes', block_hash=fin, max_results=2000, page_size=50))
        print('EVM.Codes rows', len(rows), flush=True)
    except Exception as e:
        res['errors'].append({'where': 'EVM.Codes', 'error': str(e), 'trace': traceback.format_exc()[-1200:]})
        rows = []
        print('EVM.Codes ERROR', e, flush=True)
    for k, v in rows:
        code = tohex(v)
        if not code or len(code) <= 2: continue
        try: raw = bytes.fromhex(code[2:])
        except Exception: continue
        h = '0x' + hashlib.sha256(raw).hexdigest()
        key = j(k)
        fname = (h[2:42] if h.startswith('0x') else h[:40]) + '.hex'
        with open(os.path.join(dump_dir, fname), 'w') as f: f.write(code)
        res['codes'].append({'storage_key': key, 'code_bytes': len(raw), 'sha256': h, 'file': fname})
    res['code_count'] = len(res['codes'])
    res['total_bytecode_bytes'] = sum(c['code_bytes'] for c in res['codes'])
    res['truncated'] = len(rows) >= 2000
    # exact-match map against the checked-out predeploy artefacts
    try:
        pm = json.load(open('scripts/audit/predeploy_map.json'))
        bysha = {}
        # predeploy_map.json is a list of [symbol, address, sha256]
        for row in pm:
            if isinstance(row, (list, tuple)) and len(row) >= 3:
                symbol, addr, s = row[0], row[1], row[2]
                if s: bysha.setdefault(s, []).append((addr, symbol))
        for c in res['codes']:
            if c['sha256'] in bysha: c['matches_predeploy'] = bysha[c['sha256']]
    except Exception as e:
        res['errors'].append({'where': 'predeploy_map', 'error': str(e)})
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
    with open(out, 'w') as f: json.dump(res, f, indent=1, default=str)
    print('wrote', out, 'codes', res['code_count'], 'bytes', res['total_bytecode_bytes'],
          'matched predeploys', sum(1 for c in res['codes'] if c.get('matches_predeploy')), flush=True)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'acala',
         sys.argv[2] if len(sys.argv) > 2 else 'audit-live/evm-codes-acala.json',
         sys.argv[3] if len(sys.argv) > 3 else 'audit-live/evm-codes-acala')
