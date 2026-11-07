#!/usr/bin/env python3
"""Live Acala/Karura state anchor + storage/EVM inventory probe.

Designed to run inside a GitHub Actions runner (the audit sandbox itself has no
chain-RPC egress). Uses substrate-interface for SCALE/metadata decoding, plus
plain JSON-RPC for the anchor, the :code runtime blob and EVM+ eth_getCode.

Evidence written as JSON to --out (committed back to the audit branch by CI).
"""
import argparse, datetime, hashlib, json, os, sys, urllib.request, urllib.error, traceback

CHAINS = {
    'acala': {
        'rpc': 'https://acala-rpc.aca-api.network',
        'evm': 'https://eth-rpc-acala.aca-api.network',
        'ss58': 10,
    },
    'karura': {
        'rpc': 'https://karura-rpc.aca-api.network',
        'evm': 'https://eth-rpc-karura.aca-api.network',
        'ss58': 8,
    },
}

def rpc(url, method, params, timeout=60):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json", "User-Agent": "acala-audit-probe/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(20_000_000)
        return json.loads(raw)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}

def jsonable(x, depth=0):
    if depth > 12:
        return str(x)[:200]
    if hasattr(x, 'value') and not isinstance(x, (dict, list, str, int, float, bytes)):
        try:
            return jsonable(x.value, depth + 1)
        except Exception:
            return str(x)[:200]
    if isinstance(x, bytes):
        return '0x' + x.hex()
    if isinstance(x, dict):
        return {str(k): jsonable(v, depth + 1) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [jsonable(v, depth + 1) for v in x]
    if isinstance(x, (str, int, float, bool)) or x is None:
        return x
    return str(x)[:200]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--chain', default='acala', choices=list(CHAINS))
    ap.add_argument('--out', required=True)
    ap.add_argument('--mode', default='all', choices=['anchor', 'catalogue', 'state', 'all'])
    ap.add_argument('--predeploy-map', default='scripts/audit/predeploy_map.json')
    ap.add_argument('--queries', default='scripts/audit/state_queries.json')
    ap.add_argument('--dump-evm-mismatches', default=None,
                    help='directory to write raw hex bytecode of predeploy contracts whose live code differs from repo')
    a = ap.parse_args()
    c = CHAINS[a.chain]
    out = {'chain': a.chain, 'generated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'rpc': c['rpc'], 'evm_rpc': c['evm'], 'ci_run_id': os.environ.get('GITHUB_RUN_ID'),
           'errors': []}

    # ---------- 1. anchor (dependency-free JSON-RPC) ----------
    fin = rpc(c['rpc'], 'chain_getFinalizedHead', []).get('result')
    hdr = rpc(c['rpc'], 'chain_getHeader', [fin] if fin else []).get('result') if fin else None
    blk = int(hdr['number'], 16) if hdr and isinstance(hdr.get('number'), str) else None
    rv = rpc(c['rpc'], 'state_getRuntimeVersion', [fin] if fin else []).get('result')
    out['anchor'] = {
        'finalized_hash': fin,
        'finalized_header': hdr,
        'finalized_block_number': blk,
        'runtime_version': {k: rv.get(k) for k in ('specName', 'implName', 'specVersion', 'transactionVersion')} if rv else None,
    }
    print('anchor', out['anchor']['finalized_block_number'], out['anchor']['runtime_version'], flush=True)

    # deployed runtime WASM: :code = twox128(":code") for storage value under well-known key
    code_key = '0x3a636f6465'
    code_res = rpc(c['rpc'], 'state_getStorage', [code_key, fin] if fin else [code_key], timeout=120)
    code_hex = code_res.get('result')
    if code_hex:
        blob = bytes.fromhex(code_hex[2:])
        out['runtime_code'] = {
            'storage_key': code_key, 'bytes': len(blob),
            'sha256': '0x' + hashlib.sha256(blob).hexdigest(),
            'blake2b_256': '0x' + hashlib.blake2b(blob, digest_size=32).hexdigest(),
        }
        print('runtime_code', out['runtime_code'], flush=True)
    else:
        out['errors'].append({'where': 'state_getStorage(:code)', 'response': str(code_res)[:300]})

    # ---------- 2. EVM+ predeploy bytecode ----------
    try:
        predeploy = json.load(open(a.predeploy_map))
    except Exception as e:
        predeploy = []
        out['errors'].append({'where': 'predeploy_map', 'error': str(e)})
    evm = {'chainId': rpc(c['evm'], 'eth_chainId', []).get('result'),
           'blockNumber': rpc(c['evm'], 'eth_blockNumber', []).get('result'),
           'codes': {}}
    for symbol, addr, expected_sha in predeploy:
        r = rpc(c['evm'], 'eth_getCode', [addr, 'latest'], timeout=30)
        code = r.get('result')
        rec = {'symbol': symbol, 'present': bool(code) and code != '0x'}
        if rec['present']:
            b = bytes.fromhex(code[2:])
            rec['bytes'] = len(b)
            rec['sha256'] = '0x' + hashlib.sha256(b).hexdigest()
            rec['matches_repo_bytecode'] = rec['sha256'] == expected_sha
        evm['codes'][addr] = rec
    out['evm'] = evm
    print('evm codes', len(evm['codes']), 'matched', sum(1 for r in evm['codes'].values() if r.get('matches_repo_bytecode')), flush=True)
    if a.dump_evm_mismatches:
        os.makedirs(a.dump_evm_mismatches, exist_ok=True)
        for symbol, addr, expected_sha in predeploy:
            rec = evm['codes'][addr]
            if rec.get('present') and not rec.get('matches_repo_bytecode'):
                code = rpc(c['evm'], 'eth_getCode', [addr, 'latest'], timeout=30).get('result') or '0x'
                with open(os.path.join(a.dump_evm_mismatches, f'{addr}.hex'), 'w') as f:
                    f.write(code)
                print('dumped mismatch bytecode', symbol, addr, len(code), flush=True)

    if a.mode in ('catalogue', 'state', 'all'):
        try:
            from substrateinterface import SubstrateInterface
            sub = SubstrateInterface(url=c['rpc'], ss58_format=c['ss58'])
            sub.init_runtime(block_hash=fin)
            # ---------- 3. metadata storage catalogue ----------
            cat = []
            for p in sub.metadata.pallets:
                for s in (p.storage or []):
                    try:
                        vt = s.get_value_type_string()
                    except Exception:
                        vt = None
                    try:
                        mod = s.modifier
                    except Exception:
                        mod = None
                    cat.append({'pallet': p.name, 'item': s.name, 'modifier': mod, 'value_type': vt})
            out['storage_catalogue'] = cat
            print('catalogue', len(cat), 'entries', flush=True)
        except Exception as e:
            out['errors'].append({'where': 'metadata', 'error': str(e), 'trace': traceback.format_exc()[-1500:]})
            sub = None
            print('metadata ERROR', e, flush=True)

        if a.mode in ('state', 'all') and sub is not None:
            try:
                cfg = json.load(open(a.queries))
            except Exception as e:
                cfg = {}
                out['errors'].append({'where': 'state_queries', 'error': str(e)})
            out['storage'] = {'_pallet_accounts': cfg.get('pallet_accounts', {}),
                              '_fee_sub_accounts': cfg.get('fee_sub_accounts', {})}
            for q in cfg.get('maps', []) + cfg.get('partial_maps', []):
                key = f"{q['pallet']}.{q['item']}" + (f"#{q['tag']}" if q.get('tag') else '')
                try:
                    res = sub.query_map(q['pallet'], q['item'], q.get('params'), block_hash=fin,
                                        max_results=q.get('max', 500), page_size=q.get('page', 100))
                    rows = []
                    for k, v in res:
                        rows.append([jsonable(k), jsonable(v)])
                        if len(rows) >= q.get('max', 500):
                            break
                    out['storage'][key] = {'count_returned': len(rows), 'rows': rows}
                    print('map', key, len(rows), flush=True)
                except Exception as e:
                    out['storage'][key] = {'error': str(e)}
                    print('map ERROR', key, e, flush=True)
            for q in cfg.get('values', []):
                key = f"{q['pallet']}.{q['item']}" + (f"#{q['tag']}" if q.get('tag') else (f"#{q['params'][0][:16]}" if q.get('params') else ''))
                try:
                    v = sub.query(q['pallet'], q['item'], q.get('params'), block_hash=fin)
                    out['storage'][key] = jsonable(v)
                    print('value', key, str(out['storage'][key])[:120], flush=True)
                except Exception as e:
                    out['storage'][key] = {'error': str(e)}
                    print('value ERROR', key, e, flush=True)
            for q in cfg.get('constants', []):
                key = f"{q['pallet']}.{q['item']}"
                try:
                    v = sub.get_constant(q['pallet'], q['item'], block_hash=fin)
                    out['storage'][key] = jsonable(v)
                    print('const', key, str(out['storage'][key])[:120], flush=True)
                except Exception as e:
                    out['storage'][key] = {'error': str(e)}
                    print('const ERROR', key, e, flush=True)

    os.makedirs(os.path.dirname(a.out) or '.', exist_ok=True)
    with open(a.out, 'w') as f:
        json.dump(out, f, indent=1, default=str)
    print('wrote', a.out, os.path.getsize(a.out), 'bytes', flush=True)

if __name__ == '__main__':
    main()
