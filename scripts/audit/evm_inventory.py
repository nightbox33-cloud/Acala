#!/usr/bin/env python3
"""FALLBACK evidence: enumerate EVM accounts/contracts deployed on mainnet,
their LIVE native balance, code hash and exact deployed bytecode.

Only plain state queries (query_map -> state_getKeysPaged/state_queryStorageAt)
and standard eth_getBalance/eth_getCode. Bytecode files are written only for
accounts that actually hold native value, so the artifact stays small.
"""
import json, sys, os, hashlib, datetime, traceback
import urllib.request

CHAINS = {
    'acala': ('https://acala-rpc.aca-api.network', 'https://eth-rpc-acala.aca-api.network', 10),
    'karura': ('https://karura-rpc.aca-api.network', 'https://eth-rpc-karura.aca-api.network', 8),
}
MAX_ACCOUNTS = int(os.environ.get('EVM_MAX_ACCOUNTS', '120'))

def rpc(url, method, params, timeout=8):
    req = urllib.request.Request(url, data=json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)

def j(x):
    if hasattr(x, 'value') and not isinstance(x, (dict, list, str, int, float, bytes)):
        try: return j(x.value)
        except Exception: return str(x)[:300]
    if isinstance(x, bytes): return '0x' + x.hex()
    if isinstance(x, dict): return {str(k): j(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)): return [j(v) for v in x]
    if isinstance(x, (str, int, float, bool)) or x is None: return x
    return str(x)[:300]

def main(chain, out, dump_dir):
    from substrateinterface import SubstrateInterface
    rpc_url, evm_url, ss58 = CHAINS[chain]
    sub = SubstrateInterface(url=rpc_url, ss58_format=ss58)
    fin = rpc(rpc_url, 'chain_getFinalizedHead', []).get('result')
    hdr = rpc(rpc_url, 'chain_getHeader', [fin]).get('result')
    sub.init_runtime(block_hash=fin)
    res = {'chain': chain, 'generated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'finalized_hash': fin, 'block_number': int(hdr['number'], 16),
           'rpc': rpc_url, 'evm_rpc': evm_url, 'max_accounts': MAX_ACCOUNTS,
           'accounts': {}, 'errors': []}

    try:
        rows = list(sub.query_map('EVM', 'Accounts', block_hash=fin,
                                  max_results=MAX_ACCOUNTS, page_size=100))
        print('EVM.Accounts rows:', len(rows), flush=True)
    except Exception as e:
        res['errors'].append({'where': 'EVM.Accounts', 'error': str(e),
                              'trace': traceback.format_exc()[-1200:]})
        rows = []
        print('EVM.Accounts ERROR', e, flush=True)

    os.makedirs(dump_dir, exist_ok=True)
    nonzero, contracts = [], []
    for idx, (k, v) in enumerate(rows):
        addr = j(k)
        if not isinstance(addr, str): addr = str(addr)
        info = j(v)
        is_contract = isinstance(info, dict) and info.get('contract_info') not in (None, 'None')
        rec = {'account_info': info, 'is_contract': bool(is_contract)}
        try:
            bal = rpc(evm_url, 'eth_getBalance', [addr, 'latest']).get('result')
            rec['native_balance_wei'] = int(bal, 16) if isinstance(bal, str) else 0
        except Exception as e:
            rec['balance_error'] = str(e)
        if is_contract or rec.get('native_balance_wei'):
            try:
                code = rpc(evm_url, 'eth_getCode', [addr, 'latest'], timeout=8).get('result') or '0x'
                rec['code_bytes'] = (len(code) - 2) // 2
                rec['code_sha256'] = ('0x' + hashlib.sha256(bytes.fromhex(code[2:])).hexdigest()) if len(code) > 2 else None
                if rec['code_bytes'] and rec.get('native_balance_wei'):
                    with open(os.path.join(dump_dir, addr.lower() + '.hex'), 'w') as f:
                        f.write(code)
            except Exception as e:
                rec['code_error'] = str(e)
        res['accounts'][addr] = rec
        if rec.get('native_balance_wei'): nonzero.append((rec['native_balance_wei'], addr))
        if rec.get('code_bytes'): contracts.append((rec['code_bytes'], addr))
        if idx % 200 == 0: print('  processed', idx, 'accounts', flush=True)

    res['nonzero_balance_accounts'] = sorted(nonzero, reverse=True)[:50]
    res['largest_contracts'] = sorted(contracts, reverse=True)[:30]
    res['account_count'] = len(res['accounts'])
    res['contract_count'] = len(contracts)
    res['truncated'] = len(rows) >= MAX_ACCOUNTS
    res['total_native_balance_wei'] = sum(r.get('native_balance_wei', 0) or 0 for r in res['accounts'].values())
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
    with open(out, 'w') as f: json.dump(res, f, indent=1, default=str)
    print('wrote', out, 'accounts', res['account_count'], 'contracts', res['contract_count'],
          'total wei', res['total_native_balance_wei'], flush=True)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'acala',
         sys.argv[2] if len(sys.argv) > 2 else 'audit-live/evm-inventory-acala.json',
         sys.argv[3] if len(sys.argv) > 3 else 'audit-live/evm-code-acala')
