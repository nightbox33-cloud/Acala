#!/usr/bin/env python3
"""FALLBACK: for every deployed contract whose bytecode exposes
upgradeTo/changeAdmin/owner/withdraw/flashLoan (or a dynamic DELEGATECALL),
read its LIVE storage slots and role getters via RPC and flag uninitialized
owner/admin — the classic permissionless proxy-takeover precondition.

Also measures native balance + main token balances so an empty contract is
never reported as a drain candidate.
"""
import json, sys, os, datetime, traceback
import urllib.request

CHAINS = {
    'acala': ('https://acala-rpc.aca-api.network', 'https://eth-rpc-acala.aca-api.network', 10,
              [('ACA', '0x0000000000000000000100000000000000000000'),
               ('aUSD', '0x0000000000000000000100000000000000000001')]),
    'karura': ('https://karura-rpc.aca-api.network', 'https://eth-rpc-karura.aca-api.network', 8,
               [('KAR', '0x0000000000000000000100000000000000000080'),
                ('kUSD', '0x0000000000000000000100000000000000000081')]),
}
SLOTS = {
    'slot0': '0x0000000000000000000000000000000000000000000000000000000000000000',
    'eip1967_impl': '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
    'eip1967_admin': '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
    'eip1967_beacon': '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50',
}
INTEREST = ('upgrade', 'changeAdmin', 'owner', 'withdraw', 'flash', 'emergency',
            'initialize', 'setImplementation', 'rescue', 'sweep', 'drain')
MAX_CONTRACTS = int(os.environ.get('ROLE_MAX_CONTRACTS', '70'))
ZERO = '0x' + '0' * 64

def rpc(url, method, params, timeout=12):
    req = urllib.request.Request(url, data=json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)

def j(x):
    if hasattr(x, 'value') and not isinstance(x, (dict, list, str, int, float, bytes)):
        try: return j(x.value)
        except Exception: return str(x)[:200]
    if isinstance(x, bytes): return '0x' + x.hex()
    if isinstance(x, dict): return {str(k): j(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)): return [j(v) for v in x]
    if isinstance(x, (str, int, float, bool)) or x is None: return x
    return str(x)[:200]

def main(chain, out):
    from substrateinterface import SubstrateInterface
    rpc_url, evm_url, ss58, tokens = CHAINS[chain]
    sub = SubstrateInterface(url=rpc_url, ss58_format=ss58)
    fin = rpc(rpc_url, 'chain_getFinalizedHead', []).get('result')
    hdr = rpc(rpc_url, 'chain_getHeader', [fin]).get('result')
    sub.init_runtime(block_hash=fin)
    res = {'chain': chain, 'generated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'finalized_hash': fin, 'block_number': int(hdr['number'], 16),
           'rpc': rpc_url, 'evm_rpc': evm_url, 'errors': [], 'contracts': []}

    codes = json.load(open(f'audit-live/evm-codes-{chain}.json'))
    ana = json.load(open(f'audit-live/evm-codes-analysis-{chain}.json'))
    by_sha = {c['sha256']: c for c in ana['contracts']}
    code_hash_to_sha = {c['storage_key'].lower(): c['sha256'] for c in codes['codes']}

    def interesting(rec):
        sels = rec.get('known_selectors', {})
        txt = ' '.join(sels.values()).lower()
        # NOTE: origin_auth_suspicious is deliberately NOT a filter here: the
        # heuristic triggers on PUSH1 0x32 data bytes in compiled dispatchers.
        return any(w in txt for w in INTEREST) or rec.get('delegatecall_dynamic_target')

    # address -> code_hash from live EVM.Accounts
    try:
        rows = sub.query_map('EVM', 'Accounts', block_hash=fin, max_results=20000, page_size=200)
        n = 0
        for k, v in rows:
            n += 1
            addr = j(k)
            if not isinstance(addr, str) or not addr.startswith('0x'): continue
            info = j(v)
            ci = info.get('contract_info') if isinstance(info, dict) else None
            ch = ci.get('code_hash') if isinstance(ci, dict) else None
            if not isinstance(ch, str): continue
            sha = code_hash_to_sha.get(ch.lower())
            rec = by_sha.get(sha) if sha else None
            if rec is None or not interesting(rec): continue
            res['contracts'].append({'address': addr, 'code_hash': ch, 'sha256': sha,
                                     'known_selectors': rec.get('known_selectors'),
                                     'delegate_dynamic': rec.get('delegatecall_dynamic_target'),
                                     'origin_auth': rec.get('origin_auth_suspicious')})
            if len(res['contracts']) >= MAX_CONTRACTS: break
        res['evm_accounts_scanned'] = n
    except Exception as e:
        res['errors'].append({'where': 'EVM.Accounts', 'error': str(e),
                              'trace': traceback.format_exc()[-1200:]})
    print('interesting contracts', len(res['contracts']), 'of', res.get('evm_accounts_scanned'), flush=True)

    for c in res['contracts']:
        a = c['address']
        for label, slot in SLOTS.items():
            try:
                r = rpc(evm_url, 'eth_getStorageAt', [a, slot, 'latest'])
                c[label] = r.get('result')
            except Exception as e: c[label] = 'ERR:' + str(e)
        try:
            r = rpc(evm_url, 'eth_getBalance', [a, 'latest'])
            c['native_balance_wei'] = int(r['result'], 16) if isinstance(r.get('result'), str) else None
        except Exception as e: c['native_balance_wei'] = None
        # role getters
        for name, sel in (('owner()', '0x8da5cb5b'),
                          ('implementation()', '0x5c60da1b')):
            try:
                r = rpc(evm_url, 'eth_call', [{'to': a, 'data': sel}, 'latest'])
                v = r.get('result')
                c['call_' + name[:-2]] = v if isinstance(v, str) else None
            except Exception: c['call_' + name[:-2]] = None
        c['token_balances'] = {}
        for sym, tok in tokens:
            data = '0x70a08231' + a.lower().replace('0x', '').rjust(64, '0')
            try:
                r = rpc(evm_url, 'eth_call', [{'to': tok, 'data': data}, 'latest'])
                v = r.get('result')
                c['token_balances'][sym] = int(v, 16) if isinstance(v, str) else None
            except Exception: c['token_balances'][sym] = None
        # HEURISTIC ONLY. slot0 is not Ownable's owner slot; an EIP-1967 proxy
        # legitimately has slot0=0/1, a nonzero impl slot and a nonzero admin
        # slot, and may not expose owner() at all. Only an eth_call of
        # initialize()/setup() (probe_takeover.py) can prove a takeover.
        no_owner_call = c.get('call_owner') in (ZERO, '0x', None)
        no_admin = c.get('eip1967_admin') in (ZERO, '0x0', '0x', None)
        no_impl = c.get('eip1967_impl') in (ZERO, '0x0', '0x', None)
        slot0_zero = c.get('slot0') in (ZERO, '0x0', '0x', None)
        c['heuristic_no_owner'] = bool(no_owner_call and no_admin and no_impl and slot0_zero)
        c['has_value'] = bool(c.get('native_balance_wei')) or any(c['token_balances'].values())
    res['heuristic_no_owner_with_value'] = [c['address'] for c in res['contracts']
                                       if c.get('heuristic_no_owner') and c.get('has_value')]
    res['heuristic_note'] = ('NOT a takeover finding: proxies have impl/admin slots and '
                             'Ownable stores owner outside slot 0; see probe_takeover.py eth_call results')
    res['uninitialized_count'] = sum(1 for c in res['contracts'] if c.get('heuristic_no_owner'))
    res['with_value_count'] = sum(1 for c in res['contracts'] if c.get('has_value'))
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
    with open(out, 'w') as f: json.dump(res, f, indent=1, default=str)
    print('wrote', out, 'uninitialized', res['uninitialized_count'],
          'with_value', res['with_value_count'],
          'uninitialized_WITH_VALUE', res['uninitialized_with_value'][:10], flush=True)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'acala',
         sys.argv[2] if len(sys.argv) > 2 else 'audit-live/evm-roles-acala.json')
