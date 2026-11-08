#!/usr/bin/env python3
"""FALLBACK: unified permissionless-takeover probe over LIVE EVM state.

For every live deployed bytecode that exposes initialize()/setup()/upgradeTo()/
MerkleDistributor root functions, resolve its addresses from EVM.Accounts, then:
  - simulate initialize() (4 ABIs) and GnosisSafe setup() with eth_call,
  - read EIP-1967 implementation/admin slots, owner(), getThreshold(),
    merkleRoot(), currentCycle(), paused(),
  - measure native + ERC20 balances (predeploys + registered ERC20 ids).

A candidate is ONLY flagged when a takeover call does NOT revert AND the
account holds value. No claim of drain is made from bytecode alone.
"""
import json, sys, os, datetime, traceback, collections
import urllib.request

CHAINS = {
    'acala': ('https://acala-rpc.aca-api.network', 'https://eth-rpc-acala.aca-api.network', 10),
    'karura': ('https://karura-rpc.aca-api.network', 'https://eth-rpc-karura.aca-api.network', 8),
}
ATTACKER = '0x000000000000000000000000000000000000dEaD'
ZERO = '0x' + '0' * 40
INIT = {
    '0xc0c53b8b': ('initialize(address,address,address)', 3),
    '0xc4d66de8': ('initialize(address)', 1),
    '0x8129fc1c': ('initialize()', 0),
    '0x485cc955': ('initialize(address,address)', 2),
}
SETUP_SEL = '0xb63e800d'
SPECIAL = ('0x29941edd', '0x3659cfe6', '0xb63e800d', '0xf3fef3a3')
# addresses of deployed MerkleDistributor proxies, read from the cloned
# nutsfinance/merkle-distributor@60e96956 rewards/config.ts (NOT from an explorer)
KNOWN_ADDRESSES = {
    'karura': ['0xf595F4a81B27E5CC1Daca349A69c834f375224F4',  # taiksm
               '0xff066331be693BE721994CF19905b2DC7475C5c9',  # 3usd
               '0xc907CE08ac3f1AaD3AB0Adce5A20c907334C09B3'], # lksm
    'acala':  ['0x219FA396aE50f789b0cE5e27D6EcbE6b36ef49d9',  # tdot
               '0x73D6df4395CD54DF2E07fD3880c1B47Aeb2Aed97'], # ldot
}
SLOTS = {'impl': '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
         'admin': '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
         'beacon': '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50'}

def rpc(url, method, params, timeout=12):
    req = urllib.request.Request(url, data=json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r: return json.load(r)

def j(x):
    if hasattr(x, 'value') and not isinstance(x, (dict, list, str, int, float, bytes, bool)):
        try: return j(x.value)
        except Exception: return str(x)[:200]
    if isinstance(x, bytes): return '0x' + x.hex()
    if isinstance(x, dict): return {str(k): j(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)): return [j(v) for v in x]
    if isinstance(x, (str, int, float, bool)) or x is None: return x
    return str(x)[:200]

def w(v): return v.lower().replace('0x', '').rjust(64, '0')

def call(evm, to, data, frm=ATTACKER):
    try:
        r = rpc(evm, 'eth_call', [{'from': frm, 'to': to, 'data': data}, 'latest'])
        if 'error' in r: return None, 'REVERT:' + str(r['error'])[:160]
        return r.get('result', ''), None
    except Exception as e: return None, 'ERR:' + str(e)[:160]

def setup_calldata():
    head = 8 * 32
    parts = [w(hex(head)), w('1'), w(ZERO), w(hex(head + 3 * 32)),
             w(ZERO), w(ZERO), w('0'), w(ZERO)]
    arr = [w('1'), w(ATTACKER), w('0')]
    return SETUP_SEL + ''.join(parts) + ''.join(arr)

def main(chain, out):
    from substrateinterface import SubstrateInterface
    rpc_url, evm, ss58 = CHAINS[chain]
    sub = SubstrateInterface(url=rpc_url, ss58_format=ss58)
    fin = rpc(rpc_url, 'chain_getFinalizedHead', [])['result']
    hdr = rpc(rpc_url, 'chain_getHeader', [fin])['result']
    sub.init_runtime(block_hash=fin)

    ana = json.load(open(f'audit-live/evm-codes-analysis-{chain}.json'))
    interesting = {}
    for c in ana['contracts']:
        ss = set(c['selectors'])
        inits = {sel: sig for sel, (sig, _) in INIT.items() if sel in ss}
        if inits or (ss & set(SPECIAL)):
            interesting[c['sha256']] = {'selectors': sorted(ss), 'inits': inits,
                                        'code_hash': c.get('file', '').replace('.hex', ''),
                                        'bytes': c['code_bytes']}
    # token addresses for balance measurement
    tokens = []
    try:
        for r in json.load(open('scripts/audit/predeploy_map.json'))[:12]:
            tokens.append((r[0], r[1]))
    except Exception: pass
    # reward tokens published in the cloned merkle files (cycle 12/13)
    for t in ('0x0000000000000000000100000000000000000084',
              '0x0000000000000000000300000000000000000000'):
        tokens.append(('merkleToken', t))
    try:
        st = json.load(open(f'audit-live/{chain}-state.json'))['storage']
        for _id, addr in st.get('AssetRegistry.Erc20IdToAddress', {}).get('rows', [])[:6]:
            tokens.append(('ERC20:' + str(_id)[:20], addr))
    except Exception: pass

    res = {'chain': chain, 'generated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'finalized_hash': fin, 'block_number': int(hdr['number'], 16),
           'rpc': rpc_url, 'evm_rpc': evm,
           'interesting_bytecodes': len(interesting), 'errors': [],
           'accounts': [], 'takeover_candidates': []}

    by_hash = collections.defaultdict(list)
    scanned = 0
    try:
        for k, v in sub.query_map('EVM', 'Accounts', block_hash=fin, max_results=20000, page_size=200):
            scanned += 1
            a = j(k); info = j(v)
            if not isinstance(a, str) or not a.startswith('0x'): continue
            ci = info.get('contract_info') if isinstance(info, dict) else None
            ch = ci.get('code_hash') if isinstance(ci, dict) else None
            if isinstance(ch, str): by_hash[ch.lower()].append(a)
    except Exception as e:
        res['errors'].append({'where': 'EVM.Accounts', 'error': str(e),
                              'trace': traceback.format_exc()[-1000:]})
    res['evm_accounts_scanned'] = scanned
    res['contract_accounts'] = sum(len(v) for v in by_hash.values())

    # sha256 -> code_hash via the code index
    codes = json.load(open(f'audit-live/evm-codes-{chain}.json'))['codes']
    sha2hash = {}
    for c in codes: sha2hash.setdefault(c['sha256'], []).append(c['storage_key'].lower())

    # extra: probe every account explicitly named in the cloned config
    extra = [(a.lower(), None) for a in KNOWN_ADDRESSES.get(chain, [])]
    res['known_addresses_from_clone'] = [a for a, _ in extra]
    matched = 0
    for sha, meta in interesting.items():
        for ch in sha2hash.get(sha, []):
            for addr in by_hash.get(ch, [])[:2]:
                matched += 1
                rec = {'address': addr, 'sha256': sha, 'code_bytes': meta['bytes'],
                       'inits': {}, 'slots': {}, 'views': {}, 'token_balances': {}}
                # takeover simulations
                for sel, (sig, nargs) in meta['inits'].items():
                    data = sel + ''.join(w(ATTACKER) for _ in range(nargs))
                    val, err = call(evm, addr, data)
                    rec['inits'][sig] = {'ok': val is not None, 'result': val or '', 'error': err}
                if '0xb63e800d' in meta['selectors']:
                    val, err = call(evm, addr, setup_calldata())
                    rec['setup'] = {'ok': val is not None, 'result': val or '', 'error': err}
                for name, sel in (('owner', '0x8da5cb5b'), ('implementation', '0x5c60da1b'),
                                  ('getThreshold', '0xe75235b8'), ('merkleRoot', '0x2eb4a7ab'),
                                  ('currentCycle', '0x0d4202ce'), ('paused', '0x5c975abb')):
                    if sel in meta['selectors'] or name in ('getThreshold',):
                        val, err = call(evm, addr, sel)
                        rec['views'][name] = val or ('ERR' if err else '')
                for name, slot in SLOTS.items():
                    try:
                        r = rpc(evm, 'eth_getStorageAt', [addr, slot, 'latest'])
                        v = r.get('result', '0x')
                        if isinstance(v, str) and int(v, 16) != 0: rec['slots'][name] = v
                    except Exception: pass
                try:
                    r = rpc(evm, 'eth_getBalance', [addr, 'latest'])
                    rec['native_balance_wei'] = int(r['result'], 16)
                except Exception: rec['native_balance_wei'] = 0
                for sym, tok in tokens:
                    d = '0x70a08231' + w(addr)
                    val, err = call(evm, tok, d)
                    try: bal = int(val, 16) if val and val.startswith('0x') else 0
                    except Exception: bal = 0
                    if bal: rec['token_balances'][sym + ':' + tok] = bal
                rec['has_value'] = bool(rec['native_balance_wei'] or rec['token_balances'])
                rec['takeover_ok'] = any(v['ok'] for v in rec['inits'].values()) or rec.get('setup', {}).get('ok', False)
                rec['candidate'] = bool(rec['takeover_ok'] and rec['has_value'])
                res['accounts'].append(rec)
                if rec['candidate']: res['takeover_candidates'].append(addr)
    # explicit deployed distributor addresses (may be proxies with tiny code)
    for addr, _ in extra:
        if any(r['address'].lower() == addr for r in res['accounts']): continue
        matched += 1
        rec = {'address': addr, 'sha256': None, 'code_bytes': None,
               'inits': {}, 'slots': {}, 'views': {}, 'token_balances': {},
               'from_cloned_config': True}
        for sel, (sig, nargs) in INIT.items():
            data = sel + ''.join(w(ATTACKER) for _ in range(nargs))
            val, err = call(evm, addr, data)
            rec['inits'][sig] = {'ok': val is not None, 'result': val or '', 'error': err}
        for name, slot in SLOTS.items():
            try:
                v = rpc(evm, 'eth_getStorageAt', [addr, slot, 'latest']).get('result', '0x')
                if isinstance(v, str) and int(v, 16) != 0: rec['slots'][name] = v
            except Exception: pass
        for name, sel in (('merkleRoot', '0x2eb4a7ab'), ('currentCycle', '0x0d4202ce'),
                          ('paused', '0x5c975abb'), ('owner', '0x8da5cb5b')):
            val, err = call(evm, addr, sel)
            rec['views'][name] = val or ('ERR' if err else '')
        try:
            rec['native_balance_wei'] = int(rpc(evm, 'eth_getBalance', [addr, 'latest'])['result'], 16)
        except Exception: rec['native_balance_wei'] = 0
        for sym, tok in tokens:
            val, err = call(evm, tok, '0x70a08231' + w(addr))
            try: bal = int(val, 16) if val and val.startswith('0x') else 0
            except Exception: bal = 0
            if bal: rec['token_balances'][sym + ':' + tok] = bal
        rec['has_value'] = bool(rec['native_balance_wei'] or rec['token_balances'])
        rec['takeover_ok'] = any(v['ok'] for v in rec['inits'].values())
        rec['candidate'] = bool(rec['takeover_ok'] and rec['has_value'])
        res['accounts'].append(rec)
        if rec['candidate']: res['takeover_candidates'].append(addr)
    res['accounts_probed'] = matched
    res['takeover_ok_count'] = sum(1 for r in res['accounts'] if r['takeover_ok'])
    res['with_value_count'] = sum(1 for r in res['accounts'] if r['has_value'])
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
    with open(out, 'w') as f: json.dump(res, f, indent=1, default=str)
    print('wrote', out, 'interesting bytecodes', len(interesting), 'accounts probed', matched,
          'takeover_ok', res['takeover_ok_count'], 'with_value', res['with_value_count'],
          'CANDIDATES', res['takeover_candidates'], flush=True)
    for r in res['accounts'][:15]:
        print(' ', r['address'], 'val', r['native_balance_wei'], r['token_balances'],
              'init_ok', {k: v['ok'] for k, v in r['inits'].items()},
              'setup', r.get('setup', {}).get('ok'), flush=True)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'acala',
         sys.argv[2] if len(sys.argv) > 2 else 'audit-live/takeover-acala.json')
