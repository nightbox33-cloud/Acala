#!/usr/bin/env python3
"""Probe the LIVE Karura HonzonBridge (pallet 106).

module_honzon_bridge::to_bridged/from_bridged exchanges `amount` 1:1 IN BASE
UNITS between KUSD (12 decimals) and `BridgedStableCoinCurrencyId` (an ERC20
chosen by governance). If that ERC20 has different decimals, a permissionless
call drains the bridge escrow. This script measures the actual parameter, the
escrow inventory, and the decimal mismatch, then computes the PnL.
"""
import json, sys, os, hashlib, datetime, traceback
import urllib.request

RPC = 'https://karura-rpc.aca-api.network'
EVM = 'https://eth-rpc-karura.aca-api.network'
HOLDING = '0x000000000000000000ff00000000000000000000'
KUSD_DECIMALS = 12

def rpc(url, method, params, timeout=40):
    req = urllib.request.Request(url, data=json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r: return json.load(r)

def j(x):
    if hasattr(x, 'value') and not isinstance(x, (dict, list, str, int, float, bytes)):
        try: return j(x.value)
        except Exception: return str(x)[:300]
    if isinstance(x, bytes): return '0x' + x.hex()
    if isinstance(x, dict): return {str(k): j(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)): return [j(v) for v in x]
    if isinstance(x, (str, int, float, bool)) or x is None: return x
    return str(x)[:300]

def eth_call(to, data):
    r = rpc(EVM, 'eth_call', [{'to': to, 'data': data}, 'latest'])
    if 'error' in r: return None, r['error']
    return r.get('result'), None

def u256(res):
    if not res or not isinstance(res, str): return None
    return int(res, 16)

def main(out):
    from substrateinterface import SubstrateInterface
    sub = SubstrateInterface(url=RPC, ss58_format=8)
    fin = rpc(RPC, 'chain_getFinalizedHead', []).get('result')
    hdr = rpc(RPC, 'chain_getHeader', [fin]).get('result')
    sub.init_runtime(block_hash=fin)
    res = {'chain': 'karura', 'generated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'finalized_hash': fin, 'block_number': int(hdr['number'], 16),
           'rpc': RPC, 'evm_rpc': EVM, 'errors': [],
           'finding': 'to_bridged/from_bridged swap 1:1 BASE UNITS between Token(KUSD) and Erc20(bridged)'}

    # 1. the live governance parameter
    try:
        v = j(sub.query('HonzonBridge', 'BridgedStableCoinCurrencyId', block_hash=fin))
        res['bridged_stable_coin_currency_id'] = v
        print('BridgedStableCoinCurrencyId =', v, flush=True)
    except Exception as e:
        res['errors'].append({'where': 'BridgedStableCoinCurrencyId', 'error': str(e),
                              'trace': traceback.format_exc()[-1000:]})
        v = None
        print('query ERROR', e, flush=True)

    # 2. derive H160 of the honzon-bridge pallet account (aca/hzbg)
    #    account_to_default_evm_address = blake2_256(b"evm:" ++ AccountId32)[0..20]
    acct_bytes = None
    try:
        cfg = json.load(open('scripts/audit/state_queries.json'))
        addr_ss58 = cfg['pallet_accounts'].get('aca/hzbg')
        res['honzon_bridge_account_ss58'] = addr_ss58
        from substrateinterface.utils.ss58 import ss58_decode
        acct_bytes = bytes.fromhex(ss58_decode(addr_ss58))
        h160 = '0x' + hashlib.blake2b(b'evm:' + acct_bytes, digest_size=32).digest()[:20].hex()
        res['honzon_bridge_account_h160'] = h160
    except Exception as e:
        res['errors'].append({'where': 'derive_h160', 'error': str(e)})
        h160 = None
    print('bridge h160', h160, flush=True)

    # 3. registered metadata / decimals of all ERC20s
    try:
        metas = j(sub.query_map('AssetRegistry', 'AssetMetadatas', block_hash=fin,
                                max_results=200, page_size=100))
        res['erc20_metadata'] = [[k, v] for k, v in metas if 'Erc20' in str(k)]
        print('erc20 metadata rows', len(res['erc20_metadata']), flush=True)
    except Exception as e:
        res['errors'].append({'where': 'AssetMetadatas', 'error': str(e)})
        res['erc20_metadata'] = []

    # 4. live balances of the escrow for the configured ERC20
    erc20 = None
    if isinstance(v, dict):
        erc20 = v.get('Erc20') or v.get('erc20')
    if erc20:
        res['bridged_erc20'] = erc20
        dec_reg = None
        for k, m in res['erc20_metadata']:
            if erc20.lower() in str(k).lower():
                dec_reg = m.get('decimals') if isinstance(m, dict) else None
        res['bridged_decimals_registered'] = dec_reg
        for label, target in (('holding_account', HOLDING), ('bridge_account', h160)):
            if not target: continue
            data = '0x70a08231' + target.lower().replace('0x', '').rjust(64, '0')
            val, err = eth_call(erc20, data)
            res['balanceOf_' + label] = u256(val)
            if err: res.setdefault('errors', []).append({'where': 'balanceOf_' + label, 'error': err})
        for label, sel in (('decimals', '0x313ce567'), ('totalSupply', '0x18160ddd')):
            val, err = eth_call(erc20, sel)
            res['erc20_' + label] = u256(val)
            if err: res['errors'].append({'where': 'erc20_' + label, 'error': err})
        # KUSD inventory of the escrow (Token(KUSD) lives in Tokens.Accounts)
        try:
            if res.get('honzon_bridge_account_ss58'):
                kv = j(sub.query('Tokens', 'Accounts',
                                 [res['honzon_bridge_account_ss58'], {'Token': 'KUSD'}], block_hash=fin))
                res['escrow_kusd_account_data'] = kv
                # module_currencies::transfer(Erc20, from=pallet_account, ..) requires
                # get_evm_address(pallet_account) to be Some; otherwise it reverts
                # with EvmAccountNotFound and to_bridged can never pay out.
                res['escrow_evm_address_mapping'] = j(
                    sub.query('EvmAccounts', 'EvmAddresses',
                              [res['honzon_bridge_account_ss58']], block_hash=fin))
        except Exception as e:
            res['errors'].append({'where': 'escrow_kusd', 'error': str(e)})
        # PnL of a permissionless 1-base-unit-unit call if decimals differ
        d = res.get('erc20_decimals') or dec_reg
        res['decimal_delta_vs_KUSD'] = (d - KUSD_DECIMALS) if isinstance(d, int) else None
        if isinstance(d, int) and d < KUSD_DECIMALS:
            res['pnl_note'] = ('to_bridged(amount) takes `amount` KUSD base units and returns '
                               '`amount` ERC20 base units worth 10^%d times more per unit'
                               % (KUSD_DECIMALS - d))
        elif isinstance(d, int) and d > KUSD_DECIMALS:
            res['pnl_note'] = ('from_bridged(amount) takes `amount` ERC20 base units and returns '
                               '10^%d times more KUSD base units' % (d - KUSD_DECIMALS))
        else:
            res['pnl_note'] = 'decimals match (or unknown): 1:1 is fair; no unit-mismatch drain'
    else:
        res['pnl_note'] = 'BridgedStableCoinCurrencyId NOT SET (or not an Erc20): both calls revert'

    # 5. is the pallet paused / is the chain shut down?
    try:
        res['emergency_shutdown_is_shutdown'] = j(sub.query('EmergencyShutdown', 'IsShutdown', block_hash=fin))
    except Exception as e:
        res['errors'].append({'where': 'IsShutdown', 'error': str(e)})
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
    with open(out, 'w') as f: json.dump(res, f, indent=1, default=str)
    print('wrote', out, '\n', json.dumps({k: res[k] for k in res if k in (
        'bridged_stable_coin_currency_id', 'bridged_erc20', 'bridged_decimals_registered',
        'erc20_decimals', 'erc20_totalSupply', 'balanceOf_holding_account',
        'balanceOf_bridge_account', 'decimal_delta_vs_KUSD', 'pnl_note',
        'emergency_shutdown_is_shutdown')}, indent=1), flush=True)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'audit-live/honzon-bridge-karura.json')
