#!/usr/bin/env python3
"""Read live TransactionPause storage (the BaseCallFilter's pause list)."""
import json, sys, datetime
from substrateinterface import SubstrateInterface

def jsonable(x):
    if hasattr(x, 'value') and not isinstance(x, (dict, list, str, int, float, bytes)):
        try: return jsonable(x.value)
        except Exception: return str(x)[:200]
    if isinstance(x, bytes): return '0x' + x.hex()
    if isinstance(x, dict): return {str(k): jsonable(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)): return [jsonable(v) for v in x]
    if isinstance(x, (str, int, float, bool)) or x is None: return x
    return str(x)[:200]

def main(chain, out):
    url = 'https://acala-rpc.aca-api.network' if chain == 'acala' else 'https://karura-rpc.aca-api.network'
    sub = SubstrateInterface(url=url, ss58_format=10 if chain == 'acala' else 8)
    fin = sub.rpc_request('chain_getFinalizedHead', []).get('result')
    hdr = sub.rpc_request('chain_getHeader', [fin]).get('result')
    res = {'chain': chain, 'generated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'finalized_hash': fin, 'block_number': int(hdr['number'], 16), 'items': {}}
    for pallet, item in [('TransactionPause', 'PausedTransactions'),
                         ('TransactionPause', 'PausedEvmPrecompiles')]:
        try:
            rows = [[jsonable(k), jsonable(v)] for k, v in
                    sub.query_map(pallet, item, block_hash=fin, max_results=500, page_size=100)]
            res['items'][f'{pallet}.{item}'] = rows
            print(f'{pallet}.{item}: {len(rows)} entries', flush=True)
        except Exception as e:
            res['items'][f'{pallet}.{item}'] = {'error': str(e)}
            print('ERROR', pallet, item, e, flush=True)
    with open(out, 'w') as f:
        json.dump(res, f, indent=1, default=str)
    print('wrote', out, flush=True)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'acala',
         sys.argv[2] if len(sys.argv) > 2 else 'audit-live/paused-calls-acala.json')
