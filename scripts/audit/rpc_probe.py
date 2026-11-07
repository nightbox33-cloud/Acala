#!/usr/bin/env python3
"""Live-chain anchor probe. Pure stdlib so it runs both in this sandbox and in CI.

Queries a set of foundation-configured Acala/Karura/EVM+/relay JSON-RPC endpoints,
records header/finality/runtime-version and a few storage/state reads, and dumps
everything (including failures) to a JSON file for use as audit evidence.
"""
import argparse, json, socket, ssl, time, urllib.request, urllib.error, datetime, os

ENDPOINTS = [
    # from AcalaNetwork/chopsticks/configs/*.yml, acala.js, bodhi.js, e2e-tests
    "https://acala-rpc.aca-api.network",
    "https://acala-rpc-0.aca-api.network",
    "https://acala-rpc-1.aca-api.network",
    "https://acala-rpc.n.dwellir.com",
    "https://acala-rpc.dwellir.com",
    "https://acala-polkadot.api.onfinality.io/public-http",
    "https://karura-rpc.aca-api.network",
    "https://karura-rpc-0.aca-api.network",
    "https://karura-rpc.n.dwellir.com",
    "https://eth-rpc-acala.aca-api.network",
    "https://eth-rpc-karura.aca-api.network",
    "https://blockscout.acala.network/api/eth-rpc",
    "https://polkadot-rpc.dwellir.com",
    "https://polkadot.api.onfinality.io/public-http",
]

SUBSTRATE_CALLS = [
    ("system_chain", []),
    ("system_health", []),
    ("system_localPeerId", []),
    ("chain_getHeader", []),
    ("chain_getFinalizedHead", []),
    ("state_getRuntimeVersion", []),
]
EVM_CALLS = [
    ("eth_chainId", []),
    ("eth_blockNumber", []),
    ("eth_getBlockByNumber", ["latest", False]),
]

def rpc(url, method, params, timeout=12):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json", "User-Agent": "acala-audit-probe/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(2_000_000)
        try:
            return {"ok": True, "result": json.loads(raw)}
        except Exception:
            return {"ok": True, "raw": raw.decode('utf-8', 'replace')[:2000]}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='audit-live/anchor.json')
    ap.add_argument('--endpoints', nargs='*', default=None)
    a = ap.parse_args()
    eps = a.endpoints or ENDPOINTS
    out = {
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "runner": {"hostname": socket.gethostname(), "ci": os.environ.get('GITHUB_ACTIONS'),
                   "run_id": os.environ.get('GITHUB_RUN_ID')},
        "endpoints": {},
    }
    for url in eps:
        is_evm = 'eth-rpc' in url or 'eth-rpc' in url or '/eth-rpc' in url or 'blockscout' in url
        calls = EVM_CALLS if is_evm else SUBSTRATE_CALLS
        rec = {"kind": "evm" if is_evm else "substrate", "calls": {}}
        for method, params in calls:
            rec["calls"][method] = rpc(url, method, params)
            print(url, method, rec["calls"][method]["ok"], flush=True)
        out["endpoints"][url] = rec
        print('done', url, flush=True)
    os.makedirs(os.path.dirname(a.out) or '.', exist_ok=True)
    with open(a.out, 'w') as f:
        json.dump(out, f, indent=1)
    print('wrote', a.out, flush=True)

if __name__ == '__main__':
    main()
