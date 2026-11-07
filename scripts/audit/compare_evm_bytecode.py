#!/usr/bin/env python3
"""Compare dumped live EVM bytecode with the repo's pinned deployedBytecodes.json."""
import json, sys, glob, os, hashlib

repo = json.load(open(sys.argv[1] if len(sys.argv) > 1 else
                      '/home/user/audit-work/repos/AcalaNetwork/predeploy-contracts/resources/deployedBytecodes.json'))
by_addr = {a.lower(): (s, c) for s, a, c in repo}
for f in sorted(glob.glob(sys.argv[2] if len(sys.argv) > 2 else 'audit-live/evm-mismatch-acala/*.hex')):
    addr = os.path.basename(f)[:-4].lower()
    live = open(f).read().strip()
    sym, expected = by_addr.get(addr, ('?', None))
    print(f'\n=== {sym} {addr} ===')
    print('live bytes', (len(live) - 2) // 2, 'repo bytes', (len(expected) - 2) // 2 if expected else None)
    if not expected:
        continue
    lb, eb = bytes.fromhex(live[2:]), bytes.fromhex(expected[2:])
    n = min(len(lb), len(eb))
    first = next((i for i in range(n) if lb[i] != eb[i]), None)
    print('common prefix length', first if first is not None else n)
    print('live tail ', lb[-64:].hex())
    print('repo tail ', eb[-64:].hex())
    # Solidity metadata hash is the last 34 bytes (0xa2 0x64 'i' 'p' 'f' 's' + 32-byte hash + 2-byte version)
    print('live runtime (w/o metadata)', hashlib.sha256(lb[:-34] if len(lb) > 34 else lb).hexdigest())
    print('repo runtime (w/o metadata)', hashlib.sha256(eb[:-34] if len(eb) > 34 else eb).hexdigest())
    print('metadata marker live', lb[-36:-34].hex(), 'repo', eb[-36:-34].hex())
