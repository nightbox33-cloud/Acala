#!/usr/bin/env python3
"""FALLBACK: disassemble EVERY bytecode dumped from live EVM.Codes storage,
extract the function dispatcher, flag authorization/withdrawal patterns and
map exact hashes to cloned repo artefacts.

Requires pyevmasm:  python3 -m pip install --target /tmp/evmtools pyevmasm
Usage: PYTHONPATH=/tmp/evmtools python3 scripts/audit/analyze_evm_codes.py \
         audit-live/evm-codes-acala.json audit-live/evm-codes-acala \
         audit-live/evm-codes-analysis-acala.json
"""
import json, sys, os, glob, hashlib, collections

DANGER = {'CALL', 'CALLCODE', 'DELEGATECALL', 'CREATE', 'CREATE2', 'SELFDESTRUCT',
          'SSTORE', 'CALLVALUE', 'ORIGIN', 'SUICIDE', 'COINBASE'}

# 4-byte selectors of money-moving / privilege entrypoints
KNOWN = {
    '0x2e1a7d4d': 'withdraw(uint256) [WETH/MasterChef]',
    '0xa9059cbb': 'transfer(address,uint256)',
    '0x23b872dd': 'transferFrom(address,address,uint256)',
    '0x095ea7b3': 'approve(address,uint256)',
    '0x70a08231': 'balanceOf(address)',
    '0x3ccfd60b': 'withdraw()',
    '0x5312ea8e': 'emergencyWithdraw() [MasterChef]',
    '0x441a3e70': 'withdrawAll()',
    '0x853828b6': 'withdrawAll()',
    '0x00f714ce': 'withdraw(uint256,address)',
    '0xdb006a75': 'emergencyWithdraw()',
    '0xf3fef3a3': 'withdraw(uint256,uint256)',
    '0x5cffe9de': 'flashLoan(address,address,uint256,bytes)',
    '0x42b0b30c': 'flashLoan(address,uint256,address,uint256,bytes)',
    '0x5fef4a84': 'flashLoanSimple(address,address,uint256,bytes)',
    '0x3659cfe6': 'upgradeTo(address) [proxy]',
    '0x4f1ef286': 'upgradeToAndCall(address,bytes) [proxy]',
    '0x8da5cb5b': 'owner()',
    '0xf2fde38b': 'transferOwnership(address)',
    '0x715018a6': 'renounceOwnership()',
    '0x8f283970': 'changeAdmin(address)',
    '0x5c60da1b': 'implementation() [EIP1967]',
    '0x360894a7': 'implementation()',
    '0xbb913f41': 'admin()',
    '0x38af3eed': 'acceptGovernance()',
    '0x304e6ade': 'transfer(address,uint256) [compound-like]',
    '0x69328dec': 'redeem(uint256)',
    '0xf14210a6': 'withdraw(address,uint256)',
    '0x9fbf10fc': 'withdrawAll(address)',
    '0x372500ab': 'claimRewards()',
    '0x4e71d92d': 'claim()',
    '0x2e7ba6ef': 'harvest()',
    '0x4641257d': 'collect()',
    '0xe2bbb158': 'deposit(uint256)',
    '0xb6b55f25': 'deposit(uint256)',
    '0xd0e30db0': 'deposit()',
    '0x1249c58b': 'mint()',
    '0x40c10f19': 'mint(address,uint256)',
    '0x9dc29fac': 'burn(address,uint256)',
    '0x42966c68': 'burn(uint256)',
    '0x7ff36ab5': 'swapExactETHForTokens(uint256,address[],address,uint256)',
    '0x18cbafe5': 'swapExactTokensForETH(uint256,uint256,address[],address,uint256)',
    '0x38ed1739': 'swapExactTokensForTokens(uint256,uint256,address[],address,uint256)',
    '0x022c0d9f': 'swap(uint256,uint256,address,bytes) [UniV2]',
    '0x0902f1ac': 'getReserves()',
    '0x022c0d9f': 'swap(uint256,uint256,address,bytes)',
    '0x5b0d5984': 'removeLiquidityETHWithPermit(...)',
    '0xfb3bdb41': 'swap(uint256,uint256,address[],address) [Balancer]',
    '0x5ae401dc': 'multicall(bytes[])',
    '0x1f0464d1': 'execute(bytes)',
}


def analyze(hexcode):
    from pyevmasm import disassemble_all
    code = hexcode[2:] if hexcode.startswith('0x') else hexcode
    ins = list(disassemble_all(bytes.fromhex(code)))
    counts = collections.Counter(o.name for o in ins)
    selectors = []
    for i, o in enumerate(ins):
        if o.name == 'PUSH4':
            for nxt in ins[i + 1:i + 14]:
                if nxt.name in ('EQ', 'XOR', 'SUB', 'GT', 'LT'):
                    selectors.append('0x%08x' % o.operand); break
    selectors = sorted(set(selectors))
    known = {s: KNOWN[s] for s in selectors if s in KNOWN}
    # tx.origin used anywhere near a conditional jump or a store = classic auth bug
    origin_auth = False
    for i, o in enumerate(ins):
        if o.name == 'ORIGIN':
            window = [x.name for x in ins[i + 1:i + 30]]
            if 'EQ' in window or 'JUMPI' in window or 'SSTORE' in window:
                origin_auth = True; break
    # delegatecall whose target may come from calldata/storage
    delegate_dynamic = False
    for i, o in enumerate(ins):
        if o.name == 'DELEGATECALL':
            prev = [x.name for x in ins[max(0, i - 12):i]]
            if any(n in prev for n in ('CALLDATALOAD', 'SLOAD', 'CALLER')):
                delegate_dynamic = True; break
    return {
        'selectors': selectors, 'known_selectors': known,
        'danger_ops': {k: counts[k] for k in DANGER if counts.get(k)},
        'origin_auth_suspicious': origin_auth,
        'delegatecall_dynamic_target': delegate_dynamic,
        'selfdestruct': counts.get('SELFDESTRUCT', 0) > 0,
        'instruction_count': len(ins),
    }


def main(index_path, code_dir, out_path, repos_root=None):
    idx = json.load(open(index_path))
    files = glob.glob(os.path.join(code_dir, '*.hex'))
    out = {'chain': idx['chain'], 'block_number': idx['block_number'],
           'finalized_hash': idx['finalized_hash'], 'code_count_in_index': idx['code_count'],
           'files_analyzed': len(files), 'contracts': [], 'errors': []}
    bysha = {}
    for p in sorted(files):
        hexcode = open(p).read().strip()
        try: raw = bytes.fromhex(hexcode[2:])
        except Exception as e:
            out['errors'].append({'file': p, 'error': str(e)}); continue
        sha = '0x' + hashlib.sha256(raw).hexdigest()
        rec = {'file': os.path.basename(p), 'sha256': sha, 'code_bytes': len(raw)}
        try: rec.update(analyze(hexcode))
        except Exception as e:
            out['errors'].append({'file': p, 'error': str(e)}); continue
        rec['matches_predeploy'] = next((c.get('matches_predeploy') for c in idx['codes']
                                         if c['sha256'] == sha), None)
        bysha.setdefault(sha, []).append(rec['file'])
        out['contracts'].append(rec)
    out['unique_bytecodes'] = len(bysha)
    # ranking: dynamic delegatecall, tx.origin auth, selfdestruct, withdraw-like selectors
    def score(c):
        s = 0
        s += 100 if c.get('delegatecall_dynamic_target') else 0
        s += 80 if c.get('origin_auth_suspicious') else 0
        s += 60 if c.get('selfdestruct') else 0
        s += 20 * sum(1 for k in c.get('known_selectors', {}) if 'withdraw' in k.lower() or 'flash' in k.lower() or 'upgrade' in k.lower())
        s += 5 if c.get('danger_ops', {}).get('CALLVALUE') else 0
        return s
    out['contracts'].sort(key=score, reverse=True)
    out['suspicious_top20'] = [{'sha256': c['sha256'], 'score': score(c),
                                'bytes': c['code_bytes'],
                                'known': c.get('known_selectors'),
                                'origin_auth': c.get('origin_auth_suspicious'),
                                'delegate_dynamic': c.get('delegatecall_dynamic_target')}
                               for c in out['contracts'][:20]]
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w') as f: json.dump(out, f, indent=1)
    print('wrote', out_path, 'analyzed', out['files_analyzed'], 'unique', out['unique_bytecodes'])
    for c in out['contracts'][:12]:
        print(' ', c['sha256'][:18], c['code_bytes'], 'selectors', len(c.get('selectors', [])),
              'known', list(c.get('known_selectors', {}).values())[:4],
              'origin', c.get('origin_auth_suspicious'), 'delegate', c.get('delegatecall_dynamic_target'))

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else None)
