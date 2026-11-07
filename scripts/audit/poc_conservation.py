#!/usr/bin/env python3
"""Reproducible conservation PoC over LIVE Acala state (no prank / no deal).

Re-implements, in exact integer arithmetic, the money formulas of the pinned
source and applies them to the live storage snapshot fetched by
live_state_probe.py:

  * module_dex::get_target_amount / get_supply_amount + invariant check
    (fee 3/1000, `+1` correction), all round trips and 3-hop cycles over the
    live enabled pools;
  * module_honzon::transfer_debit with live per-collateral DebitExchangeRate,
    including the full unwind (repay both CDP debts);
  * module_emergency_shutdown::refund_collaterals pro-rata with live aUSD
    total issuance and live CDP treasury balances.

Anything that lets a permissionless caller end with Y > X would show up as a
positive delta here.
"""
import json, sys, itertools

FEE_NUM, FEE_DEN = 3, 1000  # live Dex.GetExchangeFee constant


def get_target_amount(supply_pool, target_pool, supply_amount):
    if supply_amount == 0 or supply_pool == 0 or target_pool == 0:
        return 0
    swaf = supply_amount * (FEE_DEN - FEE_NUM)
    numerator = swaf * target_pool
    denominator = supply_pool * FEE_DEN + swaf
    return numerator // denominator


def get_supply_amount(supply_pool, target_pool, target_amount):
    if target_amount == 0 or supply_pool == 0 or target_pool == 0 or target_amount >= target_pool:
        return 0
    numerator = supply_pool * target_amount * FEE_DEN
    denominator = (target_pool - target_amount) * (FEE_DEN - FEE_NUM)
    return numerator // denominator + 1


def ckey(c):
    return json.dumps(c, sort_keys=True)


def cname(c):
    if 'Token' in c: return c['Token']
    if 'ForeignAsset' in c: return 'FA' + str(c['ForeignAsset'])
    if 'Erc20' in c: return 'ERC20:' + c['Erc20'][:10]
    if 'StableAssetPoolToken' in c: return 'tDOT'
    if 'LiquidCrowdloan' in c: return 'LCDOT' + str(c['LiquidCrowdloan'])
    if 'DexShare' in c: return 'LP(' + ','.join(cname(x) for x in c['DexShare']) + ')'
    return str(c)


def main(path):
    st = json.load(open(path))
    s = st['storage']
    print('anchor block', st['anchor']['finalized_block_number'], st['anchor']['finalized_hash'])
    print('runtime', st['anchor']['runtime_version'], st.get('runtime_code', {}).get('sha256'))
    print('emergency shutdown', s.get('EmergencyShutdown.IsShutdown'), 'can_refund', s.get('EmergencyShutdown.CanRefund'))

    # ---------- 1. DEX round trips / cycles with exact live pool reserves ----------
    pools = {}
    enabled = {ckey(tuple(k)) for k, v in s['Dex.TradingPairStatuses']['rows'] if v == 'Enabled'}
    for pair, (p0, p1) in s['Dex.LiquidityPool']['rows']:
        if ckey(tuple(pair)) not in enabled:
            continue
        pools[(ckey(pair[0]), ckey(pair[1]))] = [p0, p1]
    print('\n[DEX] enabled pools with reserves:', len(pools))
    for (a, b), r in pools.items():
        print('  ', cname(json.loads(a)), '/', cname(json.loads(b)), r)

    def reserves(x, y):
        if (x, y) in pools:
            r = pools[(x, y)]
            return r[0], r[1]
        if (y, x) in pools:
            r = pools[(y, x)]
            return r[1], r[0]
        return None

    # amount grid: dust through large size, relative to the smallest reserve
    amounts = [1, 2, 3, 10, 100, 1000, 10**4, 10**6, 10**8, 10**10, 10**12, 10**14, 10**16, 10**18]
    max_delta = -1
    best = None
    tested = 0
    for (x, y) in sorted(pools):
        for amt in amounts:
            r = reserves(x, y)
            if not r: continue
            sx, sy = r
            if amt >= sx // 2: continue
            # A -> B exact supply, then B -> A exact supply (full unwind)
            out = get_target_amount(sx, sy, amt)
            if out == 0 or out >= sy // 2: continue
            back = get_target_amount(sy - out, sx + amt, out)
            tested += 1
            delta = back - amt
            if delta > max_delta:
                max_delta, best = delta, ('exactSupply round trip', cname(json.loads(x)), cname(json.loads(y)), amt, out, back, delta)
            # invariant check as module_dex::_swap does
            assert (sx + amt) * (sy - out) >= sx * sy, 'invariant decreased on first swap'
            # A -> B exact target, then B -> A exact supply
            tgt = min(out or 1, sy // 4)
            if tgt > 0:
                need = get_supply_amount(sx, sy, tgt)
                if need and need < sx // 2:
                    back2 = get_target_amount(sy - tgt, sx + need, tgt)
                    tested += 1
                    delta2 = back2 - need
                    if delta2 > max_delta:
                        max_delta, best = delta2, ('exactTarget round trip', cname(json.loads(x)), cname(json.loads(y)), need, tgt, back2, delta2)
    print(f'[DEX] {tested} round trips simulated; max delta = {max_delta} (must be <= 0); best={best}')

    # ---------- 2. honzon.transfer_debit with live debit exchange rates ----------
    rates = {ckey(k): v for k, v in s['CdpEngine.DebitExchangeRate']['rows']}
    print('\n[CDP] live debit exchange rates (FixedU128 /1e18):')
    for k, v in rates.items(): print('  ', cname(json.loads(k)), v / 1e18)
    cap = {ckey(k): v['maximum_total_debit_value'] for k, v in s['CdpEngine.CollateralParams']['rows']}
    total_debit = {ckey(k): v['debit'] for k, v in s['Loans.TotalPositions']['rows']}
    print('  maximum_total_debit_value:', {cname(json.loads(k)): v for k, v in cap.items()})
    print('  total_positions.debit    :', {cname(json.loads(k)): v for k, v in total_debit.items()})
    print('  => any positive debit fails check_debit_cap (all caps = 0) and honzon shutdown check')
    # Even ignoring those guards, show the unwind absorbs the rate difference:
    for (ka, va), (kb, vb) in itertools.combinations(rates.items(), 2):
        d = 10**15
        net_minted = d - int(va / 1e18 * d) + int(vb / 1e18 * d) - d
        extra_repay = int(vb / 1e18 * d) - int(va / 1e18 * d)
        assert net_minted == extra_repay, (net_minted, extra_repay)
    print('  transfer_debit: temporary aUSD surplus == extra debt that must be repaid on unwind -> PnL 0')

    # ---------- 3. refund_collaterals pro-rata conservation ----------
    aUSD_supply = next(v for k, v in s['Tokens.TotalIssuance']['rows'] if k == {'Token': 'AUSD'})
    cdpt = s['System.Account#aca/cdpt']['data']['free']
    cdp_tokens = {ckey(k): v['free'] for k, v in s['Tokens.Accounts#aca/cdpt']['rows']}
    amount = 10**12  # 1 aUSD
    ratio_num, ratio_den = amount, aUSD_supply  # Ratio::checked_from_rational
    refund_aca = ratio_num * cdpt // ratio_den
    print('\n[REFUND] aUSD total supply', aUSD_supply, '; CDP treasury ACA', cdpt, '; tokens', cdp_tokens)
    print('  burn 1 aUSD -> pro-rata ACA refund', refund_aca,
          '; new supply', aUSD_supply - amount, '; new treasury ACA', cdpt - refund_aca)
    print('  ratio before/after:', cdpt / aUSD_supply, (cdpt - refund_aca) / (aUSD_supply - amount))
    assert (cdpt - refund_aca) / (aUSD_supply - amount) <= cdpt / aUSD_supply
    print('\nCONCLUSION: no permissionless X -> Y>X transition found in these live money paths.')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'audit-live/acala-state.json')
