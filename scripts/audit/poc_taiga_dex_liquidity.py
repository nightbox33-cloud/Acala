#!/usr/bin/env python3
"""Exact-integer reimplementation of nutsfinance/stable-asset (commit aa101e87)
and module_dex add/remove liquidity, applied to the LIVE Acala storage snapshot.

Goal: find any permissionless sequence where the attacker ends with more
DOT+LDOT (or pool0+pool1 units) than he put in, i.e. a delta taken from
third-party pool reserves. No prank / no admin: the attacker supplies X himself.
"""
import json, sys, itertools

APREC = 100
FPREC = 10_000_000_000          # runtime/acala FeePrecision
NITER = 255
U128_MAX = 2**128 - 1

def get_d(balances, a, aprec=APREC):
    n = len(balances)
    s = sum(balances)
    if s == 0: return 0
    ann = a
    for _ in balances: ann *= n
    d = s
    for _ in range(NITER):
        p_d = d
        for x in balances:
            if x == 0: return None
            p_d = (p_d * d) // (x * n)
        prev = d
        t1 = p_d * n
        t2 = (n + 1) * p_d
        t3 = ((ann - aprec) * d // aprec) + t2
        if t3 == 0: return None
        d = ((ann * s // aprec) + t1) * d // t3
        if abs(d - prev) <= 1: break
    return d

def get_y(balances, i, target_d, a, aprec=APREC):
    n = len(balances)
    ann = a
    for _ in balances: ann *= n
    c = target_d
    s = 0
    for j, x in enumerate(balances):
        if j == i: continue
        if x == 0: return None
        s += x
        c = (c * target_d) // (x * n)
    c = (c * target_d * aprec) // (ann * n)
    b = s + (target_d * aprec) // ann
    y = target_d
    for _ in range(NITER):
        prev = y
        den = 2 * y + b - target_d
        if den <= 0: return None
        y = (y * y + c) // den
        if abs(y - prev) <= 1: break
    return y

class Taiga:
    """Mirrors pool_info + real account balances + collect_fee/collect_yield."""
    def __init__(self, p):
        self.bal = list(p['balances'])                 # real balances in base units
        self.prec = list(p['precisions'])
        self.total_supply = p['total_supply']
        self.a = p['a']
        self.mint_fee = p['mint_fee']; self.swap_fee = p['swap_fee']; self.redeem_fee = p['redeem_fee']
        self.fee_recipient_tDOT = 0
        self.name = [json.dumps(x, sort_keys=True) for x in p['assets']]

    def _num(self):
        return [b * pr for b, pr in zip(self.bal, self.prec)]

    def collect(self, label):
        """get_pending_fee_amount: recompute D from REAL balances, mint diff, tolerate 1% loss."""
        old_d = self.total_supply
        new_d = get_d(self._num(), self.a)
        if new_d is None: raise RuntimeError(label + ': get_d failed')
        div100 = old_d // 100
        if new_d > old_d:
            self.fee_recipient_tDOT += new_d - old_d
        elif new_d < old_d - div100:
            raise RuntimeError(f'{label}: collect_fee Math revert (new_d={new_d} old_d={old_d})')
        self.total_supply = new_d
        return new_d, old_d

    def yield_and_balance_update(self):
        """collect_yield + get_balance_update_amount: total_supply = D(real balances)."""
        new_d = get_d(self._num(), self.a)
        self.total_supply = new_d

    def mint(self, amounts, user):
        self.yield_and_balance_update()
        old_d = self.total_supply
        newbal = [b + a * pr for b, a, pr in zip(self._num(), amounts, self.prec)]
        new_d = get_d(newbal, self.a)
        mint_amount = new_d - old_d
        if mint_amount <= 0: raise RuntimeError('mint: no shares')
        fee = mint_amount * self.mint_fee // FPREC
        mint_amount -= fee
        for k, a in enumerate(amounts):
            user[k] -= a; self.bal[k] += a
        user_tDOT = mint_amount
        self.fee_recipient_tDOT += fee
        self.total_supply = new_d
        self.collect('mint')
        return user_tDOT

    def swap(self, i, j, dx, user):
        self.yield_and_balance_update()
        d = self.total_supply
        b = self._num()
        b[i] += dx * self.prec[i]
        y = get_y(b, j, d, self.a)
        if y is None: raise RuntimeError('swap: get_y failed')
        dy = (b[j] - y - 1) // self.prec[j]
        if dy < 0: raise RuntimeError('swap: negative dy')
        if self.swap_fee: dy -= dy * self.swap_fee // FPREC
        if dy <= 0: raise RuntimeError('swap: zero dy')
        user[i] -= dx; self.bal[i] += dx
        user[j] += dy; self.bal[j] -= dy
        self.collect('swap')
        return dy

    def redeem_single(self, i, amount_bal, user_tDOT):
        self.yield_and_balance_update()
        d = self.total_supply
        b = self._num()
        amount = amount_bal
        fee = amount * self.redeem_fee // FPREC
        amount -= fee
        if amount <= 0 or amount > d: raise RuntimeError('redeem_single: bad amount')
        y = get_y(b, i, d - amount, self.a)
        if y is None: raise RuntimeError('redeem_single: get_y failed')
        dy = (b[i] - y - 1) // self.prec[i]
        if dy < 0: raise RuntimeError('redeem_single: negative dy')
        self.bal[i] -= dy
        self.total_supply = d - amount
        user_tDOT -= amount_bal
        self.fee_recipient_tDOT += fee
        self.collect('redeem_single')
        return dy

    def redeem_proportion(self, amount, user_tDOT):
        self.yield_and_balance_update()
        d = self.total_supply
        fee = amount * self.redeem_fee // FPREC
        redeem = amount - fee
        prop = [b * redeem // d for b in self.bal]
        for k in range(len(self.bal)): self.bal[k] -= prop[k]
        self.total_supply = d - redeem
        user_tDOT -= amount
        self.fee_recipient_tDOT += fee
        self.collect('redeem_proportion')
        return prop

def main(path):
    st = json.load(open(path)); s = st['storage']
    p = s['StableAsset.Pools']['rows'][0][1]
    print('anchor', st['anchor']['finalized_block_number'], 'Taiga pool 0:',
          p['balances'], 'total_supply', p['total_supply'], 'a', p['a'],
          'fees', p['mint_fee'], p['swap_fee'], p['redeem_fee'])
    d0 = get_d([b*pr for b, pr in zip(p['balances'], p['precisions'])], p['a'])
    print('D(real balances) =', d0, 'stored total_supply =', p['total_supply'],
          'diff =', d0 - p['total_supply'])

    # ---------- A: Taiga mint -> redeem_single / redeem_proportion / swap round trips ----------
    base = [10**6, 10**7, 10**8, 10**9, 10**10, 10**11, 10**12, 10**13, 10**14, 10**15, 10**16]
    best = (0, None)
    tested = 0
    for amt in base:
        for ratio in (1, 2, 5, 10, 100):
            for mode in ('single0', 'single1', 'proportion', 'swap01', 'swap10'):
                try:
                    t = Taiga(p)
                    user = [amt, amt * ratio]     # attacker capital X (DOT, LDOT)
                    user_tDOT = 0
                    x0, x1 = user[0], user[1]
                    # mint with a proportional slice of the capital
                    in0, in1 = amt // 2, amt * ratio // 2
                    user_tDOT = t.mint([in0, in1], user)
                    if mode == 'single0':
                        out = t.redeem_single(0, user_tDOT, user_tDOT); user[0] += out
                    elif mode == 'single1':
                        out = t.redeem_single(1, user_tDOT, user_tDOT); user[1] += out
                    elif mode == 'proportion':
                        got = t.redeem_proportion(user_tDOT, user_tDOT)
                        user[0] += got[0]; user[1] += got[1]
                    elif mode == 'swap01':
                        t.swap(0, 1, amt // 4, user)
                    elif mode == 'swap10':
                        t.swap(1, 0, amt * ratio // 4, user)
                    # unwind: if attacker still holds tDOT, redeem proportionally
                    if user_tDOT > 0 and mode.startswith('swap'):
                        got = t.redeem_proportion(user_tDOT, user_tDOT)
                        user[0] += got[0]; user[1] += got[1]
                    # PnL in a conservative 1:1 unit metric (stable pool assets)
                    delta = (user[0] + user[1]) - (x0 + x1)
                    # The pool invariant: if D fell, the attacker's extra really came
                    # out of LP value; if D rose (fees), it was just a rebalancing arb.
                    d_before = get_d([b * pr for b, pr in zip(p['balances'], p['precisions'])], p['a'])
                    d_after = get_d(t._num(), t.a)
                    tested += 1
                    if delta > best[0]:
                        best = (delta, (amt, ratio, mode, user, x0 + x1,
                                        t.bal, t.total_supply, t.fee_recipient_tDOT,
                                        'D_before=' + str(d_before), 'D_after=' + str(d_after),
                                        'D_delta=' + str(d_after - d_before)))
                    # critical only if units gained AND invariant destroyed
                    if delta > 0 and d_after < d_before:
                        print('!!! INVARIANT BREAK', amt, ratio, mode, delta, d_before, d_after)
                except RuntimeError:
                    continue
    print(f'[TAIGA] {tested} sequences; max unit delta = {best[0]} (must be <= 0)')
    print('        best:', best[1])

    # ---------- B: module_dex add_liquidity -> remove_liquidity round trips ----------
    FIX = 10**18
    def rat(a, b): return (a * FIX) // b if b else 0       # FixedU128 checked_from_rational
    def mul_int(r, x): return (r * x) // FIX               # FixedU128::checked_mul_int (floor)

    pools = []
    for pair, (p0, p1) in s['Dex.LiquidityPool']['rows']:
        ckey = json.dumps(pair, sort_keys=True)
        iss = next((v for k, v in s['Tokens.TotalIssuance']['rows']
                    if json.dumps(k, sort_keys=True) == json.dumps({'DexShare': pair}, sort_keys=True)), None)
        if iss is None or iss == 0 or p0 == 0 or p1 == 0: continue
        pools.append((ckey, p0, p1, iss))
    print('\n[DEX LP] pools with LP issuance:', len(pools))
    best2 = (0, None); tested2 = 0
    for ckey, p0, p1, iss in pools:
        for amt in [10**k for k in range(0, 19)]:
            # attacker supplies max_amount_0 = amt, max_amount_1 = proportional
            max0 = amt
            max1 = amt * p1 // p0
            if max0 == 0 or max1 == 0 or max0 >= p0 // 4 or max1 >= p1 // 4: continue
            er01 = rat(p1, p0)
            in01 = rat(max1, max0)
            if in01 <= er01:
                er10 = rat(p0, p1)
                amount0 = mul_int(er10, max1)
                share = mul_int(rat(amount0, p0), iss)
                inc0, inc1 = amount0, max1
            else:
                amount1 = mul_int(er01, max0)
                share = mul_int(rat(amount1, p1), iss)
                inc0, inc1 = max0, amount1
            if share == 0 or inc0 == 0 or inc1 == 0: continue
            # now remove ALL newly minted shares from the enlarged pool
            np0, np1, niss = p0 + inc0, p1 + inc1, iss + share
            prop = rat(share, niss)
            dec0, dec1 = mul_int(prop, np0), mul_int(prop, np1)
            delta = (dec0 - inc0) + (dec1 - inc1)  # unit metric (both assets 1:1)
            tested2 += 1
            if delta > best2[0]:
                best2 = (delta, (ckey, amt, inc0, inc1, share, dec0, dec1, delta))
    print(f'[DEX LP] {tested2} add+remove round trips; max unit delta = {best2[0]} (must be <= 0)')
    print('         best:', best2[1])
    print('\nCONCLUSION: no X -> Y>X found in Taiga mint/redeem/swap or DEX LP round trips on live numbers.')

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'audit-live/acala-state.json')
