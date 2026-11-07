#!/usr/bin/env python3
"""Summarise the third-party inventory that permissionless code can move,
from the live state snapshot. Prices are the LIVE oracle values (FixedU128,
1e18 = 1 USD). aUSD is deliberately NOT priced at $1 (it is depegged); only
ACA/DOT oracle prices are used for a rough USD figure.
"""
import json, sys

def cname(c):
    if 'Token' in c: return c['Token']
    if 'ForeignAsset' in c: return 'FA' + str(c['ForeignAsset'])
    if 'Erc20' in c: return 'ERC20:' + c['Erc20'][:10]
    if 'StableAssetPoolToken' in c: return 'tDOT'
    if 'LiquidCrowdloan' in c: return 'LCDOT' + str(c['LiquidCrowdloan'])
    if 'DexShare' in c: return 'LP(' + ','.join(cname(x) for x in c['DexShare']) + ')'
    return str(c)

def main(path):
    st = json.load(open(path)); s = st['storage']
    prices = {cname(k): v['value'] / 1e18 for k, v in s['AcalaOracle.Values']['rows']}
    print('live oracle USD prices:', prices)
    p_aca, p_dot = prices.get('ACA', 0), prices.get('DOT', 0)
    accounts = s['_pallet_accounts']
    print('\n=== pallet/module accounts (native ACA from System.Account, tokens from Tokens.Accounts) ===')
    total_aca = 0
    for pid, addr in accounts.items():
        a = s.get('System.Account#' + pid, {})
        free = a.get('data', {}).get('free', 0) if isinstance(a, dict) else 0
        toks = s.get('Tokens.Accounts#' + pid, {}).get('rows', [])
        if free or toks:
            print(f'  {pid:10s} {addr}  ACA={free/1e12:,.2f}  tokens=' +
                  ', '.join(f'{cname(c)}={v["free"]}' for c, v in toks))
        total_aca += free / 1e12
    print(f'  TOTAL native ACA in these module accounts: {total_aca:,.2f} ACA ~= ${total_aca*p_aca:,.0f} (ACA oracle {p_aca})')
    print('\n=== DEX liquidity pools (live reserves) ===')
    for pair, (p0, p1) in s['Dex.LiquidityPool']['rows']:
        print(f'  {cname(pair[0]):22s} {p0:>28d}   {cname(pair[1]):22s} {p1:>28d}')
    print('\n=== StableAsset (Taiga) pool 0 ===')
    print(' ', json.dumps(s['StableAsset.Pools']['rows'][0][1], indent=1))
    print('\n=== CDP / Homa / LiquidCrowdloan ===')
    for k in ['Loans.TotalPositions', 'CdpTreasury.DebitPool', 'CdpTreasury.DebitOffsetBuffer',
              'EmergencyShutdown.IsShutdown', 'EmergencyShutdown.CanRefund',
              'Homa.TotalStakingBonded', 'Homa.UnclaimedRedemption', 'Homa.ToBondPool',
              'Auction.Auctions', 'AuctionManager.CollateralAuctions']:
        print(f'  {k}: {json.dumps(s.get(k))[:500]}')
    print('\n=== aUSD supply ===')
    print(' ', next(v for k, v in s['Tokens.TotalIssuance']['rows'] if k == {'Token': 'AUSD'}))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'audit-live/acala-state.json')
