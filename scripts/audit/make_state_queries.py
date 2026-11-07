#!/usr/bin/env python3
"""Generate state_queries.json (live storage inventory queries).

Pallet accounts are derived from the PalletId constants in
runtime/{acala,karura}/src/lib.rs exactly as `AccountIdConversion` does
(b"modl" ++ PalletId ++ zero-filled to 32 bytes), then SS58-encoded.
"""
import hashlib, json, sys

B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58encode(b):
    n = int.from_bytes(b, 'big')
    s = ''
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return '1' * (len(b) - len(b.lstrip(b'\x00'))) + s

def ss58(pubkey32, prefix):
    payload = bytes([prefix]) + pubkey32
    chk = hashlib.blake2b(b'SS58PRE' + payload, digest_size=64).digest()[:2]
    return b58encode(payload + chk)

def pallet_account(pid, prefix):
    assert len(pid) == 8
    return ss58((b'modl' + pid.encode()).ljust(32, b'\x00'), prefix)

PALLET_IDS = [
    'aca/trsy', 'aca/loan', 'aca/dexm', 'aca/cdpt', 'aca/cdpe', 'aca/homa',
    'aca/hztr', 'aca/hmtr', 'aca/inct', 'aca/cpot', 'aca/reve', 'aca/aNFT',
    'aca/urls', 'aca/fees', 'aca/lqcl', 'nuts/sta', 'aca/hzbg', 'aca/xNFT',
]

# full-map iterations
MAPS = [
    ('Tokens', 'TotalIssuance', 300),
    ('CdpEngine', 'DebitExchangeRate', 100),
    ('CdpEngine', 'CollateralParams', 100),
    ('Loans', 'TotalPositions', 100),
    ('Dex', 'LiquidityPool', 500),
    ('Dex', 'TradingPairStatuses', 500),
    ('Dex', 'InitialShareExchangeRates', 100),
    ('DexOracle', 'AveragePrices', 200),
    ('AggregatedDex', 'AggregatedSwapPaths', 200),
    ('Auction', 'Auctions', 200),
    ('Auction', 'AuctionEndTime', 200),
    ('AuctionManager', 'CollateralAuctions', 200),
    ('Earning', 'Ledger', 50),
    ('Homa', 'StakingLedgers', 100),
    ('StableAsset', 'Pools', 100),
    ('Prices', 'LockedPrice', 100),
    ('AcalaOracle', 'Values', 200),
    ('AssetRegistry', 'AssetMetadatas', 300),
    ('AssetRegistry', 'Erc20IdToAddress', 100),
    ('Incentives', 'IncentiveRewardAmounts', 100),
    ('Incentives', 'ClaimRewardDeductionRates', 100),
    ('Rewards', 'PoolInfos', 100),
    ('TransactionPayment', 'TokenExchangeRate', 100),
    ('TransactionPayment', 'AlternativeFeeSwapPath', 100),
    ('TransactionPayment', 'GlobalFeeSwapPath', 100),
    ('Parameters', 'Parameters', 100),
    ('EVM', 'CodeInfos', 50),
    ('Honzon', 'Authorization', 50),
]

VALUES = [
    'System.Number', 'Balances.TotalIssuance', 'CdpTreasury.DebitPool',
    'CdpTreasury.DebitOffsetBuffer', 'CdpTreasury.ExpectedCollateralAuctionSize',
    'CdpEngine.LastAccumulationSecs', 'CdpEngine.LiquidationContracts',
    'AuctionManager.TotalCollateralInAuction', 'AuctionManager.TotalTargetInAuction',
    'Homa.RelayChainCurrentEra', 'Homa.TotalStakingBonded', 'Homa.ToBondPool',
    'Homa.TotalVoidLiquid', 'Homa.UnclaimedRedemption', 'Homa.Unbondings',
    'Homa.CommissionRate', 'Homa.FastMatchFeeRate', 'Homa.EstimatedRewardRatePerEra',
    'Homa.SoftBondedCapPerSubAccount', 'StableAsset.PoolCount',
    'EmergencyShutdown.IsShutdown', 'EmergencyShutdown.CanRefund',
    'TransactionPayment.PoolSize', 'TransactionPayment.SwapBalanceThreshold',
    'TransactionPayment.NextFeeMultiplier', 'TransactionPayment.OverrideChargeFeeMethod',
    'Auction.AuctionsIndex', 'EVM.ChainId', 'EVM.NetworkContractIndex',
    'AssetRegistry.NextForeignAssetId', 'AssetRegistry.NextStableAssetId',
    'LiquidCrowdloan.RedeemCurrencyId', 'Incentives.ClaimRewardDeductionCurrency',
    'AcalaOracle.HasDispatched', 'DexOracle.AveragePrices',
]

def main():
    prefix = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    accts = {pid: pallet_account(pid, prefix) for pid in PALLET_IDS}
    q = {'pallet_accounts_ss58_prefix': prefix, 'pallet_accounts': accts,
         'maps': [{'pallet': p, 'item': i, 'max': m, 'page': 100} for p, i, m in MAPS],
         'partial_maps': [], 'values': [], 'constants': []}
    for kv in VALUES:
        p, i = kv.split('.', 1)
        q['values'].append({'pallet': p, 'item': i, 'params': None})
    # Balances.Account and System.Account for every module account (native ACA)
    for pid, addr in accts.items():
        q['values'].append({'pallet': 'Balances', 'item': 'Account', 'params': [addr], 'tag': pid})
        q['values'].append({'pallet': 'System', 'item': 'Account', 'params': [addr], 'tag': pid})
        q['partial_maps'].append({'pallet': 'Tokens', 'item': 'Accounts', 'params': [addr],
                                  'tag': pid, 'max': 100, 'page': 100})
    q['constants'] = [
        {'pallet': 'CdpEngine', 'item': 'DefaultDebitExchangeRate'},
        {'pallet': 'CdpEngine', 'item': 'DefaultLiquidationRatio'},
        {'pallet': 'CdpEngine', 'item': 'MinimumDebitValue'},
        {'pallet': 'Dex', 'item': 'GetExchangeFee'},
    ]
    out = 'scripts/audit/state_queries.json'
    json.dump(q, open(out, 'w'), indent=1)
    print('wrote', out)
    for pid, addr in accts.items():
        print(pid, addr)

if __name__ == '__main__':
    main()
