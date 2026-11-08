// Live-mainnet fork PoC with ACCUMULATED state and PnL measurement.
//
// chopsticks 1.5.2 setupWithServer, forked at the exact anchored block.
// A fresh attacker account is funded with capital X via dev_setStorage (the
// attacker's own starting capital, NOT an admin privilege: every tested call
// is an `ensure_signed` permissionless extrinsic). Extrinsics are fake-signed
// exactly as chopsticks-core's dryRunExtrinsic does (0xdeadbeef + 0xcd*60)
// and mined with dev_newBlock({transactions:[hex]}), so state accumulates.
// We measure the attacker's full balance vector before/after each sequence.
import { setupWithServer, fetchConfig } from '@acala-network/chopsticks'
import { ApiPromise, WsProvider, Keyring } from '@polkadot/api'
import fs from 'node:fs'

const ANCHOR = process.env.ANCHOR_HASH
const OUT = process.env.OUT || 'audit-live/fork-fuzz.json'
const YAML = '/tmp/acala-fuzz-fork.yml'
fs.writeFileSync(YAML, `endpoint: https://acala-rpc.aca-api.network
mock-signature-host: true
build-block-mode: Manual
block: '${ANCHOR}'
`)

const CURRENCIES = {
  AUSD: { token: 'AUSD' }, DOT: { token: 'DOT' }, LDOT: { token: 'LDOT' },
  LCDOT: { liquidCrowdloan: 13 }, tDOT: { stableAssetPoolToken: 0 },
  FA3: { foreignAsset: 3 }, FA12: { foreignAsset: 12 }, FA20: { foreignAsset: 20 },
}
const PRICE = { ACA: 1n, AUSD: 141n, DOT: 100n, LDOT: 49500n, LCDOT: 100n,
                tDOT: 100n, FA3: 1n, FA12: 1n, FA20: 1n }

const out = { anchor: ANCHOR,
              note: 'capital X via dev_setStorage (attacker capital, no admin); all calls ensure_signed; fake-signed extrinsics mined with dev_newBlock',
              scenarios: [], errors: [] }
const log = (...a) => console.log(...a)

function decodeError(d, api) {
  try {
    if (d.isModule) { const m = api.registry.findMetaError(d.asModule); return `${m.section}::${m.name}` }
    return d.toString()
  } catch { return String(d) }
}

async function main() {
  let ctx, api
  try {
    ctx = await setupWithServer(await fetchConfig(YAML))
    log('fork server', ctx.addr)
    api = await ApiPromise.create({ provider: new WsProvider(`ws://${ctx.addr}`, 3000), noInitWarn: true })
    await api.isReady
    log('fork runtime', api.runtimeVersion.specVersion.toString())

    const keyring = new Keyring({ type: 'ed25519', ss58Format: 10 })
    const A = keyring.addFromUri('//AcalaAuditAttacker')
    const X = 10n ** 18n
    const storage = { System: { Account: [[[A.address], { providers: 1, data: { free: X.toString() } }]] },
                      Tokens: { Accounts: [] } }
    for (const cur of Object.values(CURRENCIES)) {
      storage.Tokens.Accounts.push([[A.address, cur], { free: X.toString(), reserved: 0, frozen: 0 }])
    }
    try {
        await api.rpc.provider.send('dev_setStorage', [storage])
        log('funded attacker (ACA + all tokens)', A.address)
    } catch (e) {
        out.errors.push({ where: 'dev_setStorage_full', error: String(e) })
        log('dev_setStorage full failed, falling back:', String(e).slice(0, 200))
        try {
            await api.rpc.provider.send('dev_setStorage', [
                { System: { Account: [[[A.address], { providers: 1, data: { free: X.toString() } }]] } }])
            log('funded attacker (native only)', A.address)
        } catch (e2) { log('native funding failed', String(e2).slice(0, 200)) }
        for (const cur of Object.values(CURRENCIES)) {
            try {
                await api.rpc.provider.send('dev_setStorage', [
                    { Tokens: { Accounts: [[[A.address, cur], { free: X.toString(), reserved: 0, frozen: 0 }]] } }])
            } catch (e3) { /* record but continue */ }
        }
    }

    const bal = async () => {
      const sys = await api.query.system.account(A.address)
      const r = { ACA: BigInt(sys.data.free.toString()) }
      for (const [name, cur] of Object.entries(CURRENCIES)) {
        try { const v = await api.query.tokens.accounts(A.address, cur)
              r[name] = BigInt(v.free.toString()) } catch { r[name] = 0n }
      }
      return r
    }
    const val = b => Object.entries(b).reduce((s, [k, v]) => s + v * (PRICE[k] || 0n), 0n)
    const deltas = (a, b) => Object.fromEntries(Object.keys(b).map(k => [k, (b[k] - a[k]).toString()]))

    let seq = 0
    const genesis = await api.rpc.chain.getBlockHash(0)
    const send = async (tx, label) => {
      try {
        const head = await api.rpc.chain.getBlockHash()
        const acc = await api.query.system.account(A.address)
        const nonce = Number(acc.nonce.toString())
        const call = api.registry.createType('Call', tx.method.toU8a())
        const generic = api.registry.createType('GenericExtrinsic', call)
        generic.signFake(A.address, {
          blockHash: head, genesisHash: genesis, runtimeVersion: api.runtimeVersion, nonce,
        })
        const sig = new Uint8Array(64); sig.fill(0xcd); sig.set([0xde, 0xad, 0xbe, 0xef])
        generic.signature.set(sig)
        const hex = generic.toHex()
        seq++
        await api.rpc.provider.send('dev_newBlock', [{ transactions: [hex] }])
        let failure = null
        try {
          const evs = await api.query.system.events()
          for (const { event } of evs) {
            if (event.section === 'system' && event.method === 'ExtrinsicFailed') {
              failure = decodeError(event.data[0], api)
            }
          }
        } catch (e) { /* events unavailable; outcome unknown */ }
        return { ok: failure === null, error: failure, nonce }
      } catch (e) { return { ok: false, error: String(e) } }
    }

    const scenarios = [
      ['control: self transfer 1e12 ACA', () => [api.tx.balances.transfer(A.address, 10n ** 12n)]],
      ['stableAsset.mint(DOT,LDOT)', () => [api.tx.stableAsset.mint(0, [10n ** 13n, 10n ** 13n], 0)]],
      ['stableAsset.redeemSingle(tDOT -> LDOT)', () => [api.tx.stableAsset.redeemSingle(0, 10n ** 12n, 1, 0, 2)]],
      ['stableAsset.redeemProportion(tDOT)', () => [api.tx.stableAsset.redeemProportion(0, 10n ** 12n, [0, 0])]],
      ['stableAsset.swap DOT->LDOT then LDOT->DOT', () => [
        api.tx.stableAsset.swap(0, 0, 1, 10n ** 12n, 0, 2),
        api.tx.stableAsset.swap(0, 1, 0, 10n ** 12n, 0, 2)]],
      ['dex.addLiquidity + removeLiquidity (ACA/aUSD)', () => [
        api.tx.dex.addLiquidity({ token: 'ACA' }, { token: 'AUSD' }, 10n ** 12n, 10n ** 10n, 0, false),
        api.tx.dex.removeLiquidity({ token: 'ACA' }, { token: 'AUSD' }, 10n ** 10n, 0, 0, false)]],
      ['dex.addLiquidity + removeLiquidity (aUSD/FA3 tiny side)', () => [
        api.tx.dex.addLiquidity({ token: 'AUSD' }, { foreignAsset: 3 }, 10n ** 10n, 1000n, 0, false),
        api.tx.dex.removeLiquidity({ token: 'AUSD' }, { foreignAsset: 3 }, 1000n, 0, 0, false)]],
      ['aggregatedDex DOT->aUSD (Taiga+Dex path)', () => [
        api.tx.aggregatedDex.swapWithExactSupply(
          [{ taiga: [0, 0, 1] }, { dex: [{ token: 'LDOT' }, { token: 'AUSD' }] }],
          10n ** 12n, 0)]],
      ['transactionPayment.withFeeCurrency (aUSD)', () => [
        api.tx.transactionPayment.withFeeCurrency({ token: 'AUSD' }, api.tx.system.remark('0x'))]],
      ['transactionPayment.withFeeAggregatedPath', () => [
        api.tx.transactionPayment.withFeeAggregatedPath(
          [[{ taiga: [0, 0, 1] }, { dex: [{ token: 'LDOT' }, { token: 'AUSD' }] }]],
          api.tx.system.remark('0x'))]],
      ['homa.requestRedeem(LDOT) + fastMatchRedeems', () => [
        api.tx.homa.requestRedeem(10n ** 12n, true),
        api.tx.homa.fastMatchRedeems([A.address])]],
      ['liquidCrowdloan.redeem(LCDOT->DOT)', () => [api.tx.liquidCrowdloan.redeem(10n ** 12n)]],
      ['incentives.claimRewards(Dex ACA/aUSD pool)', () => [
        api.tx.incentives.claimRewards({ dex: { dexShare: [{ token: 'ACA' }, { token: 'AUSD' }] } })]],
      ['emergencyShutdown.refundCollaterals(aUSD)', () => [
        api.tx.emergencyShutdown.refundCollaterals(10n ** 12n)]],
      ['evmAccounts.claimDefaultAccount', () => [api.tx.evmAccounts.claimDefaultAccount()]],
      ['earning.bond(ACA)', () => [api.tx.earning.bond(10n ** 12n)]],
    ]

    for (const [name, build] of scenarios) {
      let txs = []
      try { txs = build() } catch (e) { out.scenarios.push({ name, build_error: String(e) }); continue }
      const before = await bal()
      const results = []
      for (const tx of txs) results.push(await send(tx, name))
      const after = await bal()
      const d = deltas(before, after)
      const pnl = val(after) - val(before)
      const dv = Object.values(d).map(BigInt)
      // A real drain = attacker gains in some asset while losing in NO asset.
      const allNonNegative = dv.every(x => x >= 0n)
      const anyPositive = dv.some(x => x > 0n)
      const rec = { name, calls: results, deltas: d,
                    pnl_aca_units_ranking_only: pnl.toString(),
                    all_non_negative: allNonNegative,
                    suspicious: allNonNegative && anyPositive }
      out.scenarios.push(rec)
      log(name, '=>', JSON.stringify(results).slice(0, 200), 'pnl(rank)', pnl.toString(),
          'suspicious', rec.suspicious)
    }
  } catch (e) {
    out.errors.push({ where: 'setup', error: String(e), stack: e?.stack })
    log('SETUP ERROR', String(e))
  } finally {
    try { await api?.disconnect() } catch {}
    try { await ctx?.close() } catch {}
  }
  fs.writeFileSync(OUT, JSON.stringify(out, null, 1))
  log('wrote', OUT)
}

main()
