// Fork PoC: dry-run permissionless money-path calls against a chopsticks fork of
// Acala mainnet at the exact anchored block (runtime spec_version 2370).
// It records dispatch outcomes + storage-diff sizes. No admin/sudo origin is used:
// mockSignatureHost only lets us choose a signed `address` without its key.
import { setup } from '@acala-network/chopsticks-core'
import { ApiPromise, HttpProvider } from '@polkadot/api'
import fs from 'node:fs'

const endpoint = 'https://acala-rpc.aca-api.network'
const blockHash = process.env.ANCHOR_HASH
const outPath = process.env.OUT || 'audit-live/fork-poc.json'
const out = { endpoint, blockHash, runtime: 'forked live Acala mainnet', tests: [] }

const log = (...a) => console.log(...a)

try {
  log('setting up chopsticks fork at', blockHash)
  const chain = await setup({ endpoint, block: blockHash, mockSignatureHost: true, runtimeLogLevel: 1 })
  const api = await ApiPromise.create({ provider: new HttpProvider(endpoint), noInitWarn: true })
  await api.isReady
  log('fork ready; runtime', api.runtimeVersion.specVersion.toString())

  // `aca/dexm` module account: real, funded account at the anchor block (holds ACA + aUSD).
  // It is NOT an admin origin: these calls are all `ensure_signed` permissionless entrypoints.
  const ADDR = '23M5ttkmR6KcnxentoqchgBdUjzMDSzFoUyf5qMs7FsmRMvV'

  const DOT = { Token: 'DOT' }
  const ACA = { Token: 'ACA' }
  const AUSD = { Token: 'AUSD' }
  const tests = [
    ['honzon.expandPositionCollateral (attempt to mint aUSD during shutdown)',
      api.tx.honzon.expandPositionCollateral(DOT, '1000000000000', '0')],
    ['honzon.adjustLoan (attempt to increase debit during shutdown)',
      api.tx.honzon.adjustLoan(DOT, '0', '1000000000000')],
    ['honzon.transferDebit (attempt to move debit across collateral types)',
      api.tx.honzon.transferDebit(DOT, ACA, '1000000000000')],
    ['dex.swapWithExactSupply ACA->aUSD (permissionless swap)',
      api.tx.dex.swapWithExactSupply([ACA, AUSD], '1000000000000', '0')],
    ['emergencyShutdown.refundCollaterals (permissionless final redemption)',
      api.tx.emergencyShutdown.refundCollaterals('1000000000000')],
    ['stableAsset.swap pool 0 DOT->LDOT (Taiga)',
      api.tx.stableAsset.swap(0, 0, 1, '10000000000', '0', 2)],
  ]

  for (const [name, tx] of tests) {
    const call = tx.method.toHex()
    try {
      const { outcome, storageDiff } = await chain.dryRunExtrinsic({ call, address: ADDR })
      const human = outcome.toHuman()
      const json = outcome.toJSON()
      out.tests.push({ name, call, outcome: human, outcomeJson: json, storageDiffEntries: storageDiff.length })
      log(name, '=>', JSON.stringify(human).slice(0, 400))
    } catch (e) {
      out.tests.push({ name, call, error: String(e) })
      log(name, 'ERROR', String(e))
    }
  }
  await api.disconnect()
} catch (e) {
  out.setup_error = String(e)
  out.setup_stack = e?.stack
  log('setup ERROR', String(e))
}

fs.writeFileSync(outPath, JSON.stringify(out, null, 1))
log('wrote', outPath)
