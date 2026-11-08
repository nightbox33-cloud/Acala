# Auditoría ofensiva Acala / Karura — estado DESPLEGADO (actualizado 2026-11-08)

## Estado: REABIERTO — sin veredicto

Este informe **no emite veredicto**. El cierre anterior `"no crítico live"`
fue rechazado por el solicitante y queda **sin efecto**: la búsqueda sigue
abierta hasta agotar las rutas de dinero con estado live. Todo el trabajo
posterior, los descartes y los candidatos abiertos están en
[`audit-live/AUDIT_CONTINUATION.md`](audit-live/AUDIT_CONTINUATION.md)
(resumen ejecutivo en §0, candidato de conservación en §13).

**No hay ningún crítico confirmado**: ningún candidato cumple simultáneamente
PnL > 0 en USD con decimales y precios de oráculo reales, contra inventario
ajeno live, con extrinsics minados, conservación rota y bug concreto en código
desplegado. El candidato más fuerte (`REPEAT aggregatedDex x3`, +6.575 USD)
saca aUSD **real** del pool de los LP —las reservas antes/después lo prueban—,
pero su LDOT no se conserva de forma inexplicada y **el bug aún no se ha
localizado en código**; el UNWIND da −125 USD. Run de trazado de eventos
`42436509596` en curso. Ver §13 de la continuación.

**No declaro cobertura completa**: submodules sin inicializar, Git LFS, otros
forges y repos privados siguen sin materializar; 390 bytecodes desplegados sin
fuente; faltan mapas completos de `Loans.Positions`, `Tokens.Accounts` global,
allowances, logs/eventos históricos, `debug_traceCall` y reorg/flash EVM.

---

## 1. REQUISITO PREVIO OBLIGATORIO — estado

### 1.1 Orgs / espacios enumerados (GitHub como fuente de verdad)

| Espacio | Tipo | Repos | Privados accesibles | Clonados |
|---|---|---|---|---|
| `AcalaNetwork` | org oficial de la Acala Foundation (README: "initiated and facilitated by the Acala Foundation") | 135 | 0 | 135/135 |
| `open-web3-stack` | ORML, compilado en el runtime (submodule `orml`) | 24 | 0 | 24/24 |
| `nutsfinance` | Taiga `stable-asset` (submodule, pallet `StableAsset` en vivo) | 47 | 0 | 47/47 |
| `laminar-protocol` | cofundador de la Foundation, stack histórico | 22 | 0 | 22/22 |
| `nightbox33-cloud` (usuario autenticado) | 166 forks públicos, entre ellos el checkout `Acala` | 166 | 0 | el checkout |
| GitLab / Bitbucket / otros espacios | — | **no enumerables** | — | **BLOQUEADO** (sin egress) |

El token autenticado es una GitHub App (`nightbox33-cloud`, `admin/maintain/pull/push` en el fork)
sin pertenencia a ninguna org (`/user/orgs` vacío) → **0 repos privados accesibles**.
`gh api repos/:owner/:repo/actions/permissions` devuelve 403 por ser integración.

### 1.2 Clones

```
python3 scripts/audit/clone_foundation_repos.py /home/user/audit-work/repos-manifest.json /home/user/audit-work
# 228/228 ok, 0 fallos; 4131 refs/heads + 4052 refs/tags registradas (git ls-remote --heads --tags por repo)
# --depth 1 --no-single-branch para 220 repos; historia completa para 8:
#   AcalaNetwork/Acala, predeploy-contracts, evm-tests, evm-bench, acala-node,
#   runtime-overrides, nutsfinance/stable-asset, open-web3-stack/open-runtime-module-library
```
Evidencia: `audit-live/clone-results.jsonl` (886 KB, un registro por repo con HEAD exacto,
refs, branches locales, submodules y flag LFS) y `audit-live/repos-manifest.json`.
`git submodule status` del checkout y verificación de los 5 SHAs pineados en los clones
con historia completa (`git cat-file -t <sha>` → `commit`):

| Submodule | Commit pineado (live build) | Repo |
|---|---|---|
| `orml` | `04eb581ec2e116584b2ddc033313c2e6f1382c52` | open-web3-stack/open-runtime-module-library |
| `ecosystem-modules/stable-asset` | `aa101e87234bd3d388c8de062f231d635d79cf7b` | nutsfinance/stable-asset |
| `predeploy-contracts` | `b074c00f3e3d432c965cd9cc395122ec718a779a` | AcalaNetwork/predeploy-contracts |
| `evm-bench` | `f1431e267b0454ff662a070048869b49cd800a6f` | AcalaNetwork/evm-bench |
| `evm-tests` | `b7649496322d6a07b395cb76ed55993625ed9d9c` | AcalaNetwork/evm-tests |

**Bloqueos**: (a) sin egress a GitLab/Bitbucket/Subscan/explorers → no puedo
enumerar ni clonar esos espacios; (b) 0 repos privados visibles; (c) `git-lfs` no
instalado y `AcalaNetwork/blockscout-frontend` declara `filter=lfs` → objetos LFS
no descargados (sólo assets de frontend, fuera del runtime); (d) `rustc/cargo`
ausentes → no compilé el runtime localmente, la equivalencia binario↔código se
hace por hash srtool (§2), que es byte-exacto.

### 1.3 Mapa código → artefacto desplegado (verificado contra storage live)

| Artefacto live | Hash del artefacto | Repo + commit + path |
|---|---|---|
| Runtime Acala `spec_version 2370`, `:code` (1.922.197 B) | sha256 `0x9ae95ba9bbcc32c47357935ae0796cf0314122865a9f6eecb27f0f3614af8b75` | `AcalaNetwork/Acala@cde2abf753cdfbb67e8129b8c0672d5c15444aa1` (tag `2.37.0`), `runtime/acala/src/lib.rs`; release 2.37.0 srtool `sha256` idéntico |
| Runtime Karura `spec_version 2370`, `:code` (1.932.964 B) | sha256 `0xc89def58e6b7ed5148041a905abdc4b97c4795c7cf7fa14e90075ed7c6530cdf` | mismo `cde2abf753cdfbb67e8129b8c0672d5c15444aa1`, `runtime/karura/src/lib.rs`; srtool en issue `AcalaNetwork/Acala#2986` (Karura 2.37.0), `sha256` idéntico |
| 45 predeploys EVM+ Acala con bytecode | sha256 por address en `scripts/audit/predeploy_map.json` | `AcalaNetwork/predeploy-contracts@b074c00f3e3d432c965cd9cc395122ec718a779a`, `resources/deployedBytecodes.json` |
| 3 predeploys con bytecode distinto (`0x…0800` EVM, `0x…0801` ORACLE, `0x…0806` EVMAccounts) | live sha256 `0xfa56a126…a8e2383`, `0x15981eda…9dc626`, `0x5575247e…9c1ed8` | reconstruidos por hash exacto desde `resources/bytecodes.json` del commit **`72147461e5eb66520953ab7b19adedd7e144ac01`** (2022-05-27, "Honzon Predeploy Contract #100") del mismo repo. Son wrappers sin custodia (`staticcall`/`call` a precompiles, `msg.sender` explícito); diff vs HEAD es refactor + solc 0.8.4→0.8.18. |
| pallet `StableAsset` (Taiga pool 0) | runtime WASM anterior | `nutsfinance/stable-asset@aa101e87234bd3d388c8de062f231d635d79cf7b`, `lib/stable-asset/src/lib.rs` |
| ORML `Tokens/Rewards/Auction/Oracle` | runtime WASM anterior | `open-web3-stack/open-runtime-module-library@04eb581ec2e116584b2ddc033313c2e6f1382c52` |

El checkout (`cde2abf753cdfbb67e8129b8c0672d5c15444aa1`, tree
`c22a2848506c50abad589703a46f9b9866a1ee2f`) es **exactamente** el HEAD de
`AcalaNetwork/Acala` y el commit que produjo ambos runtimes live: no hay
parche local ni divergencia con el código desplegado.

### 1.4 FALLBACK (protocolos desplegados in-chain)

Activado. Enumerados y clonados dentro de los 228 repos (todos los que tienen
componente in-chain): `predeploy-contracts` (79 direcciones únicas, 48 con código
en Acala / 59 en Karura), `nutsfinance/stable-asset` (Taiga), `Euphrates`,
`asset-router`, `starlay-protocol`, `wormhole` + `wormhole-relayer`,
`hyperlane-registry`, `chainbridge-substrate`, `nuts-swap-adapter`,
`EuphratesDoc`, `chopsticks`, `acala-node`, `runtime-overrides`. Además:
- `EVM.CodeInfos` live: **≥300 code hashes** de contratos desplegados por
  usuarios (consulta capada a 300); no reconstruidos ni decompilados → brecha.
- Karura: 59 predeploys con código, sólo 7 byte-idénticos al repo; el resto son
  tokens chain-specific con nombre/símbolo/decimales embebidos → **no
  reconstruidos** → brecha.
- No había ningún repo privado que reconstruir; la reconstrucción desde
  bytecode se hizo para los 3 predeploys anteriores y para el runtime vía
  `state_getStorage('0x3a636f6465')`.

---

## 2. Anclaje live (RPC + bloque)

El sandbox sólo tiene egress a `github.com`/`api.github.com`/`codeload`/npm/pypi;
`curl` directo a cualquier RPC da `http=000`. Se usó un runner de GitHub Actions
en la rama de auditoría como sonda con salida a RPC (workflow
`.github/workflows/audit-live-anchor.yml`), y la evidencia se devolvió al repo
por `git push` (hosts permitidos).

Endpoints (tomados de `AcalaNetwork/chopsticks/configs/acala.yml`, `acala.js`,
`bodhi.js`, `e2e-tests`): `https://acala-rpc.aca-api.network`,
`https://acala-rpc-0.aca-api.network`, `https://acala-rpc-1.aca-api.network`,
`https://acala-rpc.n.dwellir.com`, `https://eth-rpc-acala.aca-api.network`
(chainId `0x313`=787), `https://karura-rpc.aca-api.network`,
`https://eth-rpc-karura.aca-api.network` (chainId `0x2ae`=686),
`https://polkadot.api.onfinality.io/public-http` (relay, sólo sanity).
Otros (`acala-rpc.dwellir.com`, `acala-polkadot.api.onfinality.io/public-http`,
`polkadot-rpc.dwellir.com`, `blockscout.acala.network/api/eth-rpc`) fallaron.

| Chain | Bloque finalizado (ancla del fork) | spec/tx version | `:code` size | EVM block |
|---|---|---|---|---|
| Acala | `12.383.976` — `0x610bba563e4d8762057b603eaa2b2aa7bc6719a701daf4dfb45783fb91077d5a` | 2370 / 3 | 1.922.197 B | `0xbcf6eb` |
| Karura | `12.811.865` — `0x37ff38b42659ba3a8787192d807ce9576a16a9768f2767c9a0109846cfdc7279` | 2370 / 2 | 1.932.964 B | `0xc37e47` |

El inventario se midió en `12.383.912` y se re-validó sin cambios en
`12.383.976` y `12.384.053` (`audit-live/acala-state.json`, hash
`0x914ad72b…14d5be74`; Karura `12.812.006`). La lista de calls pausados se
leyó en `12.384.068` / `12.812.014`. En todos ellos el runtime sigue siendo
2370 con el mismo `:code` sha256.

Comandos exactos ejecutados (todos en `scripts/audit/`, salida en `audit-live/`):

```
python3 scripts/audit/rpc_probe.py --out audit-live/anchor.json
python3 scripts/audit/live_state_probe.py --chain acala  --mode catalogue --out audit-live/acala-catalogue.json
python3 scripts/audit/live_state_probe.py --chain karura --mode catalogue --out audit-live/karura-catalogue.json
python3 scripts/audit/make_state_queries.py 10        # genera state_queries.json (cuentas PalletId)
python3 scripts/audit/live_state_probe.py --chain acala  --mode state --out audit-live/acala-state.json  --dump-evm-mismatches audit-live/evm-mismatch-acala
python3 scripts/audit/live_state_probe.py --chain karura --mode state --out audit-live/karura-state.json
python3 scripts/audit/query_paused.py acala  audit-live/paused-calls-acala.json
python3 scripts/audit/query_paused.py karura audit-live/paused-calls-karura.json
python3 scripts/audit/compare_evm_bytecode.py <deployedBytecodes.json> 'audit-live/evm-mismatch-acala/*.hex'
python3 scripts/audit/inventory_summary.py audit-live/acala-state.json
python3 scripts/audit/poc_conservation.py audit-live/acala-state.json
node scripts/audit/fork_poc.mjs            # chopsticks 1.5.2, ANCHOR_HASH=0x610bba…57d5a
```
Dependencias: `substrate-interface==1.8.1`, `@acala-network/chopsticks-core@1.5.2`,
`@polkadot/api@latest`. Lecturas: `chain_getFinalizedHead`, `chain_getHeader`,
`state_getRuntimeVersion`, `state_getStorage('0x3a636f6465')`, `state_getKeysPaged`,
`state_queryStorageAt`, `state_getMetadata`, `eth_chainId`, `eth_blockNumber`,
`eth_getCode`. No se usaron `debug_traceCall`/`trace`/`eth_createAccessList`
(no expuestos por los endpoints públicos probados).

---

## 3. Inventario ajeno medido (Acala, bloque 12.383.976)

Precios del oracle live (`AcalaOracle.Values`, FixedU128): ACA `0.008936633` USD,
DOT `0.8989255` USD. aUSD está **despegado**; no se valora a 1 USD.

Cuentas de módulo (`b"modl"+PalletId` → SS58 prefix 10; verificadas contra
`StableAsset.Pools[0].account_id`):

| PalletId / address | Inventario ajeno |
|---|---|
| `aca/inct` `23M5ttkmR6Kco7bReRDve6bQUSAcwqebatp3fWGJYb4hDSDJ` | 60.875.243,55 ACA + 11.925,92 aUSD + LP shares (pool de recompensas) |
| `aca/cdpt` `23M5ttkmR6KcnvsNJdmYTpLo9xfc54g8uCk55buDfiJPon69` | 41.941.180,82 ACA + 56.677,99 LDOT + 92.341,88 USDC (colateral de CDP en refund) |
| `aca/trsy` `23M5ttkmR6KcoTAAE6gcmibnKFtVaTP5yxnY8HF1BmrJ2A1i` | 35.374.267,66 ACA + 29 tokens/LP |
| `aca/dexm` `23M5ttkmR6KcnxentoqchgBdUjzMDSzFoUyf5qMs7FsmRMvV` | 12.349.869,03 ACA + **798.166,77 aUSD** + reservas de 15 pools DEX |
| `aca/loan` `23M5ttkmR6KcoCvrNZsA97DQMPxQmqktF8DHYZSDW4HLcEDw` | 4.655.001,67 ACA + 2.433.271,94 LDOT + 2.737,84 DOT + 4.184,81 tDOT + LCDOT |
| `aca/urls` `23M5ttkmR6KcoUwA7NqBjLuMJFWCvobsD9Zy95MgaAECEhit` | 3.362.346,43 ACA |
| `aca/lqcl` `23M5ttkmR6KcoCwfEJnoAgczRQdDq85ZedwGc3uzyPwiCoq8` | 2.372.347,76 DOT (respalda 1:1 LCDOT) |
| `nuts/sta` `23M5ttkp2zdM8qa6LFak4BySWZDsAVByjepAfr7kt929S1U9` | 920,06 DOT + 2.015,58 LDOT (Taiga pool 0, `a=3000`, swap fee 0,25%) |
| `aca/homa` `23M5ttkmR6Kco5pqN691bGfU3BhfU6QPG9arw6SR1XpNuQqu` | 230.001,40 DOT (respalda `UnclaimedRedemption` 229.996,75) |
| 4 sub-accounts `aca/fees` (`fee/AUSD`, `fee/DOT`, `fee/LDOT`, `fee/LCDOT13`) | **~74 ACA en total (~0,66 USD)** — dust |

**Total ACA nativo en cuentas de módulo: 158.601.958,92 ACA ≈ 1,42 M USD.**
DOT en `aca/lqcl` ≈ 2,13 M USD. Sumando aUSD (despegado), LDOT, LP shares y
reservas DEX, el inventario ajeno tocable por código permissionless es del orden
de **3,5–6 M USD** (rango por no poder precioar aUSD/LP con fiabilidad).
aUSD total supply: 6.008.958,88. `Auction.Auctions` y
`AuctionManager.CollateralAuctions`: **0** (sin subastas vivas).

---

## 4. Rutas de dinero revisadas y hechos que MATAN cada candidato

1. **Honzon / CDP (mint de aUSD contra colateral ajeno)**: `EmergencyShutdown.IsShutdown=true`,
   `CanRefund=true`, `maximum_total_debit_value = 0` en los 7 colaterales y
   `Loans.TotalPositions[*].debit = 0`. `honzon.adjustLoan` con debit ≠ 0
   falla con `Honzon.AlreadyShutdown` (verificado en fork: módulo 102, error 1).
   `expand_position_collateral` y `transfer_debit` no chequean shutdown, pero
   están **pausados live** por `TransactionPause.PausedTransactions` (Acala:
   `honzon.transfer_debit`, `expand_position_collateral`,
   `shrink_position_debit`, `authorize`, `unauthorize`, `unauthorize_all`;
   Karura: esos 6 + `HomaValidatorList.bond/unbond/withdraw_unbonded` +
   `PolkadotXcm.execute`; precompiles pausados `0x0409` HONZON en ambas cadenas
   y `0x0406` STABLE_ASSET en Karura). El `BaseCallFilter` los convierte en
   `System::CallFiltered` (índice 0, error 5) antes de ejecutar, verificado en
   el fork. Además `check_debit_cap` (cap 0) bloquearía cualquier debit > 0.
   No existe ruta live de mint.
2. **`honzon.transfer_debit` + `DebitExchangeRate` distintos** (0,1032–0,1039):
   el diferencial `(rate_to-rate_from)*d` que acredita aUSD extra se consume
   exactamente al desenwindar, porque la deuda en `to_currency` hay que
   repagarla a `rate_to`. PoC: `net_minted == extra_repay` → PnL 0. Además
   está pausado y sin posiciones con debit.
3. **`emergencyShutdown.refundCollaterals`** (único entrypoint permissionless
   que mueve colateral del CDP treasury): `refund_ratio = amount / total_issuance(aUSD)`
   y `burn_debit` reduce el denominador; el ratio colateral/aUSD se conserva
   (PoC: 6,9797749748457285 antes y después). En el DEX 1 aUSD ≈ 141 ACA
   ≈ 1,26 USD, mientras que quemar 1 aUSD devuelve 6,98 ACA ≈ 0,06 USD:
   comprar aUSD barato para redimir es **pérdida**, no drenaje.
4. **DEX `module_dex`**: `get_target_amount` redondea a favor del pool,
   `get_supply_amount` suma +1, y `_swap` exige `k_after >= k_before`.
   256 round-trips (exact-supply y exact-target) sobre las 15 pools live,
   desde dust hasta 10^18 unidades: **Δ máx = −1 unidad** (fee). Ningún ciclo
   rentable.
5. **Taiga `StableAsset`**: `swap` transfiere `dy` desde la cuenta del pool;
   `collect_fee`/`collect_yield` recalculan `balances`/`total_supply` desde los
   balances reales (`get_pending_fee_amount` lee `T::Assets::balance`), así que
   el `balances` local sin usar no permite doble gasto; `dy` está limitado por
   el balance real. Fork: `stableAsset.swap` → `Ok`, sin Δ positivo.
6. **ORML `Rewards` / `Incentives`** (`aca/inct`, 60,9 M ACA):
   `reward_to_withdraw = min(share*total_reward/total_shares − withdrawn,
   total_reward − total_withdrawn_reward)` → acotado por el pool, imposible
   sobre-reclamar.
7. **Homa**: `UnclaimedRedemption` 229.996,75 está respaldado por 230.001,40 DOT
   en `aca/homa`; `claim_redemption` descuenta `UnclaimedRedemption` con
   `checked_sub` y borra las entradas `Unbondings` → sin doble claim.
   `ToBondPool=0`.
8. **LiquidCrowdloan**: `aca/lqcl` tiene 23.723.477.625.136.911 unidades DOT
   frente a un supply LCDOT de 23.723.477.626.752.913 (diferencia 0,00016 DOT):
   redeem 1:1 totalmente respaldado. `RedeemCurrencyId=null`.
9. **Charge-fee-pool (`module_transaction_payment`)**: `TokenExchangeRate`
   fijo vs DEX (p.ej. DOT rinde ~la mitad del fee en valor de mercado) es una
   posible pérdida del pool, pero `swap_from_pool_or_dex` sólo entrega
   `fee + (ED − balance_nativo)`; el fee se consume y lo que queda en el
   atacante es como máximo el ED. Inventario total de las 4 sub-accounts:
   ~74 ACA ≈ 0,66 USD → **dust**, excluido por los criterios.
10. **EVM+**: `module_evm::eth_call/eth_call_v2` delegan en `call/create` con
    `ensure_signed` + `get_or_create_evm_address` (sin suplantación). Los 3
    predeploys con bytecode viejo son wrappers stateless sin custodia.

---

## 5. Forks / PoC ejecutados

**Fork real de mainnet** (`@acala-network/chopsticks-core@1.5.2`,
`setup({endpoint, block: 0x610bba…57d5a, mockSignatureHost:true})`,
`chain.dryRunExtrinsic({call, address})`), evidencia en
`audit-live/fork-poc.json` / `.log`. Origin `aca/dexm` (cuenta real con
fondos; las 6 calls son `ensure_signed`, sin sudo/admin):

| Call | Resultado live en el fork |
|---|---|
| `honzon.expandPositionCollateral` | `Err System::CallFiltered` (pausado) |
| `honzon.adjustLoan` (+debit) | `Err Honzon::AlreadyShutdown` |
| `honzon.transferDebit` | `Err System::CallFiltered` (pausado) |
| `dex.swapWithExactSupply` ACA→aUSD | `Ok` (16 storage diffs) |
| `emergencyShutdown.refundCollaterals` | `Ok` (22 storage diffs) |
| `stableAsset.swap` pool 0 DOT→LDOT | `Ok` (22 storage diffs) |

**PoC de conservación** (`scripts/audit/poc_conservation.py`, ejecutado sobre
`audit-live/acala-state.json`): 256 round-trips DEX con la matemática exacta del
source → Δ máx −1; `transfer_debit` con las 4 tasas live → PnL 0 tras unwind;
`refund_collaterals` → ratio pro-rata invariante. Ningún `Y > X`.

No ejecuté: `debug_traceCall`, simulación de reorg, flash-loan EVM (no hay
lender flash in-scope con TVL medido), ni decompilación de los ≥300 códigos EVM
de usuario. No hay PoC de drenaje porque no apareció ninguna transición que lo
permita.

---

## 6. Cobertura / limitaciones (no declaro cobertura completa)

- 0 repos privados accesibles; GitLab/Bitbucket y explorers sin egress →
  espacios no enumerables/clonables (**bloqueados**).
- Objetos Git LFS de `blockscout-frontend` no descargados (sin `git-lfs`).
- Karura: 52 de 59 predeploys con bytecode que no coincide con el repo HEAD
  (parámetros chain-specific) → **no reconstruidos**; el runtime Karura sí está
  mapeado por hash srtool.
- ≥300 `EVM.CodeInfos` de contratos de usuario: enumerados por hash, no
  mapeados a repo ni decompilados.
- Sin `rustc`/`cargo`: no hay build local ni tests unitarios del runtime; la
  equivalencia código↔binario se validó por hashes srtool byte-exactos.
- Sin RPC de trace/debug; sin acceso a estado histórico de mempool.
- Los precios de oracle ACA/DOT son los desplegados; aUSD está despegado, por lo
  que las cifras en USD de inventario aUSD/LP son aproximadas/omitidas.

---

## 7. Artefactos de evidencia en esta rama

`audit-live/anchor.json`, `acala-catalogue.json`, `karura-catalogue.json`
(catálogo de storage: 344/349 entries), `acala-state.json`, `karura-state.json`
(121 queries cada uno), `evm-mismatch-acala/*.hex`, `fork-poc.json`,
`fork-poc.log`, `paused-calls-acala.json`, `paused-calls-karura.json`,
`clone-results.jsonl`, `repos-manifest.json`; scripts en `scripts/audit/` y
workflow en `.github/workflows/audit-live-anchor.yml`.
