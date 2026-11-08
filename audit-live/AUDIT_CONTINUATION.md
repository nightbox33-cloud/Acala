# Auditoría ofensiva — continuación (búsqueda REABIERTA)

**Estado: NO hay veredicto final.** El usuario corrigió el cierre anterior con
`"si hay critico sigue buscando"`. No hay crítico confirmado ni PnL > 0
demostrado hasta este punto; se siguen agotando rutas de dinero con estado live.
Este fichero registra sólo hechos que sostienen o matan un claim.

## 1. Anclas live usadas en esta continuación

| cadena | bloque | hash finalizado | runtime |
|---|---|---|---|
| Acala | 12.384.053 / 12.384.214 | `0x914ad72b86283891d97c2761fc20ae85b8686043c56e130b0413f1ff14d5be74` | `acala/2370`, `:code` sha256 `0x9ae95ba9…` |
| Karura | 12.812.006 / 12.812.154 / 12.812.162 | `0x506d7cb9792de1a911854eef570005504e0137fc992d6d0cdce288c533e04273` | `karura/2370`, `:code` sha256 `0xc89def58…` |
| fork chopsticks | 12.383.976 / `0x5cd135304191a233aca71137be2b9db9d24fdacefc20d2e9b2fa16e7e0b09ccf` | 1.5.2 | `mockSignatureHost` |

RPC: `https://acala-rpc.aca-api.network`, `https://karura-rpc.aca-api.network`,
`https://eth-rpc-acala.aca-api.network` (chainId 787), `https://eth-rpc-karura.aca-api.network` (686).
El sandbox no tiene egress a RPC: toda lectura live se ejecuta en GitHub Actions
(`.github/workflows/audit-live-anchor.yml`) y el bot publica `audit-live/*`.

## 2. Hechos que MATAN candidatos (medidos, no teoría)

1. **Taiga `redeem_single`** (`scripts/audit/poc_taiga_dex_liquidity.py`, estado #12.384.053):
   275 secuencias `mint → redeem_single/redeem_proportion/swap`. Aparece un delta
   positivo de `+849.384.840.043` unidades en el peor caso, pero
   `D(real balances)` pasa de `2.931.757.964.069.804` a
   `2.934.761.485.954.727` (**+3.003.521.884.923**): `collect_fee` mintió tDOT al
   `fee_recipient`, el invariante **subió**. Es arbitraje de rebalanceo de un pool
   desbalanceado (`[920.055.806.327.193 DOT, 2.015.580.124.107.418 LDOT]`, `a=3000`),
   no drenaje. Ninguna secuencia produjo `D_after < D_before`.

2. **DEX `add_liquidity` + `remove_liquidity`**: 180 round-trips sobre los 15 pools
   live con `FixedU128` exacto → **Δ máximo = 0**. El doble floor de
   `checked_from_rational`/`checked_mul_int` va a favor del pool.

3. **Fee-pool (`transaction-payment`)**: inventario total medido =
   `8,123565861589 + 12,683867154059 + 30,233546549252 + 22,951113824739` ACA
   ≈ **74 ACA**, más `1.017446424393 aUSD`, `0,1544100918 DOT`,
   `0,7551435306 LDOT`, `0,0899344848 LCDOT`, y `PoolSize ≤ 14,707540857191 aUSD`.
   `SwapBalanceThreshold = 2.500.000.000.000` para los 4. Un sandwich sobre el
   swap `ExactSupply(..., min_target=0)` del sub-account está acotado por ese
   inventario y por la comisión DEX `[3,1000]` → **dust**, no crítico.

4. **`EmergencyShutdown.refund_collaterals`**: el escrow repartible es
   `CDPTreasuryPalletId = aca/cdpt` (`41.941.180,82 ACA`, `56.677,99 LDOT`,
   `9,23 FA14`), **no** `aca/trsy`. `get_debit_proportion = amount / aUSD_supply`
   con `aUSD_supply = 6.008.958,88`. Valor de redención por aUSD ≈ **$0,07**
   mientras el pool DEX `ACA/aUSD` cotiza 1 aUSD = **141,26 ACA ≈ $1,26**
   (`[5.383.609.386.517.816.058, 38.112.444.872.879.135]`). Redimir es
   perdedor ~18×: no hay arbitraje rentable contra terceros.

5. **`HonzonBridge` (Karura, pallet 106)** — candidato serio de bug de unidades:
   `to_bridged`/`from_bridged` canjean `amount` **1:1 en unidades base** entre
   `Token(KUSD)` y un `Erc20` elegido por governance. Había ERC20 registrados con
   6/8/18 decimales. **Muerto por storage live**:
   `HonzonBridge.BridgedStableCoinCurrencyId = null` en el bloque 12.812.154
   (`audit-live/honzon-bridge-karura.json`) → ambas calls revierten con
   `BridgedStableCoinCurrencyIdNotSet`. Además `Tokens.Accounts#aca/hzbg` tiene
   0 filas (sin KUSD en el escrow), `EmergencyShutdown.IsShutdown = true`, y el
   ERC20 previsto `waUSD 0xe20683ad…` (`AcalaNetwork/acala.js/.../tokens.ts`)
   tiene **12 decimales**, igual que KUSD. Y `module_currencies::transfer`
   exige `get_evm_address(pallet_account)` (el PalletId `aca/hzbg` deriva
   `0x5b828c28c334ecb918a8b5405d630349940f347b` y no tiene mapping) →
   `EvmAccountNotFound`.

6. **Replay EIP-712 (`evm-accounts.claim_account`)**: el dominio incluye
   `chainId` **y** `frame_system::block_hash(0)` (genesis) y el payload incluye
   `who.encode()`. No hay replay Acala↔Karura ni robo de mapping.

7. **ORML Rewards `add_share`**: no hace reward sniping — infla
   `total_reward`/`total_withdrawn_reward` en `add_amount*total_reward/initial_total_shares`
   y acredita la misma inflación al `withdrawn_rewards` del depositante.

8. **`aggregated-dex` `ExactTarget`**: recalcula el output con
   `ExactSupply(input_amount, exact_target_amount)` y `do_aggregated_swap`
   revierte con `ensure!(output >= min_target)`. Subestimar no produce pérdida.

9. **Inventario EVM nativo** (`audit-live/evm-inventory-{acala,karura}.json`,
   muestra de 80 cuentas, truncada): Acala `58.872,47 ACA`, Karura
   `34.355,84 KAR`. Las 6 direcciones con más balance en cada cadena son
   **EOAs** (`contract_info: None`, `code_bytes: 0`), no contratos. Los 6/4
   contratos de la muestra (hasta 15.754 B) no tienen balance nativo.

## 3. Brechas que siguen abiertas (NO declarar cobertura completa)

- Prerrequisito: 228/228 repos GitHub de las 4 orgs clonados (`failed=[]`, 17G,
  8 FULL + 220 shallow). **Faltan** GitLab/Bitbucket/otros forges, inventario de
  privados/bloqueados, `git submodule update --init --recursive` real,
  `git lfs pull`, y fetch completo de refs en los 220 shallow.
- Fallback: `EVM.CodeInfos` devuelve **300 filas en Acala con cap 300** (truncado)
  y 85 en Karura; `predeploy_map.json` sólo tiene **13 bytecodes únicos** para
  101 addresses. Los ≥300 contratos de usuario (18–23 KB) **no estaban
  reconstruidos**. En curso: volcado completo de `EVM.Codes`, desensamblado con
  `pyevmasm`, y mapa `sha256 → commit/ruta/artefacto` sobre los 415 commits de
  `AcalaNetwork/predeploy-contracts` (ya validado 3/3 con los mismatches Acala).
- No hay aún `debug_traceCall`, reorg/flash EVM, inventario USD completo con
  precio de mercado (el oráculo Acala da ACA `$0,008936633` mientras cotizaciones
  externas de 2026 dan `$0,00029–0,00031`; el runtime usa el oráculo, pero el
  inventario en USD depende de la referencia), ni lista final de repos bloqueados.

## 4. Scripts y comandos ejecutados en esta continuación

```bash
python3 scripts/audit/poc_taiga_dex_liquidity.py audit-live/acala-state.json
python3 scripts/audit/probe_honzon_bridge.py audit-live/honzon-bridge-karura.json   # en CI
python3 scripts/audit/evm_inventory.py acala audit-live/evm-inventory-acala.json audit-live/evm-code-acala
python3 -m pip install --target /tmp/evmtools pyevmasm
PYTHONPATH=/tmp/evmtools python3 scripts/audit/analyze_evm_codes.py <index> <codes-dir> <out>
python3 scripts/audit/reconstruct_predeploys.py <live-codes.json> \
  /home/user/audit-work/repos/AcalaNetwork/predeploy-contracts <out.json>
ANCHOR_HASH=<hash> OUT=audit-live/fork-fuzz.json node scripts/audit/fork_fuzz.mjs
git fetch origin arena/9267cd86-acala && git rebase origin/arena/9267cd86-acala
```

El fork fuzz usa `setupWithServer` (chopsticks 1.5.2), `dev_setStorage` para el
capital X del atacante, extrinsics fake-firmadas `0xdeadbeef + 0xcd*60` igual que
`dryRunExtrinsic`, y `dev_newBlock({transactions:[hex]})` para **acumular** estado;
mide el vector completo de balances antes/después de 16 secuencias permissionless.

## 5. Volcado completo de bytecode (cerrado) y estado del fork fuzz

**`EVM.Codes` volcado sin truncar** (`audit-live/evm-codes-{acala,karura}.json`):
Acala **380** bytecodes únicos / 2.809.638 B en el bloque 12.384.301;
Karura **85** / 670.411 B en el 12.812.242; `truncated: false` en ambos,
`errors: []`. Los 465 `.hex` están en `audit-live/evm-codes-*/`.

- Mapa `sha256 -> commit exacto` (`scripts/audit/reconstruct_predeploys.py`,
  415 commits de `AcalaNetwork/predeploy-contracts`): **15/405** bytecodes live
  reconstruidos (los predeploys; validación previa 13/13 y 3/3 con los
  mismatches). **390 bytecodes siguen sin fuente en los repos de la fundación**:
  son contratos desplegados por terceros y requieren reconstrucción desde
  bytecode, que es lo que hace el desensamblado.
- Desensamblado con `pyevmasm` (`audit-live/evm-codes-analysis-*.json`):
  380 + 85 contratos, selectores del dispatcher y patrones. Aparece un proxy
  EIP-1967 (2.141 B, `upgradeTo`/`upgradeToAndCall`/`changeAdmin`/
  `implementation`) **en ambas cadenas**, y contratos con `withdraw(uint256)`,
  `owner()`, `transferOwnership`, `flashLoan`-like. La heurística
  `origin_auth_suspicious` da muchos positivos por bytes `0x32` en dispatchers
  compilados → **se descartó como señal**; se pasa a leer slots y roles reales
  por RPC (`scripts/audit/probe_evm_roles.py`).

**Fork fuzz: la pasada anterior es INVÁLIDA, no un descarte.** Con el hash del
bloque ya entrecomillado, el fork arrancó, pero
`@polkadot/api` v17 ya no expone `api.rpc.provider`; las 16 secuencias
terminaron con `TypeError: Cannot read properties of undefined (reading 'send')`
y **0 extrinsics ejecutadas** (`deltas` vacíos, `pnl=0`). No se usa como
evidencia de conservación. Corregido guardando la instancia de `WsProvider` y
usando `provider.send(...)`; se relanza.

**HonzonBridge (confirmado dos veces)**: bloque 12.812.190,
`BridgedStableCoinCurrencyId = None`, `escrow_evm_address_mapping = None`,
`escrow_kusd_account_data = None`, 19 metadatos ERC20 leídos sin errores,
`IsShutdown = true`. Ambas calls revierten; no hay inventario ajeno en ese
bridge. **Candidato muerto.**

## 6. Lo que queda por agotar

1. Reejecutar el fork fuzz con el provider corregido y medir PnL real de las
   16 secuencias acumulativas (Homa, DEX LP, Taiga, aggregated-dex, fee-pool,
   incentives, refund, earning, EVM accounts).
2. `probe_evm_roles.py`: slots 0 / EIP-1967 impl-admin-beacon, `owner()`,
   `implementation()`, balances nativos y de ACA/aUSD/KAR/kUSD para los
   contratos con `upgradeTo`/`withdraw`/proxy; buscar owner/admin sin
   inicializar **con valor**.
3. Decompilar los contratos con valor y selectores de dinero; verificar auth.
4. Completar el prerrequisito: otros forges, submodules/LFS, refs completas,
   lista de bloqueados, mapa address/program id -> repo+commit+artefacto.
5. `debug_traceCall`/trace, reorg/flash EVM e inventario USD con precio de
   mercado (no sólo el oráculo).

**No se emite `"no crítico live"` mientras estos puntos sigan abiertos.**
