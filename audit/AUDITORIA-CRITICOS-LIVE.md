# Auditoría Acala — ¿existe un crítico *live* con drenaje de terceros?

**Rol:** auditor ofensivo de blockchain.
**Pregunta:** ¿hay una vulnerabilidad CRÍTICA real, permissionless, sobre el estado desplegado hoy, que permita a un atacante sin privilegios terminar con más valor del que aportó, tomando fondos de TERCEROS?

**Respuesta corta:** **no crítico live.**

Ninguna de las candidatas que sobrevivieron al filtro cumple los 4 criterios simultáneamente. Abajo está (1) el estado del prerequisito obligatorio, (2) el mapa dirección→repo/commit/artefacto, (3) las candidatas estudiadas y el hecho exacto que las mata, y (4) el inventario medido.

---

## 0. Limitación material (declarada, no disimulada)

No hay acceso a estado live por RPC: `rpc.acala.network`, `eth-rpc.acala.network`, `acala-rpc.dwellir.com`, `rpc.polkadot.io` y `api.subscan.io` respondieron `http 000` (bloqueado en el sandbox). Sin red hacia la cadena **no puedo confirmar**:

- el `code`/`storage` actual del runtime on-chain (spec_version desplegado hoy),
- saldos reales de cuentas módulo, pools y vaults,
- qué pallets están efectivamente instanciados/enabled hoy.

Todo lo que sigue se ancla en **código clonado + génesis en el repo**, no en memoria ni en explorers. Donde afirmo un importe, es *capacidad máxima de código*, no TVL medido.

---

## 1. Prerequisito: alcance clonado

### 1.1 Organización

- Fundación = Acala Foundation. Única org identificable: **`github.com/AcalaNetwork`**.
- `gh api orgs/AcalaNetwork/repos?type=all` → **135 repos públicos**, `?type=private` → **vacío**.
- GitLab (`gitlab.com/AcalaNetwork`), Bitbucket → inalcanzables (`http 000`).
- **Blind spot declarado:** no puedo probar la inexistencia de repos privados fuera del alcance del token. No afirmo cobertura total.

### 1.2 Clonado

- `clone.sh` (blobless, todas las ramas y tags) → **135/135 OK, 0 FAIL** (`clone.log`).
- `repos/` ≈ 275 MB. **22 repos con Rust**, **1 repo vacío** (`runtime-overrides`, 0 archivos → no se usa para lógica live).
- **8.112 archivos Rust**, **85.710 commits** en total.

### 1.3 Ancla del código

| repo | commit | fecha | notas |
|---|---|---|---|
| `Acala` | `cde2abf753cdfbb67e8129b8c0672d5c15444aa1` | 2026-08-11 | master; tag `2.37.0`; `spec_version` **2370** |
| `Acala` tag `2.36.0` | `d3a2f0d253` | — | último release con CI `Test` verde |
| `acala-node` | `7bc07519429f` | — | tag `3.2.0` |
| `substrate` | `197b8fd367` | 2021-11-20 | fork histórico, no runtime live |
| `polkadot-sdk` | `6792d05e50` | 2025-12-12 | copia de referencia del SDK |

Submodules (pineados en `.gitmodules`, resueltos a commit):

| submodule | commit |
|---|---|
| `orml` | `04eb581ec2e116584b2ddc033313c2e6f1382c52` |
| `ecosystem-modules/stable-asset` | `aa101e87234bd3d388c8de062f231d635d79cf7b` |
| `predeploy-contracts` | `b074c00f3e3d432c965cd9cc395122ec718a779a` |
| `evm-bench` | `f1431e267b0454ff662a070048869b49cd800a6f` |
| `evm-tests` | `b7649496322d6a07b395cb76ed55993625ed9d9c` |

### 1.4 Divergencia del fork `orml` (lead que quedaba abierto) — **cerrado**

`orml` apunta a `open-web3-stack/open-runtime-module-library`. Fetch completo (717 commits en `origin/master`):

- `git merge-base 04eb581 origin/master` = `0069a63c2b`
- `04eb581` **no** está en `origin/master` (5 commits propios: sólo *benchmarks*).
- `git diff 04eb581 origin/master -- '*.rs'` → **0 líneas, 0 archivos Rust**.
- Único delta pin→master: `Cargo.toml`, CI y `rust-toolchain` (13 archivos, +50/−49).

**Conclusión:** no hay divergencia de lógica en `orml`. El fork es upstream + benchmarks. Este lead queda cerrado y **elimina** la hipótesis de backdoor en rewards/auction/tokens/oracle/xtokens/xcm.

### 1.5 Prueba dura sobre rollback (resuelve la clase de bug más grave encontrada)

Antes de descartar un hallazgo que parecía crítico (`honzon::transfer_debit`), verifiqué en el SDK **la semántica real de `Err` en un dispatchable**, con fuente descargada y guardada:

- `substrate/frame/support/procedural/src/pallet/expand/call.rs:216-248` — el macro `#[pallet::call]` **reescribe el cuerpo de cada dispatchable** envolviéndolo:

  ```rust
  // We execute all dispatchable in a new storage layer, allowing them to
  // return an error at any point, and undoing any storage changes.
  #frame_support::storage::with_storage_layer::<#ok_type, #err_type, _>(|| #block)
  ```

- `substrate/frame/support/src/storage/transactional.rs:188-201` — `with_storage_layer` hace `Commit` si `Ok`, `Rollback` si `Err`.

Por tanto: **todo dispatchable que devuelve `Err` revierte TODO su storage**, sin necesidad de `#[transactional]`. Esto invalida la clase entera de "minteo intermedio no revertido" (era el vector más prometedor).

Fuentes guardadas en `audit/state/` (`sdk-pallet-call-expand.rs`, `sdk-storage-transactional.rs`, `sdk-frame-executive.rs`, ref `polkadot-stable2506` = `6fd693e6d9cfa46cd2acbcb41cd5b0451a62d67c`).

---

## 2. Mapa dirección/program-id/módulo → repo + path + commit

Todo derivado por cálculo desde el código anclado (scripts en `audit/state/`, sin red).

### 2.1 Cuentas módulo (PalletId → AccountId32 = `blake2_256("modl" ++ id)`)

Reproducible: `python3 audit/state/derive_accounts.py`.

| constante | PalletId | SS58 (prefijo 10) | EVM default (`blake2_256("evm:"++acc)[0..20]`) |
|---|---|---|---|
| TreasuryPalletId | `aca/trsy` | `21R4DsRZAmc8WQHJBs1D6kqhhZE1t9b2MRkpp9F8b2kohZPL` | `0x3aa70415dc0174f05066a96f9498c4feb3662cd9` |
| LoansPalletId | `aca/loan` | `24nmtwXa3fmYGew3iMBqi9kYr887ARKuEWiovK2tZVTb7955` | `0xda747ed384c4e8f165be29f98d8e383f24b2598c` |
| DEXPalletId | `aca/dexm` | `23xVjsrN2nMVStVAMNKwvt5bqCHsV6Z2tu4EjmWng7BwdgWY` | `0x4e97b40154dccd0aa7c0b68bac5e6f8a55b873c1` |
| CDPTreasuryPalletId | `aca/cdpt` | `24v51bdf62LK6o5qzq2FLc7Lt6wzMiYU5D4VBhqo8G6m7XQz` | `0xf8a766c7b600bc026a9acd6a4aa82e2966d6362e` |
| CDPEnginePalletId | `aca/cdpe` | `25iaH3aWZEGvXHeuSQRx23uvEVJo3w9HYamQRUFydHyPipSe` | `0x7db0222318efd2d53ecc2201c332d5bef968cb89` |
| HomaPalletId | `aca/homa` | `21wXzrAdRvBZFwuMZgBErGE2LQhEfQg8HSeL8qs2uzXsCpyW` | `0x30f46a72c3e776edc312a169a2974aa9bd5d9b5c` |
| HonzonTreasuryPalletId | `aca/hztr` | `24499qhP99d94xzWD3YiJPFzZdW6FbRQ3ZaeBLmKRWXVyQDo` | `0xece095ca90033ff7509249d47a08fdb66ef59b44` |
| HomaTreasuryPalletId | `aca/hmtr` | `26E7M8gd8vTrWc9Poy3iVPamsDmooAYxndqGHH96uWBPhZ5x` | `0xecc1a73a61adb738976c602f34f8b8aa1e8fd5c8` |
| IncentivesPalletId | `aca/inct` | `23cP2AGSpXMBPRKWV9WDbckR6b73cNQ1PGvRjbGoNj9Ticcj` | `0x1c16f5d7939af77ccdfe1f4632421893401d5055` |
| TransactionPaymentPalletId | `aca/fees` | `23xo5na3zx15SkPaDVy7rQQB5bGrPcPLE5RUukcqVjxSHxuB` | `0x5e728f0aa5c8ff8f13078b910a38086552a7206c` |
| LiquidCrowdloanPalletId | `aca/lqcl` | `25ghCoDJ2GXcfB5bULEWGzDkGR1veGse91TdMVQzru8hqyuB` | `0xd71c10d9d411c97aa613dbdfc01a8afd71c6a035` |
| StableAssetPalletId | `nuts/sta` | `24QReYrG3iSHsh6CXnDqZvVmBpxVGWmChJD8jA9iGqgsoSLg` | `0x79e441369e3820a3e7f8cb2654b89041740ddc77` |
| TreasuryReservePalletId | `aca/reve` | `25q6rAdkJy7jHy6kV9hZJ7jPFBRdPdFtwAc5PFN7Bc6TKKSW` | `0x16f2c82a7c6b728bf2c3f3403a79988b91c25a80` |
| CollatorPotId | `aca/cpot` | `21WypvSYnhMmEziHAyCyJZULcS2cZcXmnTcAafPXH26JjwuP` | `0xf11eeed126c8449eec124463327750ade465f85f` |
| NftPalletId | `aca/aNFT` | `22g28rN9AZNKRyjJHtxYZYMt9ysP6MkvAhvSCiPLqed3ZVfW` | `0xe60ec13f29f8cdd5896d812ee7ae0acc97db34ec` |
| UnreleasedNativeVault | `aca/urls` | `25SgLcoCsixMow5CpNFbiyjgLywQqvyqk1sBkrT9XeWjVURY` | `0x0fefaa04394172355eb88af6241c4839091757ee` |

Paths + commit: `runtime/acala/src/lib.rs` líneas 169–206 @ `cde2abf7`; derivación `modules/evm-accounts/src/lib.rs::account_to_default_evm_address` @ mismo commit.

### 2.2 Programa/contrato live: precompiles del sistema

`runtime/common/src/precompile/mod.rs` @ `cde2abf7`. **Gate:** todo precompile "Acala" exige `SystemContractsFilter::is_allowed(caller)` **y** `is_contract(caller)` (`mod.rs:304-317`); `is_system_contract` = dirección con prefijo `[0u8;9]` (`primitives/src/evm.rs:151,179`) → espacio de fuerza bruta ≈ `2^88`. **No invocable por EOA ni por contrato de usuario.**

| dirección | pallet | path |
|---|---|---|
| `0x…0400` | multicurrency | `precompile/multicurrency.rs` |
| `0x…0401` | nft | `precompile/nft.rs` |
| `0x…0402` | evm | `precompile/evm.rs` |
| `0x…0403` | oracle | `precompile/oracle.rs` |
| `0x…0404` | schedule | `precompile/schedule.rs` |
| `0x…0405` | dex | `precompile/dex.rs` |
| `0x…0406` | stable-asset | `precompile/stable_asset.rs` |
| `0x…0407` | homa | `precompile/homa.rs` |
| `0x…0408` | evm-accounts | `precompile/evm_accounts.rs` |
| `0x…0409` | honzon | `precompile/honzon.rs` |
| `0x…040a` | incentives | `precompile/incentives.rs` |
| `0x…040b` | xtokens | `precompile/xtokens.rs` |
| `0x…040c` | liquid-crowdloan | `precompile/liquid_crowdloan.rs` |
| `0x…040d` | earning | `precompile/earning.rs` |

### 2.3 Génesis / binario

| artefacto | evidencia medida |
|---|---|
| `resources/acala-dist.json` | génesis **raw** live (`chainType: Live`, `paraId 2000`, `relayChain polkadot`), 13.706 claves top |
| runtime wasm en génesis | **1.124.507 bytes**, `blake2_256` = `865db1a6fa9efc02203b0a966824474c8e709a3f037f4c782911ec3ca549889b` |
| `resources/karura-dist.json` | 39.820 claves; wasm 2.130.520 B; `blake2_256` = `2b3e6149affa8bd05c5ee09608a0c34d8c1a68a7c7241f872bc3ae1faa82dfe6` |
| `Sudo.Key` en génesis Acala | `0xf065057e73a3ffceff273f4555a0ea3d731ec8ef4d79954473b4ffda046d836d` |
| `Balances.TotalIssuance` génesis | `1000000000000000000000` (1e21 planck, ACA 12 dec) |
| cuentas en génesis (`System.Account`) | 13.502 (Acala) / 39.691 (Karura) |
| `badBlocks` | `0xa820d0e6…82aa7` |
| `EVM.ChainId` | constante de código `CHAIN_ID_ACALA_MAINNET = 787` (`primitives/src/evm.rs:48-49`); **no** hay valor en génesis → se fija vía `set_chain_id`/genesis config, no verificable offline |

Reproducible: `python3 audit/state/extract_genesis_facts.py`.

**Advertencia:** `acala-dist.json` es el génesis **fundacional** (2021), no el estado actual. Sirve para anclar identidades y constantes, **no** como TVL de hoy.

### 2.4 Parámetros live relevantes (del código anclado)

| parámetro | valor | path |
|---|---|---|
| `spec_version` Acala | 2370 | `runtime/acala/src/lib.rs:144` |
| `MaxAuctionsCount` | 50 | `runtime/acala/src/lib.rs:1282` |
| `NewContractExtraBytes` | 10.000 | `:1529` |
| `NetworkContractSource` | `0x0` | `:1530` |
| `DeveloperDeposit` | 50 ACA | `:1531` |
| `PublicationFee` | 10 ACA | `:1532` |
| Homa `MintThreshold` | 1 DOT | `:1632-1637` |
| Homa `RedeemThreshold` | 5 LDOT | idem |
| Earning `MinBond` | 100 ACA | `:1851` |
| `UnbondingPeriod` (earning) | 14 días | `:1852` |
| NomineesElection `MaxUnbondingChunks` | 7 | `:1690` |

---

## 3. Candidatas evaluadas y el hecho exacto que las mata

Ordenadas por cercanía a "crítico". Ninguna llega.

### C1 — `honzon::transfer_debit`: minteo de AUSD antes de validar, sin `#[transactional]`

`modules/honzon/src/lib.rs:355-377` @ `cde2abf7`:

```rust
<T as ...>::CDPTreasury::issue_debit(&who, debit_transfer, true)?;   // ← mintea AUSD a `who`
<...>::adjust_position(&who, from_currency, Zero::zero(), negative_debit)?;  // ← puede fallar
<...>::adjust_position(&who, to_currency, Zero::zero(), debit_amount)?;      // ← puede fallar
<T as ...>::CDPTreasury::burn_debit(&who, debit_transfer)?;                  // ← quema
```

La llamada **no** lleva `#[transactional]` (grep en todo el pallet: sólo `loans.rs:136,174` y `cdp-engine` 973/1066/1192 la usan; `honzon` ninguna). Verifiqué también que `cdp_engine::adjust_position` (`:895`) tampoco.

**Parecía crítico:** si el minteo sobreviviera a un `Err` en el segundo paso, sería AUSD gratis e ilimitado con balance neto positivo → drenaje de todo el stablecoin de terceros.

**Hecho que lo mata:** el macro `#[pallet::call]` del SDK envuelve **cada dispatchable** en `with_storage_layer`, que hace `Rollback` ante `Err` (`pallet/expand/call.rs:216-248` + `storage/transactional.rs:188-201`, fuentes en `audit/state/`). El `Err` de `adjust_position` revierte el `issue_debit`. **No hay minteo persistente.**

**Corroboración empírica independiente:** los propios tests del pallet usan el `assert_noop!` real (compara storage root, `frame_support/src/lib.rs:749-762`) y esperan no-op en los caminos de error:

- `modules/honzon/src/tests.rs:281` → `transfer_debit(..., u128::MAX)` ⇒ `assert_noop!(… ArithmeticError::Overflow)`
- `modules/honzon/src/tests.rs:286` → moneda no-colateral ⇒ `assert_noop!(… InvalidCollateralType)`
- `modules/honzon/src/tests.rs:306` `transfer_debit_no_ausd` ⇒ tras fallar, `free_balance(AUSD, ALICE) == 0`

Si el minteo persistiera, `assert_noop!` fallaría con *"storage has been mutated"*. El job `Test` pasó en `d3a2f0d253` (2.36.0) — `gh api .../workflows/test.yml/runs?status=success` — y este código existe desde `8147e459` *"Ability to transfer debits between loans (#2053)"*, sin cambios posteriores en esa función.

**Clasificación:** no es bug. Es estilo frágil (depende de un invariante del macro). No se reporta como crítico.

### C2 — Precompiles del sistema invocables por terceros

**Mata:** gate doble (`is_allowed` sobre prefijo `[0u8;9]` + `is_contract`) en `runtime/common/src/precompile/mod.rs:304-317`. Fuerza bruta ≈ `2^88`. No permissionless.

### C3 — `loans::adjust_position` / `confiscate_collateral_and_debit` no atómicos

**Mata:** ambas **sí** llevan `#[transactional]` (`modules/loans/src/lib.rs:136` y `:174` en el ancla), y además el layer del macro C1. Nada que explotar.

### C4 — `xcm-interface`: `send_xcm` fire-and-forget + doble fee

`modules/xcm-interface/src/lib.rs`. `withdraw_unbonded_from_sub_account`, `bond_extra_on_sub_account`, `unbond_on_sub_account`, `nominate_on_sub_account` usan `pallet_xcm::send_xcm(...)` y sólo `ensure!(result.is_ok())` — sin recibo de entrega/ejecución. `withdraw_unbonded` cobra `xcm_fee * 2` (TODO en el código).

**Mata:** el fallo produce deriva contable de Homa (liveness/grief del propio redeem, y sobre-cobro a la tesorería de Homa), **no** transferencia de valor de un tercero al atacante. El atacante no puede dirigir el mensaje ni el destino. → *no crítico* (candidato a medio/bajo).

### C5 — `incentives`: payout no atómico con recompensa pendiente

`modules/incentives/src/lib.rs:498-516`: `payout_reward_and_reaccumulate_reward` **es** `#[transactional]`; en `Err` no se pone a cero `PendingMultiRewards` (sólo `log::error!`), así que la recompensa **no se destruye**: queda reclamable. `accumulate_incentives` ignora errores por diseño (no bloquea otros pools).

**Mata:** sin pérdida ni creación de valor; peor caso, reintento. → *no crítico*.

### C6 — `auction-manager`: `inc_consumers` falla y sólo se loguea

`swap_bidders` y `new_collateral_auction` hacen `log::warn!` si `inc_consumers` falla (sin revertir) → posibles consumer refs faltantes. Los reembolsos siguen fluyendo; no se identificó quema ni desvío de fondos. Parámetros: incremento mínimo 2%, cierre 15 min, soft cap 24 h.

**Mata:** no hay ruta de valor; el defecto es de refcounts. → *no crítico*.

### C7 — `FixedRateOfAsset` (XCM weight trader)

`runtime/common/src/xcm_impl.rs`. Fast path fija `ratio`/`location` sin compra pendiente; slow path **rechaza** cambio de location o de ratio (`TooExpensive`) — esto corrige un sub-cobro previo (commit `bd3ac568`). `amount = ratio * (ref_time/SECOND) * FixedRate`; `saturating_*` en todo; refund trunca a favor del usuario ≤1 unidad; `Drop` envía el residual a `TakeRevenue`.

**Mata:** números saturados, sin panic, sin sub-cobro tras el fix; el residual va a revenue. → *no crítico*.

### C8 — `emergency-shutdown::refund_collaterals` (proporción sobre total)

`modules/emergency-shutdown/src/lib.rs:199`. `refund_ratio = get_debit_proportion(amount)` sobre **total issuance** de stablecoin, y el colateral se reparte por `refund_ratio * total_collaterals(currency)`. `refund_collaterals` está gateado por `can_refund`, que sólo se abre con `open_collateral_refund` (origin `ShutdownOrigin`) y exige cero debits y cero subastas.

**Mata:** requiere shutdown de gobernanza → excluido por regla (rol privilegiado). Además, en un escenario de quiebra el reparto proporcional es el diseño esperado, no un bug. → *no crítico*.

### C9 — `liquid-crowdloan::redeem`

`modules/liquid-crowdloan/src/lib.rs:123`. Reparte `amount * redeem_balance / lc_dot_total_supply` con `checked_mul`/`checked_div`.

**Mata:** es un prorata correcto sobre un vault propio; el atacante sólo obtiene la parte proporcional de lo que aportó. Sin exceso. → *no crítico*. (Nota: si `RedeemCurrencyId` es `None` redime 1:1; eso es gobernanza, no permissionless.)

### C10 — `honzon-bridge::to_bridged` / `from_bridged`

`modules/honzon-bridge/src/lib.rs:128,163`. Swap 1:1 contra la cuenta del pallet.

**Mata:** sin comisión ni slippage, pero también sin creación de valor: es un movimiento entre dos activos 1:1 del mismo usuario. Sólo sería crítico si el vault estuviera desbalanceado *y* alguien pudiera acuñar el bridged side gratis — el bridged side es `CurrencyId::Erc20(addr)` registrado por gobernanza y su emisión la controla el contrato ERC20, no este pallet. → *no crítico* con la evidencia disponible.

### C11 — ERC20 deposit/withdraw en `currencies` + registro

`modules/currencies/src/lib.rs:400-500`; `withdraw` exige `get_evm_address(from)` mapeada (`EvmAccountNotFound`) y envía al `Erc20HoldingAccount`; `deposit` exige saldo libre no-cero del holding y usa `get_or_create_evm_address(who)`. `asset-registry::do_register_erc20_asset` lee `name/symbol/decimals` con sender/origin cero y exige unicidad en `AssetMetadatas[Erc20(addr)]` **y** `Erc20IdToAddress[id]` → no se puede sobrescribir un mapeo existente.

**Mata:** sin overwrite no hay sustitución de token; sin `get_evm_address` no hay retiro a dirección ajena. → *no crítico*.

### C12 — Conversión de decimales EVM (`primitives::evm`)

`convert_decimals_to_evm` = `saturating_mul(1e6)`; `convert_decimals_from_evm` devuelve `None` salvo divisibilidad exacta → `execute` rechaza `value` no convertible (`InvalidDecimals`), `transfer` devuelve `OutOfFund`/`Other`.

**Mata:** el dust sub-`1e-12` **no puede entrar** en la contabilidad EVM. Se cierra toda la clase de griefing por dust. → *no crítico*.

### C13 — `nft`, `nominees-election`, `homa-validator-list`, `earning`, `aggregated-dex`, `dex-oracle`, `prices`

Revisados completos (`nft` 607 L, `nominees-election` 500 L, `homa-validator-list` 559 L, `earning` 363 L, `aggregated-dex` 754 L, `dex-oracle` 375 L, `prices` 312 L).

- `nominees-election` / `earning` / `homa-validator-list`: usan `BondingLedger`/`Guarantee` con `saturating_*` y `MinBond` (`check_min_bond` sólo exige `active > 0 ⇒ active >= MinBond`); locks vía `set_lock`/`remove_lock`. Sin ruta de retiro por encima del ledger.
- `aggregated-dex`: `min_target_amount` sólo se aplica al **final** de la ruta; los hops intermedios usan `Zero::zero()`. Es riesgo de slippage **para el propio firmante** que elige la ruta; un tercero no puede imponerla. Y `do_aggregated_swap` es `#[transactional]`.
- `dex-oracle`: `on_initialize` actualiza acumulados; **ningún consumidor de precio** en el repo lo usa (`grep` de `DexOracle`/`average_price` fuera del pallet = 0). Precio de CDP = `PriorityLockedPriceProvider` (oráculo externo). No hay ruta de manipulación permissionless dentro del repo.
- `prices::lock_price`/`unlock_price`: origin privilegiado.

**Mata (común):** o bien el origen es privilegiado, o el perjuicio recae sobre quien firma, o no hay mecanismo de creación/desvío de valor. → *no crítico*.

### C14 — `transaction-payment` (fee pools, `swap_from_pool_or_dex`)

`modules/transaction-payment/src/lib.rs:1129-1185`. El sub-account por moneda compra nativo en el DEX cuando baja del umbral; `TokenExchangeRate` y `PoolSize` se recalculan con `Ratio::saturating_from_rational`; el `supply_account = rate.saturating_mul_int(supply_amount)`.

**Mata:** `enable/disable_charge_fee_pool` y `set_alternative_fee_swap_path` requieren `UpdateOrigin` (gobernanza); el swap es del sub-account del pallet y consume su propio pool. No hay input de usuario que fije el rate. `with_fee_path`/`with_fee_currency`/`with_fee_aggregated_path` ignoran el path (`_fee_swap_path`) y sólo despachan — sin efecto económico nuevo. → *no crítico*.

### C15 — EVM: storage deposit, `refund_storage`, selfdestruct/remove

`modules/evm/src/lib.rs:1841-1917`, `2245-2290`. `charge_storage` usa `repatriate_reserved_named` con `debug_assert!(…)` sobre el remanente; `refund_storage` devuelve el reservado al `caller` y, si `maintainer == contract`, manda el resto a `TreasuryAccount`. `EvmTask::Remove` limpia `AccountStorages` por lotes y sólo cuando `maybe_cursor.is_none()` hace el refund.

**Mata:** el depósito se mueve entre cuentas ya existentes (`repatriate_reserved`), no se acuña; el peor caso es un `debug_assert` en build no-debug (comportamiento no determinista entre nodos, pero **no** theft). Y `execute` corre bajo `with_transaction` con `Rollback` cuando `exit_reason` no es éxito (`lib.rs:1949-1991`). → *no crítico*.

### C16 — Extrínsecos EVM firmados (EIP-712 / EIP-1559 / 2930)

`primitives/src/unchecked_extrinsic.rs:150-330, 404-500`. Verifica: `tip == 0` si `gas_price == 0`; `access_list` vacía salvo 2930; `chain_id` en el mensaje firmado; `signer` recuperado **debe** coincidir con `lookup(addr)`; `recover_sign_data` recomputa `tx_gas_price`/`tx_gas_limit` con `checked_*`, y `storage_entry_limit` está acotado a `u16` (`.try_into().ok()?`).

**Mata:** no hay malleability de `chain_id`, ni de nonce, ni de value. → *no crítico*.

---

## 4. Inventario medido

### 4.1 Código auditado (LOC, `cde2abf7`)

| área | LOC |
|---|---|
| `modules/` (32 pallets) | 75.663 |
| `runtime/` (acala, karura, mandala, common) | 48.834 |
| `orml/` (pin `04eb581`) | 33.268 |
| `primitives/` | 3.473 |
| `ecosystem-modules/` (stable-asset `aa101e87`) | 4.350 |
| **total** | **≈ 165.588** |

Precompiles: 19 archivos en `runtime/common/src/precompile/` (~10.7k LOC).
Runtime sizes: `acala` 2.923 L, `karura` 2.925 L, `mandala` 3.083 L.

### 4.2 Cobertura de clones

- 135 repos, 8.112 archivos Rust, 85.710 commits.
- 22 repos con código Rust; el resto: contratos (Solidity/TS), front-ends, SDKs, docs, tooling.
- Repos vacíos: 1 (`runtime-overrides`).
- **No cloneable/inalcanzable:** GitLab `AcalaNetwork`, Bitbucket `acalanetwork`, RPC/Subscan (bloqueados). No hay evidencia de repos privados en la org de GitHub accesible al token.

### 4.3 Limitaciones que impiden pasar de "no crítico por código" a "no crítico verificado en cadena"

1. **Sin estado live:** no se pudo leer `spec_version` on-chain, ni saldos, ni qué pallets están enabled hoy. El ancla es `2.37.0`/2370.
2. **Sin build:** 2 vCPU / 3 GB → imposible compilar el runtime; los PoCs son razonamiento sobre fuente + snippets de test **no compilados**.
3. **Génesis ≠ estado actual:** `acala-dist.json` es fundacional (2021); sirve para identidades/constantes, no para TVL.
4. **Oráculo externo:** el precio de CDP viene de `PriorityLockedPriceProvider` (fuente fuera del repo). Un fallo allí **no** es demostrable desde estos clones, y la regla del encargo excluye "si el oráculo devuelve 0".

### 4.4 Lo que NO afirmo

- No afirmo cobertura total de la Fundación (posibles repos privados fuera del token, o en GitLab/Bitbucket inalcanzables).
- No afirmo TVL tocable en USD: sin RPC no hay saldos. Las magnitudes de código (p.ej. `MaxAuctionsCount = 50`) son límites, no fondos.
- No afirmo que no exista un crítico: afirmo que **ninguna de las 16 clases examinadas lo es**, con el hecho concreto que las descarta.

---

## 5. Conclusión

**No crítico live.**

Ningún hallazgo cumple los 4 criterios a la vez. El vector más prometedor de esta ronda (`honzon::transfer_debit` minteando AUSD antes de validar) queda descartado por evidencia dura del SDK (`with_storage_layer` + `Rollback` en cada dispatchable) y corroborado por los propios tests `assert_noop!` del repo y por CI verde en `2.36.0`.

Los defectos reales encontrados son de robustez/liveness, no de robo:

1. `honzon::transfer_debit` depende de un invariante del macro (frágil ante refactor; conviene `#[transactional]` explícito).
2. `xcm-interface` no verifica entrega/ejecución de `send_xcm` y cobra el fee XCM dos veces → deriva contable y sobre-cobro a Homa (no theft).
3. `auction-manager` ignora fallos de `inc_consumers` (sólo `log::warn!`).
4. `aggregated-dex` aplica `min_target_amount` sólo al final de la ruta (slippage del propio firmante).

Si se quiere subir la confianza de "no crítico por código" a "no crítico verificado", hacen falta: (a) endpoint RPC alcanzable para fijar `spec_version` y saldos, y (b) una máquina que compile el runtime para correr PoCs reales.

---

### Anexo — artefactos reproducibles

| archivo | contenido |
|---|---|
| `audit/state/derive_accounts.py` | deriva PalletId → AccountId32 → SS58 → EVM default |
| `audit/state/decode_genesis.py` | clasifica las 13.706 claves del génesis por pallet |
| `audit/state/extract_genesis_facts.py` | wasm hash, TotalIssuance, Sudo.Key, nº cuentas, EVM storage |
| `audit/state/inventory.json` | 135 repos con HEAD, fecha, nº commits, archivos Rust, tags |
| `audit/state/sdk-pallet-call-expand.rs` | fuente SDK: `with_storage_layer` en cada dispatchable |
| `audit/state/sdk-storage-transactional.rs` | fuente SDK: `with_storage_layer` = Commit/Rollback |
| `audit/state/sdk-frame-executive.rs` | fuente SDK: `apply_extrinsic` |
| `audit/state/sdk-ref.txt` | commit del SDK usado (`polkadot-stable2506`) |
| `.cloned-commits.tsv` | 135 filas repo/branch/hash/commits |
