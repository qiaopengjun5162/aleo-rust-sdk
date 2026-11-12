# Changelog

All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

---
## [0.11.0](https://github.com/qiaopengjun5162/aleo-rust-sdk/compare/aleo-rust-sdk-v0.10.0...aleo-rust-sdk-v0.11.0) (2026-11-12)


### Features

* **address:** JS SDK Address parity — toPlaintext, fromProgramId, verify ([#51](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/51)) ([10563a6](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/10563a67d5d034b12ea012d6c3470003a3fc5d9c))
* **authorization:** JS SDK Authorization parity — root function name ([#53](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/53)) ([8bf57bc](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/8bf57bc1255763f2ecb2e557f0865f3d3751edf2))
* **batch:** JS PrivateKeyCiphertext / Transition / Program / RecordCiphertext parity (4 pages) ([#70](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/70)) ([83b0115](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/83b0115d7e3b6b534a66bc1fefd51096cd300294))
* **boolean:** JS SDK Boolean parity — plaintext, RNG sampling, encoding traps ([#55](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/55)) ([de71de6](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/de71de6e4a7f9368dd7c72343f33abfcc8f97b64))
* **ciphertext:** JS SDK Ciphertext parity — the three decryption keys ([#56](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/56)) ([50040c2](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/50040c2de06189f84b483b3a049443e2fabbd99d))
* **circle:** add Circle USDCx hook-data encoding ([#50](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/50)) ([70ce2df](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/70ce2df9d7e3813b70193e0b1ac9cc030390cbb6))
* **compute_key:** JS SDK ComputeKey parity — native type covers the page ([#68](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/68)) ([b8ff6de](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/b8ff6de74b288a8dee1efda9c4f70a1420951b67))
* **credits:** plan and run credits.aleo staking operations ([#36](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/36)) ([722dd17](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/722dd17d1f41d018f137028a3746e51c522db17b))
* **credits:** plan and run credits.aleo transfers, joins, and splits ([#34](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/34)) ([0c3d743](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/0c3d743495d467486ab3fa797cfe06309370356a))
* **encryption:** JS SDK EncryptionToolkit parity ([#54](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/54)) ([1e04a2f](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/1e04a2fc244c0d1729c5f1fca7a6269f5e3586a5))
* **execution_request:** JS SDK ExecutionRequest parity — and three things verify does not check ([#76](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/76)) ([5d36ba8](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/5d36ba8200e1ec903e6ed6d44a2a86b269e1be1b))
* **execution_response:** JS SDK ExecutionResponse parity — off-chain result bundle and consuming key getters ([#58](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/58)) ([3b633e1](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/3b633e15b2b134331b0e51895a647e8322f7804d))
* **execution:** build a transaction from a saved authorization ([#39](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/39)) ([936797f](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/936797f0a37c1d81ab5f088a0649c8751934bfc1))
* **execution:** estimate execution and finalize fees offline ([#37](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/37)) ([2bd59af](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/2bd59af0a099a1e3dcc3b9ead6309e49eb90b880))
* **execution:** JS SDK Execution object parity — accessors and height-aware verify ([#57](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/57)) ([8d0b147](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/8d0b147e305b80d4635dc38413eb58caf8c586d2))
* **execution:** pre-synthesize function proving keys ([#41](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/41)) ([69bc25e](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/69bc25e9a00799d1b83df59eaa45ad0be64549ad))
* **execution:** program upgrade transactions (JS buildUpgradeTransaction) ([#42](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/42)) ([eecd93e](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/eecd93e45fe7d5661bc672867a992bdc90e99b6f))
* **fee:** pay transaction fees from a private record ([#38](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/38)) ([0e94567](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/0e9456782965f7f75c44e3bf3390afce17f4518e))
* **field:** JS SDK Field parity — negate-vs-inverse trap, strict/lossy casts, integer truncation semantics ([#59](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/59)) ([5acbbc1](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/5acbbc1534dc13e134c5f97054a2f60511130158))
* **graph_key:** JS SDK GraphKey parity — native type covers the page ([#69](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/69)) ([810b64f](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/810b64fac178b76a48dbecaf361270e65c38bc59))
* **group:** JS SDK Group parity — x-coordinate-driven lossy casts, Edwards negation flips x ([#60](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/60)) ([9e2e56d](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/9e2e56d851a550caa15d8e9cad68fcc2b2830fa8))
* **hash_functions:** JS SDK Hash Functions parity — nine default-domain constructors ([#75](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/75)) ([dbdf9eb](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/dbdf9eb83a6af79ee5f3226fbd4b9895d111dd02))
* **integer_types:** JS SDK Integer Types parity — mapping table plus three native helpers ([#74](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/74)) ([7175023](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/7175023b420e9c9160e2f4a8fe42e8f559ed371f))
* **keypair:** JS SDK KeyPair parity — take-once key bag with the upstream error-message bug fixed ([#61](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/61)) ([4487074](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/4487074c18839ec9b2b735f85f773bb678c58122))
* **keys:** JS FunctionKeyProvider convenience getters and getVerifyingKey ([#45](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/45)) ([872e127](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/872e127f6adb719d62ecbea5b9cf380cb645f266))
* **keys:** offline key provider (JS OfflineKeyProvider) ([#43](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/43)) ([c0ae5bb](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/c0ae5bb7fa38d6ac15317505bb545d79b23ab36b))
* **keys:** online function key provider (JS AleoKeyProvider) ([#44](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/44)) ([e2b924d](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/e2b924d947ca805f398c67b7a6d4e7dd3cfe38ad))
* **metadata:** JS SDK Metadata parity — the static parameter-URL catalogue ([#78](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/78)) ([67d9e9d](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/67d9e9d564533a0433db1a159c9f2d223c1f4e27))
* **offline_query:** JS SDK OfflineQuery parity — QueryTrait bundle with setter/JSON traps ([#62](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/62)) ([f58a83f](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/f58a83fcbefc95398ceb598e358424cefc3a6b4c))
* **plaintext:** JS SDK Plaintext parity — raw-vs-variant bits, toObject mapping, byte-order traps ([#63](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/63)) ([8459673](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/8459673f31f64485d2713d7aeb3776a9da84b624))
* **private_key:** JS SDK PrivateKey parity — JS-compatible ciphertext1 encrypted keys, upstream vector interop ([#64](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/64)) ([0e95fd8](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/0e95fd89098a256486cc4defb73f8b38ffd449ce))
* **proving_key:** JS SDK ProvingKey parity — 6 methods with upstream checksum literal ([#72](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/72)) ([91cd6b6](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/91cd6b6bef4d5bd8b93ba73287f036ae2f12b180))
* **proving_request:** JS SDK ProvingRequest parity — the first page that needs a new type ([#77](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/77)) ([260ed4e](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/260ed4e175aa887f827062f99771b88ce819d644))
* **record_plaintext:** JS SDK RecordPlaintext parity — 18 methods with upstream vectors ([#71](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/71)) ([af5eaaa](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/af5eaaafb70902cb605a2ba3d44490627c5bf3a4))
* **record:** add a RecordProvider-style cached search API ([#40](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/40)) ([8c2ede0](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/8c2ede04a45bacdfbbe0e9d23d133ef487275572))
* **scalar:** JS SDK Scalar parity — negation-not-inverse trap, toField-bridged lossy casts ([#65](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/65)) ([3c047ed](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/3c047edbddfcb31f312b2cb9bb8f32b92d92a6dd))
* **scanner:** add /records/sns, /records/tags, /records/encrypted ([#46](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/46)) ([d367d2f](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/d367d2f74c6ecc7b6e0b494975fefcb9b47b5f78))
* **scanner:** RecordScanner parity — computeUUID, findCredits*, OwnedFilter fields ([#47](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/47)) ([279171b](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/279171b05b39bb5ee8d3bcebebc7dcd7a62c6c7d))
* **sealance:** JS SDK parity — decimal tree strings, proof objects, default depth ([#49](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/49)) ([1f6edfa](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/1f6edfae03a69c06ab8c06730a48c9ca3e4959e1))
* **signature:** JS SDK Signature parity — value signing, verifyValue, plaintext ([#52](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/52)) ([197a3b6](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/197a3b669ea97074ac801d0dbf8beb1c57d56edd))
* **transaction:** add JS Transaction parity module ([#66](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/66)) ([#66](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/66)) ([baa7026](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/baa7026d38c55c5aa0be647ac76e17d73b253c67))
* **utility_functions:** JS SDK Utility Functions parity ([#79](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/79)) ([#79](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/79)) ([a793458](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/a793458852ddf44f52dfe6ae817fdd1109138131))
* **verifying_key:** JS SDK VerifyingKey parity — 9 methods with upstream vectors ([#73](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/73)) ([1f88c8d](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/1f88c8ddea9821b27169bbb271bce95047eb22c6))
* **view_key:** JS SDK ViewKey parity — native type covers the page; decrypt + scalar/field casts wrapped ([#67](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/67)) ([fb185d4](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/fb185d4012100f1b872131cce827df8f1e7a43ee))


### Bug Fixes

* **ci:** install cargo-deny as a prebuilt binary instead of the wrapper action ([#48](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/48)) ([4c637ef](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/4c637ef1f5c4551d139109b830050ae960dd022b))

## [0.10.0](https://github.com/qiaopengjun5162/aleo-rust-sdk/compare/aleo-rust-sdk-v0.9.0...aleo-rust-sdk-v0.10.0) (2026-11-07)


### Features

* **account:** seed recovery, per-record view keys, and signing ([#30](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/30)) ([eb51824](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/eb518245ac1c22b900c6610a972c90e5c311bbbe))
* **client:** verify proofs against the consensus version of their own era ([#24](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/24)) ([d409855](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/d4098554105e80908cc087547e07fe7582e43a86))
* **delegated:** add Provable DPS delegated proving client ([#28](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/28)) ([af1a0eb](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/af1a0eba3a37cc8982eb3bdccc264ca186bb2d1f))
* **network:** add the chain-read surface (blocks, transactions, committees, balances) ([#32](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/32)) ([8ef0252](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/8ef0252f43ec718dce9a626b9da9b222aa19eec1))
* **options:** configure every service base from one network name ([#33](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/33)) ([2223b46](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/2223b46691099436bae7569e4b7a64d1acba5b20))
* **record:** make the record source switchable (local scan or hosted scan) ([#31](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/31)) ([122b428](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/122b42807495244f967b8265d4e987d6894cefb4))
* **scanner:** add Provable record scanning service client ([#29](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/29)) ([272955a](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/272955a8751226b790e7e2d642249b465a217a56))


### Bug Fixes

* **sealance:** sibling paths must carry depth+1 elements ([#26](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/26)) ([b24edc8](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/b24edc86e19b24da11be4c81cc667f140bf0912e))

## [0.9.0](https://github.com/qiaopengjun5162/aleo-rust-sdk/compare/aleo-rust-sdk-v0.8.2...aleo-rust-sdk-v0.9.0) (2026-10-29)


### ⚠ BREAKING CHANGES

* **network:** `AleoError` (and the `error` module) is removed — it was never returned by any API, so downstream code could only have referenced it in a way that did nothing; use `anyhow::Error` instead. `AleoHttpClient::find_private_credits_records` is removed; use `AleoClient::find_private_credits_records` or `RecordScanner::scan_recent`. `thiserror` is no longer a dependency.

### Code Refactoring

* **network:** split transport from Merkle queries, drop dead error module ([#19](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/19)) ([7a09179](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/7a091798ebb5fd94e2b135b34928c991d6e97d29))

## [0.8.2](https://github.com/qiaopengjun5162/aleo-rust-sdk/compare/aleo-rust-sdk-v0.8.1...aleo-rust-sdk-v0.8.2) (2026-10-24)


### Bug Fixes

* **ci:** ignore commit hashes in typos ([#17](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/17)) ([ec9aacd](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/ec9aacddaeaf4a33a87479b5bb2f858366528009))
* patch five RUSTSEC advisories, correct MSRV to 1.96, close doc gaps ([#15](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/15)) ([3a20ba5](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/3a20ba589b91a27de7c82c213cca1396c1660193))

## [0.8.1](https://github.com/qiaopengjun5162/aleo-rust-sdk/compare/aleo-rust-sdk-v0.8.0...aleo-rust-sdk-v0.8.1) (2026-10-20)


### Bug Fixes

* **ci:** stop swallowing coverage failures; run doc-tests; harden network headers ([#13](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/13)) ([074546a](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/074546a341bb055cf92e1dfdbb49c4c5fd617b9a))

## [0.8.0](https://github.com/qiaopengjun5162/aleo-rust-sdk/compare/aleo-rust-sdk-v0.7.2...aleo-rust-sdk-v0.8.0) (2026-10-20)


### Features

* upgrade to snarkVM 4.12, fix hardcoded network/consensus assumptions, de-duplicate prove pipeline ([#11](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/11)) ([7a1eb5f](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/7a1eb5f3ddd0f20574058b9c565691fa699844c7))

## [0.7.2](https://github.com/qiaopengjun5162/aleo-rust-sdk/compare/aleo-rust-sdk-v0.7.1...aleo-rust-sdk-v0.7.2) (2026-10-11)


### Bug Fixes

* **ci:** make TOML/spelling/audit checks real, drop dead release steps ([#9](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues/9)) ([3d3624f](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/3d3624f7840cf3c41e488eca0e7f5120a29c1715))

## [0.7.1](https://github.com/qiaopengjun5162/aleo-rust-sdk/compare/aleo-rust-sdk-v0.7.0...aleo-rust-sdk-v0.7.1) (2026-10-10)


### Bug Fixes

* PR-Agent config.* prefix + litellm OPENAI_API_BASE + deepseek_v4 ([f01fed4](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/f01fed433fc1452962c96a1b782668977d906767))

## [0.7.0](https://github.com/qiaopengjun5162/aleo-rust-sdk/compare/aleo-rust-sdk-v0.6.0...aleo-rust-sdk-v0.7.0) (2026-10-10)


### Features

* **account:** encrypt_private_key, is_valid_address, destroy — JS SDK feature parity ([bf132b3](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/bf132b3a26c0ad07bf3fc3f9c8a293f17a356d87))
* adapt to snarkVM 4.10.0 crates.io release ([4eba7f0](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/4eba7f0a36b607d04afd215faeccc20cd8c8db28))
* add PR template, PR-Agent config, Release Please, and pre-commit hooks ([3515fba](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/3515fba0bf47d45331e04f27219adefddd195a7d))
* add testnet_transfer example + AleoClient set_program/higher-level API ([6b8b64c](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/6b8b64c9b76948b2435458d56766ff63aeb0ea86))
* add VERSION constant and fix PR-Agent workflow ([c1723e5](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/c1723e54fd0996238b4408c751d5364776d231e9))
* consolidate to single crate aleo-rust-sdk ([6cfc0d9](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/6cfc0d9c77456a74a59fd9c68709c831249eacaf))
* **deploy:** end-to-end testnet deploy verified on chain ([467dedc](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/467dedc210acdb42a36a6a35af13febf44e687f0))
* **deploy:** implement full deploy pipeline ([6fdde7b](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/6fdde7bccc229aa9c9a85a372af50d45e6eaeed6))
* find_private_credits_records (records/all + decrypt) + client helper; v0.2.0 ([dff636d](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/dff636d739dae635ef5250a2265016c712208f26))
* initial SDK structure ([22536d2](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/22536d294876149b3ad6e1742ee17bebcc2aecf0))
* migrate to v2 JSON-RPC, restructure network crate, add testnet_query example ([97a4463](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/97a4463d3475a353bf47571c8a78f4dfa8bc3d7c))
* on-chain state queries (balance, records, block height, state root) ([0f93bf9](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/0f93bf9d49ef6637a93db43a857dcea0b2082702))
* real Aleo testnet transfer — dry-run + prove + broadcast verified ([abf0b82](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/abf0b8249595b0259d27b535fe941248a1246d96))
* **record:** 添加 record 模块 — 记录发现/解密/币选择 + 集成 AleoClient ([13d1481](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/13d1481e8b23f9e17563b2c51065e7843f33b484))
* **sdk:** add prove_execution() — full pipeline without broadcast, returns Transaction JSON ([3ea1c15](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/3ea1c151755a8c6a4f1e1ad6dc4e5d5f1312577e))
* **sdk:** add verify_execution() — deserialize + verify ZK proof locally (JS SDK verifyExecution equivalent) ([ae9cd70](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/ae9cd7062b792d68178cde9f488fb6562dd886f6))


### Bug Fixes

* **client,network:** REST-first mapping query — 修复 get_balance 读不到公开余额 ([37d3eab](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/37d3eab22a87cac54c8eaf9e81c3b9dfeca9fe1f))
* **client:** trim tx_id quotes from broadcast response ([19cefa7](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/19cefa7c0659b48f79c98522c127db063dcef1fe))
* **network:** add fetch_transaction for deploy verification ([ea99a99](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/ea99a997a889012e4a8440570786544711a14f16))
* record scanning - pagination loop, balance parsing, reduced log noise ([5b9c79a](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/5b9c79ad05a34c269cf519f597b088d71999e045))
* set release-please draft to false and fix pr-agent entryPoint ([3746c8a](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/3746c8a3fb0934f2ddc5409dfb7949a4f32136fd))
* **test,ci:** fix CI failures — fmt, clippy, deny, doctest ([5d1c397](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/5d1c39729d0594f3d8d2fa3996f33afe04c3eda7))

## [0.6.0](https://github.com/qiaopengjun5162/aleo-rust-sdk/compare/aleo-rust-sdk-v0.5.1...aleo-rust-sdk-v0.6.0) (2026-10-09)


### Features

* **account:** encrypt_private_key, is_valid_address, destroy — JS SDK feature parity ([bf132b3](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/bf132b3a26c0ad07bf3fc3f9c8a293f17a356d87))
* adapt to snarkVM 4.10.0 crates.io release ([4eba7f0](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/4eba7f0a36b607d04afd215faeccc20cd8c8db28))
* add PR template, PR-Agent config, Release Please, and pre-commit hooks ([3515fba](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/3515fba0bf47d45331e04f27219adefddd195a7d))
* add testnet_transfer example + AleoClient set_program/higher-level API ([6b8b64c](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/6b8b64c9b76948b2435458d56766ff63aeb0ea86))
* add VERSION constant and fix PR-Agent workflow ([c1723e5](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/c1723e54fd0996238b4408c751d5364776d231e9))
* consolidate to single crate aleo-rust-sdk ([6cfc0d9](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/6cfc0d9c77456a74a59fd9c68709c831249eacaf))
* **deploy:** end-to-end testnet deploy verified on chain ([467dedc](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/467dedc210acdb42a36a6a35af13febf44e687f0))
* **deploy:** implement full deploy pipeline ([6fdde7b](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/6fdde7bccc229aa9c9a85a372af50d45e6eaeed6))
* find_private_credits_records (records/all + decrypt) + client helper; v0.2.0 ([dff636d](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/dff636d739dae635ef5250a2265016c712208f26))
* initial SDK structure ([22536d2](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/22536d294876149b3ad6e1742ee17bebcc2aecf0))
* migrate to v2 JSON-RPC, restructure network crate, add testnet_query example ([97a4463](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/97a4463d3475a353bf47571c8a78f4dfa8bc3d7c))
* on-chain state queries (balance, records, block height, state root) ([0f93bf9](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/0f93bf9d49ef6637a93db43a857dcea0b2082702))
* real Aleo testnet transfer — dry-run + prove + broadcast verified ([abf0b82](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/abf0b8249595b0259d27b535fe941248a1246d96))
* **record:** 添加 record 模块 — 记录发现/解密/币选择 + 集成 AleoClient ([13d1481](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/13d1481e8b23f9e17563b2c51065e7843f33b484))
* **sdk:** add prove_execution() — full pipeline without broadcast, returns Transaction JSON ([3ea1c15](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/3ea1c151755a8c6a4f1e1ad6dc4e5d5f1312577e))
* **sdk:** add verify_execution() — deserialize + verify ZK proof locally (JS SDK verifyExecution equivalent) ([ae9cd70](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/ae9cd7062b792d68178cde9f488fb6562dd886f6))


### Bug Fixes

* **client,network:** REST-first mapping query — 修复 get_balance 读不到公开余额 ([37d3eab](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/37d3eab22a87cac54c8eaf9e81c3b9dfeca9fe1f))
* **client:** trim tx_id quotes from broadcast response ([19cefa7](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/19cefa7c0659b48f79c98522c127db063dcef1fe))
* **network:** add fetch_transaction for deploy verification ([ea99a99](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/ea99a997a889012e4a8440570786544711a14f16))
* record scanning - pagination loop, balance parsing, reduced log noise ([5b9c79a](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/5b9c79ad05a34c269cf519f597b088d71999e045))
* **test,ci:** fix CI failures — fmt, clippy, deny, doctest ([5d1c397](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/5d1c39729d0594f3d8d2fa3996f33afe04c3eda7))

## [0.5.0] - 2026-10-06

### Features

- add `ProvableQuery` — real-time Merkle path fetching from `api.provable.com/v2/testnet/statePath/{commitment}`, with auto-cached `global_state_root()` for consistent verification - ([...](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/...))
- add `authorize_and_execute_with_values()` — skip `&str` parsing, accept pre-parsed `Vec<Value>` for record inputs
- add `execute_and_broadcast_with_values()` — same pattern for the high-level client

### Bug Fixes

- fix `transfer_private` — `verify_batch` failed with `InclusionVersion::V0` does not match V1 assignment from `ConsensusVersion::V14`. Changed all `InclusionVersion` references from V0 to V1.
- fix `get_state_paths_for_commitments` — early return `Ok(Vec::new())` for empty commitments list (was returning HTTP 502)
- fix `current_state_root()` — synchronize with the state root encoded in the Merkle path from `StatePath::global_state_root()`

### Breaking Changes

- `ProvableQuery` replaces `FixedStateRootQuery` in `AleoClient` internals; public API unchanged

## [0.4.1] - 2026-10-05

### Features

- add `prove_execution()` — full pipeline without broadcast, returns Transaction JSON - ([3ea1c15](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/3ea1c15c7ab987b8666ae3f02d4086c2e06bb99b))
- add `verify_execution()` — fetch any tx from network, deserialize, verify ZK proof locally (execute + deploy supported) - ([ae9cd70](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/ae9cd70571677e5a45e68de3c6f7e93a5ac6b0c2))

### Bug Fixes

- trim tx_id quotes from broadcast response - ([19cefa7](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/19cefa77aaaa7f24a5f245288c3c8e7f70ded27a))

## [unreleased]

### Features

- find_private_credits_records (records/all + decrypt) + client helper; v0.2.0 - ([dff636d](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/dff636d739dae635ef5250a2265016c712208f26)) - qiaopengjun5162
- adapt to snarkVM 4.10.0 crates.io release - ([4eba7f0](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/4eba7f0a36b607d04afd215faeccc20cd8c8db28)) - qiaopengjun5162
- consolidate to single crate aleo-rust-sdk - ([6cfc0d9](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/6cfc0d9c77456a74a59fd9c68709c831249eacaf)) - qiaopengjun5162
- real Aleo testnet transfer — dry-run + prove + broadcast verified - ([abf0b82](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/abf0b8249595b0259d27b535fe941248a1246d96)) - qiaopengjun5162
- migrate to v2 JSON-RPC, restructure network crate, add testnet_query example - ([97a4463](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/97a4463d3475a353bf47571c8a78f4dfa8bc3d7c)) - qiaopengjun5162
- on-chain state queries (balance, records, block height, state root) - ([0f93bf9](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/0f93bf9d49ef6637a93db43a857dcea0b2082702)) - qiaopengjun5162
- add testnet_transfer example + AleoClient set_program/higher-level API - ([6b8b64c](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/6b8b64c9b76948b2435458d56766ff63aeb0ea86)) - qiaopengjun5162
- initial SDK structure - ([22536d2](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/22536d294876149b3ad6e1742ee17bebcc2aecf0)) - qiaopengjun5162

### Miscellaneous Tasks

- 补齐项目基础设施 — LICENSE/CONTRIBUTING/CHANGELOG/cliff/deny/typos/pre-commit/editorconfig + 升级 CI（coverage/release/audit） + 更新 README（badge/Features/CLI/API参考/Development） - ([16a6708](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/16a6708b791f2b3b156a7f9cc2771522e756ee61)) - qiaopengjun5162

### Refactoring

- remove unnecessary generics from AleoProgram and ExecutionEngine, replace expect with Result in AleoAccount - ([6fe14ee](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/6fe14ee9b90c7a6e7b594a114cb0b1b977dbd5ad)) - qiaopengjun5162
- remove PhantomData, add AleoError, add integration tests, add CI - ([b60b846](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/b60b846a64f68101980f8e042d6ac539ddbd84f4)) - qiaopengjun5162

### Testing

- execution.rs 多重 transition 测试覆盖 + real_prove.rs 最终版 - ([5d562d5](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/5d562d57d2d6c8a9a5233e4555b966e7f54491bf)) - qiaopengjun5162
- network.rs wait_for_confirmation retry + timeout 测试，覆盖率 76.6%→77.5% - ([070e31e](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/070e31e0cdbfc9dff0de23bab24d1dd59ff42266)) - qiaopengjun5162
- 测试覆盖从 21% 提升至 81% - ([4cf8bc1](https://github.com/qiaopengjun5162/aleo-rust-sdk/commit/4cf8bc1bd833ce6221211bd64ff604c2d0aa0e45)) - qiaopengjun5162


<!-- generated by git-cliff -->
