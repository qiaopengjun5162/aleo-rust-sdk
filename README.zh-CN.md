# Aleo Rust SDK

[![Crates.io](https://img.shields.io/crates/v/aleo-rust-sdk?color=orange)](https://crates.io/crates/aleo-rust-sdk)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE)
[![CI](https://github.com/qiaopengjun5162/aleo-rust-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/qiaopengjun5162/aleo-rust-sdk/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs.rs-aleo--rust--sdk-blue)](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/)
[![Rust](https://img.shields.io/badge/rustc-1.96+-orange?logo=rust)](https://www.rust-lang.org/)

[English](README.md) | [中文](README.zh-CN.md)

**[Aleo](https://aleo.org) 的 Rust SDK** —— 建账户、转账、生成零知识证明，全程 Rust，不用装 Node.js。

> **为什么需要这个 SDK？** 官方 [ProvableHQ/aleo-rust](https://github.com/ProvableHQ/aleo-rust) 已经**存档废弃**，不再维护。本 SDK 基于 snarkVM 4.12.0 和当前 Aleo 测试网端点提供了最新的实现。

---

## 目录

- [程序包](#程序包)
- [模块地图](#模块地图)
- [功能特性](#功能特性)
- [架构](#架构)
- [安装](#安装)
- [快速开始](#快速开始)
- [从 `@provablehq/sdk` 迁移](#从-provablehqsdk-迁移)
- [示例](#示例)
- [路线图](#路线图)
- [CLI 工具](#cli-工具)
- [相关项目](#相关项目)
- [本地开发](#本地开发)
- [Pre-commit 质量门禁](#pre-commit-质量门禁)
- [如何贡献](#如何贡献)
- [许可](#许可)

## 程序包

| 包 | crates.io | docs.rs | 说明 |
|------|-----------|---------|------|
| aleo-rust-sdk | [crates.io](https://crates.io/crates/aleo-rust-sdk) | [docs.rs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/) | 单一 crate — 下列模块全部在它内部 |
| aleo-rust-sdk (account) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/account/index.html) | 密钥链：`PrivateKey → ViewKey → ComputeKey → Address` |
| aleo-rust-sdk (program) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/program/index.html) | 程序加载、解析、检查 |
| aleo-rust-sdk (execution) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/execution/index.html) | 授权、执行、证明、打包交易 |
| aleo-rust-sdk (network) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/network/index.html) | v2 JSON-RPC + REST HTTP 客户端 + **ProvableQuery**（实时状态路径） |
| aleo-rust-sdk (record) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/record/index.html) | 记录发现、解密和币选择 |
| aleo-rust-sdk (delegated) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/delegated/index.html) | 委托证明：交给 Provable 的 TEE（DPS） |
| aleo-rust-sdk (scanner) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/scanner/index.html) | 记录扫描：交给 Provable 的 TEE（RSS） |
| aleo-rust-sdk (client) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/client/index.html) | 高层 `AleoClient` 编排器 |

CLI 工具 [`aleo-cli`](https://github.com/qiaopengjun5162/aleo-cli) 是一个独立的 crate，构建在本 SDK 之上。

## 模块地图

| 分组 | 模块 | 覆盖内容 |
|------|------|----------|
| **密钥与账户** | `account`、`address`、`private_key`、`view_key`、`compute_key`、`graph_key`、`signature`、`keypair`、`ciphertext`、`private_key_ciphertext` | 密钥链、与 JS 兼容的 `ciphertext1…` 加密私钥、值签名、按记录的 view key |
| **记录** | `record`、`record_plaintext`、`record_ciphertext`、`encryption` | 发现、解密、归属判定、承诺与序列号、币选择 |
| **程序** | `program`、`program_parity`、`metadata` | 加载与解析、JS `Program` 自省、静态参数 URL 目录 |
| **交易** | `transaction`、`transition`、`authorization`、`execution`、`execution_request`、`execution_response`、`proving_key`、`verifying_key`、`proving_request`、`offline_query`、`credits` | 授权 → 执行 → 证明 → 打包、fee 折算、按高度验证、`credits.aleo` 值操作 |
| **密码学原语** | `field`、`group`、`scalar`、`boolean`、`plaintext`、`integer_types`、`hash_functions` | 算术类型的 JS 对拍、九个默认哈希域、checked-halt 与有损转换 |
| **网络** | `network`、`options`、`client`、`hosted`、`delegated`、`scanner` | REST + JSON-RPC 传输、实时 Merkle 路径、一个网络名派生全部服务、TEE 证明/扫描 |
| **领域扩展** | `circle`、`sealance`、`utility_functions` | USDCx hook data、冻结名单排除证明、三个模块级函数 |

47 个模块的逐条说明见 rustdoc 首页。

## 功能特性

| 类别 | 功能 |
|------|------|
| **🔑 账户管理** | 生成、导入、派生 Aleo 账户（PrivateKey, ViewKey, ComputeKey, Address）。完整的密钥派生链。 |
| **📦 程序加载** | 通过 REST API 从网络获取程序、解析 `.aleo` 源文件、检查函数/映射定义。 |
| **⚡ 本地执行** | 本地授权并执行 Aleo 程序 transition，**不上链广播**——适合脱机模拟和测试。 |
| **🔐 证明生成** | 为本地执行生成零知识证明（Varuna V2）。测试网 fee 证明支持 V0 fee 密钥。 |
| **🛡️ 委托证明** (v0.10.0+) | 把证明交给 Provable 的 TEE 证明服务（DPS）。授权用 libsodium sealed box 加密传输，返回可直接广播的交易——15–60 秒本地 CPU 换成一次网络往返。 |
| **🔍 记录扫描** (v0.10.0+) | 把 view key 加密注册给 Provable 的记录扫描服务（RSS），由 TEE 一次性索引，之后按 `uuid` 查询，不必再翻 `records/all`。返回的密文仍在本地解密，伪造响应造不出可花的记录。 |
| **🌐 网络查询** | 区块高度、最新区块、按高度**或**哈希取块、区块区间、单块交易列表、交易查询、委员会与内存池、程序源码与映射值、状态根（最新**与**按高度）、以及从状态根反查所属高度。 |
| **🔗 实时状态路径** (v0.5.0+) | `ProvableQuery` 从 `api.provable.com/v2/testnet/statePath/{commitment}` 实时获取 Merkle 路径，并缓存该路径构建时对应的状态根——证明与它验证所依据的根不会对不上。不在链上的 commitment 会被回 **502**，没有 not-found 码：要读成「没有这条路径」，而不是「再试一次」。 |
| **📋 记录管理** | 按 Owner 取出、解密、过滤私密 `credits.aleo` 记录。跨区块范围扫描记录密文。 |
| **🚀 交易广播** | 提交序列化交易并等待上链。确认走 `/transaction/confirmed/{id}`：未上链 404，已上链 200 + `status` 字段——节点只是收进内存池，绝不会被当成最终确认。 |
| **🏗️ 高层客户端** | `AleoClient` 一站式编排完整生命周期：账户 → 程序 → 执行 → 证明 → 广播。 |

## 架构

```text
┌─────────────────────────────────────────────────────┐
│                    AleoClient                        │
│   （高层编排器 — 账户、程序、执行、证明、广播一站式）      │
├──────────┬──────────┬──────────┬──────────────────────┤
│  account │  program │ execution│      network         │
│  │        │         │          │                     │
│  │        │         │          │  AleoHttpClient      │
│ PK → VK  │ 解析     │ 授权     │  ├─ REST (v2)       │
│ CK → ADDR│ 检查     │ 执行     │  ├─ JSON-RPC        │
│  │        │ 从网络    │ 证明     │  ├─ ProvableQuery   │
│  ▼        │  ▼       │  ▼      │       ▼            │
├──────────┴──────────┴──────────┴──────────────────────┤
│  record                                                │
│  AleoRecord · RecordScanner · RecordManager · 币选择   │
├────────────────────────────────────────────────────────┤
│            snarkVM 4.12.0 (Process<TestnetV0>)         │
│          reqwest (异步 HTTP) — tokio 运行时           │
└──────────────────────────────────────────────────────┘
```

**v0.5.0+ 新增：** `ProvableQuery`（位于 network 层）替代了哑实现 `FixedStateRootQuery`。它通过 `ureq` 从 `api.provable.com/v2/testnet/statePath/{commitment}` 实时获取 Merkle 状态路径，缓存响应中的 `global_state_root()`，并在 `current_state_root()` 中返回——确保证明验证所用的状态根与 Merkle 路径构建时的根一致。

## 安装

在 `Cargo.toml` 中添加：

```toml
[dependencies]
aleo-rust-sdk = "0.11"
tokio = { version = "1", features = ["full"] }
```

**要求：**
- Rust **1.96+**（snarkVM 4.12.0 本身要求）
- snarkVM **4.12.0**（自动解析）
- 证明生成：推荐 ~16 GB RAM

## 快速开始

### 查询测试网（无需账户）

```rust
use aleo_rust_sdk::AleoClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;

    let height = client.get_block_height().await?;
    let root = client.get_state_root().await?;
    println!("Block height: {height}");
    println!("State root:   {root}");

    Ok(())
}
```

### 生成账户 + 查询余额

```rust
use aleo_rust_sdk::{AleoClient, AleoAccount};
use snarkvm::prelude::TestRng;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut rng = TestRng::default();
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;

    // 创建随机账户
    let account = AleoAccount::new_random(&mut rng)?;
    println!("Address: {}", account.address_str());

    // 设置账户
    client.set_account_from_private_key_str(&account.private_key_str())?;

    // 查询网络
    let height = client.get_block_height().await?;
    println!("Block height: {height}");

    // 查询余额（新账户返回 None）
    let balance = client.get_balance().await?;
    match balance {
        Some(b) => println!("余额: {b} microcredits"),
        None => println!("未找到 credits（新账户）"),
    }

    Ok(())
}
```

### 公开转账（简单字符串输入）

```rust
use aleo_rust_sdk::AleoClient;
use snarkvm::{prelude::TestRng, console::program::ProgramID};
use std::str::FromStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;
    client.set_account_from_private_key_str("APrivateKey1...")?;

    let tx_id = client.execute_and_broadcast(
        &client.require_account()?.private_key,
        &ProgramID::from_str("credits.aleo")?,
        "transfer_public",
        vec!["aleo1recipient...", "1000000u64"],
        0,       // priority fee
    ).await?;

    println!("Transaction: {tx_id}");
    println!("🔗 https://testnet.aleo.info/tx/{tx_id}");
    Ok(())
}
```

### 私密转账（记录解密）

私密转账需要提供**解密的记录值**，而非原始 `&str` 参数。使用 `execute_and_broadcast_with_values`（v0.5.0+）传入预先解析的 `Vec<Value>`：

```rust
use aleo_rust_sdk::AleoClient;
use snarkvm::{
    prelude::{TestRng, Network, FromBytes},
    console::{
        program::{Value, Record, Ciphertext, Literal, Plaintext, Identifier},
        account::ViewKey,
        network::TestnetV0,
    },
    utilities::Deserialize,
};
use std::str::FromStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;
    client.set_account_from_private_key_str("APrivateKey1...")?;

    // 加载记录（从文件、扫描或缓存）
    let ciphertext = Ciphertext::from_str("record1qyq...")?;
    let view_key = ViewKey::from_str("AViewKey1...")?;

    // 解密记录
    let record = ciphertext.decrypt(&view_key)?;

    // 构建输入值
    // credits.aleo transfer_private(record, address, u64) -> (record)
    let values = vec![
        Value::Record(record),
        Value::from_str("aleo1recipient...")?,
        Value::from_str("1000000u64")?,
    ];

    let tx_id = client.execute_and_broadcast_with_values(
        &client.require_account()?.private_key,
        &ProgramID::from_str("credits.aleo")?,
        "transfer_private",
        values,
        0,       // priority fee
    ).await?;

    println!("Private transfer: {tx_id}");
    Ok(())
}
```

CLI 工具会自动处理这个流程——参见下面 `aleo-cli transfer --mode private` 命令。

## 从 `@provablehq/sdk` 迁移

本 crate 逐页对拍了 **`@provablehq/sdk` WASM API Reference 的 32 个页面**（#51–#79）。完整对照（每一类、每个入口、六个坑、已知边界）见 [`docs/js-rust-guide.md`](docs/js-rust-guide.md)（英文）。要点：

### 先别找同名函数

对拍时先问的是「**snarkVM 原生有没有这个类型**」，而不是「这个方法在 Rust 里叫什么」。

| 上游 wasm 形态 | Rust 侧做法 |
|---|---|
| 原生类型的薄包装（大多数页面） | 薄壳转发给 snarkVM（`Address`、`ViewKey`、`Field`、`Signature` 等） |
| wasm **自己打包**的 bundle / 无 tag 枚举 | 新建泛型容器，因为 snarkVM 没有对应物（`ExecutionResponse`、`KeyPair`、`OfflineQuery`、`ProvingRequest`） |
| 给原生类型加的便利方法 | 直接复用原生类型，不造平行类（`U8..I128`、九个哈希域） |

`get*` 开头**不代表只读**：`KeyPair` 第一次取就把钥匙交出去，语义等同 `Option::take()`。

### 类别对照

| JS 能力 | Rust 入口 |
|---|---|
| `new Account()`、导入导出 | `AleoAccount::{new_random, from_private_key_str, from_seed}` |
| `RecordPlaintext` 成员、承诺 | `RecordPlaintext::{owner, get_member, microcredits, commitment, serial_number_string, to_fields, …}` |
| `Program.getFunctions` / `getMappings` / `getImports` | `program_parity::{get_functions, get_function_inputs, get_mappings, get_struct_members, get_imports, …}` |
| `Transaction` 解析、fee 折算 | `Transaction::{from_string, id, transaction_type, fee_amount, owned_records, summary, …}` |
| `hashBHP256` / `hashPedersen64` / `hashPoseidon2` 等 | `hash_functions::{bhp256, bhp512, bhp768, bhp1024, pedersen64, pedersen128, poseidon2, poseidon4, poseidon8}` |
| `getOrInitConsensusVersionTestHeights`、`verifyFunctionExecution` | `utility_functions::{consensus_version_test_heights, verify_function_execution}` |

### 第一次编译前值得知道的六个坑

| # | 现象 | 做法 |
|---|---|---|
| 1 | 加密函数签名对不上 | snarkVM 4.12 用 **rand 0.10**；把 RNG 注入进去，别用 `rand = 0.8` 项目的 `OsRng` |
| 2 | `Field::inverse()` 结果不对 | 它是**加法逆**；只有 `Group` 有真正的群逆，且 `Group::scalar_multiply` 不存在，写 `group * scalar` |
| 3 | `i128` / `u128` 的 JSON 变了 | 序列化成**字符串** |
| 4 | 找不到 BHP `hashToGroup` | BHP 不实现 `HashToGroup`，用 `HashUncompressed::hash_uncompressed` |
| 5 | 跨宽度转换结果怪 | 「checked」类操作是 `E::halt`（panic）；加宽**不做符号扩展**（`-1i8` → `255i32`） |
| 6 | `Program::from_str` 解析失败 | `import` 必须写在 program 声明之前；字面量要带显式后缀 |

## 示例

| 示例 | 源码 | 说明 |
|------|------|------|
| `testnet_query` | [examples/testnet_query.rs](examples/testnet_query.rs) | 查询测试网：区块高度、状态根、程序信息（无需密钥） |
| `testnet_transfer` | [examples/testnet_transfer.rs](examples/testnet_transfer.rs) | 完整流水线：授权 → 执行 → 证明 → 广播 credits 转账 |
| `simple_execute` | [examples/simple_execute.rs](examples/simple_execute.rs) | 最小工作流：加载程序、本地执行（脱机模拟） |
| `sdk_v2_broadcast_test` | [examples/sdk_v2_broadcast_test.rs](examples/sdk_v2_broadcast_test.rs) | 对测试网走一遍 v2 REST 接口与广播路径（需要 `PRIVATE_KEY`，会真实广播一笔 1 microcredit 自转） |

运行示例：

```bash
# 查询测试网（无需私钥）
cargo run --example testnet_query

# 完整转账（需要 PRIVATE_KEY 环境变量）
export PRIVATE_KEY="APrivateKey1..."
cargo run --example testnet_transfer

# 本地脱机执行
cargo run --example simple_execute

# 测试网真实广播 —— 需要 PRIVATE_KEY 且账户有测试网余额。
# 会真实发送一笔 1 microcredit 自转交易并消耗测试网手续费。
export PRIVATE_KEY="APrivateKey1..."
cargo run --example sdk_v2_broadcast_test
```

## 路线图

计划中的功能（按优先级排序）：

- [ ] **WASM 支持** — 通过 `wasm-pack` 编译 SDK 以支持浏览器/Node.js
- [ ] **交易历史** — 获取并解码历史交易
- [x] **程序部署辅助** — 简化 program ID 和 edition 处理
- [ ] **主网支持** — 在测试网之外添加主网配置
- [x] **记录合并** — 将多个小额记录合并为一个大记录
- [ ] **批量转账** — 单笔交易发送多次转账
- [ ] **类型安全程序绑定** — 从 Aleo 程序映射生成 Rust 结构体

## CLI 工具

[`aleo-cli`](https://github.com/qiaopengjun5162/aleo-cli) 命令行工具构建在本 SDK 之上：

```bash
# 安装
cargo install aleo-cli

# 查询测试网状态
aleo-cli query

# 查询账户余额
aleo-cli balance aleo1cu0xk4tt99pgxglpqltzk3tmpgh7qftjwukxcmewzpy0fkqghvgsxu0g03

# 生成新 Aleo 账户
aleo-cli generate

# 发送公开转账
aleo-cli transfer aleo1ss6e8... 1000000 --mode public

# 发送私密转账 (v0.4.0+)
aleo-cli transfer aleo1ss6e8... 30000 --mode private

# 部署程序
aleo-cli deploy /path/to/program.aleo program_name

# 执行并广播
aleo-cli exec credits.aleo transfer_public aleo1ss6e8... 1000u64

# 验证链上交易
aleo-cli verify at136grnr...

# 深度 ZK 证明验证
aleo-cli verify at136grnr... --deep
```

## 相关项目

| 项目 | 说明 |
|------|------|
| [ProvableHQ/snarkVM](https://github.com/ProvableHQ/snarkVM) | Aleo 区块链的零知识 VM（本 SDK 的核心依赖） |
| [ProvableHQ/snarkOS](https://github.com/ProvableHQ/snarkOS) | ZK 应用的去中心化操作系统 — Aleo 节点软件 |
| [ProvableHQ/sdk](https://github.com/ProvableHQ/sdk) | 官方 JavaScript/TypeScript Aleo SDK（NPM: `@provablehq/sdk`） |
| [Provable API v2 文档](https://docs.explorer.provable.com/docs/api/v2/intro) | REST API 参考 — 区块查询、状态路径、交易数据 |
| [qiaopengjun5162/aleo-cli](https://github.com/qiaopengjun5162/aleo-cli) | 构建在本 SDK 之上的 Aleo CLI 工具 |
| [AleoNet/workshop](https://github.com/AleoNet/workshop) | Aleo ZK 应用入门指南 |
| [Aleo developer docs](https://developer.aleo.org/) | 官方 Aleo 开发者文档 |

## 本地开发

```bash
git clone https://github.com/qiaopengjun5162/aleo-rust-sdk.git
cd aleo-rust-sdk

# 构建
just build            # cargo build --all-features
just build-release    # release 模式构建

# 测试（装了 nextest 用它，没装则回落到 cargo test）
just test             # cargo nextest run --all-features || cargo test --all-features

# 代码检查
just check            # cargo check --all-features
just clippy           # cargo clippy --all-targets --all-features -- -D warnings
just format           # cargo fmt --all -- --check

# 依赖与许可证审计
just audit            # cargo deny check

# 生成文档（docs-open 会同时打开浏览器）
just docs             # cargo doc --no-deps --all-features

# 覆盖率报告
just coverage         # cargo llvm-cov --all-features --lcov --output-path lcov.info

# 本地快速检查——不是 CI 门禁
just all              # format + check + clippy + test
```

> 🔴 **`just all` 可能本地全绿、CI 全红。** 它早于现在的工作流：不跑 `taplo`、
> `typos`、`cargo deny`、带 `-D warnings` 的 rustdoc、doc-test，也不跑覆盖率门禁。
> 用它加速本地循环可以，别拿它当可以推送的依据。

推送前要对齐 CI 门禁，用这条——步骤和顺序与 workflow 完全一致：

```bash
just gate       # fmt、taplo、typos、clippy、deny、rustdoc、test、doc-test
just gate-cov   # 上面全部 + llvm-cov 的 87% 行覆盖门禁（慢，10 分钟以上）
```

> 🔴 `cargo check`、不带 `--tests` 的 `cargo clippy`、`cargo doc` **都不编译
> `#[cfg(test)]` 模块**——改完测试代码务必单独跑 `cargo test`。`cargo nextest`
> 也不跑 doc-test，所以 `gate` 里单独加了 `cargo test --doc` 一步。

## Pre-commit 质量门禁

本项目使用 [pre-commit](https://pre-commit.com) 在每个提交前自动执行代码质量检查：

```bash
# 安装钩子（克隆后只需运行一次）
pre-commit install --hook-type pre-commit --hook-type commit-msg

# 或手动运行所有检查
pre-commit run --all-files
```

`.pre-commit-config.yaml` 里定义了 **11 个钩子**，但它们不在同一时刻运行——其中
三个分别在 `pre-push` 和 `commit-msg` 阶段：

| 阶段 | 钩子 | 检查内容 |
|------|------|---------|
| commit-msg | conventional-pre-commit | 提交信息符合 Conventional Commits |
| pre-commit | trailing-whitespace | 无尾随空格 |
| pre-commit | end-of-file-fixer | 文件以换行符结尾 |
| pre-commit | check-added-large-files | 不提交超过 500 KB 的文件 |
| pre-commit | check-merge-conflict | 无未解决的合并标记 |
| pre-commit | check-yaml | YAML 语法有效性 |
| pre-commit | check-toml | TOML 语法有效性（含本文件） |
| pre-commit | cargo fmt | `cargo fmt --all -- --check` |
| pre-commit | cargo clippy | `cargo clippy --all-targets --all-features -- -D warnings` |
| pre-commit | cargo check | `cargo check --all-features` |
| pre-push | cargo test | `cargo test`——最慢的那个，所以留到推送时 |

`pre-commit run --all-files` **只跑 `pre-commit` 阶段**，也就是 11 个里的 9 个：
不检查提交信息，也不跑测试。测试要么自己跑 `cargo test`，要么交给推送钩子。

**`language: system` 说明：** 所有本地钩子使用 `language: system`（而非 `language: rust`），直接从系统 PATH 运行工具。这确保钩子实际执行而不是静默跳过。

> **历史：** v0.4.1 及更早版本的 `.pre-commit-config.yaml` 使用了 `language: rust`，导致所有钩子静默跳过（pre-commit 尝试从 crates.io 安装它们）。v0.5.0 切换为 `language: system` 并运行 `pre-commit install` 后修复。

## 如何贡献

欢迎贡献代码！请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解如何报告 Bug、建议功能或提交代码变更。

**提交 PR 之前：**
1. 在本地复现门禁：`just gate`（**不是** `just all`，原因见[本地开发](#本地开发)一节）
2. 写符合 [conventional commits](https://www.conventionalcommits.org/) 的提交信息。
   这**就是**更新日志的工作：`CHANGELOG.md` 由 release-please 从提交标题自动生成，
   手动改会在下次发版时被覆盖，还可能与 release PR 冲突。不符合规范的提交信息会被
   钩子直接拒绝。
3. 让 CI 通过 (GitHub Actions)

## 许可

基于 [MIT 许可证](LICENSE) 或 [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)（可选）开源。

---

<p align="center">
  <b>Aleo Rust SDK</b> — 为 Aleo 生态构建 🚀
</p>
