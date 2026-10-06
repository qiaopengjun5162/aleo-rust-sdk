# Aleo Rust SDK

[![Crates.io](https://img.shields.io/crates/v/aleo-rust-sdk?color=orange)](https://crates.io/crates/aleo-rust-sdk)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE)
[![CI](https://github.com/qiaopengjun5162/aleo-rust-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/qiaopengjun5162/aleo-rust-sdk/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs.rs-aleo--rust--sdk-blue)](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/)
[![Rust](https://img.shields.io/badge/rustc-1.85+-orange?logo=rust)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)

[English](README.md) | [中文](README.zh-CN.md)

基于 **Rust** 的 [Aleo](https://aleo.org) 区块链 SDK，提供账户管理、程序加载、本地零知识证明执行、网络查询、交易广播，以及**实时 Merkle 路径获取**（通过 Provable API v2）的全套工具。

> **为什么需要这个 SDK？** 官方 [ProvableHQ/aleo-rust](https://github.com/ProvableHQ/aleo-rust) 已经**存档废弃**，不再维护。本 SDK 基于 snarkVM 4.10.0 和当前 Aleo 测试网端点提供了最新的实现。

---

## 目录

- [程序包](#程序包)
- [功能特性](#功能特性)
- [架构](#架构)
- [安装](#安装)
- [快速开始](#快速开始)
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
| aleo-rust-sdk | [crates.io](https://crates.io/crates/aleo-rust-sdk) | [docs.rs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/) | **元包** — 包含以下所有模块 |
| aleo-rust-sdk (account) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/account/index.html) | 密钥链：`PrivateKey → ViewKey → ComputeKey → Address` |
| aleo-rust-sdk (program) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/program/index.html) | 程序加载、解析、检查 |
| aleo-rust-sdk (execution) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/execution/index.html) | 授权、执行、证明、打包交易 |
| aleo-rust-sdk (network) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/network/index.html) | v2 JSON-RPC + REST HTTP 客户端 + **ProvableQuery**（实时状态路径） |
| aleo-rust-sdk (record) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/record/index.html) | 记录发现、解密和币选择 |
| aleo-rust-sdk (client) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/client/index.html) | 高层 `AleoClient` 编排器 |

CLI 工具 [`aleo-cli`](https://github.com/qiaopengjun5162/aleo-cli) 是一个独立的 crate，构建在本 SDK 之上。

## 功能特性

| 类别 | 功能 |
|------|------|
| **🔑 账户管理** | 生成、导入、派生 Aleo 账户（PrivateKey, ViewKey, ComputeKey, Address）。完整的密钥派生链。 |
| **📦 程序加载** | 通过 REST API 从网络获取程序、解析 `.aleo` 源文件、检查函数/映射定义。 |
| **⚡ 本地执行** | 本地授权并执行 Aleo 程序 transition，**不上链广播**——适合脱机模拟和测试。 |
| **🔐 证明生成** | 为本地执行生成零知识证明（Varuna V2）。测试网 fee 证明支持 V0 fee 密钥。 |
| **🌐 网络查询** | 通过 REST + JSON-RPC 查询区块高度、状态根、程序源码、映射值。 |
| **🔗 实时状态路径** (v0.5.0+) | `ProvableQuery` 从 `api.provable.com/v2/testnet/statePath/{commitment}` 实时获取 Merkle 路径——不再有哑查询或 502 错误。 |
| **📋 记录管理** | 按 Owner 取出、解密、过滤私密 `credits.aleo` 记录。跨区块范围扫描记录密文。 |
| **🚀 交易广播** | 提交序列化交易到网络并轮询确认。 |
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
│            snarkVM 4.10.0 (Process<TestnetV0>)         │
│          reqwest (异步 HTTP) — tokio 运行时           │
└──────────────────────────────────────────────────────┘
```

**v0.5.0+ 新增：** `ProvableQuery`（位于 network 层）替代了哑实现 `FixedStateRootQuery`。它通过 `ureq` 从 `api.provable.com/v2/testnet/statePath/{commitment}` 实时获取 Merkle 状态路径，缓存响应中的 `global_state_root()`，并在 `current_state_root()` 中返回——确保证明验证所用的状态根与 Merkle 路径构建时的根一致。

## 安装

在 `Cargo.toml` 中添加：

```toml
[dependencies]
aleo-rust-sdk = "0.5.0"
tokio = { version = "1", features = ["full"] }
```

**要求：**
- Rust **1.85+**
- snarkVM **4.10.0**（自动解析）
- 证明生成：推荐 ~16 GB RAM

## 快速开始

### 查询测试网（无需账户）

```rust
use aleo_rust_sdk::AleoClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = AleoClient::new("https://api.provable.com/v2/testnet")?;

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
    let mut client = AleoClient::new("https://api.provable.com/v2/testnet")?;

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
    let mut client = AleoClient::new("https://api.provable.com/v2/testnet")?;
    client.set_account_from_private_key_str("APrivateKey1...")?;

    let tx_id = client.execute_and_broadcast(
        &client.require_account()?.private_key,
        &ProgramID::from_str("credits.aleo")?,
        "transfer_public",
        vec!["aleo1recipient...", "1000000u64"],
        50000,   // base fee（microcredits）
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
    let mut client = AleoClient::new("https://api.provable.com/v2/testnet")?;
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
        50000,
        0,
    ).await?;

    println!("Private transfer: {tx_id}");
    Ok(())
}
```

CLI 工具会自动处理这个流程——参见下面 `aleo-cli transfer --mode private` 命令。

## 示例

| 示例 | 源码 | 说明 |
|------|------|------|
| `testnet_query` | [examples/testnet_query.rs](examples/testnet_query.rs) | 查询测试网：区块高度、状态根、程序信息（无需密钥） |
| `testnet_transfer` | [examples/testnet_transfer.rs](examples/testnet_transfer.rs) | 完整流水线：授权 → 执行 → 证明 → 广播 credits 转账 |
| `simple_execute` | [examples/simple_execute.rs](examples/simple_execute.rs) | 最小工作流：加载程序、本地执行（脱机模拟） |

运行示例：

```bash
# 查询测试网（无需私钥）
cargo run --example testnet_query

# 完整转账（需要 PRIVATE_KEY 环境变量）
export PRIVATE_KEY="APrivateKey1..."
cargo run --example testnet_transfer

# 本地脱机执行
cargo run --example simple_execute
```

## 路线图

计划中的功能（按优先级排序）：

- [ ] **WASM 支持** — 通过 `wasm-pack` 编译 SDK 以支持浏览器/Node.js
- [ ] **交易历史** — 获取并解码历史交易
- [ ] **程序部署辅助** — 简化 program ID 和 edition 处理
- [ ] **主网支持** — 在测试网之外添加主网配置
- [ ] **记录合并** — 将多个小额记录合并为一个大记录
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
aleo-cli exec credits.aleo transfer_public aleo1ss6e8... 1000u64 --base-fee 50000

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

# 测试
just test             # cargo nextest run --all-features

# 代码检查
just check            # cargo check --all-features
just clippy           # cargo clippy -- -D warnings
just format           # cargo fmt --all -- --check

# 生成文档
just docs             # cargo doc --no-deps --open

# 完整检查
just all              # format + check + clippy + test
```

## Pre-commit 质量门禁

本项目使用 [pre-commit](https://pre-commit.com) 在每个提交前自动执行代码质量检查：

```bash
# 安装钩子（克隆后只需运行一次）
pre-commit install --hook-type pre-commit --hook-type commit-msg

# 或手动运行所有检查
pre-commit run --all-files
```

每次 `git commit` 前自动运行以下 12 项检查：

| # | 钩子 | 检查内容 |
|---|------|---------|
| 1 | fix-byte-order-marker | BOM 编码 |
| 2 | check-case-conflict | 大小写敏感的文件名冲突 |
| 3 | check-merge-conflict | 未解决的合并标记 |
| 4 | check-symlinks | 损坏的符号链接 |
| 5 | check-yaml | YAML 语法有效性 |
| 6 | end-of-file-fixer | 文件以换行符结尾 |
| 7 | mixed-line-ending | 一致的行尾符 |
| 8 | trailing-whitespace | 无尾随空格 |
| 9 | cargo fmt | Rust 格式 (`cargo fmt --check`) |
| 10 | cargo check | 编译检查 (`cargo check`) |
| 11 | cargo clippy | 代码规范 (`cargo clippy -- -D warnings`) |
| 12 | typos | 拼写错误检测 |

**`language: system` 说明：** 所有本地钩子使用 `language: system`（而非 `language: rust`），直接从系统 PATH 运行工具。这确保钩子实际执行而不是静默跳过。

> **历史：** v0.4.1 及更早版本的 `.pre-commit-config.yaml` 使用了 `language: rust`，导致所有钩子静默跳过（pre-commit 尝试从 crates.io 安装它们）。v0.5.0 切换为 `language: system` 并运行 `pre-commit install` 后修复。

## 如何贡献

欢迎贡献代码！请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解如何报告 Bug、建议功能或提交代码变更。

**提交 PR 之前：**
1. 确保 pre-commit 钩子通过 (`pre-commit run --all-files`)
2. 检查 CI 通过 (GitHub Actions)
3. 按照 [conventional commits](https://www.conventionalcommits.org/) 更新 CHANGELOG.md

## 许可

基于 [MIT 许可证](LICENSE) 或 [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)（可选）开源。

---

<p align="center">
  <b>Aleo Rust SDK</b> — 为 Aleo 生态构建 🚀
</p>
