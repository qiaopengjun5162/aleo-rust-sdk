# Aleo Rust SDK

[![Crates.io](https://img.shields.io/crates/v/aleo-rust-sdk?color=orange)](https://crates.io/crates/aleo-rust-sdk)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE)
[![CI](https://github.com/qiaopengjun5162/aleo-rust-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/qiaopengjun5162/aleo-rust-sdk/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs.rs-aleo--rust--sdk-blue)](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/)
[![Rust](https://img.shields.io/badge/rustc-1.85+-orange?logo=rust)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)

[English](README.md) | [中文](README.zh-CN.md)

基于 **Rust** 的 [Aleo](https://aleo.org) 区块链 SDK，提供账户管理、程序加载、本地零知识证明执行、网络查询和交易广播的全套工具。

> **为什么需要这个 SDK？** 官方 [ProvableHQ/aleo-rust](https://github.com/ProvableHQ/aleo-rust) 已经**存档废弃**，不再维护。本 SDK 基于 snarkVM 4.10.0 和当前 Aleo 测试网的 v2 JSON-RPC 端点提供了最新的实现。

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
- [如何贡献](#如何贡献)
- [许可](#许可)

## 程序包

| 包 | crates.io | docs.rs | 说明 |
|------|-----------|---------|------|
| aleo-rust-sdk | [crates.io](https://crates.io/crates/aleo-rust-sdk) | [docs.rs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/) | **元包** — 包含以下所有模块 |
| aleo-rust-sdk (account) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/account/index.html) | 密钥链：`PrivateKey → ViewKey → ComputeKey → Address` |
| aleo-rust-sdk (program) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/program/index.html) | 程序加载、解析、检查 |
| aleo-rust-sdk (execution) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/execution/index.html) | 授权、执行、证明、打包交易 |
| aleo-rust-sdk (network) | — | [docs](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/network/index.html) | v2 JSON-RPC + REST HTTP 客户端 |
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
| **📋 记录管理** | 按 Owner 取出、解密、过滤私密 `credits.aleo` 记录。跨区块范围扫描记录密文。 |
| **🚀 交易广播** | 提交序列化交易到网络并轮询确认。 |
| **🏗️ 高层客户端** | `AleoClient` 一站式编排完整生命周期：账户 → 程序 → 执行 → 证明 → 广播。 |

## 架构

```text
┌─────────────────────────────────────────────────────┐
│                    AleoClient                        │
│   （高层编排器 — 账户、程序、执行、证明、广播一站式）      │
├──────────┬──────────┬──────────┬─────────────────────┤
│  account │  program │ execution│      network        │
│  │        │         │          │                    │
│  │        │         │          │  AleoHttpClient     │
│ PK → VK  │ 解析     │ 授权     │  ├─ REST (v2)      │
│ CK → ADDR│ 检查     │ 执行     │  ├─ JSON-RPC       │
│  │        │ 从网络    │ 证明     │  └─ broadcast      │
│  ▼        │  ▼       │  ▼      │       ▼            │
│  ────────────────────────────────────────────        │
│              snarkVM 4.10.0 (Process<TestnetV0>)    │
│   （程序加载、授权、执行、证明生成、验证、Transaction）    │
├──────────────────────────────────────────────────────┤
│          reqwest (异步 HTTP) — tokio 运行时           │
└──────────────────────────────────────────────────────┘
```

## 安装

在 `Cargo.toml` 中添加：

```toml
[dependencies]
aleo-rust-sdk = "0.2.0"
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

### 端到端转账

```rust
use aleo_rust_sdk::AleoClient;
use snarkvm::{prelude::TestRng, console::program::ProgramID};
use std::str::FromStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;
    client.set_account_from_private_key_str("APrivateKey1...")?;

    let transfer_id = client.execute_and_broadcast(
        &client.require_account()?.private_key,
        &ProgramID::from_str("credits.aleo")?,
        "transfer_private",
        vec!["aleo1recipient...", "1000000u64"],
        1000,   // base fee（microcredits）
        0,      // priority fee
    ).await?;

    println!("Transaction: {transfer_id}");
    println!("🔗 https://testnet.explorer.provable.com/transaction/{transfer_id}");
    Ok(())
}
```

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
- [ ] **程序部署** — 从 Rust 部署和升级 Aleo 程序
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

# 发送私密转账
aleo-cli transfer --amount 1.5 --to aleo1recipient...
```

## 相关项目

| 项目 | 说明 |
|------|------|
| [ProvableHQ/snarkVM](https://github.com/ProvableHQ/snarkVM) | Aleo 区块链的零知识 VM（本 SDK 的核心依赖） |
| [ProvableHQ/snarkOS](https://github.com/ProvableHQ/snarkOS) | ZK 应用的去中心化操作系统 — Aleo 节点软件 |
| [ProvableHQ/sdk](https://github.com/ProvableHQ/sdk) | 官方 JavaScript/TypeScript Aleo SDK（NPM: `@provablehq/sdk`） |
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

详情请见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 如何贡献

欢迎贡献代码！请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解如何报告 Bug、建议功能或提交代码变更。

## 许可

基于 [MIT 许可证](LICENSE) 或 [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)（可选）开源。

---

<p align="center">
  <b>Aleo Rust SDK</b> — 为 Aleo 生态构建 🚀
</p>
