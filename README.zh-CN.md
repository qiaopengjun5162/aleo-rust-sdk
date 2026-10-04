# Aleo Rust SDK

[![Crates.io](https://img.shields.io/crates/v/aleo-rust-sdk?color=orange)](https://crates.io/crates/aleo-rust-sdk)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![CI](https://github.com/qiaopengjun5162/aleo-rust-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/qiaopengjun5162/aleo-rust-sdk/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs.rs-aleo--rust--sdk-blue)](https://docs.rs/aleo-rust-sdk/latest/aleo_rust_sdk/)
[![Rust](https://img.shields.io/badge/rustc-1.85+-orange?logo=rust)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)

[English](README.md) | [中文](README.zh-CN.md)

基于 **Rust** 的 [Aleo](https://aleo.org) 区块链 SDK，提供账户管理、程序加载、本地执行、证明生成、网络查询和交易广播的全套工具。

> **注意：** 官方 [ProvableHQ/aleo-rust](https://github.com/ProvableHQ/aleo-rust) 已**存档废弃**。
> 本 SDK 基于 snarkVM 最新 API 和当前 v2/testnet JSON-RPC 端点填补了这一空白。

## 整体架构

| 模块 | 作用 |
|--------|---------|
| `account` | 密钥链：`PrivateKey → ViewKey → ComputeKey → Address` |
| `program` | 加载、解析和检查 Aleo 程序 |
| `execution` | 授权、执行、证明和打包交易 |
| `network` | Aleo v2 JSON-RPC 和 REST 端点的 HTTP 客户端 |
| `client` | 高层 `AleoClient`，编排完整生命周期 |

## 功能特性

- **账户管理** — 生成密钥、派生地址、处理 ViewKey
- **程序加载** — 从网络获取、解析和检查 Aleo 程序
- **本地执行** — 授权并执行 transition，不上链广播
- **证明生成** — 为本地执行生成零知识证明
- **网络查询** — 区块高度、状态根、程序信息、记录扫描
- **记录管理** — 按 Owner 取出、解密、过滤私密记录
- **交易广播** — 提交并确认 Aleo 测试网交易
- **高层客户端** — `AleoClient` 一站式编排端到端流程

## 安装

在 `Cargo.toml` 中添加：

```toml
[dependencies]
aleo-rust-sdk = "0.2.0"
```

本 SDK 要求 **Rust 1.85+**，依赖 **snarkVM 4.10.0**。

## 快速开始

```rust
use aleo_rust_sdk::{AleoClient, AleoAccount};
use snarkvm::prelude::TestRng;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut rng = TestRng::default();
    let client = AleoClient::new("https://api.explorer.provable.com/v2/testnet")?;

    // 创建一个随机账户
    let account = AleoAccount::new_random(&mut rng)?;
    println!("Address: {}", account.address_str());

    // 查询网络状态
    let height = client.get_block_height().await?;
    println!("Block height: {height}");

    Ok(())
}
```

## 示例

| 示例 | 说明 |
|---------|------|
| `testnet_query` | 查询测试网：区块高度、状态根、程序信息（无需密钥） |
| `testnet_transfer` | 完整流水线：授权 → 执行 → 证明 → 广播 credits 转账 |
| `simple_execute` | 最小工作流：加载程序、本地执行（脱机模拟） |

运行示例：

```bash
# 查询测试网状态（不需要私钥）
cargo run --example testnet_query

# 完整转账（需要设置 PRIVATE_KEY 环境变量）
export PRIVATE_KEY="APrivateKey1..."
cargo run --example testnet_transfer

# 本地脱机模拟执行
cargo run --example simple_execute
```

## CLI 工具

[`aleo-cli`](https://github.com/qiaopengjun5162/aleo-cli) 命令行工具构建在本 SDK 之上：

```bash
# 安装
cargo install aleo-cli

# 查询测试网状态
aleo-cli query

# 查询账户余额
aleo-cli balance <ADDRESS>

# 生成新 Aleo 账户
aleo-cli generate

# 发送私密转账
aleo-cli transfer --amount 1.5 --to <RECIPIENT_ADDRESS>
```

## API 参考

| 模块 | 关键类型 | 关键方法 |
|--------|-----------|-------------|
| `AleoAccount` | `PrivateKey`, `ViewKey`, `ComputeKey`, `Address` | `new_random()`, `from_private_key()`, `address_str()` |
| `AleoProgram` | `Program`, `ProgramManager` | `from_str()`, `get_function()`, `get_mappings()` |
| `AleoExecutor` | `Execution`, `ProvingKey`, `VerifyingKey` | `authorize()`, `execute()`, `prove()`, `package_transaction()` |
| `AleoHttpClient` | `reqwest::Client` | `get_block_height()`, `get_state_root()`, `fetch_program()`, `fetch_all_records()`, `broadcast_transaction()` |
| `AleoClient` | 高层编排器 | `find_private_credits_records()`, `get_balance()`, `transfer_private()` |

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

# 测试覆盖率
just coverage         # cargo llvm-cov --all-features --lcov

# 完整检查套件
just all              # format + check + clippy + test
```

## 如何贡献

欢迎贡献代码！请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解如何报告 Bug、建议功能或提交代码变更。

## 许可

本项目基于 [MIT 许可证](LICENSE) 开源。

---

<p align="center">
  <b>Aleo Rust SDK</b> — 为 Aleo 生态构建 🚀
</p>
