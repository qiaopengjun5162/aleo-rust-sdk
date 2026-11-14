/// Aleo Account Generation Demo
///
/// The very first step for any SDK user: create an account (private key,
/// view key, address), prove the round-trip from a private key string, and
/// show the JS-SDK-compatible encrypted private key format.
///
/// Everything here runs fully offline — no network, no private key needed.
///
/// # Usage
///
/// ```bash
/// cargo run --example generate_account
/// ```
use aleo_rust_sdk::AleoAccount;
use snarkvm::prelude::TestRng;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut rng = TestRng::default();

    // ── 1. Generate a fresh random account ───────────────────────────────
    println!("=== 1. 生成一个全新的 Aleo 账户 ===\n");
    let account = AleoAccount::new_random(&mut rng)?;
    println!("private key : {}", account.private_key_str());
    println!("view key    : {}", account.view_key_str());
    println!("address     : {}", account.address_str());

    // ── 2. Round-trip: reconstruct from the private key string ───────────
    println!("\n=== 2. 用私钥字符串还原账户（一致性校验）===\n");
    let restored = AleoAccount::from_private_key_str(&account.private_key_str())?;
    println!("restored address : {}", restored.address_str());
    println!(
        "round-trip ok    : {}",
        restored.address_str() == account.address_str()
    );

    // ── 3. Validate an address string ───────────────────────────────────
    println!("\n=== 3. 校验地址格式 ===\n");
    let addr = account.address_str();
    println!(
        "is_valid_address({addr}) = {}",
        AleoAccount::is_valid_address(&addr)
    );
    println!(
        "is_valid_address(garbage) = {}",
        AleoAccount::is_valid_address("not-an-address")
    );

    // ── 4. Encrypt the private key with a password ──────────────────────
    // Produces the `ciphertext1...` form that the JS SDK also uses.
    println!("\n=== 4. 用密码加密私钥（ciphertext1... 格式，JS SDK 兼容）===\n");
    let ciphertext = account.encrypt_private_key("hunter2")?;
    println!("encrypted : {ciphertext}");
    let decrypted = AleoAccount::from_ciphertext(&ciphertext, "hunter2")?;
    println!(
        "decrypt round-trip ok : {}",
        decrypted.address_str() == account.address_str()
    );

    println!("\n=== Done ===");
    Ok(())
}
