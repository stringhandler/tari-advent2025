use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::anyhow;

#[async_trait::async_trait]
pub trait WalletClient {
    async fn import_view_key(
        &self,
        view_key: &str,
        spend_key: &str,
        password: &str,
        wallet_file: &PathBuf,
    ) -> Result<(), anyhow::Error>;

    async fn scan(
        &self,
        wallet_file: &PathBuf,
        password: &str,
        remote_url: &str,
    ) -> Result<(), anyhow::Error>;
}

pub struct BinaryWalletClient {
    executable_path: String,
}

impl BinaryWalletClient {
    pub fn new(executable_path: String) -> Self {
        Self { executable_path }
    }
}

#[async_trait::async_trait]
impl WalletClient for BinaryWalletClient {
    async fn import_view_key(
        &self,
        view_key: &str,
        spend_key: &str,
        password: &str,
        wallet_file: &PathBuf,
    ) -> Result<(), anyhow::Error> {
        let import_status = Command::new(&self.executable_path)
            .arg("import-view-key")
            .arg("-v")
            .arg(view_key)
            .arg("-s")
            .arg(spend_key)
            .arg("-p")
            .arg("password1")
            .arg("-b")
            .arg("1435")
            .arg("-d")
            .arg(wallet_file)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match import_status {
            Ok(exit_status) => {
                if !exit_status.success() {
                    eprintln!("❌ Failed to import keys");
                    return Err(anyhow!(
                        "Import command failed with status: {}",
                        exit_status
                    ));
                }
                println!("✓ Keys imported successfully");
            }
            Err(e) => {
                eprintln!("❌ Error executing import-view-key: {}", e);
                return Err(anyhow!("Failed to execute import-view-key command: {}", e));
            }
        }
        Ok(())
    }

    async fn scan(
        &self,
        wallet_file: &PathBuf,
        password: &str,
        _remote_url: &str,
    ) -> Result<(), anyhow::Error> {
        let scan_status = Command::new(&self.executable_path)
            .arg("scan")
            .arg("-d")
            .arg(wallet_file)
            .arg("-n")
            .arg("10000")
            .arg("-p")
            .arg(password)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match scan_status {
            Ok(exit_status) => {
                if !exit_status.success() {
                    eprintln!("⚠️  Scan failed, but continuing...");
                } else {
                    println!("✓ Scan completed successfully");
                }
            }
            Err(e) => {
                eprintln!("⚠️  Error executing scan: {}, but continuing...", e);
                return Err(anyhow!("Failed to execute scan command: {}", e));
            }
        }

        Ok(())
    }
}

#[cfg(feature = "libminotari")]
mod libminotari {
    use super::*;
    pub struct CrateWalletClient {}

    impl CrateWalletClient {
        pub fn new() -> Self {
            Self {}
        }
    }

    #[async_trait::async_trait]
    impl WalletClient for CrateWalletClient {
        async fn import_view_key(
            &self,
            view_key: &str,
            spend_key: &str,
            password: &str,
            wallet_file: &PathBuf,
        ) -> Result<(), anyhow::Error> {
            minotari::init_with_view_key(
                view_key,
                spend_key,
                password,
                &wallet_file.to_string_lossy(),
                1435,
                None,
            )
            .await
        }

        async fn scan(
            &self,
            wallet_file: &PathBuf,
            password: &str,
            remote_url: &str,
        ) -> Result<(), anyhow::Error> {
            let scanner =
                minotari::Scanner::new(password, remote_url, &wallet_file.to_string_lossy(), 10);
            match scanner.run().await {
                Ok(_) => println!("✓ Scan completed successfully"),
                Err(e) => {
                    eprintln!("⚠️  Scan failed, but continuing...: {}", e);
                }
            }
            Ok(())
        }
    }
}
