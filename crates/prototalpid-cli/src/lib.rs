//! `prototalpid-cli`: MOLE-aware `curl`-subset HTTPS client library and SQLite wallet.

#[allow(dead_code)]
pub mod store;

pub use store::{
    CredentialSummary, EndorsementSummary, PendingSpendRecord, PendingSpendSummary, StoreStatus,
    WalletStore, default_store_path, normalize_origin_input,
};
