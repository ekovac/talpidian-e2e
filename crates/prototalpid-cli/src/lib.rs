//! `prototalpid-cli`: MOLE-aware `curl`-subset HTTPS client library and SQLite wallet.

pub mod client;
pub mod store;

pub use client::{HttpResponseData, MoleClient, MoleClientOptions};
pub use store::{
    CredentialSummary, EndorsementSummary, PendingSpendRecord, PendingSpendSummary, StoreStatus,
    WalletStore, default_store_path, normalize_origin_input,
};
