//! `prototalpid-moderator-proxy`: HTTPS MOLE Moderator reverse proxy enforcing
//! `Mole-Session` rate limits, multi-Anchor EC-IHAT endorsement redemption, and
//! deferred `held-for-update` / `signoff` / `recovery` EC-ACT session deposits.

mod request_policy;
pub mod server;
pub mod store;

pub use request_policy::compute_request_binding;
pub use server::{
    MODERATOR_ISSUE_PATH, ModeratorProxyApp, ModeratorProxyConfig, RunningModeratorProxy,
    spawn_moderator_proxy,
};
pub use store::{
    ModerationPolicy, ModeratorError, ModeratorStore, PresentationVerdict, SessionVerdict,
    TrustedAnchorSet,
};
