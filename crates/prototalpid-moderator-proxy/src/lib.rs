//! `prototalpid-moderator-proxy`: MOLE EC-ACT Moderator HTTPS reverse proxy library.

pub mod store;

pub use store::{
    ModerationPolicy, ModeratorError, ModeratorStore, PresentationVerdict, SessionVerdict,
    TrustedAnchorSet,
};
