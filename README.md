# talpidian-e2e
A [Moderation of unLinkable Endorsements (MOLE)](https://github.com/Moderation-of-unLinkable-Endorsements/internet-drafts) proof-of-concept that with a command-line client, a moderator reverse proxy implementation, and an anchor implementation.

This will likely never be production-ready. Do not use this in production, I certainly won't be. This will most likely be heavily AI-assisted, so don't take the code quality as an indicator of my competence (in either direction.)

## Background Reading

### Motivation
* [Moving past bots vs. humans](https://blog.cloudflare.com/past-bots-and-humans/)

### MOLE

Listed by their relative maturity level; less mature documents should be expected to change significantly in the future, and architectural choices should be made to reduce the cost of changes in less mature documents. Refer to the [MOLE internet drafts repository]((https://github.com/Moderation-of-unLinkable-Endorsements/internet-drafts) README for the canonical status, this categorization is just for reference by myself and by agents.

* Mature (changes in non-normative wording or small normative details are likely, but broad strokes likely represent the final state)
  * [MOLE Architecture](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-jms-mole-architecture.html)
  * [EC-IHAT (Endorsement/scarce-resource bootstrapping crypto protocol)](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-ladd-mole-ec-ihat.html)
  * [EC-ACT (Credential/client reputation crypto protocol)](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-ladd-mole-ec-ihat.html)
* Active Development (discussion or validation of these components is ongoing and significant changes are likely)
  * [MOLE Protocols](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-jms-mole-protocols.html)
  * [VOLE-IHAT (Candidate Endorsement/scarce-resource bootstrapping crypto protocol enabling federation via multi-presentation)](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-authors-mole-vole-ihat.html)
  * [MOLE HTTP Transport](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-jms-mole-http-transport.html)
* Concept Phase (Still very rough and not actively maintained while dependencies settle.)
  * [MOLE Web Explainer](https://github.com/Moderation-of-unLinkable-Endorsements/web-drafts/blob/main/explainer.md)
 
## Rough Requirements

The goal is to produce an end-to-end demonstration of MOLE protecting resources on a website from excessive traffic.

Planned dependencies:
* https://github.com/Moderation-of-unLinkable-Endorsements/mole-p256-rs (crypto implementation)
* https://hyper.rs/ (low-level HTTP implementation)
* https://github.com/clap-rs/clap (CLI parsing)
* https://docs.rs/xdg/3.0.0/xdg/index.html (identify paths for data persistence)
* data persistence: rusqlite or SQLx (tbd) (sqlite3 for data persistence)

### prototalpid-http

A Rust crate implementing the [MOLE HTTP transport](https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-jms-mole-http-transport.html)

### prototalpid-cli

A curl-subset-compatible command that implements the client element of MOLE, with a default storage mechanism for endorsements, credentials, and cookies.

### prototalpid-anchor

A service which provides endorsements to clients that can answer a very basic captcha-like challenge or execute a proof-of-work operation.

### prototalpid-moderator-proxy

A reverse proxy service that implements a basic HTTPS web server that challenges clients that don't attach an active MOLE session header, and redemption of endorsements and presentation of credentials.


## Acknowlegements

Thanks to [wbl](https://github.com/wbl) for the idea for the name, and of course to the authors of the relevant specs and underlying libraries.
