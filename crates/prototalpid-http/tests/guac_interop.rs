//! Interoperability tests between `prototalpid-http` (`ec-ihat` / `ec-act`) and
//! [`cloudflareresearch/guac`](https://github.com/cloudflareresearch/guac).

use std::num::NonZeroU16;
use std::path::PathBuf;
use std::process::Command;

use ec_act::{Backend as _, DefaultBackend as ActBackend};
use ec_ihat::DefaultBackend as IhatBackend;
use http::header::{CONTENT_TYPE, HeaderMap, HeaderValue, WWW_AUTHENTICATE};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use prototalpid_http::config::{
    AnchorConfiguration, EcActKeyConfig, EcIhatEndorsementConfig, ModeratorConfiguration,
    SupportedModeratorEndorsement,
};
use prototalpid_http::schemes::{
    CIPHERSUITE_P256_SHA256, CredentialType, EC_IHAT_CTX_RED, EndorsementType,
    generate_greased_presentation,
};
use prototalpid_http::transport::{
    MOLE_CREDENTIAL_HEADER, MoleAuthorization, MoleChallenge, MoleCredentialHeader,
    apply_mole_credential_headers, format_endorsement_request_content_type,
    format_endorsement_response_content_type, format_www_authenticate,
    parse_endorsement_request_content_type, parse_endorsement_response_content_type,
    parse_single_mole_challenge_strict, parse_www_authenticate_headers,
};
use prototalpid_http::wire::{
    EcActChallenge, EcActIssuanceRequest, EcActIssuanceResponse, EcActPresentationAndUpdate,
    EcActUpdate, EcIhatGrantPost, GrantChallenges, GrantCommitments, GrantRequest, GrantResponses,
    RecoveryHandle, RedemptionChallenge, decode_quic_varint, encode_quic_varint,
};

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex string must have even length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

fn decode_hex_array<const N: usize>(hex: &str) -> [u8; N] {
    decode_hex(hex).try_into().expect("fixed hex array length")
}

/// Resolves the root directory of the `guac` crate checkout via `cargo metadata`
/// (or `GUAC_SRC_DIR` if overridden) so tests read `guac`'s checked-in vector corpus.
fn locate_guac_source_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("GUAC_SRC_DIR") {
        return PathBuf::from(dir);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(&cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--offline",
            "--manifest-path",
        ])
        .arg(&manifest)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .or_else(|| {
            Command::new(&cargo)
                .args(["metadata", "--format-version", "1", "--manifest-path"])
                .arg(&manifest)
                .output()
                .ok()
        })
        .expect("cargo metadata failed");
    assert!(
        output.status.success(),
        "cargo metadata stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let meta: serde_json::Value = serde_json::from_slice(&output.stdout).expect("metadata JSON");
    let manifest_path = meta["packages"]
        .as_array()
        .expect("packages array")
        .iter()
        .find(|p| p["name"].as_str() == Some("guac"))
        .and_then(|p| p["manifest_path"].as_str())
        .expect("guac package present in cargo metadata");
    PathBuf::from(manifest_path)
        .parent()
        .expect("guac manifest parent")
        .to_path_buf()
}

/// Unwraps `guac`'s `GUAC\x02` secret storage envelope to inspect raw token bytes.
fn unwrap_guac_secret_envelope(envelope: &[u8]) -> &[u8] {
    assert_eq!(&envelope[..5], b"GUAC\x02");
    let (len, used) = decode_quic_varint(&envelope[40..]).expect("envelope varint");
    let len = usize::try_from(len).unwrap();
    let payload = &envelope[40 + used..];
    assert_eq!(payload.len(), len);
    payload
}

/// Computes `guac`'s PR #138 canonical challenge digest (`SHA-256(u16_be(type) || varint(len) || payload)`).
fn guac_wrapped_challenge_digest(protocol_type: u16, payload: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(2 + 8 + payload.len());
    buf.extend_from_slice(&protocol_type.to_be_bytes());
    buf.extend_from_slice(&encode_quic_varint(payload.len() as u64).unwrap());
    buf.extend_from_slice(payload);
    Sha256::digest(&buf).into()
}

#[derive(Deserialize)]
struct VectorCorpus {
    version: u8,
    cases: Vec<TranscriptCase>,
}

#[derive(Deserialize)]
struct AnchorVector {
    public_key: String,
    epoch: String,
}

#[derive(Deserialize)]
struct TranscriptCase {
    name: String,
    anchors: Vec<AnchorVector>,
    grant_exchanges: Vec<(String, String)>,
    endorsement_storage: Option<String>,
    moderator_secret: String,
    moderator_public: String,
    endpoint: String,
    balance_bits: u8,
    credential_context: String,
    retention_seconds: String,
    redemption_challenge: String,
    issuance_request: String,
    issuance_state_raw: String,
    issuance_response: String,
    credential_raw: String,
    presentation_challenge: String,
    pending_presentation: String,
    presentation: String,
    update: String,
    expected_balance: Option<String>,
}

#[test]
fn http_headers_and_media_types_interoperate_bidirectionally_with_guac() {
    // 1. WWW-Authenticate: prototalpid -> guac::http::Challenge and guac -> prototalpid
    let act_chal = EcActChallenge {
        spend_amount: 15,
        max_top_up: 5,
        credential_context: b"ctx-interop".to_vec(),
        request_context: b"req-ctx-1".to_vec(),
    };
    let red_0002 = [0x22u8; 32];
    let red_0001 = [0x11u8; 32];

    let talpid_challenges = vec![
        MoleChallenge::Endorse {
            endorsement_type: EndorsementType::EC_IHAT,
            context: Vec::new(),
        },
        MoleChallenge::Redeem {
            endorsement_type: EndorsementType::EC_IHAT,
            challenge: red_0002.to_vec(),
        },
        MoleChallenge::Redeem {
            endorsement_type: EndorsementType::NO_ENDORSEMENT,
            challenge: red_0001.to_vec(),
        },
        MoleChallenge::Credential {
            credential_type: CredentialType::EC_ACT,
            challenge: act_chal.to_bytes().unwrap(),
        },
    ];
    let combined_hdr = format_www_authenticate(&talpid_challenges).unwrap();

    let guac_parsed = guac::http::Challenge::parse([combined_hdr.as_str()]);
    assert_eq!(guac_parsed.len(), 4);
    assert_eq!(guac_parsed[0], guac::http::Challenge::Endorse);
    assert_eq!(
        guac_parsed[1],
        guac::http::Challenge::Redeem(
            guac::protocol::ModeratorChallenge::from_parts(2, &red_0002).unwrap()
        )
    );
    assert_eq!(
        guac_parsed[2],
        guac::http::Challenge::Redeem(
            guac::protocol::ModeratorChallenge::from_parts(1, &red_0001).unwrap()
        )
    );
    match &guac_parsed[3] {
        guac::http::Challenge::Present(gc) => {
            assert_eq!(gc.cost(), 15);
            assert_eq!(gc.allowance(), 5);
            assert_eq!(gc.to_bytes(), act_chal.to_bytes().unwrap());
        }
        other => panic!("expected Present challenge, got {other:?}"),
    }

    // Reverse direction: guac Display -> prototalpid HeaderMap parser
    let mut resp_headers = HeaderMap::new();
    for gc in &guac_parsed {
        resp_headers.append(
            WWW_AUTHENTICATE,
            HeaderValue::from_str(&gc.to_string()).unwrap(),
        );
    }
    assert_eq!(
        parse_www_authenticate_headers(&resp_headers),
        talpid_challenges
    );

    // Greased challenges are ignored cleanly by guac::http::Challenge::parse
    let (greased_type, greased_payload) = generate_greased_presentation().unwrap();
    let greased_chal = (MoleChallenge::Credential {
        credential_type: greased_type,
        challenge: greased_payload.clone(),
    })
    .to_header_value()
    .unwrap();
    assert!(guac::http::Challenge::parse([greased_chal.as_str()]).is_empty());

    // Greased presentation in Authorization surfaces as Unsupported(u16) in guac
    let greased_auth = (MoleAuthorization::Presentation {
        credential_type: greased_type,
        presentation: greased_payload,
    })
    .to_header_value()
    .unwrap();
    assert!(matches!(
        guac::http::Authorization::parse(&greased_auth),
        Err(guac::Error::Unsupported(code)) if code == greased_type.0
    ));

    // 2. Authorization: RedeemAndIssue (0001 & 0002), Presentation, Recovery
    for (end_type, red_bytes) in [
        (EndorsementType::NO_ENDORSEMENT, Vec::new()),
        (EndorsementType::EC_IHAT, vec![0xaa, 0xbb, 0xcc, 0xdd]),
    ] {
        let talpid_issue = MoleAuthorization::RedeemAndIssue {
            endorsement_type: end_type,
            redemption: red_bytes.clone(),
            credential_type: CredentialType::EC_ACT,
            credential_request: vec![1, 2, 3, 4, 5],
        };
        let hdr = talpid_issue.to_header_value().unwrap();
        let Some(guac::http::Authorization::Issue(greq)) =
            guac::http::Authorization::parse(&hdr).unwrap()
        else {
            panic!("expected guac Authorization::Issue");
        };
        assert_eq!(greq.endorsement_type(), end_type.0);
        assert_eq!(greq.redemption(), red_bytes.as_slice());
        assert_eq!(greq.issuance(), &[1, 2, 3, 4, 5]);

        let guac_hdr = guac::http::Authorization::Issue(greq).to_string();
        assert_eq!(
            MoleAuthorization::parse_header_str(&guac_hdr).unwrap(),
            Some(talpid_issue)
        );
    }

    let fake_pres_bytes = [0x55u8; 64].to_vec();
    let talpid_pres = MoleAuthorization::Presentation {
        credential_type: CredentialType::EC_ACT,
        presentation: fake_pres_bytes.clone(),
    };
    let pres_hdr = talpid_pres.to_header_value().unwrap();
    let Some(guac::http::Authorization::Present(gpres)) =
        guac::http::Authorization::parse(&pres_hdr).unwrap()
    else {
        panic!("expected guac Authorization::Present");
    };
    assert_eq!(gpres.key_id(), Some([0x55u8; 32]));
    assert_eq!(gpres.to_bytes(), fake_pres_bytes);
    assert_eq!(
        MoleAuthorization::parse_header_str(&guac::http::Authorization::Present(gpres).to_string())
            .unwrap(),
        Some(talpid_pres)
    );

    let handle_arr = [0x99u8; 96];
    let talpid_rec = MoleAuthorization::Recovery {
        credential_type: CredentialType::EC_ACT,
        recovery_handle: handle_arr.to_vec(),
    };
    let rec_hdr = talpid_rec.to_header_value().unwrap();
    let Some(guac::http::Authorization::Recover(ghandle)) =
        guac::http::Authorization::parse(&rec_hdr).unwrap()
    else {
        panic!("expected guac Authorization::Recover");
    };
    assert_eq!(ghandle.to_bytes(), handle_arr);
    assert_eq!(
        MoleAuthorization::parse_header_str(
            &guac::http::Authorization::Recover(ghandle).to_string()
        )
        .unwrap(),
        Some(talpid_rec)
    );

    // Concept-phase signoff-0001 is rejected by guac::http::Authorization::parse
    let signoff_hdr = (MoleAuthorization::Signoff {
        credential_type: CredentialType::EC_ACT,
        recovery_handle: handle_arr.to_vec(),
    })
    .to_header_value()
    .unwrap();
    assert!(matches!(
        guac::http::Authorization::parse(&signoff_hdr),
        Err(guac::Error::Malformed)
    ));

    // 3. Mole-Credential: response-0001, update-0001 (refund & NoUpdate), and held-for-update boundary
    for (talpid_cred, expected_guac) in [
        (
            MoleCredentialHeader::Response {
                credential_type: CredentialType::EC_ACT,
                response: vec![7, 8, 9],
            },
            guac::http::CredentialField::Response(
                guac::protocol::CredentialResponse::from_bytes(&[7, 8, 9]).unwrap(),
            ),
        ),
        (
            MoleCredentialHeader::Update {
                credential_type: CredentialType::EC_ACT,
                update: Some(vec![10, 11, 12]),
            },
            guac::http::CredentialField::Update(
                guac::protocol::CredentialUpdate::from_bytes(&[10, 11, 12]).unwrap(),
            ),
        ),
        (
            MoleCredentialHeader::Update {
                credential_type: CredentialType::EC_ACT,
                update: None,
            },
            guac::http::CredentialField::Update(
                guac::protocol::CredentialUpdate::from_bytes(&[]).unwrap(),
            ),
        ),
    ] {
        let mut hm = HeaderMap::new();
        apply_mole_credential_headers(&mut hm, &talpid_cred).unwrap();
        let val_str = hm.get(&MOLE_CREDENTIAL_HEADER).unwrap().to_str().unwrap();
        assert_eq!(
            guac::http::CredentialField::parse([val_str]).unwrap(),
            Some(expected_guac.clone())
        );
        assert_eq!(
            MoleCredentialHeader::parse_header_str(&expected_guac.to_string()).unwrap(),
            talpid_cred
        );
    }

    let held_hdr = (MoleCredentialHeader::HeldForUpdate {
        credential_type: CredentialType::EC_ACT,
        duration_secs: 30,
    })
    .to_header_value()
    .unwrap();
    assert!(matches!(
        guac::http::CredentialField::parse([held_hdr.as_str()]),
        Err(guac::Error::Malformed)
    ));

    // 4. Grant Content-Type media types
    let req_ct = format_endorsement_request_content_type(EndorsementType::EC_IHAT).unwrap();
    let resp_ct = format_endorsement_response_content_type(EndorsementType::EC_IHAT).unwrap();
    guac::http::check_content_type(&req_ct, guac::http::ENDORSEMENT_REQUEST).unwrap();
    guac::http::check_content_type(&resp_ct, guac::http::ENDORSEMENT_RESPONSE).unwrap();

    let mut ct_map = HeaderMap::new();
    ct_map.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(guac::http::ENDORSEMENT_REQUEST),
    );
    assert_eq!(
        parse_endorsement_request_content_type(&ct_map).unwrap(),
        EndorsementType::EC_IHAT
    );
    ct_map.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(guac::http::ENDORSEMENT_RESPONSE),
    );
    assert_eq!(
        parse_endorsement_response_content_type(&ct_map).unwrap(),
        EndorsementType::EC_IHAT
    );
}

#[test]
fn discovery_configs_and_batched_ec_ihat_grants_interoperate_both_ways() {
    let epoch = b"2026-11-interop".to_vec();

    // Seed portability: a 48-byte EC-IHAT seed produces the exact same PublicKey in both crates
    let shared_seed = IhatBackend::generate_seed().unwrap();
    let talpid_sk: ec_ihat::SecretKey = ec_ihat::SecretKey::from_seed(&shared_seed).unwrap();
    let talpid_pk = talpid_sk.public_key();
    let guac_anchor = guac::Anchor::from_secret(&shared_seed, epoch.clone()).unwrap();
    assert_eq!(
        guac_anchor.configuration().public_key(),
        talpid_pk.to_bytes()
    );

    // Second Anchor generated by guac::Anchor
    let guac_anchor2 = guac::Anchor::generate(epoch.clone()).unwrap();
    let pk2_bytes = guac_anchor2.configuration().public_key();
    let talpid_pk2: ec_ihat::PublicKey = ec_ihat::PublicKey::from_bytes(&pk2_bytes).unwrap();

    // AnchorConfiguration JSON <-> guac::AnchorConfig
    let anchor_cfg = AnchorConfiguration {
        grant_uri: "https://anchor.example/mole/grant".to_owned(),
        endorsement_type: EndorsementType::EC_IHAT.0,
        ciphersuite: CIPHERSUITE_P256_SHA256.to_owned(),
        anchor_key: talpid_pk.to_bytes().to_vec(),
        issuance_epoch: epoch.clone(),
    };
    let anchor_json = serde_json::to_string(&anchor_cfg).unwrap();
    let anchor_cfg_rt: AnchorConfiguration = serde_json::from_str(&anchor_json).unwrap();
    let (_, validated_pk) = anchor_cfg_rt.validate_ec_ihat().unwrap();
    let guac_anchor_cfg =
        guac::AnchorConfig::new(&validated_pk.to_bytes(), anchor_cfg_rt.issuance_epoch).unwrap();
    assert_eq!(&guac_anchor_cfg, guac_anchor.configuration());

    // ModeratorConfiguration JSON <-> guac::ModeratorConfig
    let mod_seed = ActBackend::generate_seed().unwrap();
    let mod_sk: ec_act::SecretKey = ec_act::SecretKey::from_seed(&mod_seed).unwrap();
    let mod_pk = mod_sk.public_key();
    let mod_cfg = ModeratorConfiguration::from_typed(
        "https://moderator.example/mole/issue".to_owned(),
        true,
        &[EcIhatEndorsementConfig {
            endorsement_type: EndorsementType::EC_IHAT.0,
            ciphersuite: CIPHERSUITE_P256_SHA256.to_owned(),
            issuance_epoch: epoch.clone(),
            anchor_set: vec![talpid_pk.to_bytes().to_vec(), pk2_bytes.to_vec()],
        }],
        &[EcActKeyConfig {
            credential_type: CredentialType::EC_ACT.0,
            credential_key: mod_pk.to_bytes().to_vec(),
            ciphersuite: CIPHERSUITE_P256_SHA256.to_owned(),
            balance_width: 8,
            credential_context: b"site-ctx".to_vec(),
            result_retention: 300,
        }],
    )
    .unwrap();
    let (issuance_url, sup_end, sup_keys) = mod_cfg.parse_supported().unwrap();
    assert_eq!(sup_end.len(), 2);
    let SupportedModeratorEndorsement::EcIhat(ref ec_set) = sup_end[1] else {
        panic!("expected EcIhat entry");
    };
    let guac_set = guac::AnchorSet::new(&[
        guac::AnchorConfig::new(
            ec_set.anchor_set[0].as_slice().try_into().unwrap(),
            ec_set.issuance_epoch.clone(),
        )
        .unwrap(),
        guac::AnchorConfig::new(
            ec_set.anchor_set[1].as_slice().try_into().unwrap(),
            ec_set.issuance_epoch.clone(),
        )
        .unwrap(),
    ])
    .unwrap();
    let guac_mod_cfg = guac::ModeratorConfig::new(
        issuance_url.as_str(),
        &mod_pk.to_bytes(),
        sup_keys[0].config.balance_width,
        sup_keys[0].config.credential_context.clone(),
        guac::EndorsementPolicy::Required(guac_set),
        sup_keys[0].config.result_retention,
    )
    .unwrap();
    assert_eq!(guac_mod_cfg.key_id(), sup_keys[0].key_id);
    assert_eq!(guac_mod_cfg.key_id()[31], sup_keys[0].truncated_key_id);

    // Direction A: guac::Client <-> prototalpid wire + ec_ihat Anchor (batch of 3)
    let count = NonZeroU16::new(3).unwrap();
    let (g_req1, g_pending1) = guac::Client.start_grant(&guac_anchor_cfg, count);
    let EcIhatGrantPost::Request(parsed_req) =
        EcIhatGrantPost::from_bytes(&g_req1.to_bytes()).unwrap()
    else {
        panic!("expected Step 1 GrantRequest");
    };
    assert_eq!(parsed_req.count, 3);

    let mut anchor_states = Vec::new();
    let mut commitments = Vec::new();
    for _ in 0..parsed_req.count {
        let (st, com) = ec_ihat::commit(&epoch).unwrap();
        anchor_states.push(st);
        commitments.push(com);
    }
    let session_id = [0x42u8; 32];
    let g_resp1_bytes = GrantCommitments {
        session_id,
        commitments,
    }
    .to_bytes()
    .unwrap();
    let g_resp1 = guac::protocol::EndorsementResponse::from_bytes(&g_resp1_bytes).unwrap();
    let guac::GrantStep::Continue {
        request: g_req2,
        pending: g_pending2,
    } = g_pending1.advance(&g_resp1).unwrap()
    else {
        panic!("expected GrantStep::Continue");
    };

    let EcIhatGrantPost::Challenges(parsed_ch) =
        EcIhatGrantPost::from_bytes(&g_req2.to_bytes()).unwrap()
    else {
        panic!("expected Step 2 GrantChallenges");
    };
    assert_eq!(parsed_ch.session_id, session_id);
    assert_eq!(parsed_ch.challenges.len(), 3);

    let responses: Vec<_> = anchor_states
        .into_iter()
        .zip(&parsed_ch.challenges)
        .map(|(st, ch)| ec_ihat::respond(&talpid_sk, st, ch).unwrap())
        .collect();
    let g_resp2_bytes = GrantResponses { responses }.to_bytes().unwrap();
    let g_resp2 = guac::protocol::EndorsementResponse::from_bytes(&g_resp2_bytes).unwrap();
    let guac::GrantStep::Complete(guac_endorsements) = g_pending2.advance(&g_resp2).unwrap() else {
        panic!("expected GrantStep::Complete");
    };
    assert_eq!(guac_endorsements.len(), 3);

    // Verify raw endorsement extracted from guac's storage envelope redeems in mole-p256-rs ec_ihat!
    let anchor_pks = vec![talpid_pk.clone(), talpid_pk2.clone()];
    let stored_end = guac_endorsements[0].to_storage_bytes();
    let raw_end_bytes = unwrap_guac_secret_envelope(&stored_end);
    let imported_end = ec_ihat::Endorsement::from_bytes(raw_end_bytes).unwrap();
    ec_ihat::verify(&talpid_pk, &imported_end, &epoch, EC_IHAT_CTX_RED).unwrap();
    let red_chal = RedemptionChallenge {
        redemption_context: [0x77u8; 32],
    };
    let redemption = ec_ihat::redeem(
        &anchor_pks,
        0,
        imported_end,
        &epoch,
        EC_IHAT_CTX_RED,
        &red_chal.digest(),
    )
    .unwrap();
    let nf = ec_ihat::verify_redemption(
        &anchor_pks,
        &redemption,
        &epoch,
        EC_IHAT_CTX_RED,
        &red_chal.digest(),
    )
    .unwrap();
    assert_ne!(nf, [0u8; 32]);

    // Direction B: prototalpid wire + ec_ihat Client <-> guac::Anchor (batch of 3)
    let guac_store = guac::storage::MemoryStore::default();
    let req1 = guac::protocol::EndorsementRequest::from_bytes(
        &GrantRequest { count: 3 }.to_bytes().unwrap(),
    )
    .unwrap();
    let resp1 = guac_anchor2
        .grant(&guac_store, &req1, 100, 220, NonZeroU16::MAX)
        .unwrap();
    let gc = GrantCommitments::from_bytes(&resp1.to_bytes()).unwrap();
    assert_eq!(gc.commitments.len(), 3);

    let (client_states, challenges): (Vec<_>, Vec<_>) = gc
        .commitments
        .iter()
        .map(|com| ec_ihat::challenge(&talpid_pk2, &epoch, EC_IHAT_CTX_RED, com).unwrap())
        .unzip();
    let req2 = guac::protocol::EndorsementRequest::from_bytes(
        &GrantChallenges {
            session_id: gc.session_id,
            challenges,
        }
        .to_bytes()
        .unwrap(),
    )
    .unwrap();
    let resp2 = guac_anchor2
        .grant(&guac_store, &req2, 100, 220, NonZeroU16::MAX)
        .unwrap();
    let gr = GrantResponses::from_bytes(&resp2.to_bytes()).unwrap();
    assert_eq!(gr.responses.len(), 3);

    for (cst, rmsg) in client_states.into_iter().zip(&gr.responses) {
        let finalized = ec_ihat::finalize(&talpid_pk2, cst, rmsg).unwrap();
        ec_ihat::verify(&talpid_pk2, &finalized, &epoch, EC_IHAT_CTX_RED).unwrap();
    }
}

#[test]
fn guac_checked_in_transcripts_parse_cleanly_and_pinpoint_version_skew() {
    let vectors_path = locate_guac_source_dir()
        .join("tests")
        .join("vectors")
        .join("transcripts.json");
    let raw_json = std::fs::read_to_string(&vectors_path)
        .unwrap_or_else(|e| panic!("failed reading {}: {e}", vectors_path.display()));
    let corpus: VectorCorpus = serde_json::from_str(&raw_json).expect("valid transcripts.json");
    assert_eq!(corpus.version, 2);
    assert_eq!(corpus.cases.len(), 4);

    for case in &corpus.cases {
        // 1. Grant exchange wire messages decode identically in prototalpid-http
        for (idx, (req_hex, resp_hex)) in case.grant_exchanges.iter().enumerate() {
            let req_bytes = decode_hex(req_hex);
            let resp_bytes = decode_hex(resp_hex);
            match idx {
                0 => {
                    let EcIhatGrantPost::Request(gr) =
                        EcIhatGrantPost::from_bytes(&req_bytes).unwrap()
                    else {
                        panic!("{}: expected GrantRequest", case.name);
                    };
                    assert_eq!(gr.count, 1);
                    let gc = GrantCommitments::from_bytes(&resp_bytes).unwrap();
                    assert_eq!(gc.commitments.len(), 1);
                    assert_eq!(gc.to_bytes().unwrap(), resp_bytes);
                }
                1 => {
                    let EcIhatGrantPost::Challenges(gch) =
                        EcIhatGrantPost::from_bytes(&req_bytes).unwrap()
                    else {
                        panic!("{}: expected GrantChallenges", case.name);
                    };
                    assert_eq!(gch.challenges.len(), 1);
                    assert_eq!(gch.to_bytes().unwrap(), req_bytes);
                    let gr = GrantResponses::from_bytes(&resp_bytes).unwrap();
                    assert_eq!(gr.responses.len(), 1);
                    assert_eq!(gr.to_bytes().unwrap(), resp_bytes);
                }
                _ => panic!("unexpected 3rd grant exchange"),
            }
        }

        // 2. Stored EC-IHAT endorsement in guac's corpus verifies under mole-p256-rs ec_ihat
        let anchor_pks: Vec<ec_ihat::PublicKey> = case
            .anchors
            .iter()
            .map(|a| ec_ihat::PublicKey::from_bytes(&decode_hex_array(&a.public_key)).unwrap())
            .collect();
        if let Some(ref end_hex) = case.endorsement_storage {
            let end_envelope = decode_hex(end_hex);
            let raw_end = unwrap_guac_secret_envelope(&end_envelope);
            let end = ec_ihat::Endorsement::from_bytes(raw_end).unwrap();
            let epoch = decode_hex(&case.anchors[0].epoch);
            let matching = anchor_pks
                .iter()
                .filter(|pk| ec_ihat::verify(pk, &end, &epoch, EC_IHAT_CTX_RED).is_ok())
                .count();
            assert_eq!(
                matching, 1,
                "{}: endorsement must verify under 1 anchor",
                case.name
            );
        }

        // 3. WWW-Authenticate redeem-0002 AND redeem-0001 parse cleanly in prototalpid-http
        let parsed_chal = parse_single_mole_challenge_strict(&case.redemption_challenge).unwrap();
        let MoleChallenge::Redeem {
            endorsement_type,
            challenge: red_ctx_bytes,
        } = &parsed_chal
        else {
            panic!("{}: expected MoleChallenge::Redeem", case.name);
        };
        assert_eq!(
            parsed_chal.to_header_value().unwrap(),
            case.redemption_challenge
        );
        let red_chal = RedemptionChallenge::from_bytes(red_ctx_bytes).unwrap();

        // 4. Authorization RedeemAndIssue parses cleanly and round-trips
        let Some(MoleAuthorization::RedeemAndIssue {
            endorsement_type: auth_et,
            redemption,
            credential_type,
            credential_request,
        }) = MoleAuthorization::parse_header_str(&case.issuance_request).unwrap()
        else {
            panic!("{}: expected RedeemAndIssue", case.name);
        };
        assert_eq!(auth_et, *endorsement_type);
        assert_eq!(credential_type, CredentialType::EC_ACT);

        // 5. Pinpoint Version-Skew Boundary #1: EC-IHAT Redemption Challenge Digest
        //    - Current draft (`RedemptionChallenge::digest` = SHA-256(redemption_context)) rejects
        //      guac's PR #138 transcript.
        //    - Passing guac's wrapped digest `SHA-256(0x0002 || 0x20 || redemption_context)` into
        //      mole-p256-rs `ec_ihat::verify_redemption` SUCCEEDS, proving full EC-IHAT compatibility!
        if !anchor_pks.is_empty() {
            let epoch = decode_hex(&case.anchors[0].epoch);
            let decoded_red = ec_ihat::Redemption::from_bytes(&redemption, anchor_pks.len())
                .expect("EC-IHAT Redemption wire layout matches");
            assert!(
                ec_ihat::verify_redemption(
                    &anchor_pks,
                    &decoded_red,
                    &epoch,
                    EC_IHAT_CTX_RED,
                    &red_chal.digest(),
                )
                .is_err(),
                "{}: raw challenge digest must reject PR #138 wrapped-digest redemption",
                case.name
            );
            let pr138_digest =
                guac_wrapped_challenge_digest(EndorsementType::EC_IHAT.0, &red_chal.to_bytes());
            assert!(
                ec_ihat::verify_redemption(
                    &anchor_pks,
                    &decoded_red,
                    &epoch,
                    EC_IHAT_CTX_RED,
                    &pr138_digest,
                )
                .is_ok(),
                "{}: EC-IHAT redemption must verify once PR #138 digest framing is accounted for",
                case.name
            );
        } else {
            assert!(redemption.is_empty());
        }

        // 6. Wire codecs for EC-ACT messages, state, and RecoveryHandle match byte-for-byte,
        //    while cryptographic verification enforces EC-ACTv1 vs ACTv1 domain separation!
        let params = ec_act::Params::new(case.balance_bits).unwrap();
        let pk_m =
            ec_act::PublicKey::from_bytes(&decode_hex_array(&case.moderator_public)).unwrap();
        let cred_ctx = decode_hex(&case.credential_context);
        let mut ctx_cred = cred_ctx.clone();
        ctx_cred.push(case.balance_bits);

        let iss_req = EcActIssuanceRequest::from_bytes(&params, &credential_request)
            .expect("EcActIssuanceRequest wire layout matches");
        assert_eq!(iss_req.credential_context, cred_ctx);
        assert_eq!(iss_req.to_bytes().unwrap(), credential_request);
        assert!(
            ec_act::verify_issue_request(&params, &iss_req.request).is_err(),
            "{}: EC-ACTv1 must reject pre-rename ACTv1 IssueRequestMessage proof",
            case.name
        );

        let iss_state =
            ec_act::ClientIssuanceState::from_bytes(&params, &decode_hex(&case.issuance_state_raw))
                .expect("ClientIssuanceState raw encoding matches");
        let iss_resp_bytes = decode_hex(&case.issuance_response);
        let iss_resp = EcActIssuanceResponse::from_bytes(&params, &iss_resp_bytes)
            .expect("EcActIssuanceResponse wire layout matches");
        assert_eq!(iss_resp.to_bytes(), iss_resp_bytes);
        assert!(
            ec_act::finalize_issue(&params, &pk_m, &ctx_cred, iss_state, &iss_resp.response)
                .is_err(),
            "{}: EC-ACTv1 finalize_issue must reject ACTv1 generator binding",
            case.name
        );

        let cred_raw =
            ec_act::Credential::from_bytes(&params, &decode_hex(&case.credential_raw)).unwrap();
        assert_eq!(cred_raw.balance(), 8);

        let pres_chal_bytes = decode_hex(&case.presentation_challenge);
        let pres_chal = EcActChallenge::from_bytes(&pres_chal_bytes).unwrap();
        assert_eq!(pres_chal.spend_amount, 2);
        assert_eq!(pres_chal.max_top_up, 1);
        assert_eq!(pres_chal.credential_context, cred_ctx);
        assert_eq!(pres_chal.to_bytes().unwrap(), pres_chal_bytes);

        let pres_bytes = decode_hex(&case.presentation);
        let pres = EcActPresentationAndUpdate::from_bytes(&params, &pres_bytes)
            .expect("EcActPresentationAndUpdate wire layout matches");
        assert_eq!(pres.to_bytes(), pres_bytes);

        // Compare RecoveryHandle byte-for-byte against guac::PendingPresentation::recovery_handle()
        let guac_end_policy = if case.anchors.is_empty() {
            guac::EndorsementPolicy::NotRequired
        } else {
            let cfgs: Vec<_> = case
                .anchors
                .iter()
                .map(|a| {
                    guac::AnchorConfig::new(&decode_hex_array(&a.public_key), decode_hex(&a.epoch))
                        .unwrap()
                })
                .collect();
            guac::EndorsementPolicy::Required(guac::AnchorSet::new(&cfgs).unwrap())
        };
        let guac_mod_cfg = guac::ModeratorConfig::new(
            &case.endpoint,
            &decode_hex_array(&case.moderator_public),
            case.balance_bits,
            cred_ctx.clone(),
            guac_end_policy,
            case.retention_seconds.parse().unwrap(),
        )
        .unwrap();
        let guac_pending = guac::PendingPresentation::from_storage_bytes(
            &decode_hex(&case.pending_presentation),
            &guac_mod_cfg,
        )
        .unwrap();
        let guac_handle_bytes = guac_pending.recovery_handle().to_bytes();
        let talpid_handle = pres.recovery_handle();
        assert_eq!(
            talpid_handle.to_bytes().as_slice(),
            guac_handle_bytes.as_slice()
        );
        assert_eq!(
            RecoveryHandle::from_bytes(&guac_handle_bytes).unwrap(),
            talpid_handle
        );

        let update_bytes = decode_hex(&case.update);
        if case.expected_balance.is_some() {
            let upd = EcActUpdate::from_bytes(&params, &update_bytes)
                .expect("EcActUpdate wire layout matches");
            assert_eq!(upd.to_bytes(), update_bytes);
        } else {
            assert!(update_bytes.is_empty());
        }

        // Also verify reverse direction: an EC-ACTv1 IssueRequestMessage produced by mole-p256-rs
        // is parsed by guac::Moderator::prepare_issuance and rejected as Error::Credential
        if case.anchors.is_empty() {
            let guac_mod = guac::Moderator::new(
                &decode_hex_array(&case.moderator_secret),
                guac_mod_cfg.clone(),
            )
            .unwrap();
            let (_, ec_act_req_msg) = ec_act::issue_request(&params).unwrap();
            let talpid_iss_req = EcActIssuanceRequest {
                truncated_key_id: guac_mod_cfg.key_id()[31],
                credential_context: cred_ctx,
                request: ec_act_req_msg,
            }
            .to_bytes()
            .unwrap();
            let guac_cred_req = guac::protocol::CredentialRequest::from_parts(
                EndorsementType::NO_ENDORSEMENT.0,
                &[],
                &talpid_iss_req,
            )
            .unwrap();
            assert!(matches!(
                guac_mod.prepare_issuance(&guac_cred_req, 8, 100),
                Err(guac::Error::Credential(_))
            ));
        }
    }
}
