use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use ec_ihat::{Backend as _, DefaultBackend as IhatBackend};
use http::header::{AUTHORIZATION, CACHE_CONTROL};
use http::{HeaderMap, StatusCode};
use tokio::net::TcpListener;
use url::Url;

use prototalpid_http::config::{ModeratorConfiguration, WELL_KNOWN_MOLE_MODERATOR};
use prototalpid_http::schemes::{
    CredentialType, EC_IHAT_CTX_RED, EndorsementType, generate_greased_presentation,
};
use prototalpid_http::tls::LocalCa;
use prototalpid_http::transport::{
    MOLE_SESSION_HEADER, MoleAuthorization, MoleChallenge, MoleCredentialHeader,
    parse_mole_session, parse_www_authenticate_headers,
};
use prototalpid_http::wire::{
    EcActChallenge, EcActIssuanceRequest, EcActIssuanceResponse, EcActPresentationAndUpdate,
    EcActUpdate, RedemptionChallenge,
};
use prototalpid_moderator_proxy::{
    MODERATOR_ISSUE_PATH, ModerationPolicy, ModeratorProxyConfig, ModeratorStore,
    TrustedAnchorSet, spawn_moderator_proxy,
};

async fn spawn_mock_upstream(hits: Arc<AtomicUsize>) -> (Url, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new()
        .fallback(
            |State(hits): State<Arc<AtomicUsize>>, headers: HeaderMap| async move {
                // Upstream MUST NEVER see Mole-Session or Mole Authorization!
                assert!(headers.get(&MOLE_SESSION_HEADER).is_none());
                assert!(headers.get(AUTHORIZATION).is_none());
                let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
                format!("upstream-ok-{n}")
            },
        )
        .with_state(hits);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (Url::parse(&format!("http://{addr}")).unwrap(), handle)
}

fn issue_local_endorsement(sk_a: &ec_ihat::SecretKey, ctx_iss: &[u8]) -> ec_ihat::Endorsement {
    let pk_a = sk_a.public_key();
    let (ast, com) = ec_ihat::commit(ctx_iss).unwrap();
    let (cst, ch) = ec_ihat::challenge(&pk_a, ctx_iss, EC_IHAT_CTX_RED, &com).unwrap();
    let resp = ec_ihat::respond(sk_a, ast, &ch).unwrap();
    ec_ihat::finalize(&pk_a, cst, &resp).unwrap()
}

#[tokio::test]
async fn moderator_proxy_held_session_signoff_flood_penalty_and_recovery() {
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let (upstream_url, upstream_task) = spawn_mock_upstream(upstream_hits.clone()).await;

    // Set up 3 Anchors in the trusted Anchor Set; Client uses Anchor #2 (index = 1).
    let ctx_iss = b"2026-11".to_vec();
    let sk_a1: ec_ihat::SecretKey =
        ec_ihat::SecretKey::from_seed(&IhatBackend::generate_seed().unwrap()).unwrap();
    let sk_a2: ec_ihat::SecretKey =
        ec_ihat::SecretKey::from_seed(&IhatBackend::generate_seed().unwrap()).unwrap();
    let sk_a3: ec_ihat::SecretKey =
        ec_ihat::SecretKey::from_seed(&IhatBackend::generate_seed().unwrap()).unwrap();
    let anchor_set = vec![sk_a1.public_key(), sk_a2.public_key(), sk_a3.public_key()];

    let store = Arc::new(
        ModeratorStore::open(
            None,
            8,
            b"mod-ctx-v1",
            300,
            vec![TrustedAnchorSet {
                issuance_epoch: ctx_iss.clone(),
                public_keys: anchor_set.clone(),
            }],
        )
        .unwrap(),
    );

    let policy = ModerationPolicy {
        initial_credits: 60,
        deposit_credits: 20,
        max_top_up: 0,
        hold_duration_secs: 2,
        rate_window_secs: 10,
        max_requests_per_window: 3, // 1 initial presentation + 2 Mole-Session requests allowed; 4th triggers 401!
        revoke_chain_on_flood: false,
        challenge_window_secs: 60,
        allow_no_endorsement: false,
    };

    let ca = LocalCa::generate("Moderator Test CA").unwrap();
    let leaf = ca.issue_server_cert(&[]).unwrap();
    let client = ca.http_client().unwrap();

    let proxy = spawn_moderator_proxy(
        "127.0.0.1:0".parse().unwrap(),
        leaf.server_config,
        store,
        ModeratorProxyConfig {
            public_origin: String::new(),
            upstream_origin: upstream_url,
            policy,
            maintenance_interval: Duration::from_millis(200),
        },
        None,
    )
    .await
    .unwrap();
    let origin = &proxy.origin;
    let issue_url = format!("{origin}{MODERATOR_ISSUE_PATH}");

    // 1. Unauthenticated request -> 401 with challenge-0001 and redeem-0002; zero upstream hits.
    let resp_401 = client.get(format!("{origin}/articles/1")).send().await.unwrap();
    assert_eq!(resp_401.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

    let challenges = parse_www_authenticate_headers(resp_401.headers());
    let act_chal_raw = challenges
        .iter()
        .find_map(|c| match c {
            MoleChallenge::Credential {
                credential_type: CredentialType::EC_ACT,
                challenge,
            } => Some(challenge.clone()),
            _ => None,
        })
        .unwrap();
    let red_chal_raw = challenges
        .iter()
        .find_map(|c| match c {
            MoleChallenge::Redeem {
                endorsement_type: EndorsementType::EC_IHAT,
                challenge,
            } => Some(challenge.clone()),
            _ => None,
        })
        .unwrap();

    // 2. Greased presentation -> 401 without Mole-Credential and zero upstream hits.
    let (grease_type, grease_body) = generate_greased_presentation().unwrap();
    let grease_auth = (MoleAuthorization::Presentation {
        credential_type: grease_type,
        presentation: grease_body,
    })
    .to_header_value()
    .unwrap();
    let resp_grease = client
        .get(format!("{origin}/articles/1"))
        .header(AUTHORIZATION, grease_auth)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_grease.status(), StatusCode::UNAUTHORIZED);
    assert!(MoleCredentialHeader::from_headers(resp_grease.headers()).unwrap().is_none());
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

    // 3. Fetch /.well-known/mole-moderator & run RedeemAndIssue using Anchor #2 endorsement.
    let mod_cfg: ModeratorConfiguration = client
        .get(format!("{origin}{WELL_KNOWN_MOLE_MODERATOR}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let (_, _, keys) = mod_cfg.parse_supported().unwrap();
    let key = &keys[0];
    let params = ec_act::Params::new(key.config.balance_width).unwrap();

    let endorsement = issue_local_endorsement(&sk_a2, &ctx_iss);
    let red_chal = RedemptionChallenge::from_bytes(&red_chal_raw).unwrap();
    let redemption = ec_ihat::redeem(
        &anchor_set,
        1, // Anchor #2 hidden among 3 Anchors!
        endorsement,
        &ctx_iss,
        EC_IHAT_CTX_RED,
        &red_chal.digest(),
    )
    .unwrap();

    let (iss_state, iss_req_msg) = ec_act::issue_request(&params).unwrap();
    let iss_req = EcActIssuanceRequest {
        truncated_key_id: key.truncated_key_id,
        credential_context: key.config.credential_context.clone(),
        request: iss_req_msg,
    };
    let redeem_auth = (MoleAuthorization::RedeemAndIssue {
        endorsement_type: EndorsementType::EC_IHAT,
        redemption: redemption.to_bytes(),
        credential_type: CredentialType::EC_ACT,
        credential_request: iss_req.to_bytes().unwrap(),
    })
    .to_header_value()
    .unwrap();

    let resp_iss = client
        .post(&issue_url)
        .header(AUTHORIZATION, &redeem_auth)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_iss.status(), StatusCode::OK);
    assert_eq!(resp_iss.headers().get(CACHE_CONTROL).unwrap(), "no-store");
    let Some(MoleCredentialHeader::Response { response: resp_raw, .. }) =
        MoleCredentialHeader::from_headers(resp_iss.headers()).unwrap()
    else {
        panic!("expected Mole-Credential: response-0001");
    };
    let iss_resp = EcActIssuanceResponse::from_bytes(&params, &resp_raw).unwrap();
    let cred1 = ec_act::finalize_issue(
        &params,
        &key.public_key,
        &key.ctx_cred,
        iss_state,
        &iss_resp.response,
    )
    .unwrap();
    assert_eq!(cred1.balance(), 60);

    // Replaying the same EC-IHAT Redemption MUST fail with 401!
    let resp_replay_red = client
        .post(&issue_url)
        .header(AUTHORIZATION, &redeem_auth)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_replay_red.status(), StatusCode::UNAUTHORIZED);

    // 4. Present cred1 -> 200 OK + Mole-Session + held-for-update-0001="2"
    let act_chal = EcActChallenge::from_bytes(&act_chal_raw).unwrap();
    let ctx_spend1 = act_chal.ctx_spend().unwrap();
    let (spend_state1, spend_msg1) = ec_act::prove_spend(
        &params,
        cred1,
        &key.ctx_cred,
        act_chal.spend_amount,
        act_chal.max_top_up,
        &ctx_spend1,
    )
    .unwrap();
    let pres1 = EcActPresentationAndUpdate {
        key_id: key.key_id,
        spend: spend_msg1,
    };
    let handle1 = pres1.recovery_handle();
    let pres1_auth = (MoleAuthorization::Presentation {
        credential_type: CredentialType::EC_ACT,
        presentation: pres1.to_bytes(),
    })
    .to_header_value()
    .unwrap();

    let resp_p1 = client
        .get(format!("{origin}/articles/1"))
        .header(AUTHORIZATION, &pres1_auth)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_p1.status(), StatusCode::OK);
    let session1 = parse_mole_session(resp_p1.headers()).unwrap().unwrap();
    assert_eq!(
        MoleCredentialHeader::from_headers(resp_p1.headers()).unwrap(),
        Some(MoleCredentialHeader::HeldForUpdate {
            credential_type: CredentialType::EC_ACT,
            duration_secs: 2,
        })
    );
    assert_eq!(resp_p1.bytes().await.unwrap().as_ref(), b"upstream-ok-1");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // Duplicate presentation -> 409 Conflict with retained held-for-update, NO upstream hit!
    let resp_dup = client
        .get(format!("{origin}/articles/1"))
        .header(AUTHORIZATION, &pres1_auth)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_dup.status(), StatusCode::CONFLICT);
    assert!(matches!(
        MoleCredentialHeader::from_headers(resp_dup.headers()).unwrap(),
        Some(MoleCredentialHeader::HeldForUpdate { .. })
    ));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // Premature recovery while still held -> 404 without disturbing session1!
    let rec1_auth = (MoleAuthorization::Recovery {
        credential_type: CredentialType::EC_ACT,
        recovery_handle: handle1.to_bytes().to_vec(),
    })
    .to_header_value()
    .unwrap();
    let resp_premature = client
        .post(&issue_url)
        .header(AUTHORIZATION, &rec1_auth)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_premature.status(), StatusCode::NOT_FOUND);

    // Polite follow-up request with Mole-Session -> 200 OK (upstream hit #2)!
    let resp_s1 = client
        .get(format!("{origin}/articles/2"))
        .header(MOLE_SESSION_HEADER, &session1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_s1.status(), StatusCode::OK);
    assert_eq!(resp_s1.bytes().await.unwrap().as_ref(), b"upstream-ok-2");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 2);

    // Polite Signoff -> full refund t = 20 (balance 60 -> 60), session1 invalidated!
    let signoff1_auth = (MoleAuthorization::Signoff {
        credential_type: CredentialType::EC_ACT,
        recovery_handle: handle1.to_bytes().to_vec(),
    })
    .to_header_value()
    .unwrap();
    let resp_so1 = client
        .post(&issue_url)
        .header(AUTHORIZATION, &signoff1_auth)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_so1.status(), StatusCode::OK);
    let Some(MoleCredentialHeader::Update {
        update: Some(upd1_bytes),
        ..
    }) = MoleCredentialHeader::from_headers(resp_so1.headers()).unwrap()
    else {
        panic!("expected update-0001 refund");
    };
    let upd1 = EcActUpdate::from_bytes(&params, &upd1_bytes).unwrap();
    let cred2 = ec_act::finalize_refund(
        &params,
        &key.public_key,
        &key.ctx_cred,
        spend_state1,
        &upd1.refund,
    )
    .unwrap();
    assert_eq!(cred2.balance(), 60);

    // Using session1 after signoff -> 401!
    let resp_after_so = client
        .get(format!("{origin}/articles/3"))
        .header(MOLE_SESSION_HEADER, &session1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_after_so.status(), StatusCode::UNAUTHORIZED);

    // 5. Flood rate-limit test: present cred2 on /articles/3, then exceed max_requests_per_window (3).
    let chal2_raw = parse_www_authenticate_headers(resp_after_so.headers())
        .into_iter()
        .find_map(|c| match c {
            MoleChallenge::Credential { challenge, .. } => Some(challenge),
            _ => None,
        })
        .unwrap();
    let chal2 = EcActChallenge::from_bytes(&chal2_raw).unwrap();
    let (spend_state2, spend_msg2) = ec_act::prove_spend(
        &params,
        cred2,
        &key.ctx_cred,
        chal2.spend_amount,
        chal2.max_top_up,
        &chal2.ctx_spend().unwrap(),
    )
    .unwrap();
    let pres2 = EcActPresentationAndUpdate {
        key_id: key.key_id,
        spend: spend_msg2,
    };
    let handle2 = pres2.recovery_handle();
    let resp_p2 = client
        .get(format!("{origin}/articles/3"))
        .header(
            AUTHORIZATION,
            (MoleAuthorization::Presentation {
                credential_type: CredentialType::EC_ACT,
                presentation: pres2.to_bytes(),
            })
            .to_header_value()
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let session2 = parse_mole_session(resp_p2.headers()).unwrap().unwrap();
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 3);

    // Hits 2 and 3 in window succeed (upstream hits #4, #5); hit 4 trips rate limit -> 401 (no upstream hit!).
    for _ in 0..2 {
        let resp = client
            .get(format!("{origin}/articles/3"))
            .header(MOLE_SESSION_HEADER, &session2)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 5);

    let resp_flood = client
        .get(format!("{origin}/articles/3"))
        .header(MOLE_SESSION_HEADER, &session2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_flood.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        5,
        "flood request must NOT reach upstream"
    );

    // Signoff after rate-limit breach returns penalized refund t = 0 -> balance drops 60 -> 40!
    let resp_so2 = client
        .post(&issue_url)
        .header(
            AUTHORIZATION,
            (MoleAuthorization::Signoff {
                credential_type: CredentialType::EC_ACT,
                recovery_handle: handle2.to_bytes().to_vec(),
            })
            .to_header_value()
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp_so2.status(), StatusCode::OK);
    let Some(MoleCredentialHeader::Update {
        update: Some(upd2_bytes),
        ..
    }) = MoleCredentialHeader::from_headers(resp_so2.headers()).unwrap()
    else {
        panic!("expected penalized refund");
    };
    let upd2 = EcActUpdate::from_bytes(&params, &upd2_bytes).unwrap();
    assert_eq!(upd2.refund.return_amount(), 0);
    let cred3 = ec_act::finalize_refund(
        &params,
        &key.public_key,
        &key.ctx_cred,
        spend_state2,
        &upd2.refund,
    )
    .unwrap();
    assert_eq!(cred3.balance(), 40);

    // 6. Hold-expiry + Recovery test: present cred3, wait > 2s for hold_until, recover via recovery-0001!
    let chal3_raw = parse_www_authenticate_headers(resp_flood.headers())
        .into_iter()
        .find_map(|c| match c {
            MoleChallenge::Credential { challenge, .. } => Some(challenge),
            _ => None,
        })
        .unwrap();
    let chal3 = EcActChallenge::from_bytes(&chal3_raw).unwrap();
    let (spend_state3, spend_msg3) = ec_act::prove_spend(
        &params,
        cred3,
        &key.ctx_cred,
        chal3.spend_amount,
        chal3.max_top_up,
        &chal3.ctx_spend().unwrap(),
    )
    .unwrap();
    let pres3 = EcActPresentationAndUpdate {
        key_id: key.key_id,
        spend: spend_msg3,
    };
    let handle3 = pres3.recovery_handle();
    let resp_p3 = client
        .get(format!("{origin}/articles/3"))
        .header(
            AUTHORIZATION,
            (MoleAuthorization::Presentation {
                credential_type: CredentialType::EC_ACT,
                presentation: pres3.to_bytes(),
            })
            .to_header_value()
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp_p3.status(), StatusCode::OK);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 6);

    tokio::time::sleep(Duration::from_millis(2300)).await;

    let resp_rec3 = client
        .post(&issue_url)
        .header(
            AUTHORIZATION,
            (MoleAuthorization::Recovery {
                credential_type: CredentialType::EC_ACT,
                recovery_handle: handle3.to_bytes().to_vec(),
            })
            .to_header_value()
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp_rec3.status(), StatusCode::OK);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        6,
        "recovery must NOT hit upstream"
    );
    let Some(MoleCredentialHeader::Update {
        update: Some(upd3_bytes),
        ..
    }) = MoleCredentialHeader::from_headers(resp_rec3.headers()).unwrap()
    else {
        panic!("expected recovered refund");
    };
    let upd3 = EcActUpdate::from_bytes(&params, &upd3_bytes).unwrap();
    let cred4 = ec_act::finalize_refund(
        &params,
        &key.public_key,
        &key.ctx_cred,
        spend_state3,
        &upd3.refund,
    )
    .unwrap();
    assert_eq!(cred4.balance(), 40);

    proxy.shutdown().await;
    upstream_task.abort();
}
