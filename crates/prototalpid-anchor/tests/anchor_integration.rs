use std::sync::Arc;

use cookie::Cookie;
use http::StatusCode;
use http::header::{CONTENT_TYPE, COOKIE, SET_COOKIE};

use prototalpid_anchor::{
    ANCHOR_GRANT_PATH, AnchorRuntimeConfig, AnchorStore, ChallengeMode, spawn_anchor_server,
};
use prototalpid_http::challenge::{AnchorChallengeOffer, AnchorChallengeSubmission, solve_pow};
use prototalpid_http::config::{AnchorConfiguration, WELL_KNOWN_MOLE_ANCHOR};
use prototalpid_http::schemes::{EC_IHAT_CTX_RED, EndorsementType};
use prototalpid_http::tls::LocalCa;
use prototalpid_http::transport::{
    MoleChallenge, WANT_ENDORSEMENT_HEADER, format_endorsement_request_content_type,
    parse_endorsement_response_content_type, parse_www_authenticate_headers,
};
use prototalpid_http::wire::{GrantChallenges, GrantCommitments, GrantRequest, GrantResponses};

fn extract_cookie_pair(headers: &http::HeaderMap) -> String {
    let raw = headers.get(SET_COOKIE).unwrap().to_str().unwrap();
    let parsed = Cookie::parse(raw).unwrap();
    format!("{}={}", parsed.name(), parsed.value())
}

#[tokio::test]
async fn anchor_pow_prompt_batch_grant_quota_and_replay_safety() {
    let ca = LocalCa::generate("Anchor Test CA").unwrap();
    let leaf = ca.issue_server_cert(&[]).unwrap();
    let client = ca.http_client().unwrap();

    let store = Arc::new(AnchorStore::open(None, b"2026-11").unwrap());
    let cfg = AnchorRuntimeConfig {
        challenge_mode: ChallengeMode::Both,
        pow_bits: 8,
        quota_per_challenge: 3,
        max_quota_per_session: 4,
        max_batch_size: 4,
        ..AnchorRuntimeConfig::default()
    };

    let server = spawn_anchor_server(
        "127.0.0.1:0".parse().unwrap(),
        leaf.server_config,
        store.clone(),
        cfg,
        None,
    )
    .await
    .unwrap();
    let origin = &server.origin;
    let grant_endpoint = format!("{origin}{ANCHOR_GRANT_PATH}");
    let challenge_endpoint = format!("{origin}/challenge");

    // 1. Discover AnchorConfiguration
    let resp = client
        .get(format!("{origin}{WELL_KNOWN_MOLE_ANCHOR}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let anchor_cfg: AnchorConfiguration = resp.json().await.unwrap();
    let (grant_url, pk_a) = anchor_cfg.validate_ec_ihat().unwrap();
    assert_eq!(grant_url.path(), ANCHOR_GRANT_PATH);
    assert_eq!(pk_a, server.public_key);

    // 2. Grant without session cookie -> 401
    let req_ct = format_endorsement_request_content_type(EndorsementType::EC_IHAT).unwrap();
    let resp = client
        .post(&grant_endpoint)
        .header(CONTENT_TYPE, &req_ct)
        .body(GrantRequest { count: 1 }.to_bytes().unwrap().to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 3. Solve PoW challenge -> sets anchor_session cookie (quota = 3) + endorse-0002=""
    let resp = client
        .get(&challenge_endpoint)
        .header(WANT_ENDORSEMENT_HEADER, "Mole")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let offer: AnchorChallengeOffer = resp.json().await.unwrap();
    let pow = offer.pow.as_ref().unwrap();
    let nonce = solve_pow(&offer.challenge_id, &pow.prefix, pow.bits).unwrap();

    let sub = AnchorChallengeSubmission {
        challenge_id: offer.challenge_id.clone(),
        pow_nonce: Some(nonce),
        prompt_answer: None,
    };
    let resp = client
        .post(&challenge_endpoint)
        .header(WANT_ENDORSEMENT_HEADER, "Mole")
        .json(&sub)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = extract_cookie_pair(resp.headers());
    assert_eq!(
        parse_www_authenticate_headers(resp.headers()),
        vec![MoleChallenge::Endorse {
            endorsement_type: EndorsementType::EC_IHAT,
            context: Vec::new(),
        }]
    );

    // Replaying the same solved challenge MUST fail (403)
    let resp_replay = client
        .post(&challenge_endpoint)
        .json(&sub)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_replay.status(), StatusCode::FORBIDDEN);

    // 4. Batched grant of 2 Endorsements (remaining quota becomes 1)
    let resp = client
        .post(&grant_endpoint)
        .header(COOKIE, &cookie)
        .header(CONTENT_TYPE, &req_ct)
        .body(GrantRequest { count: 2 }.to_bytes().unwrap().to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        parse_endorsement_response_content_type(resp.headers()).unwrap(),
        EndorsementType::EC_IHAT
    );
    let gc = GrantCommitments::from_bytes(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(gc.commitments.len(), 2);

    let (cstates, cmsgs): (Vec<_>, Vec<_>) = gc
        .commitments
        .iter()
        .map(|com| {
            ec_ihat::challenge(&pk_a, &anchor_cfg.issuance_epoch, EC_IHAT_CTX_RED, com).unwrap()
        })
        .unzip();

    let resp = client
        .post(&grant_endpoint)
        .header(CONTENT_TYPE, &req_ct)
        .body(
            GrantChallenges {
                session_id: gc.session_id,
                challenges: cmsgs,
            }
            .to_bytes()
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        parse_endorsement_response_content_type(resp.headers()).unwrap(),
        EndorsementType::EC_IHAT
    );
    let gr = GrantResponses::from_bytes(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(gr.responses.len(), 2);
    for (st, resp_msg) in cstates.into_iter().zip(&gr.responses) {
        let endorsement = ec_ihat::finalize(&pk_a, st, resp_msg).unwrap();
        ec_ihat::verify(&pk_a, &endorsement, &anchor_cfg.issuance_epoch, EC_IHAT_CTX_RED).unwrap();
    }

    // 5. Concurrent AnchorState replay safety (draft-ladd-mole-ec-ihat §5.3):
    // Start a 1-endorsement batch (consumes last 1 of the 3 quota), then race 8 distinct
    // ChallengeMessages for the same session_id concurrently!
    let resp = client
        .post(&grant_endpoint)
        .header(COOKIE, &cookie)
        .header(CONTENT_TYPE, &req_ct)
        .body(GrantRequest { count: 2 }.to_bytes().unwrap().to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let gc_race = GrantCommitments::from_bytes(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(gc_race.commitments.len(), 1);

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (_, ch) = ec_ihat::challenge(
            &pk_a,
            &anchor_cfg.issuance_epoch,
            EC_IHAT_CTX_RED,
            &gc_race.commitments[0],
        )
        .unwrap();
        let payload = GrantChallenges {
            session_id: gc_race.session_id,
            challenges: vec![ch],
        }
        .to_bytes()
        .unwrap();
        let client_c = client.clone();
        let url_c = grant_endpoint.clone();
        let ct = req_ct.clone();
        tasks.push(tokio::spawn(async move {
            client_c
                .post(url_c)
                .header(CONTENT_TYPE, ct)
                .body(payload)
                .send()
                .await
                .unwrap()
                .status()
        }));
    }
    let mut ok_count = 0;
    let mut bad_count = 0;
    for t in tasks {
        match t.await.unwrap() {
            StatusCode::OK => ok_count += 1,
            StatusCode::BAD_REQUEST => bad_count += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(ok_count, 1, "at most ONE GrantChallenges may ever succeed");
    assert_eq!(bad_count, 7);

    // 6. Quota is now 0 -> /mole/grant returns 429 Too Many Requests!
    let resp_429 = client
        .post(&grant_endpoint)
        .header(COOKIE, &cookie)
        .header(CONTENT_TYPE, &req_ct)
        .body(GrantRequest { count: 1 }.to_bytes().unwrap().to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp_429.status(), StatusCode::TOO_MANY_REQUESTS);

    // 7. Interactive prompt challenge tops up the remaining 1 of max_quota_per_session (4 - 3 = 1),
    // and a third challenge on the same session returns 429!
    let p_offer: AnchorChallengeOffer = client
        .get(&challenge_endpoint)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let answer = store
        .peek_prompt_answer_for_test(&p_offer.challenge_id)
        .unwrap()
        .unwrap();
    let resp_prompt = client
        .post(&challenge_endpoint)
        .header(COOKIE, &cookie)
        .json(&AnchorChallengeSubmission {
            challenge_id: p_offer.challenge_id,
            pow_nonce: None,
            prompt_answer: Some(answer),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp_prompt.status(), StatusCode::OK);

    // Third challenge on the same session hits max_quota_per_session (4) -> 429!
    let p2_offer: AnchorChallengeOffer = client
        .get(&challenge_endpoint)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let answer2 = store
        .peek_prompt_answer_for_test(&p2_offer.challenge_id)
        .unwrap()
        .unwrap();
    let resp_cap = client
        .post(&challenge_endpoint)
        .header(COOKIE, &cookie)
        .json(&AnchorChallengeSubmission {
            challenge_id: p2_offer.challenge_id,
            pow_nonce: None,
            prompt_answer: Some(answer2),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp_cap.status(), StatusCode::TOO_MANY_REQUESTS);

    server.shutdown().await;
}
