use ec_act::{Backend as _, DefaultBackend as ActBackend};
use ec_ihat::DefaultBackend as IhatBackend;
use http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, HeaderMap, HeaderValue, WWW_AUTHENTICATE};

use prototalpid_http::config::{
    AnchorConfiguration, EcActKeyConfig, EcIhatEndorsementConfig, ModeratorConfiguration,
    SupportedModeratorEndorsement, validate_https_endpoint_uri,
};
use prototalpid_http::schemes::{
    CIPHERSUITE_P256_SHA256, CredentialType, EC_IHAT_CTX_RED, EndorsementType, GREASED_TYPES,
    compute_ec_act_key_id, derive_ec_act_ctx_cred, generate_greased_presentation,
};
use prototalpid_http::tls::LocalCa;
use prototalpid_http::transport::{
    MOLE_CREDENTIAL_HEADER, MOLE_SESSION_HEADER, MoleAuthorization, MoleChallenge,
    MoleCredentialHeader, WANT_ENDORSEMENT_HEADER, apply_mole_credential_headers,
    format_endorsement_request_content_type, format_endorsement_response_content_type,
    format_mole_session, format_www_authenticate, has_want_endorsement_mole,
    parse_endorsement_request_content_type, parse_endorsement_response_content_type,
    parse_mole_session, parse_single_mole_challenge_strict, parse_www_authenticate_headers,
};
use prototalpid_http::wire::{
    EcActChallenge, EcActIssuanceRequest, EcActIssuanceResponse, EcActPresentationAndUpdate,
    EcActUpdate, EcIhatGrantPost, GrantChallenges, GrantCommitments, GrantRequest, GrantResponses,
    RecoveryHandle, RedemptionChallenge, decode_quic_varint, encode_quic_varint,
};

#[test]
fn canonical_base64url_strictness_in_headers_and_configs() {
    let sample = b"\xfb\xff\x00\x01\xfe";
    let hdr = (MoleChallenge::Endorse {
        endorsement_type: EndorsementType::EC_IHAT,
        context: sample.to_vec(),
    })
    .to_header_value()
    .unwrap();
    let quoted_val = hdr.split('"').nth(1).unwrap();
    assert!(!quoted_val.contains('='));
    assert!(!quoted_val.contains('+'));
    assert!(!quoted_val.contains('/'));
    assert_eq!(
        parse_single_mole_challenge_strict(&hdr).unwrap(),
        MoleChallenge::Endorse {
            endorsement_type: EndorsementType::EC_IHAT,
            context: sample.to_vec(),
        }
    );

    // Reject padding, standard alphabet, invalid length, and non-zero trailing pad bits ("AB" vs "AA")
    // across both HTTP transport headers and serde_with JSON configurations.
    for bad in ["YQ==", "YQ=", "A", "++//", "AB"] {
        assert!(
            parse_single_mole_challenge_strict(&format!("Mole endorse-0002=\"{bad}\"")).is_err(),
            "header accepted {bad}"
        );
    }
    for bad in ["A", "++//", "AB"] {
        let bad_json = format!(
            r#"{{"grant-uri":"https://anchor.example/grant","endorsement-type":2,"ciphersuite":"P256-SHA256","anchor-key":"AA","issuance-epoch":"{bad}"}}"#
        );
        assert!(
            serde_json::from_str::<AnchorConfiguration>(&bad_json).is_err(),
            "json accepted {bad}"
        );
    }
    assert_eq!(
        parse_single_mole_challenge_strict("Mole endorse-0002=\"AA\"").unwrap(),
        MoleChallenge::Endorse {
            endorsement_type: EndorsementType::EC_IHAT,
            context: vec![0x00],
        }
    );
}

#[test]
fn quic_varint_minimal_encoding() {
    for &v in &[0u64, 1, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1] {
        let enc = encode_quic_varint(v).unwrap();
        let (dec, used) = decode_quic_varint(&enc).unwrap();
        assert_eq!(dec, v);
        assert_eq!(used, enc.len());
    }
    assert!(encode_quic_varint(1 << 62).is_err());

    // Reject non-shortest encodings: 0 encoded in 2 bytes (0x40, 0x00), 63 in 2 bytes (0x40, 0x3f),
    // 16383 in 4 bytes (0x80, 0x00, 0x3f, 0xff).
    assert!(decode_quic_varint(&[0x40, 0x00]).is_err());
    assert!(decode_quic_varint(&[0x40, 0x3f]).is_err());
    assert!(decode_quic_varint(&[0x80, 0x00, 0x3f, 0xff]).is_err());
}

#[test]
fn www_authenticate_multi_challenge_and_strict_validation() {
    let ch1 = MoleChallenge::Credential {
        credential_type: CredentialType::EC_ACT,
        challenge: vec![1, 2, 3, 4],
    };
    let ch2 = MoleChallenge::Redeem {
        endorsement_type: EndorsementType::EC_IHAT,
        challenge: [0x42u8; 32].to_vec(),
    };
    let combined = format_www_authenticate(&[ch1.clone(), ch2.clone()]).unwrap();

    // Mix with non-Mole schemes (with and without auth-params), unknown realm param, uppercase hex,
    // and a malformed Mole challenge (which Clients must skip while retaining valid challenges).
    let complex = format!(
        "Bearer realm=\"api\", Basic, {combined}, Mole challenge-0000=\"AA\", Mole endorse-0002=\"\", realm=\"ignored\""
    );
    let mut headers = HeaderMap::new();
    headers.append(WWW_AUTHENTICATE, HeaderValue::from_str(&complex).unwrap());

    let parsed = parse_www_authenticate_headers(&headers);
    assert_eq!(
        parsed,
        vec![
            ch1,
            ch2,
            MoleChallenge::Endorse {
                endorsement_type: EndorsementType::EC_IHAT,
                context: Vec::new()
            }
        ]
    );

    // Strict single-challenge checks:
    assert!(parse_single_mole_challenge_strict("Mole ENDORSE-0002=\"\"").is_ok());
    assert!(parse_single_mole_challenge_strict("Mole challenge-0000=\"AA\"").is_err());
    assert!(parse_single_mole_challenge_strict("Mole challenge-001=\"AA\"").is_err());
    assert!(parse_single_mole_challenge_strict("Mole challenge-0001=\"AA\", redeem-0002=\"AA\"").is_err());
    assert!(parse_single_mole_challenge_strict("Mole realm=\"only\"").is_err());
    assert!(parse_single_mole_challenge_strict("Mole realm=\"a\", REALM=\"b\", endorse-0002=\"\"").is_err());
}

#[test]
fn authorization_operations_and_rejection_rules() {
    // Redeem & Issue in both parameter orders, plus NoEndorsement (0001).
    let auth_ec_ihat = MoleAuthorization::RedeemAndIssue {
        endorsement_type: EndorsementType::EC_IHAT,
        redemption: vec![9, 8, 7],
        credential_type: CredentialType::EC_ACT,
        credential_request: vec![1, 2, 3],
    };
    let s = auth_ec_ihat.to_header_value().unwrap();
    assert_eq!(MoleAuthorization::parse_header_str(&s).unwrap(), Some(auth_ec_ihat.clone()));

    let reversed = "Mole credential-request-0001=\"AQID\", redeem-0002=\"CQgH\", realm=\"ok\"";
    assert_eq!(
        MoleAuthorization::parse_header_str(reversed).unwrap(),
        Some(auth_ec_ihat)
    );

    let no_end = MoleAuthorization::RedeemAndIssue {
        endorsement_type: EndorsementType::NO_ENDORSEMENT,
        redemption: Vec::new(),
        credential_type: CredentialType::EC_ACT,
        credential_request: vec![5, 6],
    };
    let s_no_end = no_end.to_header_value().unwrap();
    assert!(s_no_end.contains("redeem-0001=\"\""));
    assert_eq!(MoleAuthorization::parse_header_str(&s_no_end).unwrap(), Some(no_end));

    // Reject non-empty redeem-0001, missing pair half, mixed ops, duplicate params, bad prefix, 0000, padded b64.
    assert!(MoleAuthorization::parse_header_str("Mole redeem-0001=\"AA\", credential-request-0001=\"AQ\"").is_err());
    assert!(MoleAuthorization::parse_header_str("Mole redeem-0002=\"AA\"").is_err());
    assert!(MoleAuthorization::parse_header_str("Mole presentation-0001=\"AA\", recovery-0001=\"AA\"").is_err());
    assert!(MoleAuthorization::parse_header_str("Mole presentation-0001=\"AA\", PRESENTATION-0001=\"AA\"").is_err());
    assert!(MoleAuthorization::parse_header_str("Mole presentation-01=\"AA\"").is_err());
    assert!(MoleAuthorization::parse_header_str("Mole presentation-0000=\"AA\"").is_err());
    assert!(MoleAuthorization::parse_header_str("Mole presentation-0001=\"YQ==\"").is_err());

    // Signoff and Recovery round-trips + quoted-string unescaping.
    let handle = [0xabu8; 96];
    let signoff = MoleAuthorization::Signoff {
        credential_type: CredentialType::EC_ACT,
        recovery_handle: handle.to_vec(),
    };
    let signoff_hdr = signoff.to_header_value().unwrap();
    assert_eq!(
        MoleAuthorization::parse_header_str(&signoff_hdr).unwrap(),
        Some(signoff)
    );

    let recovery = MoleAuthorization::Recovery {
        credential_type: CredentialType::EC_ACT,
        recovery_handle: handle.to_vec(),
    };
    let recovery_hdr = recovery.to_header_value().unwrap();
    assert_eq!(
        MoleAuthorization::parse_header_str(&recovery_hdr).unwrap(),
        Some(recovery)
    );

    // Non-Mole scheme returns Ok(None); duplicate Authorization header returns Err.
    assert_eq!(MoleAuthorization::parse_header_str("Bearer abc.def").unwrap(), None);
    let mut dup = HeaderMap::new();
    dup.append(AUTHORIZATION, HeaderValue::from_static("Mole signoff-0001=\"AA\""));
    dup.append(AUTHORIZATION, HeaderValue::from_static("Mole signoff-0001=\"AA\""));
    assert!(MoleAuthorization::from_headers(&dup).is_err());
}

#[test]
fn mole_credential_header_variants_and_cache_control() {
    let held = MoleCredentialHeader::HeldForUpdate {
        credential_type: CredentialType::EC_ACT,
        duration_secs: 30,
    };
    let mut headers = HeaderMap::new();
    apply_mole_credential_headers(&mut headers, &held).unwrap();
    assert_eq!(
        headers.get(&MOLE_CREDENTIAL_HEADER).unwrap(),
        "held-for-update-0001=\"30\""
    );
    assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(MoleCredentialHeader::from_headers(&headers).unwrap(), Some(held));

    // Unquoted token duration also parses cleanly; leading zeros, signs, and extra params fail.
    assert_eq!(
        MoleCredentialHeader::parse_header_str("held-for-update-0001=0").unwrap(),
        MoleCredentialHeader::HeldForUpdate {
            credential_type: CredentialType::EC_ACT,
            duration_secs: 0
        }
    );
    assert!(MoleCredentialHeader::parse_header_str("held-for-update-0001=\"01\"").is_err());
    assert!(MoleCredentialHeader::parse_header_str("held-for-update-0001=\"+5\"").is_err());
    assert!(MoleCredentialHeader::parse_header_str("update-0001=\"\", extra=\"1\"").is_err());

    // NoUpdate vs non-empty Update.
    let no_upd = MoleCredentialHeader::Update {
        credential_type: CredentialType::EC_ACT,
        update: None,
    };
    assert_eq!(no_upd.to_header_value().unwrap(), "update-0001=\"\"");
    assert_eq!(
        MoleCredentialHeader::parse_header_str("update-0001=\"\"").unwrap(),
        no_upd
    );

    // Repeated Mole-Credential header MUST be rejected.
    headers.append(
        MOLE_CREDENTIAL_HEADER,
        HeaderValue::from_static("update-0001=\"\""),
    );
    assert!(MoleCredentialHeader::from_headers(&headers).is_err());
}

#[test]
fn media_types_session_and_greasing() {
    let mut h = HeaderMap::new();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&format_endorsement_request_content_type(EndorsementType::EC_IHAT).unwrap()).unwrap(),
    );
    assert_eq!(
        parse_endorsement_request_content_type(&h).unwrap(),
        EndorsementType::EC_IHAT
    );

    let mut h_resp = HeaderMap::new();
    h_resp.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&format_endorsement_response_content_type(EndorsementType::EC_IHAT).unwrap()).unwrap(),
    );
    assert_eq!(
        parse_endorsement_response_content_type(&h_resp).unwrap(),
        EndorsementType::EC_IHAT
    );

    // Reject missing type, duplicate type, extra params, or 0000.
    let mut bad = HeaderMap::new();
    bad.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/mole-endorsement-request"),
    );
    assert!(parse_endorsement_request_content_type(&bad).is_err());
    bad.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/mole-endorsement-request; type=0002; type=0002"),
    );
    assert!(parse_endorsement_request_content_type(&bad).is_err());
    bad.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/mole-endorsement-request; type=0002; foo=bar"),
    );
    assert!(parse_endorsement_request_content_type(&bad).is_err());
    bad.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/mole-endorsement-request; type=0000"),
    );
    assert!(parse_endorsement_request_content_type(&bad).is_err());

    // Want-Endorsement & Mole-Session (RFC 9651 Structured Field Values)
    let mut hs = HeaderMap::new();
    hs.insert(WANT_ENDORSEMENT_HEADER, HeaderValue::from_static("Other, Mole"));
    let sess = format_mole_session(b"tok_123-abc");
    assert!(sess.starts_with(':') && sess.ends_with(':'));
    hs.insert(
        MOLE_SESSION_HEADER,
        HeaderValue::from_str(&format!("  {sess}  ")).unwrap(),
    );
    assert!(has_want_endorsement_mole(&hs));
    assert_eq!(parse_mole_session(&hs).unwrap().as_deref(), Some(sess.as_str()));

    hs.insert(MOLE_SESSION_HEADER, HeaderValue::from_static("bare-token"));
    assert!(parse_mole_session(&hs).is_err());
    hs.insert(
        MOLE_SESSION_HEADER,
        HeaderValue::from_str(&format!("{sess}; extra=1")).unwrap(),
    );
    assert!(parse_mole_session(&hs).is_err());

    // Greasing
    assert_eq!(GREASED_TYPES.len(), 16);
    for &g in &GREASED_TYPES {
        assert!(CredentialType(g).is_greased());
    }
    let (gt, gbody) = generate_greased_presentation().unwrap();
    assert!(gt.is_greased());
    assert!(!gbody.is_empty());
}

#[test]
fn full_ec_ihat_and_ec_act_wire_and_config_roundtrip() {
    // 1. Anchor & Moderator key setup
    let seed_a1 = IhatBackend::generate_seed().unwrap();
    let sk_a1: ec_ihat::SecretKey = ec_ihat::SecretKey::from_seed(&seed_a1).unwrap();
    let pk_a1 = sk_a1.public_key();

    let seed_a2 = IhatBackend::generate_seed().unwrap();
    let sk_a2 = ec_ihat::SecretKey::from_seed(&seed_a2).unwrap();
    let pk_a2 = sk_a2.public_key();

    let seed_m = ActBackend::generate_seed().unwrap();
    let sk_m = ec_act::SecretKey::from_seed(&seed_m).unwrap();
    let pk_m = sk_m.public_key();
    let l = 8u8;
    let params = ec_act::Params::new(l).unwrap();
    let ctx_iss = b"2026-11".to_vec();
    let cred_ctx = b"mod-epoch-1".to_vec();
    let ctx_cred = derive_ec_act_ctx_cred(&cred_ctx, l).unwrap();
    let key_id = compute_ec_act_key_id(&pk_m);

    // 2. Config serialization & validation
    let anchor_cfg = AnchorConfiguration {
        grant_uri: "https://anchor2.example:8443/mole/grant".to_owned(),
        endorsement_type: 2,
        ciphersuite: CIPHERSUITE_P256_SHA256.to_owned(),
        anchor_key: pk_a2.to_bytes().to_vec(),
        issuance_epoch: ctx_iss.clone(),
    };
    let anchor_json = serde_json::to_string(&anchor_cfg).unwrap();
    let anchor_cfg_dec: AnchorConfiguration = serde_json::from_str(&anchor_json).unwrap();
    let (_, pk_a2_dec) = anchor_cfg_dec.validate_ec_ihat().unwrap();
    assert_eq!(pk_a2_dec, pk_a2);

    // Reject http://, userinfo, and fragments in endpoint URIs.
    assert!(validate_https_endpoint_uri("http://example.com/mole/grant").is_err());
    assert!(validate_https_endpoint_uri("https://user@example.com/mole/grant").is_err());
    assert!(validate_https_endpoint_uri("https://example.com/mole/grant#frag").is_err());

    let mut mod_cfg = ModeratorConfiguration::from_typed(
        "https://moderator.example/mole/issue".to_owned(),
        false,
        &[EcIhatEndorsementConfig {
            endorsement_type: 2,
            ciphersuite: CIPHERSUITE_P256_SHA256.to_owned(),
            issuance_epoch: ctx_iss.clone(),
            anchor_set: vec![pk_a1.to_bytes().to_vec(), pk_a2.to_bytes().to_vec()],
        }],
        &[EcActKeyConfig {
            credential_type: 1,
            credential_key: pk_m.to_bytes().to_vec(),
            ciphersuite: CIPHERSUITE_P256_SHA256.to_owned(),
            balance_width: l,
            credential_context: cred_ctx.clone(),
            result_retention: 300,
        }],
    )
    .unwrap();
    // Inject unknown future types (endorsement-type 3, credential-type 99) to verify graceful skip.
    mod_cfg
        .endorsements
        .push(serde_json::json!({"endorsement-type": 3, "future": true}));
    mod_cfg
        .credential_keys
        .push(serde_json::json!({"credential-type": 99, "future": "ignored"}));
    let (_, sup_end, sup_keys) = mod_cfg.parse_supported().unwrap();
    assert_eq!(sup_end.len(), 1);
    assert_eq!(sup_keys.len(), 1);
    let SupportedModeratorEndorsement::EcIhat(ref ec_ihat_set) = sup_end[0] else {
        panic!("expected EcIhat");
    };
    let anchor_pks = ec_ihat_set.decode_anchor_set().unwrap();

    // 3. Batch Grant wire messages (disambiguated on /mole/grant)
    let req_bytes = GrantRequest { count: 2 }.to_bytes().unwrap();
    assert_eq!(
        EcIhatGrantPost::from_bytes(&req_bytes).unwrap(),
        EcIhatGrantPost::Request(GrantRequest { count: 2 })
    );

    let (st1, com1) = ec_ihat::commit(&ctx_iss).unwrap();
    let (st2, com2) = ec_ihat::commit(&ctx_iss).unwrap();
    let session_id = [0x11u8; 32];
    let gc_bytes = GrantCommitments {
        session_id,
        commitments: vec![com1, com2],
    }
    .to_bytes()
    .unwrap();
    let gc_dec = GrantCommitments::from_bytes(&gc_bytes).unwrap();

    let (cst1, ch1) =
        ec_ihat::challenge(&pk_a2, &ctx_iss, EC_IHAT_CTX_RED, &gc_dec.commitments[0]).unwrap();
    let (cst2, ch2) =
        ec_ihat::challenge(&pk_a2, &ctx_iss, EC_IHAT_CTX_RED, &gc_dec.commitments[1]).unwrap();
    let gch_bytes = GrantChallenges {
        session_id: gc_dec.session_id,
        challenges: vec![ch1, ch2],
    }
    .to_bytes()
    .unwrap();
    let EcIhatGrantPost::Challenges(gch_dec) = EcIhatGrantPost::from_bytes(&gch_bytes).unwrap()
    else {
        panic!("expected Challenges");
    };

    let r1 = ec_ihat::respond(&sk_a2, st1, &gch_dec.challenges[0]).unwrap();
    let r2 = ec_ihat::respond(&sk_a2, st2, &gch_dec.challenges[1]).unwrap();
    let gr_bytes = GrantResponses {
        responses: vec![r1, r2],
    }
    .to_bytes()
    .unwrap();
    let gr_dec = GrantResponses::from_bytes(&gr_bytes).unwrap();

    let mut cstates = [cst1, cst2].into_iter();
    let e1 = ec_ihat::finalize(&pk_a2, cstates.next().unwrap(), &gr_dec.responses[0]).unwrap();
    let _e2 = ec_ihat::finalize(&pk_a2, cstates.next().unwrap(), &gr_dec.responses[1]).unwrap();

    // 4. Redeem & Issue wire round-trip
    let red_chal = RedemptionChallenge {
        redemption_context: [0x77u8; 32],
    };
    let red_chal_dec = RedemptionChallenge::from_bytes(&red_chal.to_bytes()).unwrap();
    let redemption = ec_ihat::redeem(
        &anchor_pks,
        1,
        e1,
        &ctx_iss,
        EC_IHAT_CTX_RED,
        &red_chal_dec.digest(),
    )
    .unwrap();
    let _nf = ec_ihat::verify_redemption(
        &anchor_pks,
        &redemption,
        &ctx_iss,
        EC_IHAT_CTX_RED,
        &red_chal.digest(),
    )
    .unwrap();

    let (iss_state, iss_req_msg) = ec_act::issue_request(&params).unwrap();
    let iss_req = EcActIssuanceRequest {
        truncated_key_id: sup_keys[0].truncated_key_id,
        credential_context: cred_ctx.clone(),
        request: iss_req_msg,
    };
    let iss_req_dec = EcActIssuanceRequest::from_bytes(&params, &iss_req.to_bytes().unwrap()).unwrap();
    let ver_iss = ec_act::verify_issue_request(&params, &iss_req_dec.request).unwrap();
    let iss_resp_msg = ec_act::issue_response(&sk_m, &ctx_cred, 60, ver_iss).unwrap();
    let iss_resp = EcActIssuanceResponse {
        response: iss_resp_msg,
    };
    let iss_resp_dec = EcActIssuanceResponse::from_bytes(&params, &iss_resp.to_bytes()).unwrap();
    let cred = ec_act::finalize_issue(&params, &pk_m, &ctx_cred, iss_state, &iss_resp_dec.response)
        .unwrap();
    assert_eq!(cred.balance(), 60);

    // 5. Presentation, deferred verify_spend + issue_refund, Update, and RecoveryHandle
    let act_chal = EcActChallenge {
        spend_amount: 20,
        max_top_up: 0,
        credential_context: cred_ctx,
        request_context: b"GET:/protected".to_vec(),
    };
    let ctx_spend = act_chal.ctx_spend().unwrap();
    let (spend_state, spend_msg) =
        ec_act::prove_spend(&params, cred, &ctx_cred, 20, 0, &ctx_spend).unwrap();
    let pres = EcActPresentationAndUpdate {
        key_id,
        spend: spend_msg,
    };
    let pres_bytes = pres.to_bytes();
    let handle = pres.recovery_handle();
    let handle_dec = RecoveryHandle::from_bytes(&handle.to_bytes()).unwrap();
    assert_eq!(handle, handle_dec);
    assert_eq!(handle.key_id, key_id);

    let pres_dec = EcActPresentationAndUpdate::from_bytes(&params, &pres_bytes).unwrap();
    let ver_spend =
        ec_act::verify_spend(&params, &sk_m, &ctx_cred, &ctx_spend, &pres_dec.spend).unwrap();
    assert_eq!(ver_spend.nullifier(), handle.nullifier);

    // Simulate held-for-update finalization reconstructing VerifiedSpend from stored spend_bytes:
    let stored_spend_bytes = pres_dec.spend.to_bytes();
    drop(ver_spend);
    let reloaded_spend = ec_act::SpendMessage::from_bytes(&params, &stored_spend_bytes).unwrap();
    let ver_spend_later =
        ec_act::verify_spend(&params, &sk_m, &ctx_cred, &ctx_spend, &reloaded_spend).unwrap();
    let refund_msg = ec_act::issue_refund(ver_spend_later, 20).unwrap();
    let upd = EcActUpdate { refund: refund_msg };
    let upd_dec = EcActUpdate::from_bytes(&params, &upd.to_bytes()).unwrap();
    let cred2 =
        ec_act::finalize_refund(&params, &pk_m, &ctx_cred, spend_state, &upd_dec.refund).unwrap();
    assert_eq!(cred2.balance(), 60);

    // 6. LocalCa sanity check
    let ca = LocalCa::generate("Test MOLE CA").unwrap();
    let leaf = ca.issue_server_cert(&[]).unwrap();
    assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
    let _client_cfg = ca.client_config().unwrap();
}
