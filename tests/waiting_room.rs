use hibira::signing::hmac_sha256_hex;
use hibira::waiting_room::{
    sign_user, verify, waiting_room_url, Decision, Guard, UrlOptions, VerifyOptions,
};
use http::{HeaderMap, HeaderValue, Method, Uri};

// The shared test vector: signed by the Hibira server at 1800000000, ttl 30 minutes.
const SECRET: &str = "wr-secret-0123456789";
const PASS: &str = "eyJ2IjoxLCJhcHAiOiJ3ci1hcHAiLCJyb29tIjoicHJlc2FsZSIsIm4iOjQyLCJ0aWQiOiJkNzlmZTc4OWEzOGI4NjMxYjUiLCJpYXQiOjE4MDAwMDAwMDAsImV4cCI6MTgwMDAwMTgwMH0.q7Uc_O6XKwNA_LVLQITlgv_YtDi9dIwiRzUUUSsGa08";
const TICKET: &str = "eyJ2IjoxLCJhcHAiOiJ3ci1hcHAiLCJyb29tIjoicHJlc2FsZSIsIm4iOjQyLCJ0aWQiOiJkNzlmZTc4OWEzOGI4NjMxYjUiLCJpYXQiOjE4MDAwMDAwMDAsImV4cCI6MTgwMDA4NjQwMH0.l-KNMOVwV_xJJCQaQ-JXQKsrj-XlEdsTxG7X4Kp_2ck";
const NOW: i64 = 1800000100;

fn secrets() -> Vec<String> {
    vec![SECRET.to_string()]
}

#[test]
fn verifies_the_shared_vector() {
    let s = secrets();
    let p = verify(
        PASS,
        &VerifyOptions {
            secrets: &s,
            room: Some("presale"),
            app_id: Some("wr-app"),
            now: Some(NOW),
        },
    )
    .expect("valid pass");
    assert_eq!(
        (
            p.app_id.as_str(),
            p.room.as_str(),
            p.number,
            p.ticket_id.as_str()
        ),
        ("wr-app", "presale", 42, "d79fe789a38b8631b5")
    );
    assert_eq!(
        (p.issued_at, p.expires_at, p.user_id),
        (1800000000, 1800001800, None)
    );
    let rotated = vec!["old".to_string(), SECRET.to_string()];
    assert!(verify(
        PASS,
        &VerifyOptions {
            secrets: &rotated,
            now: Some(NOW),
            ..Default::default()
        }
    )
    .is_some());
}

#[test]
#[allow(clippy::type_complexity)]
fn rejects_bad_passes() {
    let s = secrets();
    let wrong = vec!["wrong".to_string()];
    let o = |room: Option<&'static str>, app: Option<&'static str>, now: i64| (room, app, now);
    let cases: Vec<(&str, &str, Vec<String>, (Option<&str>, Option<&str>, i64))> = vec![
        ("wrong secret", PASS, wrong, o(None, None, NOW)),
        ("other room", PASS, s.clone(), o(Some("other"), None, NOW)),
        ("other app", PASS, s.clone(), o(None, Some("other"), NOW)),
        ("expired", PASS, s.clone(), o(None, None, 1800001800)),
        ("ticket", TICKET, s.clone(), o(None, None, NOW)),
        ("empty", "", s.clone(), o(None, None, NOW)),
        ("no secret", PASS, vec![], o(None, None, NOW)),
        ("garbage", "a.b.c", s.clone(), o(None, None, NOW)),
    ];
    let tampered = format!("{}AAA", &PASS[..PASS.len() - 3]);
    let long = "a".repeat(1025);
    for (name, pass, secrets, (room, app, now)) in
        cases.iter().map(|c| (c.0, c.1, &c.2, c.3)).chain([
            ("tampered", tampered.as_str(), &s, (None, None, NOW)),
            ("too long", long.as_str(), &s, (None, None, NOW)),
        ])
    {
        let got = verify(
            pass,
            &VerifyOptions {
                secrets,
                room,
                app_id: app,
                now: Some(now),
            },
        );
        assert!(got.is_none(), "{name}: {got:?}");
    }
}

#[test]
fn signs_user_tokens() {
    let tok = sign_user(SECRET, "presale", "cust_42", 600, Some(1800000000)).unwrap();
    let want = format!(
        "cust_42.1800000600.{}",
        hmac_sha256_hex(
            SECRET.as_bytes(),
            b"hibira-waitroom-user.presale.cust_42.1800000600"
        )
    );
    assert_eq!(tok, want);
    assert!(sign_user(SECRET, "presale", "a.b", 0, None).is_err());
    assert!(
        sign_user(SECRET, "presale", "u", 30 * 24 * 3600, Some(1800000000))
            .unwrap()
            .starts_with("u.1800604800.")
    );
}

#[test]
fn builds_the_waiting_page_url() {
    let got = waiting_room_url(&UrlOptions {
        app_key: "key",
        room: "presale",
        return_url: Some("https://shop.test/drop?a=1"),
        lang: Some("ja"),
        ..Default::default()
    });
    assert_eq!(got, "https://ws.hibira.io/wait/key/presale?lang=ja&return=https%3A%2F%2Fshop.test%2Fdrop%3Fa%3D1");
}

fn guard() -> Guard {
    let mut g = Guard::new("key", SECRET, "presale");
    g.now = Some(NOW);
    g
}

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.append(*k, HeaderValue::from_str(v).unwrap());
    }
    h
}

#[test]
fn guard_redirects_and_denies_without_a_pass() {
    let g = guard();
    let d = g.decide(
        &Method::GET,
        &Uri::from_static("/drop"),
        &headers(&[("host", "shop.test")]),
        true,
    );
    assert_eq!(
        d,
        Decision::Redirect {
            location: "https://ws.hibira.io/wait/key/presale?return=https%3A%2F%2Fshop.test%2Fdrop"
                .into(),
            set_cookie: None,
            pass: None
        }
    );
    assert_eq!(
        g.decide(
            &Method::POST,
            &Uri::from_static("/drop"),
            &headers(&[("host", "shop.test")]),
            true
        ),
        Decision::Deny
    );
}

#[test]
fn guard_stores_a_pass_from_the_queue() {
    let g = guard();
    let uri: Uri = format!("/drop?item=7&hibira_pass={PASS}").parse().unwrap();
    match g.decide(
        &Method::GET,
        &uri,
        &headers(&[("host", "example.com"), ("x-forwarded-proto", "https")]),
        false,
    ) {
        Decision::Redirect {
            location,
            set_cookie,
            pass,
        } => {
            assert_eq!(location, "https://example.com/drop?item=7");
            assert_eq!(set_cookie.unwrap(), format!("hibira_wr_presale={PASS}; Path=/; Max-Age=1700; HttpOnly; SameSite=Lax; Secure"));
            assert_eq!(pass.unwrap().number, 42);
        }
        other => panic!("{other:?}"),
    }
    match g.decide(
        &Method::GET,
        &Uri::from_static("/drop?hibira_pass=forged"),
        &headers(&[("host", "example.com")]),
        false,
    ) {
        Decision::Redirect {
            location,
            set_cookie: None,
            ..
        } => assert!(location.starts_with("https://ws.hibira.io/wait/key/presale")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn guard_allows_a_cookie() {
    let g = guard();
    let cookie = format!("a=b; hibira_wr_presale={PASS}");
    match g.decide(
        &Method::POST,
        &Uri::from_static("/drop"),
        &headers(&[("host", "shop.test"), ("cookie", &cookie)]),
        true,
    ) {
        Decision::Allow(p) => assert_eq!(p.ticket_id, "d79fe789a38b8631b5"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn guard_passes_a_signed_user() {
    let mut g = guard();
    g.user = Some(std::sync::Arc::new(|_h: &HeaderMap| {
        Some("cust_1.1800000600.ab".to_string())
    }));
    match g.decide(
        &Method::GET,
        &Uri::from_static("/drop"),
        &headers(&[("host", "shop.test")]),
        true,
    ) {
        Decision::Redirect { location, .. } => assert!(
            location.ends_with("&user=cust_1.1800000600.ab"),
            "{location}"
        ),
        other => panic!("{other:?}"),
    }
}
