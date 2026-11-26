#![cfg(all(feature = "axum", feature = "actix"))]

use std::sync::Arc;

use hibira::waiting_room::{actix_guard, axum_guard};
use hibira::{Guard, Pass};

const SECRET: &str = "wr-secret-0123456789";
const PASS: &str = "eyJ2IjoxLCJhcHAiOiJ3ci1hcHAiLCJyb29tIjoicHJlc2FsZSIsIm4iOjQyLCJ0aWQiOiJkNzlmZTc4OWEzOGI4NjMxYjUiLCJpYXQiOjE4MDAwMDAwMDAsImV4cCI6MTgwMDAwMTgwMH0.q7Uc_O6XKwNA_LVLQITlgv_YtDi9dIwiRzUUUSsGa08";

fn guard() -> Guard {
    let mut g = Guard::new("key", SECRET, "presale");
    g.now = Some(1800000100);
    g
}

mod axum_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Extension;
    use tower::ServiceExt;

    fn app() -> axum::Router {
        axum::Router::new()
            .route(
                "/drop",
                get(|Extension(p): Extension<Pass>| async move { format!("number {}", p.number) })
                    .post(|| async { "posted" }),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(guard()),
                axum_guard,
            ))
    }

    #[tokio::test]
    async fn redirects_denies_and_allows() {
        let res = app()
            .oneshot(
                Request::get("/drop")
                    .header("host", "shop.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), 302);
        assert_eq!(
            res.headers()["location"],
            "https://ws.hibira.io/wait/key/presale?return=http%3A%2F%2Fshop.test%2Fdrop"
        );
        assert_eq!(res.headers()["cache-control"], "no-store");

        let res = app()
            .oneshot(
                Request::post("/drop")
                    .header("host", "shop.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), 403);

        let res = app()
            .oneshot(
                Request::get(format!("/drop?hibira_pass={PASS}"))
                    .header("host", "shop.test")
                    .header("x-forwarded-proto", "https")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), 302);
        assert_eq!(res.headers()["location"], "https://shop.test/drop");
        assert!(res.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .starts_with("hibira_wr_presale="));

        let res = app()
            .oneshot(
                Request::get("/drop")
                    .header("host", "shop.test")
                    .header("cookie", format!("hibira_wr_presale={PASS}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"number 42");
    }
}

mod actix_tests {
    use super::*;
    use actix_web::{middleware::from_fn, test, web, App, HttpResponse};

    #[actix_web::test]
    async fn redirects_denies_and_allows() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(guard()))
                .wrap(from_fn(actix_guard))
                .route(
                    "/drop",
                    web::get().to(|p: web::ReqData<Pass>| async move {
                        HttpResponse::Ok().body(format!("number {}", p.number))
                    }),
                )
                .route(
                    "/drop",
                    web::post().to(|| async { HttpResponse::Ok().finish() }),
                ),
        )
        .await;

        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/drop")
                .insert_header(("host", "shop.test"))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 302);
        assert_eq!(
            res.headers().get("location").unwrap(),
            "https://ws.hibira.io/wait/key/presale?return=http%3A%2F%2Fshop.test%2Fdrop"
        );

        let res =
            test::call_service(&app, test::TestRequest::post().uri("/drop").to_request()).await;
        assert_eq!(res.status(), 403);

        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/drop?a=1&hibira_pass={PASS}"))
                .insert_header(("host", "shop.test"))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 302);
        assert_eq!(
            res.headers().get("location").unwrap(),
            "http://shop.test/drop?a=1"
        );
        assert!(res
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("HttpOnly"));

        let req = test::TestRequest::get()
            .uri("/drop")
            .insert_header(("cookie", format!("hibira_wr_presale={PASS}")))
            .to_request();
        let body = test::call_and_read_body(&app, req).await;
        assert_eq!(&body[..], b"number 42");
    }
}
