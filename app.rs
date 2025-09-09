use actix_web::{cookie::Cookie, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_files::NamedFile;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use chrono::{Utc, Duration};
use std::{env, fs};
use reqwest::Client;
use dotenv::dotenv;

#[derive(Deserialize)]
struct KeyRequest {
    key: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    access: bool,
    exp: usize,
}

async fn send_webhook(message: &str, webhook_url: &str) {
    let payload = serde_json::json!({ "content": format!("```{}```", message) });
    let client = Client::new();
    if let Err(e) = client.post(webhook_url).json(&payload).send().await {
        eprintln!("Webhook送信エラー: {:?}", e);
    }
}

async fn check_key(req: web::Json<KeyRequest>, req_head: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let user_key = &req.key;
    let ip = req_head.connection_info().realip_remote_addr().unwrap_or("unknown");
    let user_agent = req_head.headers().get("User-Agent").map(|v| v.to_str().unwrap_or("")).unwrap_or("");
    let time = Utc::now().to_rfc3339();

    send_webhook(&format!(
        "パスワードが送信されました:\n日付: {}\nIP: {}\nデバイス: {}\n入力キー: {}",
        time, ip, user_agent, user_key
    ), &data.webhook_url).await;

    if data.keys.contains(user_key) {
        let exp = (Utc::now() + Duration::minutes(1)).timestamp() as usize;
        let claims = Claims { access: true, exp };
        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(data.secret.as_bytes())).unwrap();

        let cookie = Cookie::build("TOKEN", token)
            .http_only(true)
            .secure(true)
            .max_age(time::Duration::seconds(60))
            .same_site(actix_web::cookie::SameSite::Strict)
            .finish();

        HttpResponse::Ok().cookie(cookie).json(serde_json::json!({"ok": true}))
    } else {
        HttpResponse::Unauthorized().json(serde_json::json!({"ok": false}))
    }
}

async fn script_html(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let token = req.cookie("TOKEN").map(|c| c.value().to_string());
    let ip = req.connection_info().realip_remote_addr().unwrap_or("unknown");
    let user_agent = req.headers().get("User-Agent").map(|v| v.to_str().unwrap_or("")).unwrap_or("");
    let time = Utc::now().to_rfc3339();

    if token.is_none() {
        send_webhook(&format!(
            "❌️不正なログイン:認証トークンが見つかりません\n日付: {}\nIP: {}\nデバイス: {}",
            time, ip, user_agent
        ), &data.webhook_url).await;
        return HttpResponse::Unauthorized().body("No token provided");
    }

    let decoded = decode::<Claims>(
        token.unwrap().as_str(),
        &DecodingKey::from_secret(data.secret.as_bytes()),
        &Validation::new(Algorithm::HS256)
    );

    match decoded {
        Ok(c) if c.claims.access => {
            send_webhook(&format!(
                "✅ 正常アクセス\n日付: {}\nIP: {}\nデバイス: {}",
                time, ip, user_agent
            ), &data.webhook_url).await;

            NamedFile::open("private/Script.html").unwrap()
                .use_last_modified(true)
                .into_response(&req)
        },
        Err(e) => {
            send_webhook(&format!(
                "❌️不正なログイン:無効なトークン\n日付: {}\nIP: {}\nデバイス: {}\n理由: {:?}",
                time, ip, user_agent, e
            ), &data.webhook_url).await;
            HttpResponse::Forbidden().body("Invalid or expired token")
        }
    }
}

struct AppState {
    keys: Vec<String>,
    secret: String,
    webhook_url: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let secret = env::var("SECRET").expect("SECRET is not set");
    let webhook_url = env::var("DISCORD_WEBHOOK_URL").expect("DISCORD_WEBHOOK_URL is not set");
    let variation = env::var("VARIATION").unwrap_or_default();
    let port: u16 = env::var("PORT").unwrap_or("8080".to_string()).parse().unwrap();

    let data_json = fs::read_to_string("data/data.json").expect("data.json not found");
    let keys: Vec<String> = serde_json::from_value(serde_json::from_str::<serde_json::Value>(&data_json).unwrap()["key"].clone())
        .unwrap_or_default();

    println!("=========================");
    println!(" ");
    println!("Copyright (C) 2025 @kiyu4776");
    println!("This file is proprietary and confidential.");
    println!("Unauthorized reproduction or distribution is prohibited.");
    println!(" ");
    println!("Var : {}", variation);
    println!(" ");
    println!("==========log============");

    let state = web::Data::new(AppState { keys, secret, webhook_url });

    println!("✅ サーバー起動: http://localhost:{}", port);

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/api/check-key", web::post().to(check_key))
            .route("/Script.html", web::get().to(script_html))
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}