use askama::Template;
use askama_axum::IntoResponse;
use axum::{http::StatusCode, response::Html, routing::get, Router};

mod passkey;
use passkey::AppState;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate;

async fn index() -> impl IntoResponse {
    let template = IndexTemplate {};
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
}

#[tokio::main]
async fn main() {
    let state = passkey::app_state();

    let app = Router::new()
        .route("/", get(index))
        .nest("/register", passkey::register::router(state.clone()))
        .nest("/auth", passkey::auth::router(state.clone()));
    // .with_state(state);

    println!("Starting server on http://localhost:3001");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
