use http::StatusCode;
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tracing::{debug, error, warn};
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use crate::dto::{AccountInvitation, ChangePasswordRequest, InvitationRequest, LoggedUser, LoginResponse, NewUserRequest, RefreshResponse, UpdateInvitationRequest, UserAccount};

static AUTH_API_URL: OnceLock<String> = OnceLock::new();
static AUTH_APP_SECRET: OnceLock<String> = OnceLock::new();
static HTTP_CLIENT: OnceLock<Client> = OnceLock::new();

/// JWT auth middleware — validates the bearer token by calling the auth-api.
pub async fn jwt_auth(mut req: Request, next: Next) -> Response {
    async fn authenticate(req: &mut Request) -> Option<LoggedUser> {
        let header = req.headers().get("Authorization")?;
        let token = header.to_str().ok()?.strip_prefix("Bearer ")?;
        validate_token(token).await.ok()
    }

    match authenticate(&mut req).await {
        Some(claims) => {
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

pub fn init(url: String, secret: String) {
    let _ = AUTH_API_URL.set(url);
    let _ = AUTH_APP_SECRET.set(secret);
}

fn auth_url() -> &'static str {
    AUTH_API_URL.get().expect("AUTH_API_URL not initialized")
}

fn app_token() -> &'static str {
    AUTH_APP_SECRET.get().expect("AUTH_APP_SECRET not initialized")
}

fn client() -> &'static Client {
    HTTP_CLIENT.get_or_init(Client::new)
}

fn bearer(token: &str) -> String {
    format!("Bearer {}", token)
}

async fn send(builder: RequestBuilder) -> Result<reqwest::Response, (StatusCode, String)> {
    builder.send().await.map_err(|e| {
        error!(error = %e, "auth-api request failed (connection error)");
        (StatusCode::BAD_GATEWAY, e.to_string())
    })
}

async fn get(url: &str, token: &str) -> Result<reqwest::Response, (StatusCode, String)> {
    send(client().get(url).header("Authorization", bearer(token))).await
}

async fn post(url: &str, token: &str) -> Result<reqwest::Response, (StatusCode, String)> {
    send(client().post(url).header("Authorization", bearer(token))).await
}

async fn post_json<T: Serialize>(url: &str, token: &str, body: &T) -> Result<reqwest::Response, (StatusCode, String)> {
    send(client().post(url).header("Authorization", bearer(token)).json(body)).await
}

async fn put_json<T: Serialize>(url: &str, token: &str, body: &T) -> Result<reqwest::Response, (StatusCode, String)> {
    send(client().put(url).header("Authorization", bearer(token)).json(body)).await
}

async fn delete(url: &str, token: &str) -> Result<reqwest::Response, (StatusCode, String)> {
    send(client().delete(url).header("Authorization", bearer(token))).await
}

// ---- Request body types ----

#[derive(Serialize)]
struct LoginBody<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Serialize)]
struct CreateAccountBody {
    display_name: String,
    email: String,
    password: String,
}

#[derive(Serialize)]
struct ChangePasswordBody<'a> {
    current_password: &'a str,
    new_password: &'a str,
}

#[derive(Serialize)]
struct UpdateNameBody<'a> {
    display_name: &'a str,
}

#[derive(Serialize)]
struct ValidateTokenBody<'a> {
    user_token: &'a str,
}

// ---- Response type from auth-api token validation ----

#[derive(Deserialize)]
struct ValidateTokenResponse {
    valid: bool,
    sub: Option<String>,
    name: Option<String>,
    email: Option<String>,
    admin: Option<bool>,
}

// ---- Shared response handlers ----

async fn forward_response<T: for<'de> Deserialize<'de>>(
    resp: reqwest::Response,
) -> Result<T, (StatusCode, String)> {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    if status.is_success() {
        resp.json::<T>().await.map_err(|e| {
            error!(error = %e, "auth-api response deserialization failed");
            (StatusCode::BAD_GATEWAY, e.to_string())
        })
    } else {
        let msg = resp.text().await.unwrap_or_default();
        warn!(status = %status, body = %msg, "auth-api returned error");
        Err((status, msg))
    }
}

async fn forward_empty_response(resp: reqwest::Response) -> Result<(), (StatusCode, String)> {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    if status.is_success() {
        Ok(())
    } else {
        let msg = resp.text().await.unwrap_or_default();
        warn!(status = %status, body = %msg, "auth-api returned error");
        Err((status, msg))
    }
}

// ---- Public functions ----

/// Validate a user JWT by calling auth-api's /auth/validate endpoint.
/// Called by the jwt_auth middleware for every protected request.
pub async fn validate_token(user_token: &str) -> Result<LoggedUser, String> {
    let url = format!("{}/auth/validate", auth_url());
    debug!(url = %url, "calling auth-api validate");
    let resp = post_json(&url, app_token(), &ValidateTokenBody { user_token }).await.map_err(|e| e.1)?;

    let body: ValidateTokenResponse = resp.json().await.map_err(|e| e.to_string())?;
    if body.valid {
        Ok(LoggedUser {
            sub: body.sub.unwrap(),
            name: body.name.unwrap(),
            email: body.email.unwrap(),
            admin: body.admin.unwrap(),
            exp: 0,
        })
    } else {
        Err("Invalid token".to_string())
    }
}

/// Forward a login request to auth-api (app-token protected).
pub async fn login(email: &str, password: &str) -> Result<LoginResponse, (StatusCode, String)> {
    let url = format!("{}/login", auth_url());
    debug!(url = %url, "calling auth-api login");
    let resp = post_json(&url, app_token(), &LoginBody { email, password }).await?;
    forward_response::<LoginResponse>(resp).await
}

/// Forward a create-account request to auth-api (public endpoint).
pub async fn create_account(req: NewUserRequest) -> Result<LoginResponse, (StatusCode, String)> {
    let url = format!("{}/accounts", auth_url());
    debug!(url = %url, "calling auth-api create_account");
    let body = CreateAccountBody { display_name: req.display_name, email: req.email, password: req.password };
    let resp = send(client().post(&url).json(&body)).await?; // no auth header — public endpoint
    forward_response::<LoginResponse>(resp).await
}

/// Forward a token refresh request to auth-api (user-JWT protected).
pub async fn refresh(user_token: &str) -> Result<RefreshResponse, (StatusCode, String)> {
    let url = format!("{}/auth/refresh", auth_url());
    let resp = post(&url, user_token).await?;
    forward_response::<RefreshResponse>(resp).await
}

/// Forward a change-password request to auth-api (user-JWT protected).
pub async fn change_password(
    user_token: &str,
    req: &ChangePasswordRequest,
) -> Result<RefreshResponse, (StatusCode, String)> {
    let url = format!("{}/accounts/change_passwd", auth_url());
    let body = ChangePasswordBody { current_password: &req.current_password, new_password: &req.new_password };
    let resp = post_json(&url, user_token, &body).await?;
    forward_response::<RefreshResponse>(resp).await
}

/// Forward an update-name request to auth-api (user-JWT protected).
pub async fn update_name(
    user_token: &str,
    display_name: &str,
) -> Result<UserAccount, (StatusCode, String)> {
    let url = format!("{}/accounts/update_name", auth_url());
    let resp = put_json(&url, user_token, &UpdateNameBody { display_name }).await?;
    forward_response::<UserAccount>(resp).await
}

// ---- Invitation proxies ----

pub async fn list_invitations(user_token: &str) -> Result<Vec<AccountInvitation>, (StatusCode, String)> {
    let url = format!("{}/accounts/invitations", auth_url());
    forward_response(get(&url, user_token).await?).await
}

pub async fn get_invitation(user_token: &str, id: &str) -> Result<AccountInvitation, (StatusCode, String)> {
    let url = format!("{}/accounts/invitations/{}", auth_url(), id);
    forward_response(get(&url, user_token).await?).await
}

pub async fn create_invitation(user_token: &str, req: &InvitationRequest) -> Result<AccountInvitation, (StatusCode, String)> {
    let url = format!("{}/accounts/invitations", auth_url());
    forward_response(post_json(&url, user_token, req).await?).await
}

pub async fn update_invitation(user_token: &str, id: &str, req: &UpdateInvitationRequest) -> Result<AccountInvitation, (StatusCode, String)> {
    let url = format!("{}/accounts/invitations/{}", auth_url(), id);
    forward_response(put_json(&url, user_token, req).await?).await
}

pub async fn delete_invitation(user_token: &str, id: &str) -> Result<(), (StatusCode, String)> {
    let url = format!("{}/accounts/invitations/{}", auth_url(), id);
    forward_empty_response(delete(&url, user_token).await?).await
}