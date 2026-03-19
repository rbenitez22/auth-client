//! Axum route handlers for auth-related endpoints.
//!
//! `auth_router(on_user_login)` accepts a callback invoked after a successful
//! login or account creation, allowing the caller to sync the user into a
//! local database or perform other app-specific side effects.
//! Pass `|_| Ok(())` if no sync is needed.

use std::sync::Arc;

use axum::extract::Path;
use axum::middleware::from_fn;
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use http::{HeaderMap, StatusCode};

use crate::client::{self, jwt_auth};
use crate::dto::{
    AccountInvitation, ChangePasswordRequest, InvitationRequest, LoginRequest, LoginResponse,
    LoggedUser, NewUserRequest, RefreshResponse, UpdateInvitationRequest, UpdateNameRequest, UserAccount,
};

/// Callback type invoked after a successful login or account creation.
/// Receives the authenticated user; returns `Err(msg)` to abort with 500.
pub type OnUserLogin = Arc<dyn Fn(&UserAccount) -> Result<(), String> + Send + Sync>;

fn extract_bearer(headers: &HeaderMap) -> Result<&str, (StatusCode, String)> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing authorization token".to_string()))
}

// ---- Public handlers ----

async fn login(
    Extension(on_user_login): Extension<OnUserLogin>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let response = client::login(&payload.email, &payload.password).await?;
    on_user_login(&response.user_account)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(response))
}

async fn create_account(
    Extension(on_user_login): Extension<OnUserLogin>,
    Json(payload): Json<NewUserRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let response = client::create_account(payload).await?;
    on_user_login(&response.user_account)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(response))
}

// ---- Protected handlers ----

pub async fn refresh_token(
    headers: HeaderMap,
    Extension(_user): Extension<LoggedUser>,
) -> Result<Json<RefreshResponse>, (StatusCode, String)> {
    let token = extract_bearer(&headers)?;
    client::refresh(token).await.map(Json)
}

pub async fn change_password(
    headers: HeaderMap,
    Extension(_user): Extension<LoggedUser>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<Json<RefreshResponse>, (StatusCode, String)> {
    let token = extract_bearer(&headers)?;
    client::change_password(token, &payload).await.map(Json)
}

pub async fn update_name(
    headers: HeaderMap,
    Extension(_user): Extension<LoggedUser>,
    Json(payload): Json<UpdateNameRequest>,
) -> Result<Json<UserAccount>, (StatusCode, String)> {
    let token = extract_bearer(&headers)?;
    client::update_name(token, &payload.display_name)
        .await
        .map(Json)
}

// ---- Invitation handlers (admin only) ----

pub async fn list_invitations(
    headers: HeaderMap,
    Extension(user): Extension<LoggedUser>,
) -> Result<(StatusCode, Json<Vec<AccountInvitation>>), (StatusCode, String)> {
    if !user.admin {
        return Err((StatusCode::FORBIDDEN, "Admin access required".to_string()));
    }
    let token = extract_bearer(&headers)?;
    client::list_invitations(token)
        .await
        .map(|items| (StatusCode::OK, Json(items)))
}

pub async fn get_invitation(
    headers: HeaderMap,
    Extension(user): Extension<LoggedUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<AccountInvitation>), (StatusCode, String)> {
    if !user.admin {
        return Err((StatusCode::FORBIDDEN, "Admin access required".to_string()));
    }
    let token = extract_bearer(&headers)?;
    client::get_invitation(token, &id)
        .await
        .map(|inv| (StatusCode::OK, Json(inv)))
}

pub async fn create_invitation(
    headers: HeaderMap,
    Extension(user): Extension<LoggedUser>,
    Json(body): Json<InvitationRequest>,
) -> Result<(StatusCode, Json<AccountInvitation>), (StatusCode, String)> {
    if !user.admin {
        return Err((StatusCode::FORBIDDEN, "Admin access required".to_string()));
    }
    let token = extract_bearer(&headers)?;
    client::create_invitation(token, &body)
        .await
        .map(|inv| (StatusCode::CREATED, Json(inv)))
}

pub async fn update_invitation(
    headers: HeaderMap,
    Extension(user): Extension<LoggedUser>,
    Path(id): Path<String>,
    Json(body): Json<UpdateInvitationRequest>,
) -> Result<(StatusCode, Json<AccountInvitation>), (StatusCode, String)> {
    if !user.admin {
        return Err((StatusCode::FORBIDDEN, "Admin access required".to_string()));
    }
    let token = extract_bearer(&headers)?;
    client::update_invitation(token, &id, &body)
        .await
        .map(|inv| (StatusCode::OK, Json(inv)))
}

pub async fn delete_invitation(
    headers: HeaderMap,
    Extension(user): Extension<LoggedUser>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !user.admin {
        return Err((StatusCode::FORBIDDEN, "Admin access required".to_string()));
    }
    let token = extract_bearer(&headers)?;
    client::delete_invitation(token, &id)
        .await
        .map(|_| StatusCode::NO_CONTENT)
}

// ---- Router builder ----

/// Returns a Router with all auth routes mounted.
///
/// `on_user_login` is called after successful login or account creation.
/// Use it to sync the user into a local DB, or pass `|_| Ok(())` to skip.
///
/// ```rust
/// auth_router(|user| user_service::upsert_shadow_user(user))
/// ```
///
/// Public routes:    POST /login, POST /accounts
/// Protected routes: POST /auth/refresh, POST /accounts/change_passwd,
///                   PUT  /accounts/update_name, CRUD /accounts/invitations
pub fn auth_router(
    on_user_login: impl Fn(&UserAccount) -> Result<(), String> + Send + Sync + 'static,
) -> Router {
    let callback: OnUserLogin = Arc::new(on_user_login);

    let public = Router::new()
        .route("/login", post(login))
        .route("/accounts", post(create_account))
        .layer(Extension(callback));

    let protected = Router::new()
        .route("/auth/refresh", post(refresh_token))
        .route("/accounts/change_passwd", post(change_password))
        .route("/accounts/update_name", put(update_name))
        .route("/accounts/invitations", get(list_invitations).post(create_invitation))
        .route("/accounts/invitations/:id", get(get_invitation).put(update_invitation).delete(delete_invitation))
        .route_layer(from_fn(jwt_auth));

    public.merge(protected)
}