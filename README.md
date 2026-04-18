# auth-client

A Rust library that proxies authentication operations to a central `auth-api` service. Designed for use in Axum web applications that delegate user identity management to a shared auth backend.

## Overview

`auth-client` provides three layers of functionality, all controlled via Cargo feature flags:

| Feature | What it adds |
|---------|-------------|
| `dto` *(default)* | Serde-serializable request/response types |
| `client` | HTTP client functions + JWT Axum middleware |
| `routes` | Ready-to-mount Axum router with all auth endpoints |
| `full` | Everything (`client` + `routes`) |

---

## Quick Start

### 1. Add the dependency

```toml
# Cargo.toml
[dependencies]
auth-client = { path = "../auth-client", features = ["full"] }
```

### 2. Initialize the client

Call `init` once at application startup, before any request handling:

```rust
auth_client::client::init(
    std::env::var("AUTH_API_URL").expect("AUTH_API_URL not set"),
    std::env::var("AUTH_APP_SECRET").expect("AUTH_APP_SECRET not set"),
);
```

### 3. Mount the router and middleware

```rust
use auth_client::routes::{auth_router, AuthCallbacks};
use auth_client::client::jwt_auth;
use axum::{Router, middleware};

let app = Router::new()
    .nest("/auth", auth_router(
        AuthCallbacks::default()
            .on_user_login(|user| {
                // Sync newly logged-in user to your local DB
                my_db::upsert_user(user).map_err(|e| e.to_string())
            })
            .on_user_update(|user| {
                // Keep local profile in sync after name changes
                my_db::update_user_name(user).map_err(|e| e.to_string())
            }),
    ))
    // Apply JWT middleware to all routes that need it
    .layer(middleware::from_fn(jwt_auth));
```

---

## Feature Details

### `dto` — Data Types

All request/response types used across the library. Zero dependencies beyond `serde`.

**Request types:**

| Type | Fields |
|------|--------|
| `LoginRequest` | `email`, `password` |
| `NewUserRequest` | `display_name`, `email`, `password` |
| `ChangePasswordRequest` | `current_password`, `new_password` |
| `UpdateNameRequest` | `display_name` |
| `InvitationRequest` | `email`, `display_name`, `is_admin` |
| `UpdateInvitationRequest` | `email`, `display_name`, `is_admin` |

**Response types:**

| Type | Fields |
|------|--------|
| `LoginResponse` | `token: String`, `user_account: UserAccount` |
| `RefreshResponse` | `token: String` |
| `UserAccount` | `id`, `display_name`, `email`, `auth_type`, `admin` |
| `AccountInvitation` | `id`, `email`, `display_name`, `is_admin` |

**JWT claims (middleware):**

```rust
pub struct LoggedUser {
    pub sub: String,   // user ID
    pub name: String,
    pub email: String,
    pub admin: bool,
    pub exp: usize,
}
```

---

### `client` — HTTP Client & JWT Middleware

Requires `features = ["client"]` or higher.

#### Initialization

```rust
auth_client::client::init(url: String, secret: String)
```

Sets the auth-api base URL and the shared application secret used for server-to-server authentication. Uses `OnceLock` — safe to call from `main` before the async runtime starts.

```rust
auth_client::client::init_resource_metadata(url: String)
```

Optional. When set, `jwt_auth` includes a `WWW-Authenticate: Bearer resource_metadata="<url>"` header on every 401 response. `url` should be the full URL to this server's `/.well-known/oauth-protected-resource` endpoint. Required for MCP clients (e.g. Claude) to auto-discover the OAuth flow on token expiry.

```rust
// Example
auth_client::client::init_resource_metadata(
    "https://garcon.example.com/.well-known/oauth-protected-resource".to_string(),
);
```

#### JWT Middleware

```rust
pub async fn jwt_auth(mut req: Request, next: Next) -> Response
```

An Axum middleware function. Validates Bearer tokens against the auth-api. On success, injects a `LoggedUser` into request extensions. On failure, returns `401 Unauthorized` (with `WWW-Authenticate` header if `init_resource_metadata` was called).

**Extracting the current user in handlers:**

```rust
use axum::Extension;
use auth_client::dto::LoggedUser;

async fn my_handler(Extension(user): Extension<LoggedUser>) -> String {
    format!("Hello, {}", user.name)
}
```

#### Client Functions

All functions are async and return `Result<T, (StatusCode, String)>` (except `validate_token`).

```rust
// Token validation (used internally by middleware)
validate_token(user_token: &str) -> Result<LoggedUser, String>

// Auth operations
login(email: &str, password: &str) -> Result<LoginResponse, (StatusCode, String)>
create_account(req: NewUserRequest) -> Result<LoginResponse, (StatusCode, String)>
refresh(user_token: &str) -> Result<RefreshResponse, (StatusCode, String)>
change_password(user_token: &str, req: &ChangePasswordRequest) -> Result<RefreshResponse, (StatusCode, String)>
update_name(user_token: &str, display_name: &str) -> Result<UserAccount, (StatusCode, String)>

// Invitation management (admin only)
list_invitations(user_token: &str) -> Result<Vec<AccountInvitation>, (StatusCode, String)>
get_invitation(user_token: &str, id: &str) -> Result<AccountInvitation, (StatusCode, String)>
create_invitation(user_token: &str, req: &InvitationRequest) -> Result<AccountInvitation, (StatusCode, String)>
update_invitation(user_token: &str, id: &str, req: &UpdateInvitationRequest) -> Result<AccountInvitation, (StatusCode, String)>
delete_invitation(user_token: &str, id: &str) -> Result<(), (StatusCode, String)>
```

---

### `routes` — Axum Router

Requires `features = ["routes"]` or `"full"`.

#### Router

```rust
pub fn auth_router(callbacks: AuthCallbacks) -> Router
```

Returns a fully configured Axum `Router` with these endpoints:

| Method | Path | Auth Required | Admin Only |
|--------|------|:---:|:---:|
| `POST` | `/login` | No | No |
| `POST` | `/accounts` | No | No |
| `POST` | `/auth/refresh` | Yes | No |
| `POST` | `/accounts/change_passwd` | Yes | No |
| `PUT` | `/accounts/update_name` | Yes | No |
| `GET` | `/accounts/invitations` | Yes | Yes |
| `GET` | `/accounts/invitations/:id` | Yes | Yes |
| `POST` | `/accounts/invitations` | Yes | Yes |
| `PUT` | `/accounts/invitations/:id` | Yes | Yes |
| `DELETE` | `/accounts/invitations/:id` | Yes | Yes |

#### Callbacks

```rust
pub struct AuthCallbacks { /* ... */ }

impl Default for AuthCallbacks { /* all callbacks None */ }

impl AuthCallbacks {
    pub fn on_user_login(self, f: impl Fn(&UserAccount) -> Result<(), String> + Send + Sync + 'static) -> Self
    pub fn on_user_update(self, f: impl Fn(&UserAccount) -> Result<(), String> + Send + Sync + 'static) -> Self
}
```

| Callback | Triggered by | Receives |
|----------|-------------|---------|
| `on_user_login` | `POST /login`, `POST /accounts` | `&UserAccount` |
| `on_user_update` | `PUT /accounts/update_name` | `&UserAccount` |

Returning `Err(String)` from a callback causes the handler to return `500 Internal Server Error`.

---

## Error Handling

The library does not define a custom error type. Errors surface as `(StatusCode, String)` tuples:

| Status | Cause |
|--------|-------|
| `401 Unauthorized` | Missing or invalid Bearer token |
| `403 Forbidden` | Non-admin user accessing admin-only endpoint |
| `500 Internal Server Error` | Callback returned `Err` |
| `502 Bad Gateway` | Network error or malformed response from auth-api |

---

## Architecture

```
auth-client
├── dto.rs       ← Pure types, always available
├── client.rs    ← HTTP proxy + JWT middleware (feature: client)
└── routes.rs    ← Axum handlers + router builder (feature: routes)
```

The client stores four singletons via `OnceLock`:
- `AUTH_API_URL` — base URL of the auth-api
- `AUTH_APP_SECRET` — shared app secret (sent as `Authorization: <secret>` on server-to-server calls)
- `HTTP_CLIENT` — shared `reqwest::Client`
- `RESOURCE_METADATA_URL` — optional; when set, 401 responses include `WWW-Authenticate`

---

## Environment Variables (Recommended)

The library does not read environment variables directly; call `init` with whatever values you supply.

```
AUTH_API_URL=https://auth.internal
AUTH_APP_SECRET=super-secret-value
```
