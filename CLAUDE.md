# auth-client — Integration Reference for Claude Code

This file describes how to correctly integrate `auth-client` into an Axum application.
Treat every code block here as a verified pattern from the actual source.

---

## Dependency Declaration

```toml
# Cargo.toml — choose the right feature set:
# "dto"    → types only (no reqwest/axum)
# "client" → types + HTTP client + jwt_auth middleware
# "routes" → types + client + full Axum router (most common)
# "full"   → alias for client + routes

[dependencies]
auth-client = { path = "path/to/auth-client", features = ["full"] }
```

Axum `0.7`, `reqwest` `0.12`, `tokio` `1`, and `http` `1` are pulled in transitively when
`client` or higher is enabled. Do not re-add them unless you need to pin versions.

---

## Initialization — MUST happen once before serving requests

```rust
// In main(), before building the Router:
auth_client::client::init(
    std::env::var("AUTH_API_URL").expect("AUTH_API_URL required"),
    std::env::var("AUTH_APP_SECRET").expect("AUTH_APP_SECRET required"),
);
```

`init` uses `OnceLock`. Calling it more than once is safe (second call is ignored).
The library panics if any client function is called before `init`.

---

## Mounting the Router (feature = "routes" or "full")

```rust
use auth_client::routes::{auth_router, AuthCallbacks};
use axum::{Router, middleware};
use auth_client::client::jwt_auth;

let app = Router::new()
    // Mount auth routes under any prefix you want
    .nest("/auth", auth_router(
        AuthCallbacks::default()
            .on_user_login(|user| {
                // Sync user to local DB on login or account creation.
                // Return Err(String) to abort with 500.
                Ok(())
            })
            .on_user_update(|user| {
                // Called after PUT /accounts/update_name succeeds.
                Ok(())
            }),
    ))
    // jwt_auth validates Bearer tokens; injects LoggedUser into extensions.
    // Apply to the sub-router or the whole app as needed.
    .layer(middleware::from_fn(jwt_auth));
```

### Routes mounted by `auth_router`

| Method | Path (relative to nest prefix) | Needs JWT | Admin only |
|--------|-------------------------------|:---------:|:----------:|
| POST | `/login` | No | No |
| POST | `/accounts` | No | No |
| POST | `/auth/refresh` | Yes | No |
| POST | `/accounts/change_passwd` | Yes | No |
| PUT | `/accounts/update_name` | Yes | No |
| GET | `/accounts/invitations` | Yes | Yes |
| GET | `/accounts/invitations/:id` | Yes | Yes |
| POST | `/accounts/invitations` | Yes | Yes |
| PUT | `/accounts/invitations/:id` | Yes | Yes |
| DELETE | `/accounts/invitations/:id` | Yes | Yes |

---

## JWT Middleware — Extracting the Current User

```rust
use axum::Extension;
use auth_client::dto::LoggedUser;

// In any handler behind jwt_auth middleware:
async fn protected_handler(
    Extension(user): Extension<LoggedUser>,
) -> String {
    // user.sub   → user ID (String)
    // user.name  → display name
    // user.email → email address
    // user.admin → bool
    // user.exp   → JWT expiry (usize, Unix timestamp)
    format!("Hello {}", user.name)
}
```

If the Bearer token is missing or invalid, the middleware returns `401` before the handler runs.
Admin checks (`user.admin == false`) are enforced inside the route handlers for invitation endpoints.

---

## Calling Client Functions Directly (feature = "client" or higher)

Use these when you need to perform auth operations outside of the bundled router
(e.g., a custom handler, a background task, or a CLI tool).

All functions are `async`. All return `Result<T, (StatusCode, String)>` except `validate_token`.

```rust
use auth_client::client;
use auth_client::dto::*;

// Login
let resp: LoginResponse = client::login("user@example.com", "password").await
    .map_err(|(status, msg)| /* handle */)?;
// resp.token           → JWT string
// resp.user_account    → UserAccount

// Create account
let resp: LoginResponse = client::create_account(NewUserRequest {
    display_name: "Alice".into(),
    email: "alice@example.com".into(),
    password: "hunter2".into(),
}).await?;

// Refresh token — pass the raw token string (without "Bearer ")
let resp: RefreshResponse = client::refresh(&token).await?;

// Change password
let resp: RefreshResponse = client::change_password(&token, &ChangePasswordRequest {
    current_password: "old".into(),
    new_password: "new".into(),
}).await?;

// Update display name
let user: UserAccount = client::update_name(&token, "New Name").await?;

// Invitation CRUD (admin token required)
let invites: Vec<AccountInvitation> = client::list_invitations(&token).await?;
let invite: AccountInvitation = client::get_invitation(&token, &id).await?;
let invite: AccountInvitation = client::create_invitation(&token, &InvitationRequest {
    email: "bob@example.com".into(),
    display_name: "Bob".into(),
    is_admin: false,
}).await?;
let invite: AccountInvitation = client::update_invitation(&token, &id, &UpdateInvitationRequest {
    email: "bob@example.com".into(),
    display_name: "Bobby".into(),
    is_admin: true,
}).await?;
client::delete_invitation(&token, &id).await?;
```

---

## DTO Types (feature = "dto", always available)

### Request structs

```rust
LoginRequest          { email: String, password: String }
NewUserRequest        { display_name: String, email: String, password: String }
ChangePasswordRequest { current_password: String, new_password: String }
UpdateNameRequest     { display_name: String }
InvitationRequest     { email: String, display_name: String, is_admin: bool }
UpdateInvitationRequest { email: String, display_name: String, is_admin: bool }
```

### Response structs

```rust
LoginResponse    { token: String, user_account: UserAccount }
RefreshResponse  { token: String }
UserAccount      { id: String, display_name: String, email: String, auth_type: String, admin: bool }
AccountInvitation { id: String, email: String, display_name: String, is_admin: bool }
LoggedUser       { sub: String, name: String, email: String, admin: bool, exp: usize }
```

All structs derive `Serialize`, `Deserialize`. `UserAccount` and `AccountInvitation` also derive `Debug`, `Clone`, `PartialEq`.

---

## Error Handling Conventions

```rust
// Pattern for propagating auth-client errors in Axum handlers:
async fn my_handler(...) -> Result<Json<Foo>, (StatusCode, String)> {
    let result = auth_client::client::some_fn(...).await?;  // propagates (StatusCode, String)
    Ok(Json(result))
}
```

| Status Code | Meaning |
|-------------|---------|
| 401 | Missing/invalid Bearer token |
| 403 | Non-admin accessing admin endpoint |
| 500 | Callback hook returned Err |
| 502 | Network error or bad response from auth-api |

---

## Checklist When Integrating

1. Add `auth-client` to `Cargo.toml` with the right feature flag.
2. Call `auth_client::client::init(url, secret)` in `main` before building the router.
3. Mount `auth_router(AuthCallbacks::default())` under a path prefix.
4. Apply `middleware::from_fn(jwt_auth)` to any routes that need authentication.
5. Extract `Extension<LoggedUser>` in handlers that need the current user's identity.
6. Implement `on_user_login` / `on_user_update` callbacks if local user records need to stay in sync.
