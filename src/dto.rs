use serde::{Deserialize, Serialize};

// --- API request types ---

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct NewUserRequest {
    pub display_name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateNameRequest {
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationRequest {
    pub email: String,
    pub display_name: String,
    pub is_admin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInvitationRequest {
    pub email: String,
    pub display_name: String,
    pub is_admin: bool,
}

// --- API response types ---

#[derive(Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user_account: UserAccount,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshResponse {
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserAccount {
    pub id: String,
    pub display_name: String,
    pub email: String,
    pub auth_type: String,
    pub admin: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountInvitation {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub is_admin: bool,
}

// --- Middleware / JWT claims ---

#[derive(Serialize, Deserialize, Clone)]
pub struct LoggedUser {
    pub sub: String,
    pub name: String,
    pub email: String,
    pub admin: bool,
    pub exp: usize,
}