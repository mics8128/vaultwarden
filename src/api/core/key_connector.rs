// Key Connector support, modeled on Bitwarden's server:
// https://github.com/bitwarden/server/blob/main/src/Api/KeyManagement/Controllers/AccountsKeyManagementController.cs
//
// Like upstream, Key Connector is an organization SSO setting ("Member decryption options"), stored on the
// organization. Owners and admins never use it, they keep their master password.
use rocket::Route;
use rocket::http::Status;
use rocket::serde::json::Json;
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        ApiResult, EmptyResult, JsonResult,
        core::{accept_org_invite, log_user_event},
    },
    auth::Headers,
    db::{
        DbConn,
        models::{
            EventType, Membership, MembershipStatus, MembershipType, OrgPolicy, OrgPolicyType, Organization,
            OrganizationId, User, UserId,
        },
    },
    sso::FAKE_SSO_IDENTIFIER,
};

// https://github.com/bitwarden/server/blob/main/src/Core/Auth/Enums/MemberDecryptionType.cs
pub const MEMBER_DECRYPTION_MASTER_PASSWORD: i32 = 0;
pub const MEMBER_DECRYPTION_KEY_CONNECTOR: i32 = 1;

pub fn routes() -> Vec<Route> {
    routes![
        post_set_key_connector_key,
        post_convert_to_key_connector,
        post_enroll_to_key_connector,
        get_confirmation_details,
    ]
}

impl Organization {
    /// Upstream's `KeyConnectorEnabled` + `KeyConnectorUrl`: the URL when members of this organization use Key Connector
    pub fn key_connector_url(&self) -> Option<&str> {
        self.key_connector_url.as_deref().filter(|url| {
            CONFIG.key_connector_enabled()
                && self.member_decryption_type == MEMBER_DECRYPTION_KEY_CONNECTOR
                && !url.is_empty()
        })
    }
}

/// The organization (and the user's membership) whose Key Connector the user uses. Upstream allows one Key Connector
/// organization per self-hosted server, and it requires the Single organization policy.
async fn key_connector_membership(user_uuid: &UserId, conn: &DbConn) -> Option<(Organization, Membership)> {
    if !CONFIG.key_connector_enabled() {
        return None;
    }
    for member in Membership::find_any_state_by_user(user_uuid, conn).await {
        if let Some(org) = Organization::find_by_uuid(&member.org_uuid, conn).await
            && org.key_connector_url().is_some()
        {
            return Some((org, member));
        }
    }
    None
}

/// Resolves the `orgIdentifier`/`orgSsoIdentifier` the clients send. Vaultwarden has one global SSO, so clients
/// get `FAKE_SSO_IDENTIFIER`, which stands for the user's Key Connector organization.
async fn find_key_connector_org(
    identifier: &str,
    user_uuid: &UserId,
    conn: &DbConn,
) -> Option<(Organization, Membership)> {
    if identifier == FAKE_SSO_IDENTIFIER {
        return key_connector_membership(user_uuid, conn).await;
    }
    let org = Organization::find_by_uuid(&OrganizationId::from(identifier.to_owned()), conn).await?;
    let member = Membership::find_by_user_and_org(user_uuid, &org.uuid, conn).await?;
    org.key_connector_url().is_some().then_some((org, member))
}

/// `UserDecryptionOptions.KeyConnectorOption` of a login response. Upstream sends it on SSO logins to the
/// organization's members; owners and admins are left out so they set (and keep) a master password.
/// Enrolled users also get it on API key logins, so the CLI unlocks without `bw unlock`.
pub async fn user_decryption_option(user: &User, sso_login: bool, conn: &DbConn) -> Option<Value> {
    let (org, member) = key_connector_membership(&user.uuid, conn).await?;
    let eligible = user.uses_key_connector || (sso_login && member.atype < MembershipType::Admin);
    eligible.then(|| org.key_connector_url().map(|url| json!({ "KeyConnectorUrl": url }))).flatten()
}

// Upstream's KeyConnectorAuthorizationHandler: enrolled users, owners and admins cannot (re)enroll
async fn check_can_use_key_connector(user: &User, conn: &DbConn) -> EmptyResult {
    if !CONFIG.key_connector_enabled() {
        err!("Key Connector is not enabled on this server")
    }
    if user.uses_key_connector
        || Membership::find_any_state_by_user(&user.uuid, conn).await.iter().any(|m| m.atype >= MembershipType::Admin)
    {
        err!("Cannot use Key Connector")
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyPairData {
    encrypted_private_key: String,
    public_key: String,
}

// The V1 request. V2 (`keyConnectorKeyWrappedUserKey` + `accountKeys`) needs signing keys, which Vaultwarden
// does not support; the clients only send it behind a feature flag Vaultwarden never enables.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetKeyConnectorKeyData {
    key: String,
    keys: KeyPairData,
    kdf: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
    org_identifier: String,
}

// Finishes provisioning a new SSO user whose master key the client just stored on the Key Connector
#[post("/accounts/set-key-connector-key", data = "<data>")]
async fn post_set_key_connector_key(data: Json<SetKeyConnectorKeyData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data = data.into_inner();
    let mut user = headers.user;

    check_can_use_key_connector(&user, &conn).await?;
    if user.private_key.is_some() || !user.password_hash.is_empty() {
        err!("Account already initialized, cannot set Key Connector key")
    }
    let Some((_, member)) = find_key_connector_org(&data.org_identifier, &user.uuid, &conn).await else {
        err!("Organization not found or user is not a member of it")
    };

    user.client_kdf_type = data.kdf;
    user.client_kdf_iter = data.kdf_iterations;
    user.client_kdf_memory = data.kdf_memory;
    user.client_kdf_parallelism = data.kdf_parallelism;
    user.akey = data.key;
    user.private_key = Some(data.keys.encrypted_private_key);
    user.public_key = Some(data.keys.public_key);
    user.password_hash = Vec::new();
    user.uses_key_connector = true;
    user.save(&conn).await?;

    log_user_event(EventType::UserMigratedKeyToKeyConnector, &user.uuid, headers.device.atype, &headers.ip.ip, &conn)
        .await;

    // Upstream accepts the organization invite here
    if member.status == MembershipStatus::Invited as i32 {
        accept_org_invite(&user, member, None, &conn).await?;
    }
    Ok(())
}

// Upstream's ConvertUserToKeyConnectorCommand: drops the master password of an existing user,
// whose master key the client already stored on the Key Connector
async fn convert_to_key_connector(headers: Headers, wrapped_user_key: Option<String>, conn: DbConn) -> EmptyResult {
    let mut user = headers.user;

    check_can_use_key_connector(&user, &conn).await?;
    if user.private_key.is_none() {
        err!("Account is not initialized, cannot convert to Key Connector")
    }

    user.password_hash = Vec::new();
    user.password_hint = None;
    user.uses_key_connector = true;
    if let Some(key) = wrapped_user_key.filter(|k| !k.trim().is_empty()) {
        user.akey = key;
    }
    user.save(&conn).await?;

    log_user_event(EventType::UserMigratedKeyToKeyConnector, &user.uuid, headers.device.atype, &headers.ip.ip, &conn)
        .await;
    Ok(())
}

#[post("/accounts/convert-to-key-connector")]
async fn post_convert_to_key_connector(headers: Headers, conn: DbConn) -> EmptyResult {
    convert_to_key_connector(headers, None, conn).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyConnectorEnrollmentData {
    key_connector_key_wrapped_user_key: String,
}

#[post("/accounts/key-connector/enroll", data = "<data>")]
async fn post_enroll_to_key_connector(
    data: Json<KeyConnectorEnrollmentData>,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    convert_to_key_connector(headers, Some(data.into_inner().key_connector_key_wrapped_user_key), conn).await
}

// Shown in the client's "Confirm Key Connector domain" dialog
#[get("/accounts/key-connector/confirmation-details/<org_sso_identifier>")]
async fn get_confirmation_details(org_sso_identifier: &str, headers: Headers, conn: DbConn) -> JsonResult {
    let Some((org, _)) = find_key_connector_org(org_sso_identifier, &headers.user.uuid, &conn).await else {
        err_code!("Organization not found", Status::NotFound.code)
    };
    Ok(Json(json!({
        "organizationName": org.name,
        "object": "keyConnectorConfirmationDetails",
    })))
}

/// Upstream's Require single sign-on authentication policy: owners and admins are exempt
pub async fn check_password_login_allowed(user: &User, conn: &DbConn) -> EmptyResult {
    if CONFIG.sso_enabled() && OrgPolicy::is_applicable_to_user(&user.uuid, OrgPolicyType::RequireSso, None, conn).await
    {
        err!("Your organization requires you to sign in with single sign-on")
    }
    Ok(())
}

/// Upstream's Single organization / Require SSO policy validators: neither can be turned off while the organization
/// uses Key Connector
pub async fn check_policy_change(
    org_id: &OrganizationId,
    policy: OrgPolicyType,
    enabled: bool,
    conn: &DbConn,
) -> EmptyResult {
    if !enabled
        && matches!(policy, OrgPolicyType::SingleOrg | OrgPolicyType::RequireSso)
        && Organization::find_by_uuid(org_id, conn).await.is_some_and(|org| org.key_connector_url().is_some())
    {
        err!(
            "Key Connector is enabled and requires the Single organization and Require single sign-on authentication policies"
        )
    }
    Ok(())
}

// The organization SSO settings, set from the Vaultwarden admin page (upstream: Admin Console > Single sign-on)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgSsoSettings {
    member_decryption_type: i32,
    key_connector_url: Option<String>,
    require_sso: bool,
}

/// Extra fields for the admin organizations overview
pub async fn admin_org_json(org: &Organization, json: &mut Value, conn: &DbConn) {
    let policy_enabled =
        async |atype| OrgPolicy::find_by_org_and_type(&org.uuid, atype, conn).await.is_some_and(|p| p.enabled);
    json["memberDecryptionType"] = json!(org.member_decryption_type);
    json["keyConnectorUrl"] = json!(org.key_connector_url);
    json["keyConnectorEnabled"] = json!(org.key_connector_url().is_some());
    json["singleOrgPolicy"] = json!(policy_enabled(OrgPolicyType::SingleOrg).await);
    json["requireSsoPolicy"] = json!(policy_enabled(OrgPolicyType::RequireSso).await);
}

/// Saves the organization SSO settings with upstream's SsoConfigService checks.
/// Returns the event to log when Key Connector was turned on or off.
pub async fn update_org_sso_settings(
    org_id: &OrganizationId,
    data: OrgSsoSettings,
    conn: &DbConn,
) -> ApiResult<Option<EventType>> {
    let Some(mut org) = Organization::find_by_uuid(org_id, conn).await else {
        err!("Organization doesn't exist")
    };
    let was_enabled = org.key_connector_url().is_some();
    let url = data.key_connector_url.map(|u| u.trim().trim_end_matches('/').to_owned()).filter(|u| !u.is_empty());

    match data.member_decryption_type {
        MEMBER_DECRYPTION_MASTER_PASSWORD => {
            if was_enabled {
                for member in Membership::find_by_org(org_id, conn).await {
                    if User::find_by_uuid(&member.user_uuid, conn).await.is_some_and(|u| u.uses_key_connector) {
                        err!("Key Connector cannot be disabled at this moment.")
                    }
                }
            }
        }
        MEMBER_DECRYPTION_KEY_CONNECTOR => {
            if !CONFIG.key_connector_enabled() || !CONFIG.sso_enabled() {
                err!(
                    "You must enable SSO and Key Connector (`SSO_ENABLED`, `KEY_CONNECTOR_ENABLED`) to use Key Connector."
                )
            }
            let Some(origin) = url
                .as_deref()
                .and_then(|u| url::Url::parse(u).ok())
                .filter(|u| matches!(u.scheme(), "http" | "https"))
                .map(|u| u.origin().ascii_serialization())
            else {
                err!("Key Connector URL must be a valid http(s) URL")
            };
            // The web vault fetches the key from the connector, so the CSP has to allow it
            let connect_src = CONFIG.allowed_connect_src().to_lowercase();
            if !connect_src.split_whitespace().any(|src| src.trim_end_matches('/') == origin) {
                err!(format!("Add {origin} to `ALLOWED_CONNECT_SRC` so the web vault can reach the Key Connector"))
            }
            if !OrgPolicy::find_by_org_and_type(org_id, OrgPolicyType::SingleOrg, conn).await.is_some_and(|p| p.enabled)
            {
                err!("Key Connector requires the Single Organization policy to be enabled.")
            }
            if !data.require_sso {
                err!("Key Connector requires the Require Single Sign-On Authentication policy to be enabled.")
            }
            for other in Organization::get_all(conn).await {
                if other.uuid != org.uuid && other.key_connector_url().is_some() {
                    err!(format!("Key Connector is already used by the organization {}", other.name))
                }
            }
        }
        _ => err!("Unsupported member decryption option"),
    }

    let mut policy = match OrgPolicy::find_by_org_and_type(org_id, OrgPolicyType::RequireSso, conn).await {
        Some(p) => p,
        None => OrgPolicy::new(org_id.clone(), OrgPolicyType::RequireSso, false, "null".to_owned()),
    };
    if policy.enabled != data.require_sso {
        policy.enabled = data.require_sso;
        policy.save(conn).await?;
    }

    org.member_decryption_type = data.member_decryption_type;
    org.key_connector_url = url;
    org.save(conn).await?;

    let enabled = org.key_connector_url().is_some();
    Ok(match (was_enabled, enabled) {
        (false, true) => Some(EventType::OrganizationEnabledKeyConnector),
        (true, false) => Some(EventType::OrganizationDisabledKeyConnector),
        _ => None,
    })
}
