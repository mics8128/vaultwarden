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
    api::{ApiResult, EmptyResult, JsonResult, core::log_user_event},
    auth::{Headers, LoginJwtClaims},
    db::{
        DbConn,
        models::{
            EventType, Membership, MembershipStatus, MembershipType, OrgPolicy, OrgPolicyType, Organization,
            OrganizationId, SsoUser, User, UserId,
        },
    },
    mail,
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
    // A revoked member no longer gets the organization's Key Connector (upstream drops revoked users from it)
    for member in Membership::find_any_state_by_user(user_uuid, conn).await {
        if revoked(member.status) {
            continue;
        }
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
    (org.key_connector_url().is_some() && !revoked(member.status)).then_some((org, member))
}

/// The server's Key Connector organization (upstream allows one per self-hosted server)
pub async fn key_connector_org(conn: &DbConn) -> Option<Organization> {
    if !CONFIG.key_connector_enabled() {
        return None;
    }
    Organization::get_all(conn).await.into_iter().find(|org| org.key_connector_url().is_some())
}

/// Upstream's SSO just-in-time provisioning: an SSO user who has no vault keys yet and no organization joins the
/// Key Connector organization as an invited User. `set-key-connector-key` then accepts the invite (mailing the
/// organization's billing email), and an owner confirms the member to share the organization key.
pub async fn auto_join_key_connector_org(user: &User, conn: &DbConn) -> EmptyResult {
    if user.private_key.is_some() || !Membership::find_any_state_by_user(&user.uuid, conn).await.is_empty() {
        return Ok(());
    }
    let Some(org) = key_connector_org(conn).await else {
        return Ok(());
    };
    let mut member = Membership::new(user.uuid.clone(), org.uuid, None);
    member.status = MembershipStatus::Invited as i32;
    member.save(conn).await
}

/// `UserDecryptionOptions.KeyConnectorOption` of a login response. Upstream sends it on SSO logins to the
/// organization's members; owners and admins are left out so they set (and keep) a master password.
/// Enrolled users also get it on API key logins, so the CLI unlocks without `bw unlock`.
pub async fn user_decryption_option(user: &User, sso_login: bool, conn: &DbConn) -> Option<Value> {
    let (org, member) = key_connector_membership(&user.uuid, conn).await?;
    // Enrolled users unlock only while active members; a new SSO user may still be invited (JIT, set-key accepts it)
    let eligible = (user.uses_key_connector && active_member(member.status))
        || (sso_login && !user.uses_key_connector && member.atype < MembershipType::Admin);
    eligible.then(|| org.key_connector_url().map(|url| json!({ "KeyConnectorUrl": url }))).flatten()
}

/// The `esapp_sub` and `esapp_kc` access token claims of a Key Connector member that is not revoked: the Ory
/// identity id (the SSO subject), and "invited" or "member". Key Connector looks the member up by the id, lets an
/// invited user only store a first key (the clients store it before `set-key-connector-key` accepts the invite),
/// and refuses tokens without them.
pub async fn set_esapp_claims(claims: &mut LoginJwtClaims, conn: &DbConn) {
    (claims.esapp_sub, claims.esapp_kc) = match esapp_claims(&claims.sub, conn).await {
        Some((sub, kc)) => (Some(sub), Some(kc.to_owned())),
        None => (None, None),
    };
}

async fn esapp_claims(user_uuid: &UserId, conn: &DbConn) -> Option<(String, &'static str)> {
    let (_, member) = key_connector_membership(user_uuid, conn).await?;
    let sso_user = SsoUser::find_by_user(user_uuid, conn).await?;
    Some((sso_subject(&sso_user.identifier)?, member_state(member.status)))
}

// key_connector_membership already skips revoked memberships
fn member_state(status: i32) -> &'static str {
    if active_member(status) {
        "member"
    } else {
        "invited"
    }
}

/// `sso_users.identifier` is `{issuer}/{subject}`
fn sso_subject(identifier: &str) -> Option<String> {
    identifier.rsplit_once('/').map(|(_, sub)| sub).filter(|sub| !sub.is_empty()).map(str::to_owned)
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
    let Some((org, mut member)) = find_key_connector_org(&data.org_identifier, &user.uuid, &conn).await else {
        err!("Organization not found or user is not a member of it")
    };
    // Upstream accepts the organization invite here. Check the policies before changing anything, and accept first:
    // a failed user save then leaves an accepted invite and the client can retry.
    let accepting = member.status == MembershipStatus::Invited as i32;
    if accepting {
        member.status = MembershipStatus::Accepted as i32;
        OrgPolicy::check_user_allowed(&member, "join", &conn).await?;
        member.save(&conn).await?;
    }

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

    // The account is set up; a mail failure must not report it as failed
    if accepting
        && CONFIG.mail_enabled()
        && let Err(e) =
            mail::send_invite_accepted(&user.email, &member.invited_by_email.unwrap_or(org.billing_email), &org.name)
                .await
    {
        error!("Error sending invite accepted email: {e:#?}");
    }
    Ok(())
}

/// Revoking subtracts 128 from the status (`Membership::revoke`); older rows use -1
fn revoked(status: i32) -> bool {
    status < MembershipStatus::Invited as i32
}

/// An invited or revoked membership does not yet (or no longer) give access to the organization
fn active_member(status: i32) -> bool {
    status >= MembershipStatus::Accepted as i32
}

// Upstream's ConvertUserToKeyConnectorCommand (and its V2, enroll) drops an existing user's master password. Not
// offered here: it cannot be undone, and members are provisioned by SSO instead. Owners and admins keep theirs.
const NO_CONVERSION: &str =
    "This server does not convert existing accounts to Key Connector, contact your administrator";

#[post("/accounts/convert-to-key-connector")]
fn post_convert_to_key_connector(_headers: Headers) -> EmptyResult {
    err!(NO_CONVERSION)
}

#[post("/accounts/key-connector/enroll")]
fn post_enroll_to_key_connector(_headers: Headers) -> EmptyResult {
    err!(NO_CONVERSION)
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

    // Upstream locks the member decryption options once members use Key Connector. A new URL would send their
    // login tokens elsewhere, and turning it off would leave them without a master password.
    if (data.member_decryption_type != org.member_decryption_type || url != org.key_connector_url)
        && has_key_connector_members(org_id, conn).await
    {
        err!("Key Connector settings cannot be changed while members use Key Connector.")
    }

    match data.member_decryption_type {
        MEMBER_DECRYPTION_MASTER_PASSWORD => {}
        MEMBER_DECRYPTION_KEY_CONNECTOR => {
            if !CONFIG.key_connector_enabled() || !CONFIG.sso_enabled() {
                err!(
                    "You must enable SSO and Key Connector (`SSO_ENABLED`, `KEY_CONNECTOR_ENABLED`) to use Key Connector."
                )
            }
            let Some(origin) = url.as_deref().and_then(key_connector_origin) else {
                err!("Key Connector URL must be a valid https URL")
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

async fn has_key_connector_members(org_id: &OrganizationId, conn: &DbConn) -> bool {
    for member in Membership::find_by_org(org_id, conn).await {
        if User::find_by_uuid(&member.user_uuid, conn).await.is_some_and(|u| u.uses_key_connector) {
            return true;
        }
    }
    false
}

/// The origin of a Key Connector URL. Members send their login token to it, so plain http is only for loopback.
fn key_connector_origin(url: &str) -> Option<String> {
    let url = url::Url::parse(url).ok()?;
    let loopback = match url.host()? {
        url::Host::Domain(domain) => domain == "localhost",
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    };
    (url.scheme() == "https" || (url.scheme() == "http" && loopback)).then(|| url.origin().ascii_serialization())
}

/// Upstream refuses owners and admins who use Key Connector; here they keep it (the user's decision), so a promotion
/// is logged next to the caller's `OrganizationUserUpdated` event.
pub async fn log_key_connector_promotion(member: &Membership, new_type: i32, conn: &DbConn) {
    if member.atype >= MembershipType::Admin || new_type < MembershipType::Admin {
        return;
    }
    if User::find_by_uuid(&member.user_uuid, conn).await.is_some_and(|u| u.uses_key_connector) {
        warn!(
            "Key Connector member {} of organization {} promoted to {}, they keep Key Connector",
            member.uuid, member.org_uuid, new_type
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_states_after_a_real_revoke() {
        for status in [MembershipStatus::Invited, MembershipStatus::Accepted, MembershipStatus::Confirmed] {
            let mut member = Membership::new(UserId::from("u".to_owned()), OrganizationId::from("o".to_owned()), None);
            member.status = status as i32;
            assert!(member.revoke());
            assert!(revoked(member.status), "revoked {}", member.status);
            assert!(!active_member(member.status));
            assert!(member.restore());
            assert!(!revoked(member.status));
        }
        assert!(revoked(MembershipStatus::Revoked as i32));
        assert!(!active_member(MembershipStatus::Invited as i32));
        assert!(active_member(MembershipStatus::Accepted as i32));
        assert!(active_member(MembershipStatus::Confirmed as i32));
        assert_eq!(member_state(MembershipStatus::Invited as i32), "invited");
        assert_eq!(member_state(MembershipStatus::Accepted as i32), "member");
        assert_eq!(member_state(MembershipStatus::Confirmed as i32), "member");
    }

    #[test]
    fn esapp_sub_is_the_sso_subject() {
        assert_eq!(
            sso_subject("https://auth.esapp.net/6720d4d7-0000-4000-8000-000000000000").as_deref(),
            Some("6720d4d7-0000-4000-8000-000000000000")
        );
        assert_eq!(sso_subject("https://auth.esapp.net/"), None);
        assert_eq!(sso_subject("no-issuer"), None);
    }

    #[test]
    fn key_connector_url_needs_https_except_loopback() {
        assert_eq!(key_connector_origin("https://kc.esapp.net/").as_deref(), Some("https://kc.esapp.net"));
        assert_eq!(key_connector_origin("http://localhost:3002").as_deref(), Some("http://localhost:3002"));
        assert_eq!(key_connector_origin("http://127.0.0.1:3002").as_deref(), Some("http://127.0.0.1:3002"));
        assert_eq!(key_connector_origin("http://[::1]:3002").as_deref(), Some("http://[::1]:3002"));
        assert_eq!(key_connector_origin("http://kc.esapp.net"), None);
        assert_eq!(key_connector_origin("http://192.168.0.153:3002"), None);
        assert_eq!(key_connector_origin("ftp://localhost"), None);
        assert_eq!(key_connector_origin("not a url"), None);
    }
}
