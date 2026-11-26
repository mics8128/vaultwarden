use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, RwLock},
};

use rocket::{
    Catcher, Route,
    fs::NamedFile,
    http::ContentType,
    response::{Redirect, content::RawHtml as Html},
    serde::json::Json,
};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult, core::now},
    auth::decode_file_download,
    crypto::sha256_hex,
    db::{
        DbConn,
        models::{AttachmentId, CipherId},
    },
    error::Error,
    util::{Cached, EtagCached},
};

pub fn routes() -> Vec<Route> {
    // If adding more routes here, consider also adding them to
    // crate::utils::LOGGED_ROUTES to make sure they appear in the log
    let mut routes = routes![attachments, alive, alive_head, static_files];
    if CONFIG.web_vault_enabled() {
        routes.append(&mut routes![
            web_index,
            web_index_direct,
            web_index_head,
            app_id,
            apple_app_site_association,
            web_files,
            vaultwarden_css,
            esapp_signout_js
        ]);
    }

    #[cfg(debug_assertions)]
    if CONFIG.reload_templates() {
        routes.append(&mut routes![static_files_dev]);
    }

    routes
}

pub fn catchers() -> Vec<Catcher> {
    if CONFIG.web_vault_enabled() {
        catchers![not_found]
    } else {
        catchers![]
    }
}

#[catch(404)]
fn not_found() -> ApiResult<Html<String>> {
    // Return the page
    let json = json!({
        "urlpath": CONFIG.domain_path()
    });
    let text = CONFIG.render_template("404", &json)?;
    Ok(Html(text))
}

struct CssCache {
    css: String,
    etag: String,
}

static CSS_CACHE: RwLock<Option<Arc<CssCache>>> = RwLock::new(None);

pub fn invalidate_css_cache() {
    *CSS_CACHE.write().unwrap() = None;
}

#[get("/css/vaultwarden.css")]
fn vaultwarden_css() -> EtagCached<String> {
    // If reload_templates is false, and we already have the CSS Cached, return this
    if !CONFIG.reload_templates()
        && let Some(cached) = CSS_CACHE.read().unwrap().as_ref()
    {
        return EtagCached::new(cached.css.clone(), ContentType::CSS, &cached.etag);
    }

    // Else, there is either no cache, or reload_templates is true and we need to rebuild the CSS
    let css_options = json!({
        "email_change_allowed": CONFIG.email_change_allowed(),
        "emergency_access_allowed": CONFIG.emergency_access_allowed(),
        "load_user_scss": true,
        "mail_2fa_enabled": CONFIG._enable_email_2fa(),
        "mail_enabled": CONFIG.mail_enabled(),
        "sends_allowed": CONFIG.sends_allowed(),
        "remember_2fa_disabled": CONFIG.disable_2fa_remember(),
        "password_hints_allowed": CONFIG.password_hints_allowed(),
        "signup_disabled": CONFIG.is_signup_disabled(),
        "sso_enabled": CONFIG.sso_enabled(),
        "sso_only": CONFIG.sso_enabled() && CONFIG.sso_only(),
        "webauthn_2fa_supported": CONFIG.is_webauthn_2fa_supported(),
        "yubico_enabled": CONFIG._enable_yubico() && CONFIG.yubico_client_id().is_some() && CONFIG.yubico_secret_key().is_some(),
    });

    let scss = match CONFIG.render_template("scss/vaultwarden.scss", &css_options) {
        Ok(t) => t,
        Err(e) => {
            // Something went wrong loading the template. Use the fallback
            warn!("Loading scss/vaultwarden.scss.hbs or scss/user.vaultwarden.scss.hbs failed. {e}");
            CONFIG
                .render_fallback_template("scss/vaultwarden.scss", &css_options)
                .expect("Fallback scss/vaultwarden.scss.hbs to render")
        }
    };

    let css = match grass_compiler::from_string(
        scss,
        &grass_compiler::Options::default().style(grass_compiler::OutputStyle::Compressed),
    ) {
        Ok(css) => css,
        Err(e) => {
            // Something went wrong compiling the scss. Use the fallback
            warn!("Compiling the Vaultwarden SCSS styles failed. {e}");
            let mut css_options = css_options;
            css_options["load_user_scss"] = json!(false);
            let scss = CONFIG
                .render_fallback_template("scss/vaultwarden.scss", &css_options)
                .expect("Fallback scss/vaultwarden.scss.hbs to render");
            grass_compiler::from_string(
                scss,
                &grass_compiler::Options::default().style(grass_compiler::OutputStyle::Compressed),
            )
            .expect("SCSS to compile")
        }
    };

    let etag = sha256_hex(css.as_bytes());
    let cached = Arc::new(CssCache {
        css,
        etag,
    });

    if !CONFIG.reload_templates() {
        *CSS_CACHE.write().unwrap() = Some(Arc::clone(&cached));
    }

    // Etag Caching will let the browser send us an etag to verify and send new content if needed
    EtagCached::new(cached.css.clone(), ContentType::CSS, &cached.etag)
}

#[get("/")]
async fn web_index() -> Cached<Option<(ContentType, String)>> {
    let index = tokio::fs::read_to_string(Path::new(&CONFIG.web_vault_folder()).join("index.html")).await.ok();
    let index = match (index, esapp_logout_url()) {
        (Some(html), Some(_)) => Some(inject_signout_script(&html, &CONFIG.domain_path())),
        (index, _) => index,
    };
    Cached::short(index.map(|html| (ContentType::HTML, html)), false)
}

fn esapp_logout_url() -> Option<String> {
    CONFIG.esapp_logout_url().filter(|u| !u.is_empty())
}

// esapp: a same-origin script (allowed by the CSP) that leaves the web vault for ESAPP_LOGOUT_URL after a sign-out
fn inject_signout_script(html: &str, domain_path: &str) -> String {
    let tag = format!("<script src=\"{domain_path}/esapp-signout.js\"></script></head>");
    html.replacen("</head>", &tag, 1)
}

// The web vault signs out by clearing the active account and reloading; locking reloads but keeps the account.
// So an account seen earlier in this tab and gone now is a sign-out. If the web vault changes either, this never
// fires and the web vault keeps its own behaviour.
#[get("/esapp-signout.js")]
fn esapp_signout_js() -> Option<(ContentType, String)> {
    let url = serde_json::to_string(&esapp_logout_url()?).ok()?;
    Some((
        ContentType::JavaScript,
        format!(
            r#"(() => {{
  const key = "global_account_activeAccountId", flag = "esapp_vault_signed_in";
  const read = (s) => {{ try {{ return JSON.parse(s.getItem(key)); }} catch {{ return null; }} }};
  const signedIn = () => read(sessionStorage) || read(localStorage);
  try {{
    if (!signedIn() && sessionStorage.getItem(flag)) {{
      sessionStorage.removeItem(flag);
      location.replace({url});
      return;
    }}
    const mark = () => {{ if (signedIn()) {{ sessionStorage.setItem(flag, "1"); clearInterval(timer); }} }};
    const timer = setInterval(mark, 1000);
    mark();
  }} catch {{}}
}})();
"#
        ),
    ))
}

// Make sure that `/index.html` redirect to actual domain path.
// If not, this might cause issues with the web-vault
#[get("/index.html")]
fn web_index_direct() -> Redirect {
    Redirect::to(format!("{}/", CONFIG.domain_path()))
}

#[head("/")]
fn web_index_head() -> EmptyResult {
    // Add an explicit HEAD route to prevent uptime monitoring services from
    // generating "No matching routes for HEAD /" error messages.
    //
    // Rocket automatically implements a HEAD route when there's a matching GET
    // route, but relying on this behavior also means a spurious error gets
    // logged due to <https://github.com/SergioBenitez/Rocket/issues/1098>.
    Ok(())
}

#[get("/app-id.json")]
fn app_id() -> Cached<(ContentType, Json<Value>)> {
    let content_type = ContentType::new("application", "fido.trusted-apps+json");

    Cached::long(
        (
            content_type,
            Json(json!({
            "trustedFacets": [
                {
                "version": { "major": 1, "minor": 0 },
                "ids": [
                    // Per <https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-appid-and-facets-v2.0-id-20180227.html#determining-the-facetid-of-a-calling-application>:
                    //
                    // "In the Web case, the FacetID MUST be the Web Origin [RFC6454]
                    // of the web page triggering the FIDO operation, written as
                    // a URI with an empty path. Default ports are omitted and any
                    // path component is ignored."
                    //
                    // This leaves it unclear as to whether the path must be empty,
                    // or whether it can be non-empty and will be ignored. To be on
                    // the safe side, use a proper web origin (with empty path).
                    &CONFIG.domain_origin(),
                    "ios:bundle-id:com.8bit.bitwarden",
                    "android:apk-key-hash:dUGFzUzf3lmHSLBDBIv+WaFyZMI" ]
                }]
            })),
        ),
        true,
    )
}

#[get("/.well-known/apple-app-site-association")]
fn apple_app_site_association() -> Cached<(ContentType, Json<Value>)> {
    Cached::long(
        (
            ContentType::JSON,
            Json(json!({
                "webcredentials": {
                    "apps": [
                        "LTZ2PFU5D6.com.8bit.bitwarden",
                        "LTZ2PFU5D6.com.8bit.bitwarden.beta"
                    ]
                }
            })),
        ),
        true,
    )
}

#[get("/<p..>", rank = 10)] // Only match this if the other routes don't match
async fn web_files(p: PathBuf) -> Cached<Option<NamedFile>> {
    Cached::long(NamedFile::open(Path::new(&CONFIG.web_vault_folder()).join(p)).await.ok(), true)
}

#[get("/attachments/<cipher_id>/<file_id>?<token>")]
async fn attachments(cipher_id: CipherId, file_id: AttachmentId, token: String) -> Option<NamedFile> {
    let Ok(claims) = decode_file_download(&token) else {
        return None;
    };
    if claims.sub != cipher_id || claims.file_id != file_id {
        return None;
    }

    NamedFile::open(Path::new(&CONFIG.attachments_folder()).join(cipher_id.as_ref()).join(file_id.as_ref())).await.ok()
}

// We use DbConn here to let the alive healthcheck also verify the database connection.
#[get("/alive")]
fn alive(_conn: DbConn) -> Json<String> {
    now()
}

#[head("/alive")]
fn alive_head(_conn: DbConn) -> EmptyResult {
    // Avoid logging spurious "No matching routes for HEAD /alive" errors
    // due to <https://github.com/SergioBenitez/Rocket/issues/1098>.
    Ok(())
}

// This endpoint/function is used during development and development only.
// It allows to easily develop the admin interface by always loading the files from disk instead from a slice of bytes
// This will only be active during a debug build and only when `RELOAD_TEMPLATES` is set to `true`
// NOTE: Do not forget to add any new files added to the `STATIC_FILES` HashMap below!
#[cfg(debug_assertions)]
#[get("/vw_static/<filename>", rank = 1)]
pub async fn static_files_dev(filename: PathBuf) -> Option<NamedFile> {
    warn!("LOADING STATIC FILES FROM DISK");
    let file = filename.to_str().unwrap_or_default();
    let ext = filename.extension().unwrap_or_default();

    let path = if ext == "png" || ext == "svg" {
        tokio::fs::canonicalize(Path::new(file!()).parent().unwrap().join("../static/images/").join(file)).await
    } else {
        tokio::fs::canonicalize(Path::new(file!()).parent().unwrap().join("../static/scripts/").join(file)).await
    };

    if let Ok(path) = path {
        return NamedFile::open(path).await.ok();
    }
    None
}

pub struct StaticFile {
    pub content_type: ContentType,
    pub bytes: &'static [u8],
    pub etag: String,
}

pub static STATIC_FILES: LazyLock<HashMap<&'static str, StaticFile>> = LazyLock::new(|| {
    [
        ("404.png", ContentType::PNG, &include_bytes!("../static/images/404.png")[..]),
        ("mail-github.png", ContentType::PNG, &include_bytes!("../static/images/mail-github.png")[..]),
        ("logo-gray.png", ContentType::PNG, &include_bytes!("../static/images/logo-gray.png")[..]),
        ("error-x.svg", ContentType::SVG, &include_bytes!("../static/images/error-x.svg")[..]),
        ("hibp.png", ContentType::PNG, &include_bytes!("../static/images/hibp.png")[..]),
        ("vaultwarden-icon.png", ContentType::PNG, &include_bytes!("../static/images/vaultwarden-icon.png")[..]),
        ("vaultwarden-favicon.png", ContentType::PNG, &include_bytes!("../static/images/vaultwarden-favicon.png")[..]),
        ("404.css", ContentType::CSS, &include_bytes!("../static/scripts/404.css")[..]),
        ("admin.css", ContentType::CSS, &include_bytes!("../static/scripts/admin.css")[..]),
        ("admin.js", ContentType::JavaScript, &include_bytes!("../static/scripts/admin.js")[..]),
        ("admin_settings.js", ContentType::JavaScript, &include_bytes!("../static/scripts/admin_settings.js")[..]),
        ("admin_users.js", ContentType::JavaScript, &include_bytes!("../static/scripts/admin_users.js")[..]),
        (
            "admin_organizations.js",
            ContentType::JavaScript,
            &include_bytes!("../static/scripts/admin_organizations.js")[..],
        ),
        (
            "admin_diagnostics.js",
            ContentType::JavaScript,
            &include_bytes!("../static/scripts/admin_diagnostics.js")[..],
        ),
        ("bootstrap.css", ContentType::CSS, &include_bytes!("../static/scripts/bootstrap.css")[..]),
        ("bootstrap.bundle.js", ContentType::JavaScript, &include_bytes!("../static/scripts/bootstrap.bundle.js")[..]),
        ("jdenticon-3.3.0.js", ContentType::JavaScript, &include_bytes!("../static/scripts/jdenticon-3.3.0.js")[..]),
        ("datatables.js", ContentType::JavaScript, &include_bytes!("../static/scripts/datatables.js")[..]),
        ("datatables.css", ContentType::CSS, &include_bytes!("../static/scripts/datatables.css")[..]),
    ]
    .into_iter()
    .map(|(name, content_type, bytes)| {
        (
            name,
            StaticFile {
                content_type,
                bytes,
                etag: sha256_hex(bytes),
            },
        )
    })
    .collect()
});

#[get("/vw_static/<filename>", rank = 2)]
pub fn static_files(filename: &str) -> Result<EtagCached<&'static [u8]>, Error> {
    if let Some(file) = STATIC_FILES.get(filename) {
        Ok(EtagCached::new(file.bytes, file.content_type.clone(), &file.etag))
    } else {
        err!(format!("Static file not found: {}", filename.escape_debug()))
    }
}

#[cfg(test)]
mod tests {
    use super::inject_signout_script;

    #[test]
    fn signout_script_goes_once_into_the_head() {
        let html = "<html><head><title>x</title></head><body></head></body></html>";
        assert_eq!(
            inject_signout_script(html, "/vw"),
            "<html><head><title>x</title><script src=\"/vw/esapp-signout.js\"></script></head><body></head></body></html>"
        );
        // No head: the page stays as it was
        assert_eq!(inject_signout_script("<p>x</p>", ""), "<p>x</p>");
    }
}
