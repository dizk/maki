use std::env;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use isahc::ReadResponseExt;
use isahc::config::Configurable;
use maki_storage::StateDir;
use maki_storage::auth::{OAuthTokens, delete_tokens, load_tokens, save_tokens};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use tracing::warn;

use crate::AgentError;
use crate::providers::urlenc;

const TOKEN_ENV_VARS: &[&str] = &["GH_COPILOT_TOKEN", "COPILOT_GITHUB_TOKEN"];
const COPILOT_DOMAIN: &str = "github.com";
const PROVIDER: &str = "copilot";
const CLIENT_ID: &str = "Iv1.b507a08c87ecfe98";
const DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
const ACCESS_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const COPILOT_TOKEN_URL: &str = "https://api.github.com/copilot_internal/v2/token";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_TIMEOUT: Duration = Duration::from_secs(900);
const DEFAULT_POLL_INTERVAL: u64 = 5;

#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    interval: Option<u64>,
    expires_in: u64,
}

#[derive(Deserialize)]
struct AccessTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct CopilotTokenResponse {
    token: String,
    expires_at: u64,
}

pub(crate) fn load_token() -> Result<String, AgentError> {
    for key in TOKEN_ENV_VARS {
        if let Ok(token) = env::var(key)
            && !token.trim().is_empty()
        {
            return Ok(token);
        }
    }

    if let Ok(dir) = StateDir::resolve() {
        if let Some(token) = load_saved_token(&dir)? {
            return Ok(token);
        }
        if let Some(creds) = maki_storage::auth::load_provider_credentials(&dir, PROVIDER) {
            return Ok(creds.api_key);
        }
    }

    for path in copilot_config_paths() {
        if let Ok(contents) = fs::read_to_string(path)
            && let Some(token) = extract_json_oauth_token(&contents, COPILOT_DOMAIN)
        {
            return Ok(token);
        }
    }

    for path in gh_config_paths() {
        if let Ok(contents) = fs::read_to_string(path)
            && let Some(token) = extract_yaml_oauth_token(&contents, COPILOT_DOMAIN)
        {
            return Ok(token);
        }
    }

    Err(AgentError::Config {
        message: "Copilot token not found. Run `maki auth login copilot`, `gh auth login --web`, or set GH_COPILOT_TOKEN.".into(),
    })
}

fn load_saved_token(dir: &StateDir) -> Result<Option<String>, AgentError> {
    let Some(tokens) = load_tokens(dir, PROVIDER) else {
        return Ok(None);
    };
    if !tokens.is_expired() {
        return Ok(Some(tokens.access));
    }
    match refresh_copilot_token(&tokens.refresh) {
        Ok(fresh) => {
            let access = fresh.access.clone();
            save_tokens(dir, PROVIDER, &fresh)?;
            Ok(Some(access))
        }
        Err(err) => {
            warn!(error = %err, "Copilot OAuth refresh failed, clearing stale token");
            delete_tokens(dir, PROVIDER).ok();
            Ok(None)
        }
    }
}

pub(crate) fn endpoint_from_token(token: &str) -> Option<String> {
    token
        .split(';')
        .find_map(|part| part.strip_prefix("proxy-ep="))
        .map(|host| format!("https://{}", host.replacen("proxy.", "api.", 1)))
}

fn http_client(timeout: Duration) -> Result<isahc::HttpClient, AgentError> {
    isahc::HttpClient::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(timeout)
        .build()
        .map_err(|e| AgentError::Config {
            message: format!("http client: {e}"),
        })
}

fn request_device_code() -> Result<DeviceCodeResponse, AgentError> {
    let client = http_client(REQUEST_TIMEOUT)?;
    let body = format!("client_id={}&scope=read:user", urlenc(CLIENT_ID));
    let request = isahc::Request::builder()
        .method("POST")
        .uri(DEVICE_CODE_URL)
        .header("accept", "application/json")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body.into_bytes())?;
    let mut response = client.send(request).map_err(|e| AgentError::Config {
        message: format!("device code request: {e}"),
    })?;
    if !response.status().is_success() {
        let body_text = response.text().unwrap_or_else(|_| "unknown error".into());
        return Err(AgentError::Config {
            message: format!("device code request failed: {body_text}"),
        });
    }
    let body_text = response.text()?;
    serde_json::from_str(&body_text).map_err(Into::into)
}

fn poll_access_token(device: &DeviceCodeResponse) -> Result<String, AgentError> {
    let client = http_client(REQUEST_TIMEOUT)?;
    let interval = Duration::from_secs(device.interval.unwrap_or(DEFAULT_POLL_INTERVAL).max(1));
    let deadline = Instant::now() + Duration::from_secs(device.expires_in).min(POLL_TIMEOUT);
    let body = format!(
        "client_id={}&device_code={}&grant_type=urn:ietf:params:oauth:grant-type:device_code",
        urlenc(CLIENT_ID),
        urlenc(&device.device_code),
    );
    loop {
        if Instant::now() > deadline {
            return Err(AgentError::Config {
                message: "device authorization timed out".into(),
            });
        }
        thread::sleep(interval);
        let request = isahc::Request::builder()
            .method("POST")
            .uri(ACCESS_TOKEN_URL)
            .header("accept", "application/json")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body.clone().into_bytes())?;
        let mut response = client.send(request).map_err(|e| AgentError::Config {
            message: format!("device token poll: {e}"),
        })?;
        let body_text = response.text()?;
        let token: AccessTokenResponse = serde_json::from_str(&body_text)?;
        if let Some(access_token) = token.access_token {
            return Ok(access_token);
        }
        match token.error.as_deref() {
            Some("authorization_pending") => {}
            Some("slow_down") => thread::sleep(interval),
            Some(error) => {
                let suffix = token
                    .error_description
                    .map(|description| format!(": {description}"))
                    .unwrap_or_default();
                return Err(AgentError::Config {
                    message: format!("device authorization failed: {error}{suffix}"),
                });
            }
            None => {
                return Err(AgentError::Config {
                    message: format!("invalid device token response: {body_text}"),
                });
            }
        }
    }
}

fn refresh_copilot_token(github_token: &str) -> Result<OAuthTokens, AgentError> {
    let client = http_client(REQUEST_TIMEOUT)?;
    let request = isahc::Request::builder()
        .method("GET")
        .uri(COPILOT_TOKEN_URL)
        .header("accept", "application/json")
        .header("authorization", format!("Bearer {github_token}"))
        .header("user-agent", "GitHubCopilotChat/0.35.0")
        .header("editor-version", "vscode/1.107.0")
        .header("editor-plugin-version", "copilot-chat/0.35.0")
        .header("copilot-integration-id", "vscode-chat")
        .body(())?;
    let mut response = client.send(request).map_err(|e| AgentError::Config {
        message: format!("Copilot token refresh: {e}"),
    })?;
    if !response.status().is_success() {
        let body_text = response.text().unwrap_or_else(|_| "unknown error".into());
        return Err(AgentError::Config {
            message: format!("Copilot token refresh failed: {body_text}"),
        });
    }
    let body_text = response.text()?;
    let token: CopilotTokenResponse = serde_json::from_str(&body_text)?;
    Ok(OAuthTokens {
        access: token.token,
        refresh: github_token.into(),
        expires: token.expires_at * 1000,
        account_id: None,
    })
}

pub fn login(dir: &StateDir) -> Result<(), AgentError> {
    let device = request_device_code()?;
    println!(
        "Open this URL in your browser:\n\n  {}\n",
        device.verification_uri
    );
    println!("Enter code: {}\n", device.user_code);
    println!("Waiting for authorization...");
    let github_token = poll_access_token(&device)?;
    let tokens = refresh_copilot_token(&github_token)?;
    save_tokens(dir, PROVIDER, &tokens)?;
    println!("Authenticated successfully.");
    Ok(())
}

pub fn logout(dir: &StateDir) -> Result<(), AgentError> {
    if delete_tokens(dir, PROVIDER)?
        || maki_storage::auth::delete_provider_credentials(dir, PROVIDER)?
    {
        println!("Logged out of Copilot.");
    } else {
        println!("Not currently logged in to Copilot.");
    }
    Ok(())
}

fn copilot_config_paths() -> Vec<PathBuf> {
    let base = config_dir().map(|config| config.join("github-copilot"));
    base.map(|base| vec![base.join("hosts.json"), base.join("apps.json")])
        .unwrap_or_default()
}

fn gh_config_paths() -> Vec<PathBuf> {
    config_dir()
        .map(|config| vec![config.join("gh").join("hosts.yml")])
        .unwrap_or_default()
}

fn config_dir() -> Option<PathBuf> {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| maki_storage::paths::home().map(|home| home.join(".config")))
}

fn extract_json_oauth_token(contents: &str, domain: &str) -> Option<String> {
    let value: JsonValue = serde_json::from_str(contents).ok()?;
    value.as_object()?.iter().find_map(|(key, value)| {
        if key.starts_with(domain) {
            value["oauth_token"].as_str().map(ToOwned::to_owned)
        } else {
            None
        }
    })
}

fn extract_yaml_oauth_token(contents: &str, domain: &str) -> Option<String> {
    let value: YamlValue = serde_yaml::from_str(contents).ok()?;
    value.as_mapping()?.iter().find_map(|(key, value)| {
        if key.as_str().is_some_and(|key| key.starts_with(domain)) {
            value["oauth_token"].as_str().map(ToOwned::to_owned)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_endpoint_from_copilot_token() {
        let token = "tid=1;exp=2;proxy-ep=proxy.individual.githubcopilot.com;sku=x";
        assert_eq!(
            endpoint_from_token(token).as_deref(),
            Some("https://api.individual.githubcopilot.com")
        );
    }

    #[test]
    fn extracts_matching_oauth_token() {
        let contents = r#"{
            "github.com": {
                "oauth_token": "token-1"
            }
        }"#;
        assert_eq!(
            extract_json_oauth_token(contents, "github.com").as_deref(),
            Some("token-1")
        );
    }

    #[test]
    fn ignores_other_domains() {
        let contents = r#"{
            "enterprise.example.com": {
                "oauth_token": "token-1"
            }
        }"#;
        assert_eq!(extract_json_oauth_token(contents, "github.com"), None);
    }

    #[test]
    fn extracts_matching_gh_oauth_token() {
        let contents = r#"
github.com:
  oauth_token: token-1
  user: octocat
"#;
        assert_eq!(
            extract_yaml_oauth_token(contents, "github.com").as_deref(),
            Some("token-1")
        );
    }

    #[test]
    fn ignores_other_gh_domains() {
        let contents = r#"
enterprise.example.com:
  oauth_token: token-1
"#;
        assert_eq!(extract_yaml_oauth_token(contents, "github.com"), None);
    }
}
