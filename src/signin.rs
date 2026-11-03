//! Signing a Google account in from the apps, with Google's authorization-code flow and PKCE
//! (https://developers.google.com/identity/protocols/oauth2/web-server): the link the app opens asks Google for
//! Gmail, offline, and comes back to core's `/oauth/callback` with `state`, which core matches to the sign-in. Core
//! then gives the node the code (`credentials.code`), and the extension exchanges it with the PKCE verifier it kept and
//! the same redirect. Nothing to paste. Google's device flow can't grant Gmail.
//!
//! The value that goes in the vault is the refresh token, alone, as the form's `value` matches. Nothing here writes it
//! anywhere else, logs it or keeps it once it's given, and the code and the verifier are never in a log or an error.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use pointman_extension::protocol::CredentialsSignInResponse;
use sha2::{Digest, Sha256};

use crate::api::{segment, token_answer, Endpoints, Failure, OAuthClient};

/// What a sign-in asks for: who the account is (`openid email`), its mail read, labelled and drafted
/// (`gmail.modify`), and sent (`gmail.send`).
pub const SCOPES: [&str; 4] =
    ["openid", "email", "https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.send"];

/// The scopes every command needs, which Google lets a person untick: a sign-in without one of them is refused.
pub const NEEDED: [&str; 2] =
    ["https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.send"];

/// How long a sign-in waits for its code, at most.
pub const WAIT: Duration = Duration::from_secs(30 * 60);

struct Pending {
    client: OAuthClient,
    verifier: String,
    redirect: String,
    label: String,
    until: Instant,
}

/// The sign-ins under way, by the node's session id.
#[derive(Default)]
pub struct SignIns {
    open: Mutex<HashMap<String, Pending>>,
}

/// `n` random bytes, base64url without padding: URL-safe, as a state and a PKCE verifier must be.
pub fn random(n: usize) -> anyhow::Result<String> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|e| anyhow!("no randomness for the sign-in: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// PKCE's S256 challenge for a verifier (RFC 7636 §4.2).
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The link the person opens: Google's sign-in, asking for every scope offline, with the account chooser and the
/// consent screen each time (so Google always gives a refresh token, and a second account is picked, not assumed).
pub fn link(auth: &str, client_id: &str, redirect: &str, state: &str, challenge: &str) -> String {
    let scope = SCOPES.join(" ");
    let query = [
        ("client_id", client_id),
        ("redirect_uri", redirect),
        ("response_type", "code"),
        ("scope", scope.as_str()),
        ("access_type", "offline"),
        ("prompt", "select_account consent"),
        ("state", state),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ];
    let query: Vec<String> = query.iter().map(|(k, v)| format!("{k}={}", segment(v))).collect();
    format!("{auth}?{}", query.join("&"))
}

/// The code alone: what core gives, or a whole callback link pasted by hand (`…/oauth/callback?state=…&code=…`).
pub fn code_of(given: &str) -> String {
    let given = given.trim();
    let Some((_, query)) = given.split_once('?').filter(|_| given.contains("code=")) else {
        return given.to_string();
    };
    query.split('&').find_map(|kv| kv.strip_prefix("code=")).map(unescape).unwrap_or_else(|| given.to_string())
}

/// A query value, percent-decoded.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = b.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
        match (b[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
                continue;
            }
            (b'+', _) => out.push(b' '),
            (c, _) => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl SignIns {
    /// Start one: Google's link, and the state core matches its callback to (`state` says the link comes back by
    /// redirect, to the node's `redirect_uri`).
    pub fn start(
        &self,
        ends: &Endpoints,
        client: OAuthClient,
        session: &str,
        redirect: &str,
        label: &str,
    ) -> anyhow::Result<CredentialsSignInResponse> {
        if session.is_empty() {
            bail!("a sign-in needs the node's session");
        }
        let redirect = redirect.trim();
        if redirect.is_empty() {
            bail!(
                "this node can't sign a Google account in yet: it doesn't give sign-ins a redirect back to Pointman. \
                 Upgrade it (pointman upgrade), then sign in again"
            );
        }
        let verifier = random(48)?;
        let state = random(24)?;
        let url = link(&ends.auth, &client.id, redirect, &state, &challenge(&verifier));
        let named = if label.is_empty() { String::new() } else { format!(" for {label}") };
        let prompt = format!("Sign in with the Google account{named} and allow Gmail. Pointman finishes by itself.");
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        open.retain(|_, p| p.until > Instant::now());
        open.insert(
            session.to_string(),
            Pending {
                client,
                verifier,
                redirect: redirect.to_string(),
                label: label.to_string(),
                until: Instant::now() + WAIT,
            },
        );
        Ok(CredentialsSignInResponse { url, prompt: Some(prompt), state: Some(state), ..Default::default() })
    }

    /// Core's callback gave the code: the refresh token, once Google takes it with the verifier.
    pub fn code(&self, agent: &ureq::Agent, ends: &Endpoints, session: &str, code: &str) -> anyhow::Result<String> {
        let p = {
            let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
            open.retain(|_, p| p.until > Instant::now());
            open.remove(session).ok_or_else(|| anyhow!("this sign-in has ended: start it again"))?
        };
        let code = code_of(code);
        if code.is_empty() {
            bail!("Google gave no code: start the sign-in again");
        }
        let got = token_answer(agent.post(&format!("{}/token", ends.oauth)).send_form(&[
            ("code", code.as_str()),
            ("client_id", p.client.id.as_str()),
            ("client_secret", p.client.secret.as_str()),
            ("redirect_uri", p.redirect.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", p.verifier.as_str()),
        ]));
        let v = match got {
            Ok(v) => v,
            Err(Failure::Said { reason, .. }) if reason == "invalid_grant" => bail!(
                "Google didn't take the sign-in's code (invalid_grant: it ran out or was used already): start the \
                 sign-in again"
            ),
            Err(Failure::Said { reason, .. }) if reason == "redirect_uri_mismatch" => bail!(
                "Google says {} isn't one of the OAuth client's authorised redirect URIs: add it to the client in \
                 Google Cloud console, then sign in again",
                p.redirect
            ),
            Err(Failure::Said { reason, .. }) if reason == "invalid_client" || reason == "unauthorized_client" => {
                bail!(
                "Google refused the OAuth client ({reason}): gmail.client must be a Web application client's ID and \
                 secret"
            )
            }
            Err(e) => return Err(e.into()),
        };
        let Some(refresh) = v["refresh_token"].as_str().filter(|t| !t.is_empty()) else {
            bail!("Google signed it in but gave no refresh token: start the sign-in again");
        };
        let granted: Vec<&str> = v["scope"].as_str().unwrap_or_default().split(' ').collect();
        let missing: Vec<&str> = NEEDED
            .iter()
            .filter(|s| !granted.contains(s))
            .map(|s| s.trim_start_matches("https://www.googleapis.com/auth/"))
            .collect();
        if !missing.is_empty() {
            let who = if p.label.is_empty() { "it".to_string() } else { p.label.clone() };
            bail!(
                "the sign-in didn't allow {}: sign {who} in again and tick every box Google shows",
                missing.join(", ")
            );
        }
        Ok(refresh.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_is_rfc_7636s() {
        // RFC 7636, appendix B
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn randoms_are_url_safe_and_differ() {
        let (a, b) = (random(48).unwrap(), random(48).unwrap());
        assert_ne!(a, b);
        assert_eq!(a.len(), 64, "48 bytes are 64 characters: a verifier is 43 to 128");
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), "{a}");
        assert!(random(24).unwrap().len() <= 128, "a state is at most 128 characters");
    }

    #[test]
    fn the_link_asks_for_every_scope_offline_with_pkce() {
        let url = link(
            "https://accounts.google.com/o/oauth2/v2/auth",
            "123-abc.apps.googleusercontent.com",
            "https://james.pointman.network/oauth/callback",
            "st4te",
            "ch4llenge",
        );
        assert!(url
            .starts_with("https://accounts.google.com/o/oauth2/v2/auth?client_id=123-abc.apps.googleusercontent.com&"));
        for part in [
            "redirect_uri=https%3A%2F%2Fjames.pointman.network%2Foauth%2Fcallback",
            "response_type=code",
            "scope=openid%20email%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.modify%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.send&",
            "access_type=offline",
            "prompt=select_account%20consent",
            "state=st4te",
            "code_challenge=ch4llenge",
            "code_challenge_method=S256",
        ] {
            assert!(url.contains(&format!("&{part}")), "{part} in {url}");
        }
    }

    #[test]
    fn the_code_comes_alone_or_from_a_pasted_link() {
        assert_eq!(code_of(" 4/0AbcD-ef "), "4/0AbcD-ef");
        assert_eq!(
            code_of("https://x.pointman.network/oauth/callback?state=s&code=4%2F0AbcD-ef&scope=email"),
            "4/0AbcD-ef"
        );
    }
}
