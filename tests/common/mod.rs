//! A fake Google: OAuth's token endpoint (refresh tokens, and the authorization code with its PKCE verifier) and the
//! parts of Gmail's API the extension calls, on a local port, over plain HTTP/1.1. Each account has its own mailbox,
//! picked by the access token a call carries; a call without a token it gave is a 401. It keeps every request it was
//! sent.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};

pub const CLIENT_ID: &str = "123-fake.apps.googleusercontent.com";
pub const CLIENT_SECRET: &str = "GOCSPX-fakeclientsecret01";
pub const WORK_REFRESH: &str = "1//0gWORKrefreshTOKENfor-the-tests";
pub const HOME_REFRESH: &str = "1//0gHOMErefreshTOKENfor-the-tests";
pub const NEW_REFRESH: &str = "1//0gNEWrefreshTOKENfrom-a-sign-in";
pub const CODE: &str = "4/0AfakeAUTHcode-for-the-tests";
pub const ALL_SCOPES: &str = "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/gmail.send";

/// One request it was sent.
#[derive(Debug, Clone)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    /// The account its token was for, if it had one.
    pub account: String,
    pub form: HashMap<String, String>,
    pub json: Value,
}

impl Req {
    pub fn q(&self, k: &str) -> Option<&str> {
        self.query.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str())
    }
}

/// One account's mail.
#[derive(Default, Clone)]
pub struct Mailbox {
    pub email: String,
    pub messages: Vec<Value>,
    pub drafts: Vec<Value>,
    pub sent: Vec<Value>,
}

#[derive(Default)]
pub struct State {
    pub requests: Vec<Req>,
    /// Each refresh token's account.
    pub refresh: HashMap<String, String>,
    pub revoked: Vec<String>,
    pub tokens: HashMap<String, String>,
    pub boxes: HashMap<String, Mailbox>,
    /// The sign-in under way: the PKCE challenge and redirect it was started with, and the scopes the person allows.
    pub challenge: String,
    pub redirect: String,
    pub granted: String,
    pub made: u32,
    /// What the token endpoint answers instead, as it is, when set: a status and a body that isn't JSON.
    pub garbled: Option<(u16, String)>,
}

#[derive(Clone)]
pub struct Fake {
    pub url: String,
    state: Arc<Mutex<State>>,
}

pub fn b64(s: &str) -> String {
    URL_SAFE_NO_PAD.encode(s.as_bytes())
}

/// A message as Gmail's `format=full` gives it.
pub fn message(id: &str, thread: &str, from: &str, subject: &str, when_ms: u64, text: &str) -> Value {
    json!({
        "id": id, "threadId": thread, "labelIds": ["INBOX", "UNREAD"], "snippet": text.chars().take(20).collect::<String>(),
        "internalDate": when_ms.to_string(),
        "payload": {"mimeType": "multipart/mixed", "headers": [
            {"name": "From", "value": from}, {"name": "To", "value": "me@example.com"},
            {"name": "Subject", "value": subject}, {"name": "Message-ID", "value": format!("<{id}@mail.example.com>")},
            {"name": "References", "value": "<first@mail.example.com>"}
        ], "parts": [
            {"mimeType": "text/plain", "body": {"size": text.len(), "data": b64(text)}},
            {"mimeType": "application/pdf", "filename": "notes.pdf", "body": {"size": 2048, "attachmentId": "att1"}}
        ]}
    })
}

impl Fake {
    /// A fake with two accounts, work and home, each with mail.
    pub fn start() -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let fake =
            Fake { url, state: Arc::new(Mutex::new(State { granted: ALL_SCOPES.into(), ..Default::default() })) };
        {
            let mut s = fake.state();
            s.refresh.insert(WORK_REFRESH.into(), "work".into());
            s.refresh.insert(HOME_REFRESH.into(), "home".into());
            s.refresh.insert(NEW_REFRESH.into(), "new".into());
            s.boxes.insert(
                "work".into(),
                Mailbox {
                    email: "james@work.example.com".into(),
                    messages: vec![
                        message(
                            "w1",
                            "tw1",
                            "Bob <bob@example.com>",
                            "Quarterly plan",
                            1_762_200_000_000,
                            "The plan is attached. Secret numbers inside.",
                        ),
                        message("w2", "tw2", "Ann <ann@example.com>", "Lunch?", 1_762_100_000_000, "Lunch on Friday?"),
                    ],
                    ..Default::default()
                },
            );
            s.boxes.insert(
                "home".into(),
                Mailbox {
                    email: "james@home.example.com".into(),
                    messages: vec![message(
                        "h1",
                        "th1",
                        "Mum <mum@example.com>",
                        "Sunday",
                        1_762_150_000_000,
                        "Dinner on Sunday.",
                    )],
                    ..Default::default()
                },
            );
        }
        let f = fake.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let f = f.clone();
                std::thread::spawn(move || f.serve(stream));
            }
        });
        fake
    }

    pub fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn requests(&self) -> Vec<Req> {
        self.state().requests.clone()
    }

    /// The requests to Gmail (not OAuth's).
    pub fn api_requests(&self) -> Vec<Req> {
        self.requests().into_iter().filter(|r| r.path != "/token").collect()
    }

    pub fn mailbox(&self, account: &str) -> Mailbox {
        self.state().boxes.get(account).cloned().unwrap_or_default()
    }

    fn serve(&self, mut stream: TcpStream) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut words = line.split_whitespace();
        let method = words.next().unwrap_or_default().to_string();
        let target = words.next().unwrap_or_default().to_string();
        let mut headers = HashMap::new();
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (unescape(p), pairs(q)),
            None => (unescape(&target), vec![]),
        };
        let length: usize = headers.get("content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
        let mut body = vec![0u8; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        let text = String::from_utf8_lossy(&body).into_owned();
        let as_json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let form: HashMap<String, String> =
            if path == "/token" { pairs(&text).into_iter().collect() } else { HashMap::new() };
        let token = headers.get("authorization").and_then(|a| a.strip_prefix("Bearer ")).unwrap_or_default();
        let account = self.state().tokens.get(token).cloned().unwrap_or_default();
        self.state().requests.push(Req {
            method: method.clone(),
            path: path.clone(),
            query: query.clone(),
            account: account.clone(),
            form: form.clone(),
            json: as_json.clone(),
        });
        let garbled = if path == "/token" { self.state().garbled.clone() } else { None };
        let (status, text) = match garbled {
            Some(answer) => answer,
            None => {
                let (status, out) = if path == "/token" {
                    self.oauth(&form)
                } else if account.is_empty() {
                    error(401, "authError", "Invalid Credentials")
                } else {
                    self.api(&account, &method, &path, &query, &as_json)
                };
                (status, if out.is_null() { String::new() } else { out.to_string() })
            }
        };
        let head = format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            if status < 400 { "OK" } else { "Error" },
            text.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(text.as_bytes());
        let _ = stream.flush();
    }

    fn oauth(&self, form: &HashMap<String, String>) -> (u16, Value) {
        let get = |k: &str| form.get(k).cloned().unwrap_or_default();
        let oauth_error =
            |status: u16, e: &str| (status, json!({"error": e, "error_description": format!("fake: {e}")}));
        if get("client_id") != CLIENT_ID || get("client_secret") != CLIENT_SECRET {
            return oauth_error(401, "invalid_client");
        }
        let mut s = self.state();
        s.made += 1;
        let n = s.made;
        match get("grant_type").as_str() {
            "refresh_token" => {
                let refresh = get("refresh_token");
                if s.revoked.contains(&refresh) {
                    return oauth_error(400, "invalid_grant");
                }
                let Some(account) = s.refresh.get(&refresh).cloned() else { return oauth_error(400, "invalid_grant") };
                let token = format!("at-{account}-{n}");
                s.tokens.insert(token.clone(), account);
                (200, json!({"access_token": token, "expires_in": 3599, "token_type": "Bearer"}))
            }
            "authorization_code" => {
                let verifier = get("code_verifier");
                if get("code") != CODE
                    || get("redirect_uri") != s.redirect
                    || gmail::signin::challenge(&verifier) != s.challenge
                {
                    return oauth_error(400, "invalid_grant");
                }
                let token = format!("at-new-{n}");
                s.tokens.insert(token.clone(), "new".into());
                (
                    200,
                    json!({"access_token": token, "refresh_token": NEW_REFRESH, "expires_in": 3599,
                        "scope": s.granted, "token_type": "Bearer", "id_token": "x.y.z"}),
                )
            }
            _ => oauth_error(400, "unsupported_grant_type"),
        }
    }

    fn api(&self, account: &str, method: &str, path: &str, query: &[(String, String)], body: &Value) -> (u16, Value) {
        let q = |k: &str| query.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone()).unwrap_or_default();
        let mut s = self.state();
        s.made += 1;
        let n = s.made;
        let mb = s.boxes.entry(account.to_string()).or_default();
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        match (method, parts.as_slice()) {
            ("GET", ["gmail", "v1", "users", "me", "profile"]) => {
                (200, json!({"emailAddress": mb.email, "messagesTotal": mb.messages.len()}))
            }
            ("GET", ["gmail", "v1", "users", "me", "messages"]) => {
                let max: usize = q("maxResults").parse().unwrap_or(100);
                let found: Vec<Value> = if q("q").contains("nothing") {
                    vec![]
                } else {
                    mb.messages.iter().take(max).map(|m| json!({"id": m["id"], "threadId": m["threadId"]})).collect()
                };
                (200, json!({"messages": found, "resultSizeEstimate": found.len()}))
            }
            ("GET", ["gmail", "v1", "users", "me", "messages", id]) => {
                match mb.messages.iter().find(|m| m["id"] == *id) {
                    Some(m) => (200, m.clone()),
                    None => error(404, "notFound", "Requested entity was not found."),
                }
            }
            ("POST", ["gmail", "v1", "users", "me", "drafts"]) => {
                let raw = body["message"]["raw"].as_str().unwrap_or_default().to_string();
                let thread = body["message"]["threadId"].as_str().map(String::from).unwrap_or(format!("t{n}"));
                let draft =
                    json!({"id": format!("d{n}"), "message": {"id": format!("m{n}"), "threadId": thread, "raw": raw}});
                mb.drafts.push(draft.clone());
                (200, json!({"id": draft["id"], "message": {"id": draft["message"]["id"], "threadId": thread}}))
            }
            ("GET", ["gmail", "v1", "users", "me", "drafts", id]) => match mb.drafts.iter().find(|d| d["id"] == *id) {
                Some(d) => {
                    let headers = raw_headers(d["message"]["raw"].as_str().unwrap_or_default());
                    (
                        200,
                        json!({"id": d["id"], "message": {"id": d["message"]["id"], "payload": {"headers": headers}}}),
                    )
                }
                None => error(404, "notFound", "Requested entity was not found."),
            },
            ("POST", ["gmail", "v1", "users", "me", "drafts", "send"]) => {
                let Some(i) = mb.drafts.iter().position(|d| d["id"] == body["id"]) else {
                    return error(404, "notFound", "Requested entity was not found.");
                };
                let d = mb.drafts.remove(i);
                mb.sent.push(d["message"].clone());
                (200, json!({"id": d["message"]["id"], "threadId": d["message"]["threadId"], "labelIds": ["SENT"]}))
            }
            ("POST", ["gmail", "v1", "users", "me", "messages", "send"]) => {
                let sent = json!({"id": format!("s{n}"), "threadId": format!("t{n}"), "raw": body["raw"]});
                mb.sent.push(sent.clone());
                (200, json!({"id": sent["id"], "threadId": sent["threadId"], "labelIds": ["SENT"]}))
            }
            _ => error(404, "notFound", &format!("the fake has no {method} {path}")),
        }
    }
}

fn error(status: u16, reason: &str, message: &str) -> (u16, Value) {
    (status, json!({"error": {"code": status, "message": message, "errors": [{"reason": reason}]}}))
}

/// A raw message's headers, as Gmail's `payload.headers` lists them.
pub fn raw_headers(raw: &str) -> Vec<Value> {
    let text = String::from_utf8_lossy(&gmail::mail::decode(raw)).into_owned();
    let head = text.split("\r\n\r\n").next().unwrap_or_default();
    let mut out: Vec<(String, String)> = Vec::new();
    for line in head.split("\r\n") {
        if line.starts_with(' ') {
            if let Some(last) = out.last_mut() {
                last.1.push_str(line);
            }
        } else if let Some((k, v)) = line.split_once(':') {
            out.push((k.to_string(), v.trim().to_string()));
        }
    }
    out.into_iter().map(|(k, v)| json!({"name": k, "value": v})).collect()
}

/// A raw message's text.
pub fn raw_body(raw: &str) -> String {
    let text = String::from_utf8_lossy(&gmail::mail::decode(raw)).into_owned();
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.replace("\r\n", "")).unwrap_or_default();
    String::from_utf8_lossy(&base64::engine::general_purpose::STANDARD.decode(body).unwrap_or_default()).into_owned()
}

fn pairs(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (unescape(k), unescape(v))
        })
        .collect()
}

fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
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
