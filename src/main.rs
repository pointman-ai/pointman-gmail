//! The extension's process: the node starts it (`bin/gmail`, from the extension's folder) and talks to it over stdin
//! and stdout. It searches, reads, drafts and sends mail, and signs Google accounts in from the apps. Nothing reaches
//! Google without a sign-in in the vault; mail is sent when gmail.send is called (the yes before it is the workflow's
//! or the task's); and no token, code or message body is ever logged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use gmail::accounts::{self, item};
use gmail::api::{access_token, agent, segment, Api, Endpoints, OAuthClient};
use gmail::mail::{self, Draft};
use gmail::signin::SignIns;
use gmail::v1::{
    Account, AccountsParams, AccountsResult, AddParams, AddResult, ClientParams, ClientResult, DraftParams,
    DraftResult, Problem, ReadParams, ReadResult, SearchParams, SearchResult, SendParams, SendResult, Settings,
};
use gmail::{and, count, CLIENT_ITEM};
use pointman_extension::protocol::{CredentialsCodeRequest, CredentialsCodeResponse, CredentialsSignInRequest};
use pointman_extension::{Extension, Handle, Job};
use regex::Regex;
use serde_json::{json, Value};

struct Ext {
    h: Handle,
    agent: ureq::Agent,
    ends: Endpoints,
    /// Access tokens by vault item, until they run out.
    tokens: Mutex<HashMap<String, (String, Instant)>>,
}

impl Ext {
    /// The accounts signed in, by label.
    fn have(&self) -> anyhow::Result<Vec<String>> {
        Ok(accounts::labels(self.h.secrets("gmail.")?))
    }

    fn setting(&self) -> String {
        self.h.typed_settings::<Settings>().map(|s| s.account).unwrap_or_default()
    }

    fn reads(&self, asked: &str) -> anyhow::Result<Vec<String>> {
        accounts::for_read(&self.have()?, asked, &self.setting())
    }

    fn write(&self, asked: &str, kind: &str) -> anyhow::Result<String> {
        accounts::for_write(&self.have()?, asked, &self.setting(), kind)
    }

    /// The Web application client the sign-ins go through: the vault's `gmail.client`.
    fn client(&self) -> anyhow::Result<OAuthClient> {
        let value = self.h.secret(CLIENT_ITEM).map_err(|_| {
            anyhow!(
                "no Google OAuth client yet: type /gmail client in the app and paste a Web application client's ID \
                 and secret"
            )
        })?;
        OAuthClient::parse(&value).ok_or_else(|| {
            anyhow!(
                "{CLIENT_ITEM} isn't a client ID and secret (…apps.googleusercontent.com, a space, then the secret): \
                 add it again with /gmail client"
            )
        })
    }

    /// An access token for an account, made again when it's within a minute of running out, or `fresh`.
    fn token(&self, label: &str, fresh: bool) -> anyhow::Result<String> {
        let name = item(label);
        if !fresh {
            let cached = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((token, until)) = cached.get(&name) {
                if *until > Instant::now() + Duration::from_secs(60) {
                    return Ok(token.clone());
                }
            }
        }
        let value = self.h.secret(&name)?;
        let refresh = Regex::new(r"1//[A-Za-z0-9_-]+")
            .expect("compiles")
            .find(&value)
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| anyhow!("{name} isn't a Google refresh token: sign it in again with /gmail add {label}"))?;
        let (token, lasts) = access_token(&self.agent, &self.ends, &self.client()?, &refresh, &name)?;
        self.tokens.lock().unwrap_or_else(|e| e.into_inner()).insert(name, (token.clone(), Instant::now() + lasts));
        Ok(token)
    }

    fn api<T>(&self, label: &str, f: impl FnOnce(&Api) -> anyhow::Result<T>) -> anyhow::Result<T> {
        let token = |fresh: bool| self.token(label, fresh);
        f(&Api { agent: &self.agent, ends: &self.ends, token: &token })
    }
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

fn problem(account: &str, e: &anyhow::Error) -> Problem {
    Problem { account: account.to_string(), error: format!("{e:#}"), ..Default::default() }
}

/// Each account's failure in a line, for a read's text.
fn failures(failed: &[Problem]) -> String {
    failed.iter().map(|f| format!("\nCouldn't ask {}: {}", f.account, f.error)).collect()
}

/// A read that asked every account it was given, and every one failed: the error is theirs.
fn all_failed(labels: &[String], failed: &[Problem]) -> anyhow::Result<()> {
    if !labels.is_empty() && failed.len() == labels.len() {
        let each: Vec<String> = failed.iter().map(|f| format!("{}: {}", f.account, f.error)).collect();
        bail!("{}", each.join("; "));
    }
    Ok(())
}

fn message_url(api: &Api, id: &str) -> String {
    api.gmail(&format!("users/me/messages/{}", segment(id)))
}

fn accounts_list(x: &Ext, _: &Job, _: AccountsParams) -> anyhow::Result<AccountsResult> {
    let have = x.have()?;
    if have.is_empty() {
        return Ok(AccountsResult {
            text: "No Google account is signed in: add the OAuth client with /gmail client if it isn't there, then \
                   /gmail add <label> in the app."
                .into(),
            ..Default::default()
        });
    }
    let setting = x.setting();
    let mut out = AccountsResult::default();
    let mut lines = Vec::new();
    for label in &have {
        let mut a = Account { label: label.clone(), chosen: *label == setting, ..Default::default() };
        match x.api(label, |api| api.get(&api.gmail("users/me/profile"), &[])) {
            Ok(v) => {
                a.email = s(&v["emailAddress"]);
                a.works = true;
                lines.push(format!("{label} ({})", a.email));
            }
            Err(e) => {
                a.error = format!("{e:#}");
                lines.push(format!("{label} (not working: {})", a.error));
            }
        }
        out.accounts.push(a);
    }
    let chosen = if setting.is_empty() { String::new() } else { format!(" The account setting uses {setting}.") };
    out.text = format!("{}: {}.{chosen}", count(have.len(), "Google account", "Google accounts"), lines.join(", "));
    Ok(out)
}

fn search(x: &Ext, _: &Job, p: SearchParams) -> anyhow::Result<SearchResult> {
    let labels = x.reads(&p.account)?;
    let limit = (if p.limit <= 0 { 10 } else { p.limit.min(50) }).to_string();
    let mut out = SearchResult { accounts: labels.clone(), ..Default::default() };
    for label in &labels {
        let got = x.api(label, |api| {
            let list =
                api.get(&api.gmail("users/me/messages"), &[("q", p.query.as_str()), ("maxResults", limit.as_str())])?;
            let mut found = Vec::new();
            for m in list["messages"].as_array().into_iter().flatten() {
                let v = api.get(
                    &message_url(api, m["id"].as_str().unwrap_or_default()),
                    &[
                        ("format", "metadata"),
                        ("metadataHeaders", "From"),
                        ("metadataHeaders", "To"),
                        ("metadataHeaders", "Subject"),
                        ("metadataHeaders", "Date"),
                    ],
                )?;
                found.push(mail::summary(label, &v));
            }
            Ok(found)
        });
        match got {
            Ok(found) => out.messages.extend(found),
            Err(e) => out.failed.push(problem(label, &e)),
        }
    }
    all_failed(&labels, &out.failed)?;
    out.messages.sort_by(|a, b| b.date.cmp(&a.date));
    let several = labels.len() > 1;
    let mut text = if out.messages.is_empty() {
        format!("No messages for \"{}\" in {}.", p.query, and(&labels))
    } else {
        format!(
            "{} for \"{}\" in {}, newest first:",
            count(out.messages.len(), "message", "messages"),
            p.query,
            and(&labels)
        )
    };
    for m in &out.messages {
        let unread = if m.unread { " (unread)" } else { "" };
        let at = if several { format!("{} ", m.account) } else { String::new() };
        text.push_str(&format!("\n- {} {}: {}{unread} [{at}{}]", m.date, m.from, m.subject, m.id));
    }
    text.push_str(&failures(&out.failed));
    out.text = text;
    Ok(out)
}

fn read(x: &Ext, _: &Job, p: ReadParams) -> anyhow::Result<ReadResult> {
    let labels = x.reads(&p.account)?;
    let mut errors = Vec::new();
    for label in &labels {
        match x.api(label, |api| api.get(&message_url(api, &p.id), &[("format", "full")])) {
            Ok(v) => return Ok(message(label, &v)),
            Err(e) => errors.push(format!("{label}: {e:#}")),
        }
    }
    bail!("no message {} in {} ({})", p.id, and(&labels), errors.join("; "))
}

fn message(label: &str, v: &Value) -> ReadResult {
    let h = mail::headers(v);
    let get = |k: &str| h.get(k).cloned().unwrap_or_default();
    let (body, from_html) = mail::text(v);
    let (body, truncated) = mail::cut(body, mail::MAX_BODY);
    let attachments = mail::attachments(v);
    let mut out = ReadResult {
        account: label.to_string(),
        id: s(&v["id"]),
        thread_id: s(&v["threadId"]),
        from: get("from"),
        to: get("to"),
        cc: get("cc"),
        subject: get("subject"),
        date: mail::date(v),
        labels: mail::labels(v),
        from_html,
        truncated,
        message_id: get("message-id"),
        ..Default::default()
    };
    let size = format!(
        "{} of text{}{}",
        count(body.chars().count(), "character", "characters"),
        if from_html { ", from its HTML" } else { "" },
        if truncated { ", cut at 100,000" } else { "" }
    );
    let files = if attachments.is_empty() {
        String::new()
    } else {
        let names: Vec<String> = attachments.iter().map(|a| a.name.clone()).collect();
        format!("; {}: {}", count(attachments.len(), "attachment", "attachments"), names.join(", "))
    };
    out.text = format!(
        "\"{}\" from {}, {}, in {label}: {size}{files}. Its words are in body: private, so say what it's about and \
         post them only when asked.",
        out.subject, out.from, out.date
    );
    out.body = body;
    out.attachments = attachments;
    out
}

fn draft(x: &Ext, _: &Job, p: DraftParams) -> anyhow::Result<DraftResult> {
    let mut d = Draft {
        to: p.to.clone(),
        cc: p.cc.clone(),
        subject: p.subject.clone(),
        body: p.body.clone(),
        ..Default::default()
    };
    let reply = p.reply_to.trim();
    if reply.is_empty() {
        if d.subject.trim().is_empty() {
            bail!("subject: what is it about? (only a reply takes its message's)");
        }
        d.rfc5322()?;
    } else {
        mail::check_addresses("to", &d.to)?;
        mail::check_addresses("cc", &d.cc)?;
    }
    let label = x.write(&p.account, "gmail.draft")?;
    x.api(&label, |api| {
        let mut thread = String::new();
        if !reply.is_empty() {
            let orig = api.get(
                &message_url(api, reply),
                &[
                    ("format", "metadata"),
                    ("metadataHeaders", "Message-ID"),
                    ("metadataHeaders", "References"),
                    ("metadataHeaders", "Subject"),
                    ("metadataHeaders", "From"),
                    ("metadataHeaders", "Reply-To"),
                ],
            )?;
            let h = mail::headers(&orig);
            thread = s(&orig["threadId"]);
            d.in_reply_to = h.get("message-id").cloned().unwrap_or_default();
            d.references = h.get("references").cloned().unwrap_or_default();
            if d.to.is_empty() {
                let back = h.get("reply-to").or_else(|| h.get("from")).cloned().unwrap_or_default();
                if !back.is_empty() {
                    d.to = vec![back];
                }
            }
            if d.subject.trim().is_empty() {
                d.subject = mail::re(&h.get("subject").cloned().unwrap_or_default());
            }
        }
        let raw = d.raw()?;
        let mut message = json!({ "raw": raw });
        if !thread.is_empty() {
            message["threadId"] = json!(thread);
        }
        let made = api.send_json("POST", &api.gmail("users/me/drafts"), &[], &json!({"message": message}))?;
        let draft = s(&made["id"]);
        let reply_note = if thread.is_empty() { "" } else { ", in the thread it answers" };
        Ok(DraftResult {
            text: format!(
                "Drafted \"{}\" to {} in {label}{reply_note}: draft {draft}. Nothing is sent: gmail.send with \
                 draft={draft} sends it.",
                d.subject,
                and(&d.to)
            ),
            account: label.clone(),
            draft,
            message: s(&made["message"]["id"]),
            thread_id: s(&made["message"]["threadId"]),
            to: d.to.clone(),
            subject: d.subject.clone(),
            ..Default::default()
        })
    })
}

fn send(x: &Ext, _: &Job, p: SendParams) -> anyhow::Result<SendResult> {
    let draft = p.draft.trim().to_string();
    let direct = Draft {
        to: p.to.clone(),
        cc: p.cc.clone(),
        subject: p.subject.clone(),
        body: p.body.clone(),
        ..Default::default()
    };
    if draft.is_empty() {
        if p.to.is_empty() || p.subject.trim().is_empty() || p.body.trim().is_empty() {
            bail!("gmail.send needs a draft (gmail.draft's), or to, subject and body");
        }
        direct.rfc5322()?;
    } else if !p.to.is_empty() || !p.cc.is_empty() || !p.subject.is_empty() || !p.body.is_empty() {
        bail!("give a draft, or to, subject and body, not both: a draft is sent as it is");
    }
    let label = x.write(&p.account, "gmail.send")?;
    x.api(&label, |api| {
        let (sent, to, subject) = if draft.is_empty() {
            let raw = direct.raw()?;
            let sent = api.send_json("POST", &api.gmail("users/me/messages/send"), &[], &json!({ "raw": raw }))?;
            (sent, p.to.clone(), p.subject.clone())
        } else {
            let d = api.get(&api.gmail(&format!("users/me/drafts/{}", segment(&draft))), &[("format", "metadata")])?;
            let h = mail::headers(&d["message"]);
            let to: Vec<String> = h.get("to").map(|t| vec![t.clone()]).unwrap_or_default();
            let subject = h.get("subject").cloned().unwrap_or_default();
            let sent = api.send_json("POST", &api.gmail("users/me/drafts/send"), &[], &json!({"id": draft}))?;
            (sent, to, subject)
        };
        Ok(SendResult {
            text: format!("Sent \"{subject}\" to {} from {label}.", and(&to)),
            account: label.clone(),
            message: s(&sent["id"]),
            thread_id: s(&sent["threadId"]),
            to,
            subject,
            ..Default::default()
        })
    })
}

fn main() -> anyhow::Result<()> {
    let mut ext = Extension::new()?;
    let x = Arc::new(Ext { h: ext.handle(), agent: agent(), ends: Endpoints::from_env(), tokens: Mutex::default() });
    let signins = Arc::new(SignIns::default());

    let xx = x.clone();
    ext.typed_command(move |job: &Job, p: AccountsParams| accounts_list(&xx, job, p));
    let xx = x.clone();
    ext.typed_command(move |job: &Job, p: SearchParams| search(&xx, job, p));
    let xx = x.clone();
    ext.typed_command(move |job: &Job, p: ReadParams| read(&xx, job, p));
    let xx = x.clone();
    ext.typed_command(move |job: &Job, p: DraftParams| draft(&xx, job, p));
    let xx = x.clone();
    ext.typed_command(move |job: &Job, p: SendParams| send(&xx, job, p));

    // `/gmail add` and `/gmail client` posted (an agent, an older app): the apps open the forms for them
    ext.typed_command(|_: &Job, _: AddParams| {
        Ok(AddResult {
            text: "A Google account is signed in from the Pointman app, so its token never goes in a post: type \
                   `/gmail add <label>` there and tap Sign in."
                .into(),
            ..Default::default()
        })
    });
    ext.typed_command(|_: &Job, _: ClientParams| {
        Ok(ClientResult {
            text: "The Google OAuth client is added in the Pointman app, so its secret never goes in a post: type \
                   `/gmail client` there and paste its client ID and secret."
                .into(),
            ..Default::default()
        })
    });

    // Sign in from the apps: Google's authorization-code flow with PKCE, back through core's /oauth/callback
    let (xx, si) = (x.clone(), signins.clone());
    ext.on(move |p: CredentialsSignInRequest| {
        if p.form != "account" {
            bail!("the Gmail extension signs in accounts only (form: account); the OAuth client is pasted with /gmail client");
        }
        let label = p.label.trim();
        if label == CLIENT_ITEM.trim_start_matches("gmail.") {
            bail!("{CLIENT_ITEM} is the OAuth client's place in the vault: call the account something else");
        }
        let session = p.session.as_option().map(|s| s.id.as_str()).unwrap_or_default();
        si.start(&xx.ends, xx.client()?, session, &p.redirect_uri, label)
    });
    let (xx, si) = (x.clone(), signins);
    ext.on(move |p: CredentialsCodeRequest| {
        let session = p.session.as_option().map(|s| s.id.as_str()).unwrap_or_default();
        let value = si.code(&xx.agent, &xx.ends, session, &p.code)?;
        Ok(CredentialsCodeResponse { value, ..Default::default() })
    });

    ext.run()
}
