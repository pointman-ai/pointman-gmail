//! Gmail's messages as the commands give them, and the mail they send: a message's headers, its text (the plain part,
//! else the HTML part as text) and its attachments' names, and a new message as RFC 5322 (`raw`, base64url), which
//! Gmail sends from the signed-in account, with any files attached (`multipart/mixed`).

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context as _};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use regex::Regex;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::v1::{Attachment, Mail};

/// The most a message's attachments may come to: base64 makes 15 MB about 20 MB of message, under Gmail's 25 MB.
pub const MAX_ATTACHED: u64 = 15 * 1024 * 1024;

/// The most of a message's text a read gives.
pub const MAX_BODY: usize = 100_000;

/// A message's headers by their lower-case names (the first of each).
pub fn headers(msg: &Value) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for h in msg["payload"]["headers"].as_array().into_iter().flatten() {
        let (Some(name), Some(value)) = (h["name"].as_str(), h["value"].as_str()) else { continue };
        out.entry(name.to_ascii_lowercase()).or_insert_with(|| value.to_string());
    }
    out
}

/// When Gmail got it (its `internalDate`, in ms), as RFC 3339.
pub fn date(msg: &Value) -> String {
    let ms: i128 = msg["internalDate"].as_str().and_then(|d| d.parse().ok()).unwrap_or(0);
    if ms == 0 {
        return String::new();
    }
    OffsetDateTime::from_unix_timestamp_nanos(ms * 1_000_000)
        .ok()
        .and_then(|d| d.format(&Rfc3339).ok())
        .unwrap_or_default()
}

pub fn labels(msg: &Value) -> Vec<String> {
    msg["labelIds"].as_array().into_iter().flatten().filter_map(|l| l.as_str().map(String::from)).collect()
}

/// A message as a search lists it (Gmail's `format=metadata`).
pub fn summary(account: &str, msg: &Value) -> Mail {
    let h = headers(msg);
    let get = |k: &str| h.get(k).cloned().unwrap_or_default();
    let labels = labels(msg);
    Mail {
        account: account.to_string(),
        id: msg["id"].as_str().unwrap_or_default().to_string(),
        thread_id: msg["threadId"].as_str().unwrap_or_default().to_string(),
        from: get("from"),
        to: get("to"),
        subject: get("subject"),
        date: date(msg),
        snippet: msg["snippet"].as_str().unwrap_or_default().to_string(),
        unread: labels.iter().any(|l| l == "UNREAD"),
        labels,
        ..Default::default()
    }
}

/// Gmail's base64url (with or without its padding) as bytes.
pub fn decode(data: &str) -> Vec<u8> {
    let clean: String = data.chars().filter(|c| !c.is_whitespace() && *c != '=').collect();
    let clean = clean.replace('+', "-").replace('/', "_");
    URL_SAFE_NO_PAD.decode(clean.as_bytes()).unwrap_or_default()
}

/// The parts of a message, depth first: the payload itself, then each part's.
fn parts(payload: &Value) -> Vec<&Value> {
    let mut out = vec![payload];
    for p in payload["parts"].as_array().into_iter().flatten() {
        out.extend(parts(p));
    }
    out
}

fn is_attachment(part: &Value) -> bool {
    !part["filename"].as_str().unwrap_or_default().is_empty() || part["body"]["attachmentId"].is_string()
}

/// A message's text (Gmail's `format=full`): its first plain part, else its first HTML part as text. Whether it was
/// HTML.
pub fn text(msg: &Value) -> (String, bool) {
    let all = parts(&msg["payload"]);
    let of = |mime: &str| {
        all.iter()
            .find(|p| p["mimeType"].as_str() == Some(mime) && !is_attachment(p) && p["body"]["data"].is_string())
            .map(|p| String::from_utf8_lossy(&decode(p["body"]["data"].as_str().unwrap_or_default())).into_owned())
    };
    if let Some(plain) = of("text/plain") {
        return (plain.replace("\r\n", "\n"), false);
    }
    if let Some(html) = of("text/html") {
        return (html_text(&html), true);
    }
    (String::new(), false)
}

/// A message's attachments: name, type and size.
pub fn attachments(msg: &Value) -> Vec<Attachment> {
    parts(&msg["payload"])
        .into_iter()
        .filter(|p| is_attachment(p))
        .map(|p| Attachment {
            name: p["filename"].as_str().unwrap_or_default().to_string(),
            mime_type: p["mimeType"].as_str().unwrap_or_default().to_string(),
            bytes: p["body"]["size"].as_i64().unwrap_or_default(),
            ..Default::default()
        })
        .collect()
}

/// HTML as text: no scripts, styles or tags, a line where a block ends, the common entities read, blank runs
/// squeezed.
pub fn html_text(html: &str) -> String {
    let drop = Regex::new(r"(?is)<(script|style|head)\b.*?</(script|style|head)\s*>").expect("compiles");
    let breaks = Regex::new(r"(?i)<br\s*/?>|</(p|div|tr|li|h[1-6]|table|blockquote)\s*>").expect("compiles");
    let tags = Regex::new(r"(?s)<[^>]*>").expect("compiles");
    let spaces = Regex::new(r"[ \t\u{a0}]+").expect("compiles");
    let blank = Regex::new(r"\n\s*\n(\s*\n)+").expect("compiles");
    let s = drop.replace_all(html, "");
    let s = breaks.replace_all(&s, "\n");
    let s = tags.replace_all(&s, "");
    let s = s
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&amp;", "&");
    let s = spaces.replace_all(&s, " ");
    let lines: Vec<&str> = s.lines().map(str::trim).collect();
    blank.replace_all(lines.join("\n").trim(), "\n\n").into_owned()
}

/// Text cut at `max` characters, and whether it was.
pub fn cut(text: String, max: usize) -> (String, bool) {
    match text.char_indices().nth(max) {
        Some((i, _)) => (text[..i].to_string(), true),
        None => (text, false),
    }
}

/// An address list's entries checked: each has an @, and none could add a header.
pub fn check_addresses(what: &str, list: &[String]) -> anyhow::Result<()> {
    for a in list {
        if a.contains(['\r', '\n']) {
            bail!("{what}: {a:?} has a line break");
        }
        if !a.contains('@') {
            bail!("{what}: {a:?} isn't an address (name@example.com, or Name <name@example.com>)");
        }
    }
    Ok(())
}

/// A header's value as RFC 2047 when it isn't ASCII: UTF-8 words of at most 45 bytes each.
pub fn header_word(value: &str) -> String {
    if value.is_ascii() {
        return value.to_string();
    }
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in value.chars() {
        if chunk.len() + c.len_utf8() > 45 {
            words.push(format!("=?UTF-8?B?{}?=", STANDARD.encode(chunk.as_bytes())));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(format!("=?UTF-8?B?{}?=", STANDARD.encode(chunk.as_bytes())));
    }
    words.join("\r\n ")
}

/// A file a message carries: its name, its type and what's in it.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct File {
    pub name: String,
    pub mime_type: String,
    pub data: Vec<u8>,
}

impl File {
    pub fn listed(&self) -> Attachment {
        Attachment {
            name: self.name.clone(),
            mime_type: self.mime_type.clone(),
            bytes: self.data.len() as i64,
            ..Default::default()
        }
    }
}

/// A file's type from its name's ending: the common ones, else `application/octet-stream`.
pub fn mime_type(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "txt" | "md" => "text/plain",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "json" => "application/json",
        "zip" => "application/zip",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => "application/octet-stream",
    }
}

/// The files at `paths`, read to attach: each must be inside `inside` (the node's fetched board files), after links
/// and `..` are resolved, and together at most [`MAX_ATTACHED`]. A board link the node didn't fetch, a path anywhere
/// else, or too much, is refused before anything is read into the message.
pub fn attach(paths: &[String], inside: &Path) -> anyhow::Result<Vec<File>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let root = inside
        .canonicalize()
        .with_context(|| format!("attachments: no board files were fetched here ({})", inside.display()))?;
    let mut found = Vec::new();
    let mut total = 0u64;
    for p in paths {
        if p.starts_with("pointman://") {
            bail!("attachments: {p} wasn't fetched by the node: attach board files (pointman://asset/<id>?v=<n>)");
        }
        let real = Path::new(p).canonicalize().with_context(|| format!("attachments: can't find {p}"))?;
        if !real.starts_with(&root) || !real.is_file() {
            bail!("attachments: {p} isn't a board file: attach board files only (pointman://asset/<id>?v=<n>)");
        }
        total += real.metadata()?.len();
        if total > MAX_ATTACHED {
            bail!("attachments: more than 15 MB in all, over what Gmail takes once encoded: share a link instead");
        }
        found.push(real);
    }
    found
        .into_iter()
        .map(|real| {
            let name = real.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
            let data = std::fs::read(&real).with_context(|| format!("attachments: can't read {name}"))?;
            Ok(File { mime_type: mime_type(&name).into(), name, data })
        })
        .collect()
}

/// Bytes as base64 in lines of 76, CRLF between them.
fn base64_lines(data: &[u8]) -> String {
    let encoded = STANDARD.encode(data);
    let lines: Vec<&str> = encoded.as_bytes().chunks(76).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
    lines.join("\r\n")
}

/// A file name as a header parameter: no quotes, backslashes or line breaks, RFC 2047 when it isn't ASCII.
fn file_name(name: &str) -> String {
    let clean: String = name.chars().filter(|c| !matches!(c, '"' | '\\' | '\r' | '\n')).collect();
    header_word(&clean).replace("\r\n ", "")
}

/// What a new message says: who to, the subject and the text, the files it carries, and the message it answers.
#[derive(Debug, Default, Clone)]
pub struct Draft {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub body: String,
    pub files: Vec<File>,
    /// The Message-ID it answers, and the References before it.
    pub in_reply_to: String,
    pub references: String,
}

impl Draft {
    /// As RFC 5322, plain text in UTF-8 (base64, so any text goes), with CRLF line ends. Gmail adds From, Date and
    /// Message-ID.
    pub fn rfc5322(&self) -> anyhow::Result<String> {
        check_addresses("to", &self.to)?;
        check_addresses("cc", &self.cc)?;
        for (what, v) in [("subject", &self.subject), ("reply_to", &self.in_reply_to), ("reply_to", &self.references)] {
            if v.contains(['\r', '\n']) {
                bail!("{what} has a line break");
            }
        }
        if self.to.is_empty() {
            bail!("to: who is it to?");
        }
        let mut m = String::new();
        m.push_str(&format!("To: {}\r\n", self.to.join(", ")));
        if !self.cc.is_empty() {
            m.push_str(&format!("Cc: {}\r\n", self.cc.join(", ")));
        }
        m.push_str(&format!("Subject: {}\r\n", header_word(&self.subject)));
        if !self.in_reply_to.is_empty() {
            m.push_str(&format!("In-Reply-To: {}\r\n", self.in_reply_to));
            let refs = format!("{} {}", self.references, self.in_reply_to);
            m.push_str(&format!("References: {}\r\n", refs.trim()));
        }
        m.push_str("MIME-Version: 1.0\r\n");
        let body = self.body.replace("\r\n", "\n").replace('\n', "\r\n");
        let text = format!(
            "Content-Type: text/plain; charset=\"UTF-8\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
            base64_lines(body.as_bytes())
        );
        if self.files.is_empty() {
            m.push_str(&text);
            return Ok(m);
        }
        // "=_" never comes up in base64, so the boundary can't be in any part
        let boundary = "=_pointman_mixed";
        m.push_str(&format!("Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n"));
        m.push_str(&format!("--{boundary}\r\n{text}"));
        for f in &self.files {
            let name = file_name(&f.name);
            m.push_str(&format!(
                "--{boundary}\r\nContent-Type: {}; name=\"{name}\"\r\nContent-Disposition: attachment; \
                 filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
                f.mime_type,
                base64_lines(&f.data)
            ));
        }
        m.push_str(&format!("--{boundary}--\r\n"));
        Ok(m)
    }

    /// Gmail's `raw`: the message as base64url.
    pub fn raw(&self) -> anyhow::Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(self.rfc5322()?.as_bytes()))
    }
}

/// A reply's subject: Re: and the message's, unless it says Re: already.
pub fn re(subject: &str) -> String {
    let s = subject.trim();
    if s.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("re:")) {
        s.to_string()
    } else {
        format!("Re: {s}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn b64(s: &str) -> String {
        URL_SAFE_NO_PAD.encode(s.as_bytes())
    }

    #[test]
    fn a_draft_is_rfc_5322_with_its_text_in_base64() {
        let d = Draft {
            to: vec!["Bob <bob@example.com>".into(), "ann@example.com".into()],
            cc: vec!["cat@example.com".into()],
            subject: "Lunch on Friday?".into(),
            body: "Hi Bob,\nFriday at 1?\n".into(),
            in_reply_to: "<abc@mail.gmail.com>".into(),
            references: "<first@mail.gmail.com>".into(),
            ..Default::default()
        };
        let m = d.rfc5322().unwrap();
        assert!(m.starts_with("To: Bob <bob@example.com>, ann@example.com\r\nCc: cat@example.com\r\n"), "{m}");
        assert!(m.contains("Subject: Lunch on Friday?\r\n"));
        assert!(m.contains("In-Reply-To: <abc@mail.gmail.com>\r\n"));
        assert!(m.contains("References: <first@mail.gmail.com> <abc@mail.gmail.com>\r\n"));
        let body = m.split("\r\n\r\n").nth(1).unwrap().replace("\r\n", "");
        assert_eq!(STANDARD.decode(body).unwrap(), b"Hi Bob,\r\nFriday at 1?\r\n");
        assert_eq!(decode(&d.raw().unwrap()), m.as_bytes(), "raw is the message as base64url");
    }

    #[test]
    fn nothing_in_a_draft_can_add_a_header() {
        let d = Draft {
            to: vec!["bob@example.com".into()],
            subject: "Hi\r\nBcc: eve@example.com".into(),
            ..Default::default()
        };
        assert!(d.rfc5322().is_err());
        let d = Draft { to: vec!["bob@example.com\nBcc: eve@example.com".into()], ..Default::default() };
        assert!(d.rfc5322().is_err());
        let d = Draft { to: vec!["bob".into()], ..Default::default() };
        assert!(d.rfc5322().unwrap_err().to_string().contains("isn't an address"));
    }

    #[test]
    fn a_subject_that_isnt_ascii_is_encoded() {
        assert_eq!(header_word("Hello"), "Hello");
        let w = header_word("Café ☕");
        assert!(w.starts_with("=?UTF-8?B?") && w.ends_with("?="), "{w}");
        assert_eq!(
            STANDARD.decode(w.trim_start_matches("=?UTF-8?B?").trim_end_matches("?=")).unwrap(),
            "Café ☕".as_bytes()
        );
        let long = header_word(&"é".repeat(60));
        assert!(long.split("\r\n ").all(|w| w.len() <= 75), "{long}");
    }

    #[test]
    fn a_messages_text_is_its_plain_part_else_its_html() {
        let msg = json!({"payload": {"mimeType": "multipart/mixed", "parts": [
            {"mimeType": "multipart/alternative", "parts": [
                {"mimeType": "text/plain", "body": {"size": 9, "data": b64("Hi there\r\n")}},
                {"mimeType": "text/html", "body": {"size": 20, "data": b64("<p>Hi <b>there</b></p>")}}
            ]},
            {"mimeType": "application/pdf", "filename": "invoice.pdf", "body": {"size": 12345, "attachmentId": "att1"}}
        ]}});
        assert_eq!(text(&msg), ("Hi there\n".to_string(), false));
        let a = attachments(&msg);
        assert_eq!(a.len(), 1);
        assert_eq!(
            (a[0].name.as_str(), a[0].mime_type.as_str(), a[0].bytes),
            ("invoice.pdf", "application/pdf", 12345)
        );

        let html = json!({"payload": {"mimeType": "text/html", "body": {"data": b64(
            "<html><head><style>p{}</style></head><body><p>Hello&nbsp;Bob,</p><p>See you &amp; Ann<br>at 1</p><script>x()</script></body></html>"
        )}}});
        assert_eq!(text(&html), ("Hello Bob,\nSee you & Ann\nat 1".to_string(), true));
    }

    #[test]
    fn a_summary_says_who_what_and_when() {
        let msg = json!({"id": "m1", "threadId": "t1", "labelIds": ["INBOX", "UNREAD"], "snippet": "Friday?",
            "internalDate": "1762128000000",
            "payload": {"headers": [{"name": "From", "value": "Bob <bob@example.com>"}, {"name": "Subject", "value": "Lunch"}]}});
        let m = summary("work", &msg);
        assert_eq!((m.account.as_str(), m.id.as_str(), m.thread_id.as_str()), ("work", "m1", "t1"));
        assert_eq!((m.from.as_str(), m.subject.as_str()), ("Bob <bob@example.com>", "Lunch"));
        assert_eq!(m.date, "2025-11-03T00:00:00Z");
        assert!(m.unread);
    }

    #[test]
    fn gmails_base64_reads_with_or_without_padding() {
        assert_eq!(decode("SGk_"), b"Hi?");
        assert_eq!(decode("SGk="), b"Hi");
        assert_eq!(decode("SGk"), b"Hi");
    }

    #[test]
    fn a_reply_says_re_once() {
        assert_eq!(re("Lunch"), "Re: Lunch");
        assert_eq!(re("RE: Lunch"), "RE: Lunch");
    }
}
