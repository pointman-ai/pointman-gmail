//! Which Google accounts a call uses. Each is a label in the vault (`gmail.work` is `work`). A call may name one with
//! `account`; else the `account` setting's is used. With neither, a read uses every account signed in, and a write
//! uses the only one, or stops and lists them rather than send or change something as the wrong person.

use anyhow::bail;

use crate::CLIENT_ITEM;

/// The accounts' labels from the vault's `gmail.*` names: sorted, without the OAuth client's.
pub fn labels(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = items
        .into_iter()
        .filter(|n| n != CLIENT_ITEM)
        .filter_map(|n| n.strip_prefix("gmail.").map(String::from))
        .filter(|l| !l.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The vault item of a label.
pub fn item(label: &str) -> String {
    format!("gmail.{label}")
}

fn listed(have: &[String]) -> String {
    if have.is_empty() {
        "none".into()
    } else {
        have.join(", ")
    }
}

fn none_signed_in() -> anyhow::Error {
    anyhow::anyhow!(
        "no Google account is signed in: add the OAuth client with /gmail client if it isn't there, then type \
         /gmail add <label> in the app and tap Sign in"
    )
}

/// The one account the call or the setting names, if either does, and that it's signed in.
pub fn named(have: &[String], asked: &str, setting: &str) -> anyhow::Result<Option<String>> {
    let (want, from) = match (asked.trim(), setting.trim()) {
        ("", "") => return Ok(None),
        ("", s) => (s, "the account setting"),
        (a, _) => (a, "account"),
    };
    if have.iter().any(|h| h == want) {
        return Ok(Some(want.to_string()));
    }
    if have.is_empty() {
        return Err(none_signed_in());
    }
    bail!(
        "no Google account {want} is signed in ({from}); there's {}: pass account=<label> of one of them, or sign \
         {want} in with /gmail add {want}",
        listed(have)
    )
}

/// The accounts a read uses: the one named, else every one signed in.
pub fn for_read(have: &[String], asked: &str, setting: &str) -> anyhow::Result<Vec<String>> {
    if let Some(one) = named(have, asked, setting)? {
        return Ok(vec![one]);
    }
    if have.is_empty() {
        return Err(none_signed_in());
    }
    Ok(have.to_vec())
}

/// The account a write uses: the one named, else the only one signed in. With several and none named it stops and
/// lists them.
pub fn for_write(have: &[String], asked: &str, setting: &str, kind: &str) -> anyhow::Result<String> {
    if let Some(one) = named(have, asked, setting)? {
        return Ok(one);
    }
    match have {
        [] => Err(none_signed_in()),
        [one] => Ok(one.clone()),
        _ => bail!(
            "nothing done: {} Google accounts are signed in ({}) and {kind} doesn't say which to use: pass \
             account=<label> with it, or set the account setting",
            have.len(),
            listed(have)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn have() -> Vec<String> {
        labels(vec!["gmail.work".into(), "gmail.client".into(), "gmail.personal".into()])
    }

    #[test]
    fn the_client_isnt_an_account() {
        assert_eq!(have(), ["personal", "work"]);
        assert_eq!(item("work"), "gmail.work");
    }

    #[test]
    fn a_read_uses_the_one_named_else_every_one() {
        assert_eq!(for_read(&have(), "", "").unwrap(), ["personal", "work"]);
        assert_eq!(for_read(&have(), "work", "").unwrap(), ["work"]);
        assert_eq!(for_read(&have(), "", "personal").unwrap(), ["personal"]);
        assert_eq!(for_read(&have(), "work", "personal").unwrap(), ["work"], "the call's beats the setting's");
        let e = for_read(&have(), "school", "").unwrap_err().to_string();
        assert!(e.contains("school") && e.contains("personal, work") && e.contains("/gmail add school"), "{e}");
        let e = for_read(&have(), "", "school").unwrap_err().to_string();
        assert!(e.contains("the account setting"), "{e}");
    }

    #[test]
    fn a_write_uses_the_one_named_or_the_only_one_or_stops() {
        assert_eq!(for_write(&have(), "work", "", "gmail.send").unwrap(), "work");
        assert_eq!(for_write(&have(), "", "personal", "gmail.send").unwrap(), "personal");
        let e = for_write(&have(), "", "", "gmail.send").unwrap_err().to_string();
        assert!(e.starts_with("nothing done: 2 Google accounts") && e.contains("personal, work"), "{e}");
        assert_eq!(for_write(&["work".to_string()], "", "", "gmail.send").unwrap(), "work");
    }

    #[test]
    fn with_none_signed_in_it_says_how() {
        for e in [
            for_read(&[], "", "").unwrap_err(),
            for_write(&[], "", "", "x").unwrap_err(),
            for_read(&[], "w", "").unwrap_err(),
        ] {
            assert!(e.to_string().contains("/gmail add"), "{e}");
        }
    }
}
