//! Gmail on Pointman: Gmail (`mail`) for every agent, through Google's APIs (`api`), with any number of Google
//! accounts, each signed in from the apps by redirect (`signin`) and kept in the vault as `gmail.<label>`. Which
//! account a call uses is `accounts`'. The commands' params are proto/gmail/v1/gmail.proto's.

pub mod accounts;
pub mod api;
pub mod mail;
pub mod signin;

/// proto/gmail/v1/gmail.proto's messages, as buffa builds them (build.rs).
pub mod proto {
    pointman_extension::include_proto!();
}
pub use proto::gmail::v1;

/// The vault item with the Google OAuth client: every other `gmail.<label>` is an account's sign-in.
pub const CLIENT_ITEM: &str = "gmail.client";

/// A list in words: `a`, `a and b`, `a, b and c`.
pub fn and(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// `1 message`, `2 messages`.
pub fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}
