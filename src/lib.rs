//! Gmail on Pointman: Gmail (`mail`) for every agent, through Google's APIs (`api`), with any number of Google
//! accounts, each signed in from the apps by redirect (`signin`) and kept in the vault as `gmail.<label>`. Which
//! account a call uses is `accounts`'. The commands' params are proto/gmail/v1/gmail.proto's. On a hosted Pointman,
//! sign-ins use core's shared Google client, Pointman's own, and exchange and refresh through core; a self-hosted one
//! uses its own client, `gmail.client`.

pub mod accounts;
pub mod api;
pub mod mail;
pub mod signin;

/// proto/gmail/v1/gmail.proto's messages, as buffa builds them (build.rs).
pub mod proto {
    pointman_extension::include_proto!();
}
pub use proto::gmail::v1;

/// The vault item with a self-hosted Pointman's own Google OAuth client: every other `gmail.<label>` is an account's
/// sign-in.
pub const CLIENT_ITEM: &str = "gmail.client";

/// The provider the account form names as its `shared_client`: core's shared client for it is Pointman's own.
pub const PROVIDER: &str = "google";

/// Before an account's refresh token in the vault when Pointman's shared client signed it in: its refreshes go through
/// core. Without it, the account was signed in with `gmail.client`.
pub const SHARED: &str = "shared:";

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
