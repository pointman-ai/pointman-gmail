# gmail

A Pointman extension that gives every agent Gmail, with any number of Google accounts. Each account is signed in from
the Pointman apps and kept in the vault as `gmail.<label>`, so every machine with the extension uses the same sign-ins,
and no agent depends on one person's own connectors. Agents read freely. Mail is sent when `gmail.send` is called: the
yes before a send is the workflow's or the task's.

| File | What |
|---|---|
| `SKILL.md` | The agents' guidance: the commands, accounts, sending, keeping mail private |
| `proto/gmail/v1/gmail.proto` | The commands' params and results, and the settings |
| `src/` | The process: `signin` (authorization code + PKCE, shared or own client), `accounts` (which account a call uses), `mail`, `api` (the HTTP calls, and refreshes through core) |

## Install

```
pointman add pointman-ai/pointman-gmail
```

## Sign accounts in

**`/gmail add <label>`** in the app for each account (`/gmail add work`, `/gmail add personal`), and tap Sign in.
Google's page opens; pick the account and allow it. Pointman finishes the sign-in by itself: nothing to paste.

On a hosted Pointman that's all: the sign-in goes through Pointman's own Google client, core's shared client, whose
redirect URI is `https://api.pointman.ai/v1/oauth/google/callback`. The extension never holds that client's secret:
it exchanges the code and refreshes the account's token through core. The vault keeps the refresh token with `shared:`
before it, so its refreshes keep going through core.

The sign-in asks for `openid email`, `gmail.modify` (read, label and draft mail) and `gmail.send`. It's Google's
authorization-code flow with PKCE, coming back by redirect; Google's device flow can't grant Gmail. It needs node
0.4.12 or later.

### A self-hosted Pointman: your own OAuth client, once

A Pointman with no shared client (its core says it has none) signs in with a client of yours, before the first
`/gmail add`:

1. In [Google Cloud console](https://console.cloud.google.com/), in a project of yours:
   - APIs & Services › Library: turn on the **Gmail API**.
   - OAuth consent screen: add the scopes above, and publish it **In production** (or make it **Internal** for a
     Google Workspace organisation). While it's in Testing, Google's refresh tokens run out after 7 days.
   - Credentials › Create OAuth client ID › **Web application**, with the authorised redirect URI
     `https://<your Pointman>/oauth/callback`: your core's own callback, not the shared client's.

   gcal can use the same client: each sign-in asks only for its own extension's scopes.
2. **`/gmail client`** in the app: paste the client's ID, a space, then its secret.

An account is refreshed with the client that signed it in, so accounts signed in before a Pointman had a shared client
keep using `gmail.client`.

## The commands

| Command | What it does |
|---|---|
| `gmail.accounts {}` | Each account's label and address, and whether its sign-in works |
| `gmail.search {query, account?, limit?}` | Messages matching a Gmail search, newest first, from every account unless one is named |
| `gmail.read {id, account?}` | One message: headers, its text (`body`), attachments' names |
| `gmail.draft {to, cc?, subject, body, reply_to?, account?}` | A draft, nothing sent; `reply_to` puts it in the message's thread |
| `gmail.send {draft \| to, cc?, subject, body, account?}` | Sends a draft or a new message, at once |
| `/gmail add`, `/gmail client` | Open the forms for an account's sign-in and for a self-hosted Pointman's OAuth client, in the app |

**Which account.** A call may name one with `account`; the `account` setting is the default. With neither, a read uses
every account signed in and says which each result came from, and a write uses the only one, or stops and lists them.

## Develop

`cargo test` runs the commands under the SDK's stand-in node against a fake Google on a local port (`tests/common`):
no real account is called. Change a command's params in the proto, then `pointman-extension manifest write` to write
extension.toml's schemas again; `tests/manifest.rs` fails while they differ. A release is a tag that's
extension.toml's version (`git tag v0.1.0 && git push origin v0.1.0`): `release.yml` builds each platform.
