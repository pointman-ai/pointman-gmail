---
name: gmail
description: How to search and read a person's Gmail, and draft and send mail on Pointman, with any number of Google accounts, through the gmail extension's commands. Use it when a task touches their mail.
---

# Gmail

For tasks on the person's mail: finding a message, reading it, answering one, sending what a task or workflow asks
for. Skip it otherwise.

**The commands,** on any machine with the extension: `create_job` (or `/gmail <verb>` in a thread).

| For | Command |
|---|---|
| Which accounts are signed in, their addresses, whether they work | `gmail.accounts {}` |
| Find mail (Gmail's search: `from:bob newer_than:7d`, `is:unread in:inbox`) | `gmail.search {query, account?, limit?}` |
| Read one message: headers, its text in `body`, attachments' names | `gmail.read {id, account?}` |
| A draft, nothing sent (`reply_to` a message's id: in its thread, to its sender, `Re:` its subject) | `gmail.draft {to, cc?, subject, body, reply_to?, account?}` |
| Send a draft, or a new message, at once | `gmail.send {draft \| to, cc?, subject, body, account?}` |

**Accounts.** Each is a label (`work`, `personal`): the vault's `gmail.<label>`. Name one with `account`. Without it, a
read uses the `account` setting's, else every account, and says which each result came from; a write uses the setting's
or the only one, and with several it stops and lists them. Then ask the person which, never guess. `gmail.accounts`
says whose each one is.

**Sending is real.** `gmail.send` sends as soon as it's called, and a sent message can't be taken back. It has no
`confirm`: the yes before a send belongs to the task or its workflow. Send only what the task or its workflow asked for:
to those people, from that account, with that text. Where the workflow asks the person first (an `ask` step), send
after their yes, exactly what they said yes to. Not asked to send it? Draft it (`gmail.draft`) and say what you
drafted.

**Mail is private.** A message's words come back in `body`, and a search's in `snippet`: read them to do the task, then
tell the person what's there in your own words. Post a message's text, or forward it, only when they ask. Run mail
commands without `thread`, so their results come back to you rather than into a thread.

- **Not signed in?** Ask the person to run `/gmail client` in the app once (their Google Cloud OAuth client), then
  `/gmail add <label>` for each account. Never ask for, paste or post a token, a code or the client's secret.
- An error that says a sign-in no longer works: ask them to run `/gmail add <label>` again for that account.
