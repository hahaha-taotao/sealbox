# Mail command / MCP audit

## Scope

UI commands in both desktop and mobile expose `mail_set_seen` and `mail_delete` only through the Tauri invoke handler. Both accept `{ request: { entryId, uid, folder } }`; marking additionally requires the boolean `seen`. Omitted/blank folder defaults to `INBOX`. Return type is `Result<(), String>` / frontend void.

Both operations explicitly require an unlocked session, resolve the existing mailbox credential and endpoint from the vault, then call the server before changing local cache. They hold the session guard across network and cache commit to prevent another vault/unlock session receiving the result. This serializes other session access during the existing network timeout. UID zero is rejected before networking. Audit contains only action, entry ID, UID, server/cache outcome; it excludes credentials, message contents, raw server errors, folder names and attachment paths. If cache fails after server success, audit still records `server=ok cache=error`; caller receives the cache error rather than a false success.

## Existing MCP capabilities (verified source)

One advertised/callable mail tool already exists, with exactly six actions:

| Action | Capability |
| --- | --- |
| accounts | Vault mailbox metadata, no credential |
| folders | Live server folders / roles |
| list | Live one-folder page, max 50; optional folder, beforeUid, filter, keyword |
| search | Synced local-cache subject/sender search only, across cached folders |
| read | Read-only body and attachment list; optional folder |
| save | Download one attachment into a new file in an existing directory; optional folder, no overwrite |

`filter` already supports all/unread/attached/flagged. `folder` defaults to INBOX for list/read/save. `keyword` already exists for list and search. The root schema is closed and the server separately validates action-specific allowed parameters. Server bounds are retained even though advertised schemas remove unsupported bound keywords for host compatibility.

The MCP mailbox is read-only: no send/delete/seen/move action or separate mutation tool is added. `save` does write a local file, so the combined tool deliberately retains `readOnly=false` metadata; this is not permission to write mailbox state.

The server six-tool allowlist and tool catalog already agree on the single name `mail`. The attached client tool schema in this task context only showed accounts/list/read/save and omitted folders/search/filter/folder/keyword: that is a stale client registration compared with server source, not missing server implementation. Reinitialize/update client discovery to receive the current schema.

## Concrete gaps fixed

- Removed unreachable legacy mail_accounts/mail_list/mail_read/mail_download_attachment internal dispatch and the obsolete MailAuth-only credential loader. The internal dispatcher now matches the external single-mail whitelist too.
- Account-list output redaction collected secrets only for MailAuth while results also included Mailbox entries. It now collects both mailbox credential kinds.
- Local MCP search previously accepted any existing non-mail credential entry ID and returned an empty cache result. It now checks mailbox payload type and zeroizes the temporary payload.

## Concurrent refresh correctness

Core implements delete tombstones, transactionally incremented cache revision, UIDVALIDITY observation/reset, and revision-conditional page upsert. All five network cache page paths pass the observed UIDVALIDITY to the atomic reset/upsert API so a rebuilt server folder can reuse UIDs without old tombstones suppressing new mail. The command layer captures revision before each unlocked-network cold list or sync fetch, then drops stale pages; cold list rereads local state instead of returning stale live rows. Stale sync pages also skip unread persistence, trimming and notification samples. Desktop background page refresh already holds the same session mutex across network and upsert, so explicit writes serialize against it. Body callbacks only apply local-seen when their pre-network revision still matches. Prefetch body caching is UPDATE-only in core and does not resurrect deleted rows.

### Existing freshness limitation

A local cached body hit does not contact the server and therefore does not discover a remote UIDVALIDITY change on its own. Until the next network list/sync observes the new namespace, that local body can reflect the previous namespace. This existing offline-cache behavior is unchanged; newly synchronized pages atomically clear the old namespace as described above. No live mailbox credentials or device interaction were used for this audit.

## Validation

Added tests cover Tauri request parsing / required seen / forbidden extra fields / unlocked-session requirement, advertised read capability schema, all write action rejection, single-tool alias rejection, action-specific parameter validation, and non-mail local-search rejection. Core protocol and tombstone/revision tests are maintained by mail-protocol teammate.

Validation actually run after coordinating the shared Cargo lock:

- `cargo test -p sealbox -p sealbox-mobile mail -- --nocapture`: desktop 7 passed, mobile 2 passed, zero failures.
- `cargo check -p sealbox -p sealbox-mobile --tests`: passed on the host target after the final UIDVALIDITY integration.
- Initial Windows-target check stopped in the `ring` dependency because the host lacks `lib.exe`; it did not reach package checking. The available host target successfully checks both packages instead.
- Core teammate reports the final `cargo test -p sealbox-core`: 214 passed, zero failures.
- Strict `git diff --check` for this task's six Rust files and this document: passed.

Existing unrelated unused-import/dead-code/duplicate-test warnings remain. No package build, installation, commit or push is performed.
