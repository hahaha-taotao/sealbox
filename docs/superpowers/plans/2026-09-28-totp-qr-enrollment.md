# TOTP 二维码与 URI 登记实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用户可在本机导入网站提供的 TOTP 二维码或 `otpauth://` URI，确认后安全关联至 Sealbox 网站凭据，之后继续使用现有自动填码流程。

**Architecture:** Rust/Tauri 独占 URI/二维码解析、TOTP 密钥暂存与金库写入；Vue 只接收 issuer/account 等非敏感预览元数据和不透明短时句柄。短时句柄绑定已解锁会话，确认时一次性消费并通过既有加密 upsert 写入；同时收窄网站凭据 reveal/edit 路径，避免已保存 TOTP 密钥回到 Vue。二维码解码采用 `rqrr` 与禁用默认格式的 `image`（仅 PNG/JPEG），在读取和解码前限制字节、宽高、总像素。

**Tech Stack:** Tauri 2、Vue 3、Rust、现有 `totp-rs` / `normalize_totp_secret`、`rqrr`、`image`、`node --test`、Cargo tests。

**Design:** `docs/superpowers/specs/2026-09-28-browser-otp-enrollment-and-page-detection-design.md` §3.1、§4、§5、§6、§7

---

## File map

| File | Responsibility |
|---|---|
| Modify `src-tauri/Cargo.toml` / `Cargo.lock` | Add QR decoder and PNG/JPEG-only image reader dependencies |
| Create `src-tauri/src/totp_enrollment.rs` | Bounded image decode, QR extraction, URI metadata parsing, short-lived enrollment staging |
| Modify `src-tauri/src/totp.rs` | Expose/reuse strict parser and normalized metadata without relaxing SHA1/6/30 validation |
| Modify `src-tauri/src/commands.rs` | Preview, cancel and one-shot apply TOTP enrollment commands; preserve secrets inside Rust |
| Modify `src-tauri/src/lib.rs` | Declare enrollment module and register commands |
| Modify `src-tauri/src/vault.rs` | Backend-only update/create operations preserving unrelated entry data and encrypting TOTP via existing upsert |
| Modify `src/App.vue` | URI/image import dialog, metadata-only confirmation, target choice and replace confirmation |
| Modify `src/lib/tauri.ts` | Safe preview DTO and command types |
| Modify `src-tauri/src/commands.rs` reveal DTO and `src/App.vue` edit flow | Stop returning saved `totp_secret` into Vue; use `has_totp` metadata and backend preservation |
| Tests | `src-tauri/src/totp_enrollment.rs`, `src-tauri/src/totp.rs`, `src-tauri/src/vault.rs`, command tests, frontend build |

## Task 1: Safe metadata parser and URI validation

**Files:** `src-tauri/src/totp.rs`, `src-tauri/src/totp_enrollment.rs`

- [ ] **Step 1: Add failing tests for metadata extraction**

  Cover a valid `otpauth://totp/Issuer:account?...` URI, percent-encoded issuer/account labels, absent label, missing secret, HOTP, duplicate `secret`/`issuer` parameters, malformed percent escapes, invalid Base32 and unsupported `algorithm`, `digits`, and `period`. Assert errors and serialized preview DTO never contain the secret or full URI.

- [ ] **Step 2: Run the narrow test and confirm it fails**

  Run `cargo test --manifest-path src-tauri/Cargo.toml totp_enrollment::tests --offline`.
  Expected: compile/test failure because metadata parsing and preview DTO are not implemented.

- [ ] **Step 3: Implement strict parser with secret-bearing result private to Rust**

  Introduce a private parsed value containing normalized secret plus safe issuer/account metadata. Use the existing TOTP normalizer for secret and parameter validation. Decode query parameters with the existing strict percent-decoder. Reject duplicate security-relevant parameters instead of silently taking one. Define a serializable preview type containing only an opaque handle, issuer, account label and fixed algorithm/digits/period metadata; do not derive `Debug` for secret-bearing values.

- [ ] **Step 4: Run the narrow tests**

  Re-run the command above. Expected: all parser and secret-redaction tests pass.

- [ ] **Step 5: Commit**

  Commit only parser, tests and dependencies touched by this task using `feat(totp): parse enrollment URI metadata safely`.

## Task 2: Bounded local QR image decoder

**Files:** `src-tauri/Cargo.toml`, `src-tauri/Cargo.lock`, `src-tauri/src/totp_enrollment.rs`

- [ ] **Step 1: Add failing decoder tests**

  Add a synthetic QR fixture encoding a valid TOTP URI plus tests for corrupt bytes, unsupported image signature, no QR, multiple QR payloads, malformed URI payload, byte-size overflow, dimension overflow and total-pixel overflow. Use a test-only generated fixture; do not check in real account QR images.

- [ ] **Step 2: Set explicit decode limits and minimal crate features**

  Add `rqrr` and `image` with default features disabled and only PNG/JPEG enabled. Set `MAX_QR_IMAGE_BYTES = 5 MiB`, `MAX_QR_IMAGE_WIDTH = 4096`, `MAX_QR_IMAGE_HEIGHT = 4096`, and `MAX_QR_IMAGE_PIXELS = 16_000_000`. Confirm the selected crate versions are compatible with the repository Rust toolchain and Windows MSVC target before locking them.

- [ ] **Step 3: Decode one QR locally**

  Read only a validated absolute path, reject oversized metadata before reading, sniff/decode by content rather than filename extension, enforce dimensions before allocating a pixel buffer, convert to grayscale, run `rqrr`, and require exactly one decodable QR payload. Feed that payload to the same strict URI parser from Task 1. Never log file bytes, URI, parser payload, or secret.

- [ ] **Step 4: Run decoder tests**

  Run `cargo test --manifest-path src-tauri/Cargo.toml totp_enrollment::tests --offline`.
  Expected: valid fixture produces safe metadata and opaque handle; all malformed/oversized/ambiguous fixtures fail closed.

- [ ] **Step 5: Commit**

  Commit QR decoder and fixture tests with `feat(totp): decode bounded local enrollment QR images`.

## Task 3: Rust-only staged secret lifecycle

**Files:** `src-tauri/src/totp_enrollment.rs`, `src-tauri/src/commands.rs`, `src-tauri/src/lib.rs`

- [ ] **Step 1: Add failing lifecycle tests**

  Test that a URI or image preview returns metadata plus an opaque random handle but no secret; handles expire after 5 minutes, are single-use, are bound to the current unlocked session generation, and are cleared on cancel, lock/unlock generation change, successful consume and parse failure. Verify stale/unknown handles cannot write entries.

- [ ] **Step 2: Implement staging store and Tauri commands**

  Keep staged secrets in a Rust-owned `Mutex<HashMap<Handle, StagedTotp>>` in `AppState` or a dedicated managed service. `StagedTotp` stores normalized secret and safe metadata with creation time/session generation; serialize neither the type nor the secret. Add commands `totp_enrollment_preview_uri`, `totp_enrollment_preview_image`, `totp_enrollment_cancel`, and a one-shot apply command. All require an unlocked session. Apply consumes the handle before attempting persistence; any error drops and zeroizes the staged secret where supported.

- [ ] **Step 3: Run command/lifecycle tests**

  Run `cargo test --manifest-path src-tauri/Cargo.toml totp_enrollment --offline`.
  Expected: no preview or error JSON contains normalized secret or original URI; stale handle cannot be reused.

- [ ] **Step 4: Commit**

  Commit staging lifecycle and commands with `feat(totp): stage enrollment secrets in the backend`.

## Task 4: Backend-only attach to existing or new website entry

**Files:** `src-tauri/src/vault.rs`, `src-tauri/src/commands.rs`, related tests

- [ ] **Step 1: Add failing tests for attach/replace semantics**

  Test attaching staged TOTP to an existing website entry preserves its id, username, password, notes, URL, tags, folder and flags; replacing an existing TOTP requires an explicit `replace=true`; `replace=false` leaves it unchanged; new entry creation requires explicit website metadata and stores the secret encrypted; invalid/consumed handle causes no write.

- [ ] **Step 2: Implement one-shot apply operation**

  In Rust, retrieve existing Website payload without serializing it to Vue, replace only `totp_secret`, and call `Vault::upsert_entry` so normalization/encryption and `has_totp` remain centralized. For new entries, accept title, URL, username and optional password from user-entered metadata, and keep staged secret in Rust. Reject non-website target IDs.

- [ ] **Step 3: Remove the existing reveal-to-Vue TOTP leak**

  Change website reveal DTO to expose password and `has_totp` but not `totp_secret`; ensure edit UI does not assign a secret string to Vue state. When saving an edited website, preserve the existing secret in Rust if the request omits it; removal and replacement go through explicit backend TOTP commands. Add tests asserting reveal JSON never contains `totp_secret` or the Base32 test value.

- [ ] **Step 4: Run focused backend tests**

  Run `cargo test --manifest-path src-tauri/Cargo.toml totp_enrollment --offline` and `cargo test --manifest-path src-tauri/Cargo.toml fill::tests --offline`.
  Expected: attach/replace and existing fill tests pass; serialized reveal never returns the TOTP secret.

- [ ] **Step 5: Commit**

  Commit backend vault and DTO changes with `fix(security): keep TOTP secrets inside the vault backend`.

## Task 5: Desktop import and confirmation UI

**Files:** `src/App.vue`, `src/lib/tauri.ts`, `src-tauri/src/commands.rs`

- [ ] **Step 1: Add typed safe preview API**

  Define `TotpEnrollmentPreview` with `handle`, `issuer`, `account`, fixed algorithm/digits/period, and no `secret` or `uri` property. Add API wrappers for URI preview, image preview, cancel, and apply.

- [ ] **Step 2: Add file picker and paste entry points**

  In website credential create/edit UI add “导入 TOTP” with two choices: “选择二维码图片” (PNG/JPEG) and “粘贴 otpauth URI”. Use existing `@tauri-apps/plugin-dialog` pattern for image selection. Pass only path/URI to local Tauri commands; clear URI form state after cancel, failure or success.

- [ ] **Step 3: Add metadata confirmation and destination selection**

  Show issuer/account and target existing entry or new website entry fields; if target already has TOTP, require an explicit replacement checkbox/confirmation. Never show the secret, full URI, QR payload or secret-bearing errors. The final confirmation invokes the one-shot Rust apply command.

- [ ] **Step 4: Run UI validation**

  Run `npm run build` and `cargo test --manifest-path src-tauri/Cargo.toml totp_enrollment --offline`.
  Expected: Vue type check/build passes and the backend still enforces all invariants regardless of UI.

- [ ] **Step 5: Commit**

  Commit UI/API changes with `feat(ui): add local TOTP enrollment flow`.

## Task 6: Full validation and documentation

**Files:** `README.md`, test files as needed

- [ ] **Step 1: Document safe enrollment flow**

  Explain that user obtains the QR/URI from the service’s own 2FA setup screen, imports it locally once, confirms the intended entry, and can then rely on automatic TOTP fill. State explicitly that Sealbox cannot derive the secret from an OTP value and does not read SMS/email.

- [ ] **Step 2: Run release validations**

  Run `node scripts/check-version.mjs v0.2.0`, `cargo test --manifest-path src-tauri/Cargo.toml --offline`, `node --test extension/fill-logic.test.js`, `npm run build`, and `git -c core.whitespace=cr-at-eol diff --check`.
  Expected: all pass; no change to extension permissions or remote services.

- [ ] **Step 3: Commit docs/tests**

  Commit with `docs(totp): document local TOTP enrollment`.

## Acceptance criteria

- TOTP enrollment QR/URI is processed locally and the secret remains backend-only until encrypted storage.
- Existing entry fields are preserved; replacing/removing TOTP is explicit.
- Existing edit/reveal UI no longer serializes the TOTP secret into Vue.
- Unsupported/malformed QR/URI and bounded-resource violations fail without modifying the vault.
- Current browser fill behavior and all project checks remain green.
