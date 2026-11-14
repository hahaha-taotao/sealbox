import { invoke } from "@tauri-apps/api/core";

export type EntryKind =
  | "website"
  | "api_token"
  | "ssh"
  | "mailbox"
  | "mail_auth"
  | "server"
  | "database"
  | "client_cert";

export interface EntryDto {
  id: string;
  kind: EntryKind;
  title: string;
  account: string | null;
  url: string | null;
  folder_id: string | null;
  tags: string[];
  pinned: boolean;
  expires_at: string | null;
  use_count: number;
  last_used_at: string | null;
  updated_at: string;
  has_totp: boolean;
  fingerprint: string | null;
}

export interface EntryField {
  label: string;
  value: string;
}

export interface EntryProfile {
  entry: EntryDto;
  notes: string | null;
  fields: EntryField[];
}

export interface Counts {
  total: number;
  website: number;
  api_token: number;
  ssh: number;
  mailbox: number;
  mail_auth: number;
  server: number;
  database: number;
  client_cert: number;
  trash: number;
}

export interface Status {
  initialized: boolean;
  unlocked: boolean;
  counts: Counts | null;
  biometry_enabled: boolean;
}

export interface Folder {
  id: string;
  name: string;
}

export interface SyncView {
  configured: boolean;
  kind: "webdav" | "s3" | null;
  endpoint: string;
  username: string;
  bucket: string;
  region: string;
  prefix: string;
  has_secret: boolean;
  device_id: string;
  last_sync_at: string | null;
  last_result: string | null;
  auto_sync: boolean;
  auto_sync_secs: number;
  conditional_verified: boolean;
}

export interface SyncConflict { id: string; title: string; kind: 'edit_edit' | 'delete_edit'; local_deleted: boolean; remote_deleted: boolean }
export interface SyncPreview { token: string; expires_in_secs: number; report: SyncReport }
export interface SyncReport {
  phase?: 'preview' | 'conflicts' | 'committed' | 'local_pending' | 'blocked';
  blocked?: string | null;
  retryable?: boolean;
  conflict_details?: SyncConflict[];
  pulled: number;
  pushed: number;
  unchanged: number;
  removed: number;
  conflicts: string[];
  remote_missing: boolean;
}

export interface SettingsView {
  clipboard_secs: number;
  biometry_enabled: boolean;
}

export interface MobileRelease {
  current_version: string;
  latest_version: string;
  published_at: string | null;
  notes: string | null;
  release_url: string;
  download_url: string;
  asset_name: string;
  asset_size: number;
  update_available: boolean;
}

export interface UpdateDownload {
  path: string;
  bytes: number;
}

export const KINDS: { id: EntryKind; label: string; count: keyof Counts }[] = [
  { id: "website", label: "网站", count: "website" },
  { id: "api_token", label: "Token", count: "api_token" },
  { id: "ssh", label: "SSH", count: "ssh" },
  { id: "mailbox", label: "邮箱", count: "mailbox" },
  { id: "mail_auth", label: "授权码", count: "mail_auth" },
  { id: "server", label: "服务器", count: "server" },
  { id: "database", label: "数据库", count: "database" },
  { id: "client_cert", label: "证书", count: "client_cert" },
];

export function kindLabel(kind: EntryKind) {
  return (
    {
      website: "网站账号",
      api_token: "API Token",
      ssh: "SSH",
      mailbox: "邮箱",
      mail_auth: "邮箱授权码",
      server: "服务器",
      database: "数据库",
      client_cert: "客户端证书",
    } as const
  )[kind];
}

export interface BackupSummary { version: number; entries: number; trash: number; folders: number; tags: number; tombstones: number; includes_settings: boolean; warnings: string[] }
export interface BackupPreview { token: string; summary: BackupSummary }
export interface CsvPreview { token: string; summary: { format: string; total: number; importable: number; skipped_existing: number; skipped_invalid: number; sample: { title: string; url: string; username: string; has_password: boolean; has_totp: boolean }[] } }
export interface DocumentRef { uri: string; name: string }

export interface MailAccount {
  id: string;
  title: string;
  email: string;
  provider: string;
  providerLabel: string;
  supported: boolean;
}

export interface MailFolder {
  name: string;
  /** inbox / sent / drafts / archive / trash / other. */
  role: string;
  display: string;
  unread: number;
}

export type MailFilter = "all" | "unread" | "attached" | "flagged";

export interface MailMessage {
  uid: number;
  from: string;
  subject: string;
  date: string;
  hasAttachment: boolean;
  seen: boolean;
  flagged: boolean;
  /** 缓存里的正文摘要，只有本地缓存会填。 */
  preview?: string;
}

/** 各角色未读数，统一口径；侧栏角标只算 inbox + archive。 */
export interface MailUnreadByRole {
  inbox: number;
  archive: number;
  sent: number;
  drafts: number;
  trash: number;
  other: number;
}

/** `cached` 表示这次列表直接来自本地缓存，`fetchedAt` 是缓存的更新时间（ISO-8601）。 */
export interface MailListResult {
  messages: MailMessage[];
  cached: boolean;
  fetchedAt: string | null;
}

/** `mail_list` 目前直接返回一排消息，缓存状态由后端补 `{ messages, cached, fetchedAt }`；两种都认。 */
export type MailListPayload = MailMessage[] | MailListResult;

export function normalizeMailList(payload: MailListPayload | null | undefined): MailListResult {
  if (Array.isArray(payload)) return { messages: payload, cached: false, fetchedAt: null };
  if (payload === null || typeof payload !== "object") return { messages: [], cached: false, fetchedAt: null };
  return {
    messages: Array.isArray(payload.messages) ? payload.messages : [],
    cached: payload.cached === true,
    fetchedAt: typeof payload.fetchedAt === "string" ? payload.fetchedAt : null,
  };
}

export interface MailBody {
  text: string;
  html: string | null;
  truncated: boolean;
}

export interface MailAttachment {
  part: string;
  filename: string;
  mime: string;
  size: number | null;
}

export interface MailProbeReport {
  host: string;
  port: number;
  folders: MailFolder[];
  unread: number;
}

export interface MailDiscoveredServer {
  host: string;
  port: number;
  /** preset / autoconfig / guess. */
  source: string;
}

export const api = {
  documentOpen: (mimeTypes: string[]) => invoke<DocumentRef | null>("document_open", { mimeTypes }),
  documentSave: (suggestedName: string, mime: string) => invoke<DocumentRef | null>("document_save", { suggestedName, mime }),
  backupInspect: (uri: string, backupPassword: string) => invoke<BackupPreview>("backup_inspect", { uri, backupPassword }),
  backupRestore: (token: string, overwrite: boolean, restoreSettings: boolean) => invoke<{ imported: number; skipped: number }>("backup_restore", { token, overwrite, restoreSettings }),
  backupRestoreNew: (token: string, newPassword: string | null, restoreSettings: boolean) => invoke<{ imported: number; skipped: number }>("backup_restore_new", { token, newPassword, restoreSettings }),
  backupExport: (uri: string, password: string, includeSettings: boolean) => invoke("backup_export", { uri, password, includeSettings }),
  csvPreview: (uri: string) => invoke<CsvPreview>("csv_preview", { uri }),
  csvCommit: (token: string, password: string, riskConfirmed: boolean, overwrite: boolean) => invoke<{ inserted: number; updated: number; skipped_existing: number; skipped_invalid: number }>("csv_commit", { token, password, riskConfirmed, overwrite }),
  csvExport: (uri: string, password: string, riskConfirmed: boolean) => invoke("csv_export", { uri, password, riskConfirmed }),
  renameFolder: (id: string, name: string) => invoke("rename_folder", { id, name }),
  mergeFolders: (sourceId: string, targetId: string) => invoke("merge_folders", { sourceId, targetId }),
  renameTag: (oldName: string, newName: string) => invoke("rename_tag", { oldName, newName }),
  deleteTag: (name: string) => invoke("delete_tag", { name }),
  mergeTags: (sourceName: string, targetName: string) => invoke("merge_tags", { sourceName, targetName }),
  importClientCert: (input: Record<string, unknown>, certUri: string | null, keyUri: string | null, passphrase: string | null) => invoke<EntryDto>("import_client_cert", { input, certUri, keyUri, passphrase }),
  status: () => invoke<Status>("get_status"),
  setup: (password: string) => invoke("setup_vault", { password }),
  unlock: (password: string) => invoke("unlock_vault", { password }),
  unlockDek: (dekB64: string) => invoke("unlock_with_dek", { dekB64 }),
  exportDek: () => invoke<string>("export_dek"),
  setBiometry: (enabled: boolean) => invoke("set_biometry_enabled", { enabled }),
  entries: (filter: Record<string, unknown>) => invoke<EntryDto[]>("list_entries", { filter }),
  counts: (filter: Record<string, unknown>) => invoke<Counts>("list_counts", { filter }),
  folders: () => invoke<Folder[]>("list_folders"),
  createFolder: (name: string) => invoke<Folder>("create_folder", { name }),
  deleteFolder: (id: string) => invoke<number>("delete_folder", { id }),
  tags: () => invoke<string[]>("list_tags"),
  save: (input: Record<string, unknown>) => invoke<EntryDto>("create_entry", { input }),
  remove: (ids: string[]) => invoke<number>("delete_entries", { ids }),
  restore: (ids: string[]) => invoke<number>("restore_entries", { ids }),
  emptyTrash: () => invoke<number>("empty_trash"),
  pin: (id: string, pinned: boolean) => invoke("pin_entry", { id, pinned }),
  copy: (id: string, field: string) => invoke("copy_secret", { id, field }),
  reveal: (id: string) => invoke<Record<string, unknown>>("reveal_secret", { id }),
  notes: (id: string) => invoke<string | null>("get_notes", { id }),
  profile: (id: string) => invoke<EntryProfile>("entry_profile", { id }),
  settings: () => invoke<SettingsView>("settings_get"),
  saveSettings: (clipboardSecs: number) =>
    invoke("settings_set", { clipboardSecs }),
  syncStatus: () => invoke<SyncView>("sync_status"),
  syncSave: (input: Record<string, unknown>) => invoke<SyncView>("sync_save", { input }),
  syncClear: () => invoke("sync_clear"),
  changeMaster: (oldPassword: string, newPassword: string) => invoke<void>('change_master', { oldPassword, newPassword }),
  syncPreview: () => invoke<SyncPreview>('sync_preview'),
  syncCommit: (token: string, resolutions: { id: string; choice: string; confirm_delete_edit: boolean }[]) => invoke<SyncReport>('sync_commit', { token, resolutions }),
  syncVerifyConditional: () => invoke<{ verified: boolean; probe_cleaned: boolean; scope: string }>('sync_verify_conditional'),
  syncNow: () => invoke<SyncReport>("sync_now"),
  mailAccounts: () => invoke<MailAccount[]>("mail_accounts"),
  mailFolders: (entryId: string, refresh = false) => invoke<MailFolder[]>("mail_folders", { request: { entryId, refresh } }),
  /** 缓存优先：可能先返回本地缓存、随后后台刷新再返回一次。 */
  mailList: (entryId: string, folder: string, options: { beforeUid?: number; filter?: MailFilter; keyword?: string } = {}) =>
    invoke<MailListPayload>("mail_list", {
      request: { entryId, folder, beforeUid: options.beforeUid ?? null, filter: options.filter ?? "all", keyword: options.keyword ?? "" },
    }),
  /** markSeen 只在本地记已读，不回写服务器。 */
  mailBody: (entryId: string, uid: number, folder: string, options: { markSeen?: boolean } = {}) =>
    invoke<MailBody>("mail_body", { request: { entryId, uid, folder, markSeen: options.markSeen === true } }),
  /** 静默预热正文缓存，返回实际拉取的封数。 */
  mailPrefetch: (entryId: string, folder: string, limit = 5) =>
    invoke<number>("mail_prefetch", { request: { entryId, folder, limit } }),
  mailUnreadByRole: () => invoke<MailUnreadByRole>("mail_unread_by_role"),
  mailAttachments: (entryId: string, uid: number, folder: string) =>
    invoke<MailAttachment[]>("mail_attachments", { request: { entryId, uid, folder } }),
  mailSaveAttachment: (entryId: string, uid: number, part: string, uri: string, folder: string) =>
    invoke<number>("mail_save_attachment", { request: { entryId, uid, part, path: uri, folder } }),
  mailDiscover: (email: string) => invoke<MailDiscoveredServer>("mail_discover", { request: { email } }),
  mailTest: (request: { entryId?: string | null; email?: string; secret?: string; imapHost?: string | null; imapPort?: number | null }) =>
    invoke<MailProbeReport>("mail_test", { request }),
  mailSync: () => invoke<number>("mail_sync"),
  mailUnreadCount: () => invoke<number>("mail_unread_count"),
  appVersion: () => invoke<string>("app_version"),
  checkUpdate: () => invoke<MobileRelease>("check_mobile_update"),
  downloadUpdate: (url: string) => invoke<UpdateDownload>("download_mobile_update", { url }),
  installUpdate: (path: string) => invoke("install_mobile_update", { path }),
};
