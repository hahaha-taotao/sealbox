import { invoke } from "@tauri-apps/api/core";

export type EntryKind = "website" | "api_token" | "ssh" | "mailbox" | "mail_auth" | "server" | "database";

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

export interface ListFilter {
  query?: string | null;
  kind?: EntryKind | null;
  folder_id?: string | null;
  uncategorized?: boolean;
  tag?: string | null;
  trash?: boolean;
  sort?: "use_count" | "updated" | "title";
}

export interface FolderDto {
  id: string;
  name: string;
}

export interface AuditEvent {
  id: string;
  at: string;
  action: string;
  entry_id: string | null;
  detail: string;
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
  trash: number;
}

export interface Status {
  initialized: boolean;
  unlocked: boolean;
  hello_enabled: boolean;
  hello_available: boolean;
  counts: Counts | null;
}

export interface McpStatus {
  running: boolean;
  port: number;
  url: string;
  fill_url: string;
  has_token: boolean;
  has_fill_token: boolean;
}

export type SecretPayload =
  | { type: "website"; url?: string | null; username?: string | null; password: string; totp_secret?: string | null }
  | { type: "api_token"; service: string; account?: string | null; token: string }
  | { type: "ssh"; key_type: string; private_key: string; passphrase?: string | null; public_fingerprint?: string | null }
  | {
      type: "mailbox";
      email: string;
      password: string;
      imap_host?: string | null;
      imap_port?: number | null;
      smtp_host?: string | null;
      smtp_port?: number | null;
    }
  | { type: "mail_auth"; email: string; provider: string; auth_code: string }
  | { type: "server"; host: string; port?: number | null; protocol: string; username: string; password: string }
  | {
      type: "database";
      engine: string;
      host: string;
      port?: number | null;
      database: string;
      username: string;
      password: string;
    };

export interface UpsertEntry {
  id?: string | null;
  kind: EntryKind;
  title: string;
  account?: string | null;
  url?: string | null;
  folder_id?: string | null;
  tags: string[];
  pinned: boolean;
  expires_at?: string | null;
  notes?: string | null;
  secret: SecretPayload;
}

export const api = {
  status: () => invoke<Status>("get_status"),
  setup: (password: string) => invoke("setup_vault", { password }),
  unlock: (password: string) => invoke("unlock_vault", { password }),
  unlockHello: () => invoke("unlock_hello"),
  lock: () => invoke("lock_vault"),
  list: (filter: ListFilter) => invoke<EntryDto[]>("list_entries", { filter }),
  create: (input: UpsertEntry) => invoke<EntryDto>("create_entry", { input }),
  remove: (ids: string[]) => invoke<number>("delete_entries", { ids }),
  restore: (ids: string[]) => invoke<number>("restore_entries", { ids }),
  emptyTrash: () => invoke<number>("empty_trash"),
  pin: (id: string, pinned: boolean) => invoke("pin_entry", { id, pinned }),
  folders: () => invoke<FolderDto[]>("list_folders"),
  createFolder: (name: string) => invoke<FolderDto>("create_folder", { name }),
  tags: () => invoke<string[]>("list_tags"),
  audit: () => invoke<AuditEvent[]>("list_audit"),
  copy: (id: string, field: string) => invoke("copy_secret", { id, field }),
  reveal: (id: string) => invoke<SecretPayload>("reveal_secret", { id }),
  notes: (id: string) => invoke<string | null>("get_notes", { id }),
  tick: () => invoke<boolean>("tick_idle"),
  genPassword: (opts: {
    mode?: "password" | "passphrase";
    length?: number;
    upper?: boolean;
    lower?: boolean;
    digits?: boolean;
    symbols?: boolean;
    ensureEach?: boolean;
    wordCount?: number;
    separator?: string;
  }) => invoke<string>("gen_password", { opts }),
  exportBackup: (password: string, path: string) => invoke("export_backup", { password, path }),
  importBackup: (password: string, path: string, overwrite: boolean) =>
    invoke<[number, number]>("import_backup", { password, path, overwrite }),
  settingsGet: () => invoke<{ idle_secs: number; clipboard_secs: number; hotkey: string }>("settings_get"),
  settingsSet: (settings: { idle_secs: number; clipboard_secs: number; hotkey: string }) =>
    invoke("settings_set", { settings }),
  setHello: (enabled: boolean) => invoke("set_hello_enabled", { enabled }),
  changeMaster: (oldPassword: string, newPassword: string) =>
    invoke("change_master", { oldPassword, newPassword }),
  window: (action: string) => invoke("window_control", { action }),
  home: () =>
    invoke<{ counts: Counts; recent: EntryDto[]; expiring: EntryDto[] }>("home_overview"),
  mcpStatus: () => invoke<McpStatus>("mcp_status"),
  mcpStart: () => invoke<McpStatus>("mcp_start"),
  mcpStop: () => invoke<McpStatus>("mcp_stop"),
  mcpRotate: () => invoke<McpStatus>("mcp_rotate_token"),
  fillRotate: () => invoke<McpStatus>("fill_rotate_token"),
  revealMcpToken: () => invoke<string>("reveal_mcp_token"),
  revealFillToken: () => invoke<string>("reveal_fill_token"),
  copyMcpToken: () => invoke("copy_mcp_token"),
  copyFillToken: () => invoke("copy_fill_token"),
  copyMcpSnippet: () => invoke("copy_mcp_snippet"),
  fillOpenPairing: () =>
    invoke<{ active: boolean; code: string | null; expires_in_secs: number; port: number }>("fill_open_pairing"),
  fillPairingStatus: () =>
    invoke<{ active: boolean; code: string | null; expires_in_secs: number; port: number }>("fill_pairing_status"),
  mcpTools: () => invoke<{ name: string; description: string }[]>("mcp_tools"),
  mcpHttpLogs: () =>
    invoke<
      {
        id: string;
        at: string;
        credential_id: string;
        method: string;
        url: string;
        status: number;
        bytes: number;
        sha256: string;
        body: string;
      }[]
    >("mcp_http_logs"),
};
