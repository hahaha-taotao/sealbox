import { invoke } from "@tauri-apps/api/core";

export type EntryKind = "website" | "api_token" | "ssh";

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
  trash: number;
}

export interface Status {
  initialized: boolean;
  unlocked: boolean;
  hello_enabled: boolean;
  hello_available: boolean;
  counts: Counts | null;
}

export type SecretPayload =
  | { type: "website"; url?: string | null; username?: string | null; password: string; totp_secret?: string | null }
  | { type: "api_token"; service: string; account?: string | null; token: string }
  | { type: "ssh"; key_type: string; private_key: string; passphrase?: string | null; public_fingerprint?: string | null };

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
  folders: () => invoke<FolderDto[]>("list_folders"),
  createFolder: (name: string) => invoke<FolderDto>("create_folder", { name }),
  tags: () => invoke<string[]>("list_tags"),
  audit: () => invoke<AuditEvent[]>("list_audit"),
  copy: (id: string, field: string) => invoke("copy_secret", { id, field }),
  reveal: (id: string) => invoke<SecretPayload>("reveal_secret", { id }),
  notes: (id: string) => invoke<string | null>("get_notes", { id }),
  tick: () => invoke<boolean>("tick_idle"),
  genPassword: (opts: { length: number; upper: boolean; lower: boolean; digits: boolean; symbols: boolean }) =>
    invoke<string>("gen_password", { opts }),
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
};
