<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from "vue";
import { listen } from "@tauri-apps/api/event";
import { onBackButtonPress } from "@tauri-apps/api/app";
import type { PluginListener } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { authenticate, checkStatus, getData, hasData, removeData, setData } from "@choochmeque/tauri-plugin-biometry-api";
import { KINDS, api, kindLabel, type BackupPreview, type CsvPreview, type DocumentRef, type Counts, type EntryDto, type EntryField, type EntryKind, type Folder, type MobileRelease, type SyncReport, type SyncView } from "./api";
import { DB_ENGINES, SERVER_PROTOCOLS, optionsWithStored, databaseFields, defaultPort } from "../../../src/lib/entry-options";
import { preservePayload } from "../../../src/lib/entry-patch.mjs";
import { completeChoices, buildResolutions, type SyncChoice } from '../../../src/lib/sync-choice.mjs';

type Page = "lock" | "vault" | "detail" | "edit" | "settings" | "sync";
const page = ref<Page>("lock");
const initialized = ref(false);
const biometryOn = ref(false);
const biometryReady = ref(false);
const password = ref("");
const password2 = ref("");
const error = ref("");
const toast = ref("");
let toastTimer: number | undefined;
function showToast(message: string, ms = 1800) {
  toast.value = message;
  if (toastTimer !== undefined) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    toast.value = "";
    toastTimer = undefined;
  }, ms);
}
const counts = ref<Counts | null>(null);
const scopedCounts = ref<Counts | null>(null);
const entries = ref<EntryDto[]>([]);
const folders = ref<Folder[]>([]);
const tags = ref<string[]>([]);
const kind = ref<EntryKind | "">("");
const query = ref("");
const folderId = ref("");
const tag = ref("");
const trash = ref(false);
const uncategorized = ref(false);
const filtersOpen = ref(false);
const selected = ref<EntryDto | null>(null);
const revealed = ref("");
const notes = ref("");
const fields = ref<EntryField[]>([]);
const editing = ref(false);
const form = reactive(blankForm());
let editBaseline: Record<string, unknown> | null = null;
const certDocument = ref<DocumentRef | null>(null);
const keyDocument = ref<DocumentRef | null>(null);
const clearCertPassphrase = ref(false);
const engineOptions = computed(() => optionsWithStored(DB_ENGINES, form.engine));
const protocolOptions = computed(() => optionsWithStored(SERVER_PROTOCOLS, form.protocol));
const dbFields = computed(() => databaseFields(form.engine));
function changeConnectionType() {
  const port = defaultPort(form.kind, form.kind === 'server' ? form.protocol : form.engine);
  if (port !== undefined) form.port = port ? String(port) : '';
}
const management = ref<'' | 'backup-export' | 'backup-restore' | 'csv-import' | 'csv-export' | 'organization' | 'password'>('');
const transferDocument = ref<DocumentRef | null>(null);
const backupPreview = ref<BackupPreview | null>(null);
const csvPreview = ref<CsvPreview | null>(null);
const transferPassword = ref('');
const newMaster = ref('');
const repeatMaster = ref('');
const reuseBackupPassword = ref(true);
const restoreSettings = ref(false);
const includeSettings = ref(false);
const overwrite = ref(false);
const riskConfirmed = ref(false);
const categoryTargets = reactive<Record<string, string>>({});
function clearManagement() {
  management.value = ''; transferDocument.value = null; backupPreview.value = null; csvPreview.value = null;
  transferPassword.value = ''; newMaster.value = ''; repeatMaster.value = ''; riskConfirmed.value = false;
  restoreSettings.value = false; includeSettings.value = false; overwrite.value = false;
}
function openManagement(mode: typeof management.value) { clearManagement(); error.value = ''; management.value = mode; }
function clearEdit() { editBaseline = null; Object.assign(form, blankForm()); certDocument.value = null; keyDocument.value = null; clearCertPassphrase.value = false; }
const sync = ref<SyncView | null>(null);
const report = ref<SyncReport | null>(null);
const syncToken = ref('');
const syncChoices = reactive<Record<string, SyncChoice>>({});
const syncConflicts = computed(() => report.value?.conflict_details ?? []);
const syncCanCommit = computed(() => Boolean(syncToken.value) && completeChoices(syncConflicts.value, syncChoices));
function clearSyncPreview() { syncToken.value = ''; report.value = null; for (const id of Object.keys(syncChoices)) delete syncChoices[id]; }
async function previewSync() {
  clearSyncPreview();
  const result = await api.syncPreview();
  if (page.value === 'lock') return;
  syncToken.value = result.token; report.value = result.report;
  for (const item of syncConflicts.value) syncChoices[item.id] = { choice: '', confirm_delete_edit: false };
}
async function commitSync() {
  if (!syncCanCommit.value || busy.value) return;
  busy.value = true; error.value = '';
  try {
    const result = await api.syncCommit(syncToken.value, buildResolutions(syncConflicts.value, syncChoices));
    syncToken.value = ''; report.value = result; await loadVault(); sync.value = await api.syncStatus();
  } catch (caught) { showError(caught); } finally { busy.value = false; }
}
async function verifySync() {
  busy.value = true;
  try { const result = await api.syncVerifyConditional(); showToast(result.verified ? '安全条件写入已验证' : '服务端未通过安全验证'); }
  catch (caught) { showError(caught); } finally { busy.value = false; }
}
async function changeMaster() {
  if (newMaster.value.length < 10 || newMaster.value !== repeatMaster.value) { error.value = '新主密码至少 10 位，且两次输入必须一致'; return; }
  busy.value = true;
  try {
    await api.changeMaster(transferPassword.value, newMaster.value);
    try { await removeData({ domain: DOMAIN, name: DEK_NAME }); } catch { showToast('请在系统设置中清除旧指纹凭据；本机已禁用指纹', 4000); }
    clearManagement(); clearEdit(); clearSyncPreview(); biometryOn.value = false; biometryReady.value = false;
    page.value = 'lock'; entries.value = []; selected.value = null; fields.value = []; notes.value = ''; revealed.value = '';
    showToast('主密码已修改，请用新主密码解锁');
  } catch (caught) { showError(caught); } finally { transferPassword.value = ''; busy.value = false; }
}
const syncKind = ref<"webdav" | "s3">("webdav");
const syncForm = reactive({ endpoint: "", username: "", secret: "", bucket: "", region: "us-east-1", prefix: "", auto: true, autoSecs: 60 });
const idleSecs = ref(60);
const busy = ref(false);
const appVersion = ref("");
const release = ref<MobileRelease | null>(null);
const updateStage = ref<"idle" | "checking" | "available" | "downloading" | "ready" | "error">("idle");
const updateError = ref("");
const updateCheckedAt = ref("");
const downloadedBytes = ref(0);
const downloadTotal = ref<number | null>(null);
const downloadedPath = ref("");
const updateDialogOpen = ref(false);
let autoUpdateChecked = false;
const updateProgress = computed(() => {
  if (!downloadTotal.value || downloadTotal.value <= 0) return null;
  return Math.min(100, Math.round((downloadedBytes.value / downloadTotal.value) * 100));
});
const aboutUpdateText = computed(() => {
  if (updateStage.value === "checking") return "正在检查更新…";
  if (updateStage.value === "downloading") {
    return updateProgress.value === null ? "正在下载更新…" : `正在下载更新… ${updateProgress.value}%`;
  }
  if (updateStage.value === "ready") return "更新已下载，等待安装";
  if (updateStage.value === "error") return "更新未完成，可重试";
  if (release.value?.update_available) return `发现新版本 v${release.value.latest_version}`;
  if (updateCheckedAt.value) return `已是最新版本 · ${updateCheckedAt.value} 检查`;
  return "从 GitHub Releases 检查";
});
const aboutUpdateAction = computed(() => {
  if (updateStage.value === "checking") return "检查中…";
  return release.value?.update_available || updateStage.value === "downloading" || updateStage.value === "ready"
    ? "查看更新"
    : "检查更新";
});

let backListener: PluginListener | null = null;
let backQueue: Promise<void> = Promise.resolve();

function canGoBackInApp() {
  if (management.value) return true;
  if (page.value === "vault") return filtersOpen.value;
  return page.value === "detail" || page.value === "edit" || page.value === "settings" || page.value === "sync";
}

function goBack() {
  if (management.value) { clearManagement(); return; }
  if (page.value === 'edit') clearEdit();
  switch (page.value) {
    case "detail":
      page.value = "vault";
      break;
    case "edit":
      page.value = editing.value ? "detail" : "vault";
      break;
    case "sync":
      page.value = "settings";
      break;
    case "settings":
      page.value = "vault";
      break;
    case "vault":
      filtersOpen.value = false;
      break;
  }
}

function syncBackListener() {
  backQueue = backQueue
    .then(async () => {
      const wanted = canGoBackInApp();
      if (wanted === Boolean(backListener)) return;
      if (wanted) {
        backListener = await onBackButtonPress(() => {
          if (canGoBackInApp()) goBack();
        });
        return;
      }
      const listener = backListener;
      backListener = null;
      await listener?.unregister();
    })
    .catch(() => {});
}

watch([page, filtersOpen, management], syncBackListener);

const DOMAIN = "com.sealbox.mobile";
const DEK_NAME = "vault-dek";

function blankForm() {
  return {
    id: "" as string | undefined,
    kind: "website" as EntryKind,
    title: "",
    account: "",
    url: "",
    password: "",
    token: "",
    service: "",
    privateKey: "",
    passphrase: "",
    email: "",
    provider: "",
    authCode: "",
    host: "",
    port: "",
    protocol: "ssh",
    engine: "postgres",
    database: "",
    username: "",
    totp: "",
    certPem: "",
    keyPem: "",
    folderId: "",
    tags: "",
    notes: "",
    pinned: false,
    expiresAt: '',
  };
}

const visible = computed(() =>
  kind.value ? entries.value.filter((row) => row.kind === kind.value) : entries.value,
);

let queryTimer: number | undefined;
function clearQueryTimer() {
  if (queryTimer !== undefined) {
    window.clearTimeout(queryTimer);
    queryTimer = undefined;
  }
}
watch(query, () => {
  clearQueryTimer();
  if (page.value === "lock") return;
  queryTimer = window.setTimeout(() => {
    queryTimer = undefined;
    void loadVault().catch(showError);
  }, 200);
});

function showError(caught: unknown) {
  error.value = caught instanceof Error ? caught.message : String(caught);
}

async function refreshStatus() {
  const status = await api.status();
  initialized.value = status.initialized;
  biometryOn.value = status.biometry_enabled;
  counts.value = status.counts;
  if (!status.unlocked && page.value !== "lock") page.value = "lock";
  if (!status.unlocked) updateDialogOpen.value = false;
  biometryReady.value = false;
  if (status.biometry_enabled && !status.unlocked) {
    try {
      const available = await checkStatus();
      const stored = await hasData({ domain: DOMAIN, name: DEK_NAME });
      biometryReady.value = Boolean(available.isAvailable && stored);
    } catch {
      biometryReady.value = false;
    }
  }
}

let loadSeq = 0;
async function loadVault() {
  clearQueryTimer();
  const seq = ++loadSeq;
  const scope = {
    query: query.value.trim() || null,
    folder_id: folderId.value || null,
    uncategorized: uncategorized.value,
    tag: tag.value || null,
    trash: trash.value,
    sort: "updated",
  };
  const [rows, folderRows, tagRows, countRows, scopedCountRows] = await Promise.all([
    api.entries(scope),
    api.folders(),
    api.tags(),
    api.counts({}),
    api.counts(scope),
  ]);
  if (seq !== loadSeq) return;
  entries.value = rows;
  folders.value = folderRows;
  tags.value = tagRows;
  counts.value = countRows;
  scopedCounts.value = scopedCountRows;
}

async function openVault() {
  page.value = "vault";
  void autoCheckUpdate();
  await loadVault();
}

async function submitPassword() {
  error.value = "";
  busy.value = true;
  try {
    if (!initialized.value) {
      if (password.value.length < 10) throw new Error('主密码至少 10 位');
      if (password.value !== password2.value) throw new Error("两次主密码不一致");
      await api.setup(password.value);
    } else {
      await api.unlock(password.value);
    }
    password.value = "";
    password2.value = "";
    await openVault();
  } catch (caught) {
    showError(caught);
  } finally {
    busy.value = false;
  }
}

async function unlockFingerprint() {
  error.value = "";
  try {
    const stored = await getData({
      domain: DOMAIN,
      name: DEK_NAME,
      reason: "用指纹打开印盒",
      cancelTitle: "取消",
    });
    await api.unlockDek(stored.data);
    await openVault();
  } catch (caught) {
    showError(caught);
  }
}

async function toggleBiometry() {
  error.value = "";
  try {
    if (biometryOn.value) {
      await removeData({ domain: DOMAIN, name: DEK_NAME });
      await api.setBiometry(false);
      biometryOn.value = false;
      showToast("指纹解锁已关闭");
      return;
    }
    await authenticate("确认后启用指纹解锁", {
      title: "启用指纹",
      cancelTitle: "取消",
      allowDeviceCredential: false,
      confirmationRequired: false,
    });
    const dek = await api.exportDek();
    await setData({ domain: DOMAIN, name: DEK_NAME, data: dek });
    await api.setBiometry(true);
    biometryOn.value = true;
    showToast("指纹解锁已打开，只在这台手机生效");
  } catch (caught) {
    showError(caught);
  }
}

async function openDetail(row: EntryDto) {
  selected.value = row;
  revealed.value = "";
  fields.value = [];
  notes.value = "";
  page.value = "detail";
  try {
    const profile = await api.profile(row.id);
    if (selected.value?.id !== row.id) return;
    selected.value = profile.entry;
    fields.value = profile.fields;
    notes.value = profile.notes ?? "";
  } catch (caught) {
    showError(caught);
  }
}

async function reveal() {
  if (!selected.value) return;
  const payload = await api.reveal(selected.value.id);
  revealed.value = String(payload.password ?? payload.token ?? payload.private_key ?? payload.auth_code ?? "");
}

async function copy(field: string) {
  if (!selected.value) return;
  await api.copy(selected.value.id, field);
  showToast("已复制，约 20 秒后清空剪贴板", 1600);
}

function startCreate(next: EntryKind) {
  clearEdit();
  form.kind = next;
  editing.value = false;
  page.value = "edit";
}

async function startEdit() {
  if (!selected.value) return;
  const row = selected.value;
  clearEdit();
  form.id = row.id;
  form.kind = row.kind;
  form.title = row.title;
  form.account = row.account ?? "";
  form.url = row.url ?? "";
  form.folderId = row.folder_id ?? "";
  form.tags = row.tags.join(", ");
  form.notes = notes.value;
  form.pinned = row.pinned;
  form.expiresAt = row.expires_at ?? '';
  if (row.kind !== "client_cert") {
    const payload = await api.reveal(row.id);
    if (page.value === 'lock' || selected.value?.id !== row.id) return;
    editBaseline = { ...payload };
    fillFromPayload(payload);
  }
  editing.value = true;
  page.value = "edit";
}

function fillFromPayload(payload: Record<string, unknown>) {
  form.password = String(payload.password ?? "");
  form.token = String(payload.token ?? "");
  form.service = String(payload.service ?? "");
  form.privateKey = String(payload.private_key ?? "");
  form.passphrase = String(payload.passphrase ?? "");
  form.email = String(payload.email ?? "");
  form.provider = String(payload.provider ?? "");
  form.authCode = String(payload.auth_code ?? "");
  form.host = String(payload.host ?? "");
  form.port = payload.port ? String(payload.port) : "";
  form.protocol = String(payload.protocol ?? "ssh");
  form.engine = String(payload.engine ?? "postgres");
  form.database = String(payload.database ?? "");
  form.username = String(payload.username ?? "");
  form.totp = String(payload.totp_secret ?? "");
}

function secretPayload() {
  const changes = visibleSecretPayload();
  return preservePayload(editBaseline, changes);
}
function visibleSecretPayload(): Record<string, unknown> {
  const port = form.port ? Number(form.port) : null;
  switch (form.kind) {
    case "website":
      return { type: "website", url: form.url || null, username: form.account || null, password: form.password, totp_secret: form.totp || null };
    case "api_token":
      return { type: "api_token", service: form.service || form.title, account: form.account || null, token: form.token };
    case "ssh":
      return { type: "ssh", ...(!editBaseline ? { key_type: "openssh", public_fingerprint: null } : {}), private_key: form.privateKey, passphrase: form.passphrase || null };
    case "mailbox":
      return { type: "mailbox", email: form.email, password: form.password, ...(!editBaseline ? { imap_host: null, imap_port: null, smtp_host: null, smtp_port: null } : {}) };
    case "mail_auth":
      return { type: "mail_auth", email: form.email, provider: form.provider, auth_code: form.authCode };
    case "server":
      return { type: "server", host: form.host, port, protocol: form.protocol, username: form.username, password: form.password };
    case "database":
      return { type: "database", engine: form.engine, host: form.host, port, database: form.database, username: form.username, password: form.password };
    case "client_cert":
      return { type: "client_cert", cert_pem: form.certPem, key_pem: form.keyPem, passphrase: form.passphrase || null };
  }
}

async function saveEntry() {
  error.value = "";
  try {
    const input = {
      id: form.id || null,
      kind: form.kind,
      title: form.title,
      account: form.account || form.email || form.username || null,
      url: form.url || null,
      folder_id: form.folderId || null,
      tags: form.tags.split(/[,，]/).map((item) => item.trim()).filter(Boolean),
      pinned: form.pinned,
      expires_at: form.expiresAt || null,
      notes: form.notes || null,
      ...(editing.value ? { expected_updated_at: selected.value?.updated_at } : {}),
    };
    if (form.port && (!Number.isInteger(Number(form.port)) || Number(form.port) < 0 || Number(form.port) > 65535)) throw new Error('端口必须为 0–65535 的整数');
    if (form.kind === 'client_cert' && (!editing.value || certDocument.value || keyDocument.value) && (!certDocument.value || !keyDocument.value)) throw new Error('请选择证书与私钥文件');
    const saved = form.kind === 'client_cert'
      ? await api.importClientCert(input, certDocument.value?.uri ?? null, keyDocument.value?.uri ?? null, clearCertPassphrase.value ? '' : form.passphrase || null)
      : await api.save({ ...input, secret: secretPayload() });
    clearEdit();
    await loadVault();
    await openDetail(saved);
  } catch (caught) {
    showError(caught);
  }
}

async function moveTrash() {
  if (!selected.value) return;
  await api.remove([selected.value.id]);
  await loadVault();
  page.value = "vault";
}

async function restoreSelected() {
  if (!selected.value) return;
  await api.restore([selected.value.id]);
  await loadVault();
  page.value = "vault";
}

async function togglePin() {
  if (!selected.value) return;
  await api.pin(selected.value.id, !selected.value.pinned);
  selected.value.pinned = !selected.value.pinned;
  await loadVault();
}

async function addFolder() {
  const name = window.prompt("文件夹名称");
  if (!name) return;
  const folder = await api.createFolder(name);
  await pickFolder(folder.id);
}

async function chooseCert(which: 'cert' | 'key') {
  try {
    const doc = await api.documentOpen(['application/x-pem-file', 'application/pkix-cert', 'application/octet-stream']);
    if (doc) (which === 'cert' ? certDocument : keyDocument).value = doc;
  } catch (caught) { showError(caught); }
}
async function chooseTransfer() {
  try {
    const doc = await api.documentOpen(management.value === 'csv-import' ? ['text/csv', 'text/plain', 'application/octet-stream'] : ['application/octet-stream']);
    if (!doc) return;
    transferDocument.value = doc; backupPreview.value = null; csvPreview.value = null;
    if (management.value === 'csv-import') csvPreview.value = await api.csvPreview(doc.uri);
  } catch (caught) { showError(caught); }
}
async function inspectBackup() {
  error.value = ''; busy.value = true; backupPreview.value = null;
  try {
    if (!transferDocument.value) throw new Error('请先选择 .svbak 备份');
    backupPreview.value = await api.backupInspect(transferDocument.value.uri, transferPassword.value);
    transferPassword.value = '';
  } catch (caught) { showError(caught); } finally { busy.value = false; }
}
async function runTransfer() {
  error.value = ''; busy.value = true;
  try {
    if (management.value === 'backup-restore') {
      if (!backupPreview.value) throw new Error('请先校验并预览备份');
      if (!initialized.value && !reuseBackupPassword.value && (newMaster.value.length < 10 || newMaster.value !== repeatMaster.value)) throw new Error('新主密码至少 10 位，且两次输入必须一致');
      const result = initialized.value
        ? await api.backupRestore(backupPreview.value.token, overwrite.value, restoreSettings.value)
        : await api.backupRestoreNew(backupPreview.value.token, reuseBackupPassword.value ? null : newMaster.value, restoreSettings.value);
      clearManagement(); await refreshStatus();
      // A restored new vault must be opened with its master password, never an implicit unlocked session.
      if (page.value !== 'lock') await loadVault();
      showToast(`恢复 ${result.imported} 条，跳过 ${result.skipped} 条`);
    } else if (management.value === 'csv-import') {
      if (!csvPreview.value || !riskConfirmed.value || !transferPassword.value) throw new Error('请先预览、输入主密码并确认明文风险');
      const result = await api.csvCommit(csvPreview.value.token, transferPassword.value, riskConfirmed.value, overwrite.value);
      clearManagement(); await loadVault(); showToast(`新增 ${result.inserted}，更新 ${result.updated}，跳过 ${result.skipped_existing + result.skipped_invalid}`);
    } else {
      if (!transferPassword.value || !riskConfirmed.value) throw new Error('请输入主密码并确认导出风险');
      const isCsv = management.value === 'csv-export';
      const doc = await api.documentSave(isCsv ? 'sealbox-websites.csv' : 'sealbox.svbak', isCsv ? 'text/csv' : 'application/octet-stream');
      if (!doc) return;
      if (isCsv) await api.csvExport(doc.uri, transferPassword.value, riskConfirmed.value);
      else await api.backupExport(doc.uri, transferPassword.value, includeSettings.value);
      clearManagement(); showToast('导出完成，请妥善保管文件');
    }
  } catch (caught) { showError(caught); transferPassword.value = ''; }
  finally { busy.value = false; }
}
async function organize(action: 'rename' | 'delete' | 'merge', kind: 'folder' | 'tag', id: string, name: string) {
  try {
    if (action === 'rename') {
      const next = window.prompt('新名称', name)?.trim(); if (!next || next === name) return;
      if (kind === 'folder') await api.renameFolder(id, next); else await api.renameTag(name, next);
    } else {
      const target = categoryTargets[id];
      if (action === 'merge' && (!target || target === id)) throw new Error('请选择不同的合并目标');
      if (!window.confirm(`${action === 'delete' ? '删除分类只解除关联，不会删除条目' : '合并后保留目标分类，条目不会删除'}。操作不可撤销，是否继续？`)) return;
      if (kind === 'folder') {
        if (action === 'delete') await api.deleteFolder(id); else await api.mergeFolders(id, target);
      } else {
        if (action === 'delete') await api.deleteTag(name); else await api.mergeTags(name, target);
      }
    }
    folderId.value = ''; tag.value = ''; await loadVault(); showToast('分类已更新；条目未删除');
  } catch (caught) { showError(caught); }
}

async function pickFolder(id: string) {
  folderId.value = id;
  uncategorized.value = false;
  trash.value = false;
  await loadVault();
}

async function pickUncategorized() {
  folderId.value = "";
  uncategorized.value = true;
  trash.value = false;
  await loadVault();
}

async function toggleTrash() {
  trash.value = !trash.value;
  if (trash.value) {
    folderId.value = "";
    uncategorized.value = false;
  }
  await loadVault();
}

async function openSettings() {
  const settings = await api.settings();
  idleSecs.value = settings.idle_secs;
  biometryOn.value = settings.biometry_enabled;
  page.value = "settings";
  if (!appVersion.value) {
    appVersion.value = await api.appVersion().catch(() => "");
  }
}

function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${Math.ceil(bytes / 1024)} KB`;
  return `${Math.ceil(bytes)} B`;
}

function formatWhen(value: string | null) {
  if (!value) return "";
  return value.slice(0, 16).replace("T", " ");
}

async function checkForUpdates(auto = false) {
  if (updateStage.value === "checking" || updateStage.value === "downloading") return;
  updateStage.value = "checking";
  updateError.value = "";
  try {
    const found = await api.checkUpdate();
    release.value = found;
    appVersion.value = found.current_version;
    updateCheckedAt.value = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    downloadedPath.value = "";
    downloadedBytes.value = 0;
    downloadTotal.value = found.asset_size || null;
    updateStage.value = found.update_available ? "available" : "idle";
    if (found.update_available && page.value !== "lock") {
      updateDialogOpen.value = true;
    } else if (!found.update_available && !auto) {
      showToast("已是最新版本");
    }
  } catch (caught) {
    updateStage.value = "error";
    updateError.value = caught instanceof Error ? caught.message : String(caught);
    if (auto) {
      updateStage.value = "idle";
      updateError.value = "";
    } else {
      showToast(`检查更新失败：${updateError.value}`, 2400);
    }
  }
}

async function autoCheckUpdate() {
  if (autoUpdateChecked) return;
  autoUpdateChecked = true;
  await checkForUpdates(true);
}

function onUpdateClick() {
  if (release.value?.update_available || updateStage.value === "downloading" || updateStage.value === "ready") {
    updateDialogOpen.value = true;
    return;
  }
  void checkForUpdates();
}

async function downloadUpdate() {
  if (!release.value || updateStage.value === "downloading") return;
  updateStage.value = "downloading";
  updateError.value = "";
  downloadedBytes.value = 0;
  downloadTotal.value = release.value.asset_size || null;
  const stop = await listen<{ bytes: number; total: number | null }>("mobile-update-progress", (event) => {
    downloadedBytes.value = event.payload.bytes;
    downloadTotal.value = event.payload.total;
  });
  try {
    const saved = await api.downloadUpdate(release.value.download_url);
    downloadedPath.value = saved.path;
    downloadedBytes.value = saved.bytes;
    updateStage.value = "ready";
    if (page.value !== "lock") updateDialogOpen.value = true;
  } catch (caught) {
    updateStage.value = "error";
    updateError.value = caught instanceof Error ? caught.message : String(caught);
  } finally {
    stop();
  }
}

async function installUpdate() {
  if (!downloadedPath.value || !release.value) return;
  try {
    await api.installUpdate(downloadedPath.value);
    showToast("已打开系统安装界面");
  } catch (caught) {
    updateStage.value = "error";
    updateError.value = caught instanceof Error ? caught.message : String(caught);
  }
}

function retryUpdate() {
  if (release.value?.update_available) void downloadUpdate();
  else void checkForUpdates();
}

async function openReleasePage() {
  if (!release.value) return;
  try {
    await openUrl(release.value.release_url);
  } catch (caught) {
    updateError.value = caught instanceof Error ? caught.message : String(caught);
  }
}

async function saveIdle() {
  await api.saveSettings(Number(idleSecs.value) || 60, 20);
  showToast("已保存");
}

async function openSync() {
  sync.value = await api.syncStatus();
  syncKind.value = sync.value.kind ?? "webdav";
  syncForm.endpoint = sync.value.endpoint;
  syncForm.username = sync.value.username;
  syncForm.bucket = sync.value.bucket;
  syncForm.region = sync.value.region || "us-east-1";
  syncForm.prefix = sync.value.prefix;
  syncForm.auto = sync.value.auto_sync;
  syncForm.autoSecs = sync.value.auto_sync_secs;
  page.value = "sync";
}

async function saveSync(run: boolean) {
  error.value = "";
  busy.value = true;
  try {
    sync.value = await api.syncSave({
      kind: syncKind.value,
      endpoint: syncForm.endpoint,
      username: syncForm.username,
      secret: syncForm.secret || null,
      bucket: syncForm.bucket || null,
      region: syncForm.region || null,
      prefix: syncForm.prefix || null,
      auto_sync: syncForm.auto,
      auto_sync_secs: Number(syncForm.autoSecs) || 60,
    });
    if (run) {
      report.value = await api.syncNow();
      sync.value = await api.syncStatus();
    } else {
      showToast("已保存", 1600);
    }
    syncForm.secret = "";
  } catch (caught) {
    showError(caught);
  } finally {
    busy.value = false;
  }
}

async function lockNow() {
  clearQueryTimer();
  await api.lock();
  page.value = "lock";
  updateDialogOpen.value = false;
  entries.value = [];
  selected.value = null;
  fields.value = [];
  revealed.value = "";
  notes.value = ''; clearEdit(); clearManagement(); syncForm.secret = '';
}

onMounted(async () => {
  await refreshStatus();
  await listen("lock-now", () => {
    clearEdit(); clearManagement(); notes.value = ''; selected.value = null; syncForm.secret = '';
    clearQueryTimer();
    fields.value = [];
    revealed.value = "";
    page.value = "lock";
    updateDialogOpen.value = false;
    entries.value = [];
  });
  await listen<{ ok: boolean; error: string | null; report: SyncReport | null }>(
    "sync-finished",
    async (event) => {
      if (page.value === "lock") return;
      const report = event.payload.report;
      if (report && (report.pulled > 0 || report.removed > 0) && page.value === "vault") {
        await loadVault();
      }
      if (!sync.value) return;
      try {
        sync.value = await api.syncStatus();
      } catch {
        // Vault locked between the event and the refresh; nothing to show.
      }
    },
  );
  window.setInterval(() => {
    if (page.value !== "lock") void api.tick();
  }, 5000);
});
</script>

<template>
  <div class="app">
    <section v-if="management" class="view">
      <div class="top">
        <button class="link" type="button" @click="clearManagement()">返回</button>
        <h1>{{ management === 'password' ? '修改主密码' : management === 'backup-export' ? '导出加密备份' : management === 'backup-restore' ? '恢复加密备份' : management === 'csv-import' ? 'CSV 网站导入' : management === 'csv-export' ? 'CSV 网站导出' : '文件夹与标签' }}</h1>
      </div>
      <div class="scroll">
        <div v-if="error" class="pad"><p class="error">{{ error }}</p></div>

        <div v-if="management === 'password'" class="pad">
          <p class="hint">至少 10 位，完成后重新解锁；指纹凭据会失效。</p>
          <div class="field"><label>旧主密码</label><input v-model="transferPassword" type="password" /></div>
          <div class="field"><label>新密码</label><input v-model="newMaster" type="password" /></div>
          <div class="field"><label>重复</label><input v-model="repeatMaster" type="password" /></div>
          <button class="primary" type="button" :disabled="busy" @click="changeMaster">修改主密码</button>
        </div>

        <div v-else-if="management === 'backup-export'" class="pad">
          <p class="hint">.svbak 仍是加密备份，但文件本身要保管好。保存位置由导出流程里的系统对话框决定。</p>
          <div class="field"><label>主密码</label><input v-model="transferPassword" type="password" /></div>
          <div class="group" style="margin:0 0 14px">
            <label class="set"><span class="t">同时备份空闲锁定和剪贴板秒数（不含设备、指纹、同步凭据）</span><input v-model="includeSettings" type="checkbox" /></label>
            <label class="set"><span class="t">我了解 .svbak 仍是加密备份，但文件本身要保管好</span><input v-model="riskConfirmed" type="checkbox" /></label>
          </div>
          <button class="primary" type="button" :disabled="busy" @click="runTransfer">导出</button>
        </div>

        <div v-else-if="management === 'backup-restore'" class="pad">
          <button class="ghost" type="button" @click="chooseTransfer">选择文件</button>
          <p class="hint">{{ transferDocument?.name || '未选择文件' }}</p>
          <div class="gap"></div>
          <div class="field"><label>主密码</label><input v-model="transferPassword" type="password" /></div>
          <button class="ghost" type="button" :disabled="busy" @click="inspectBackup">校验并预览</button>
          <div v-if="backupPreview" class="group" style="margin:14px 0">
            <div class="set"><span class="t">版本</span><span>{{ backupPreview.summary.version }}</span></div>
            <div class="set"><span class="t">条目</span><span>{{ backupPreview.summary.entries }}</span></div>
            <div class="set"><span class="t">回收站</span><span>{{ backupPreview.summary.trash }}</span></div>
            <div class="set"><span class="t">文件夹</span><span>{{ backupPreview.summary.folders }}</span></div>
            <div class="set"><span class="t">标签</span><span>{{ backupPreview.summary.tags }}</span></div>
            <div class="set"><span class="t">墓碑</span><span>{{ backupPreview.summary.tombstones }}</span></div>
            <div class="set"><span class="t">包含设置</span><span>{{ backupPreview.summary.includes_settings ? '是' : '否' }}</span></div>
          </div>
          <p v-for="(warning, index) in backupPreview?.summary.warnings || []" :key="index" class="error">{{ warning }}</p>
          <div class="group" style="margin:0 0 14px">
            <label class="set"><span class="t">覆盖已有条目</span><input v-model="overwrite" type="checkbox" /></label>
            <label class="set"><span class="t">同时恢复空闲锁定和剪贴板秒数</span><input v-model="restoreSettings" type="checkbox" /></label>
            <label v-if="!initialized" class="set"><span class="t">继续使用备份中的主密码</span><input v-model="reuseBackupPassword" type="checkbox" /></label>
          </div>
          <template v-if="!initialized && !reuseBackupPassword">
            <div class="field"><label>新主密码</label><input v-model="newMaster" type="password" /></div>
            <div class="field"><label>重复</label><input v-model="repeatMaster" type="password" /></div>
            <p class="hint">至少 10 位，且两次输入必须一致。</p>
          </template>
          <button class="primary" type="button" :disabled="!backupPreview || busy" @click="runTransfer">恢复</button>
        </div>

        <div v-else-if="management === 'csv-import'" class="pad">
          <p class="hint">这是明文网站迁移，不含证书、SSH、服务器，不要用表格软件打开。</p>
          <button class="ghost" type="button" @click="chooseTransfer">选择文件</button>
          <p class="hint">{{ transferDocument?.name || '未选择文件' }}</p>
          <div v-if="csvPreview" class="group" style="margin:14px 0">
            <div class="set"><span class="t">总计</span><span>{{ csvPreview.summary.total }}</span></div>
            <div class="set"><span class="t">可导入</span><span>{{ csvPreview.summary.importable }}</span></div>
            <div class="set"><span class="t">已存在跳过</span><span>{{ csvPreview.summary.skipped_existing }}</span></div>
            <div class="set"><span class="t">无效跳过</span><span>{{ csvPreview.summary.skipped_invalid }}</span></div>
          </div>
          <div v-for="(row, index) in csvPreview?.summary.sample || []" :key="index" class="group" style="margin:0 0 14px">
            <div class="set"><span class="t">标题</span><span>{{ row.title }}</span></div>
            <div class="set"><span class="t">网址</span><span>{{ row.url }}</span></div>
            <div class="set"><span class="t">用户名</span><span>{{ row.username }}</span></div>
            <div class="set"><span class="t">有密码</span><span>{{ row.has_password ? '是' : '否' }}</span></div>
            <div class="set"><span class="t">有 TOTP</span><span>{{ row.has_totp ? '是' : '否' }}</span></div>
          </div>
          <div class="field"><label>主密码</label><input v-model="transferPassword" type="password" /></div>
          <div class="group" style="margin:0 0 14px">
            <label class="set"><span class="t">我确认这是明文网站迁移，文件含网站密码，不要用表格软件打开</span><input v-model="riskConfirmed" type="checkbox" /></label>
            <label class="set"><span class="t">覆盖已有网站条目</span><input v-model="overwrite" type="checkbox" /></label>
          </div>
          <button class="primary" type="button" :disabled="busy" @click="runTransfer">导入</button>
        </div>

        <div v-else-if="management === 'csv-export'" class="pad">
          <p class="hint">这是明文网站迁移，不含证书、SSH、服务器，不要用表格软件打开。保存位置由导出流程里的系统对话框决定。</p>
          <div class="field"><label>主密码</label><input v-model="transferPassword" type="password" /></div>
          <div class="group" style="margin:0 0 14px">
            <label class="set"><span class="t">我确认这是明文网站迁移，文件含网站密码，不要用表格软件打开</span><input v-model="riskConfirmed" type="checkbox" /></label>
          </div>
          <button class="primary" type="button" :disabled="busy" @click="runTransfer">导出</button>
        </div>

        <div v-else class="pad">
          <p class="hint">删除和合并都不删除条目。</p>
          <div class="lbl">文件夹</div>
          <p v-if="!folders.length" class="hint">还没有文件夹。</p>
          <div v-for="folder in folders" :key="folder.id" class="group" style="margin:0 0 14px">
            <div class="set"><span class="t">{{ folder.name }}</span></div>
            <div class="pad">
              <div class="field">
                <label>合并目标</label>
                <select v-model="categoryTargets[folder.id]">
                  <option value="">选择其他文件夹</option>
                  <option v-for="other in folders.filter(item => item.id !== folder.id)" :key="other.id" :value="other.id">{{ other.name }}</option>
                </select>
              </div>
            </div>
            <button class="set" type="button" @click="organize('rename', 'folder', folder.id, folder.name)"><span class="t">重命名</span></button>
            <button class="set" type="button" @click="organize('delete', 'folder', folder.id, folder.name)"><span class="t">删除</span></button>
            <button class="set" type="button" @click="organize('merge', 'folder', folder.id, folder.name)"><span class="t">合并</span></button>
          </div>
          <div class="lbl">标签</div>
          <p v-if="!tags.length" class="hint">还没有标签。</p>
          <div v-for="name in tags" :key="name" class="group" style="margin:0 0 14px">
            <div class="set"><span class="t">{{ name }}</span></div>
            <div class="pad">
              <div class="field">
                <label>合并目标</label>
                <select v-model="categoryTargets[name]">
                  <option value="">选择其他标签</option>
                  <option v-for="other in tags.filter(item => item !== name)" :key="other" :value="other">{{ other }}</option>
                </select>
              </div>
            </div>
            <button class="set" type="button" @click="organize('rename', 'tag', name, name)"><span class="t">重命名</span></button>
            <button class="set" type="button" @click="organize('delete', 'tag', name, name)"><span class="t">删除</span></button>
            <button class="set" type="button" @click="organize('merge', 'tag', name, name)"><span class="t">合并</span></button>
          </div>
        </div>
      </div>
    </section>

    <section v-else-if="page === 'lock'" class="view lock">
      <div class="mark">印</div>
      <h1>{{ initialized ? "打开印盒" : "设置主密码" }}</h1>
      <p class="hint">主密码至少 10 位。指纹只在这台手机上生效。</p>
      <div class="gap"></div>
      <div class="field"><label>主密码</label><input v-model="password" type="password" @keyup.enter="submitPassword" /></div>
      <div v-if="!initialized" class="field"><label>再输入一次</label><input v-model="password2" type="password" /></div>
      <p v-if="error" class="error">{{ error }}</p>
      <button class="primary" :disabled="busy" @click="submitPassword">{{ initialized ? "解锁" : "创建保险库" }}</button>
      <div class="gap"></div>
      <button v-if="biometryReady" class="ghost" @click="unlockFingerprint">用指纹解锁</button>
      <button v-if="!initialized" class="ghost" @click="openManagement('backup-restore')">从 .svbak 备份恢复，无需先建库</button>
    </section>

    <template v-else-if="page === 'vault'">
      <div class="view">
        <div class="searchbar">
          <input v-model="query" placeholder="搜索键名、账号、网址、备注" />
          <button
            class="icon"
            :class="{ on: filtersOpen }"
            :aria-expanded="filtersOpen"
            aria-label="筛选"
            @click="filtersOpen = !filtersOpen"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 7h16M7 12h10M10 17h4"/></svg>
          </button>
        </div>
        <div class="chips folders">
          <button class="chip" :class="{ on: !folderId && !uncategorized && !trash }" @click="pickFolder('')">全部 {{ counts?.total ?? 0 }}</button>
          <button class="chip" :class="{ on: uncategorized }" @click="pickUncategorized()">未归类</button>
          <button v-for="folder in folders" :key="folder.id" class="chip" :class="{ on: folderId === folder.id }" @click="pickFolder(folder.id)">{{ folder.name }}</button>
          <button class="chip" @click="addFolder">+ 新建</button>
        </div>
        <div v-if="filtersOpen" class="panel">
          <div class="lbl">类型</div>
          <div class="chips flat">
            <button class="chip" :class="{ on: !kind }" @click="kind = ''">全部</button>
            <button v-for="item in KINDS" :key="item.id" class="chip" :class="{ on: kind === item.id }" @click="kind = item.id">
              {{ item.label }} {{ scopedCounts?.[item.count] ?? 0 }}
            </button>
          </div>
          <template v-if="tags.length">
            <div class="lbl">标签</div>
            <div class="chips flat">
              <button class="chip" :class="{ on: !tag }" @click="tag = ''; loadVault()">全部</button>
              <button v-for="item in tags" :key="item" class="chip" :class="{ on: tag === item }" @click="tag = item; loadVault()">{{ item }}</button>
            </div>
          </template>
          <div class="lbl">其他</div>
          <div class="chips flat">
            <button class="chip" :class="{ on: trash }" @click="toggleTrash">回收站 {{ counts?.trash ?? 0 }}</button>
          </div>
          <button v-if="trash" class="danger" @click="api.emptyTrash().then(loadVault)">清空回收站，不可恢复</button>
        </div>
        <div class="scroll">
          <div class="list">
            <button v-for="row in visible" :key="row.id" class="item" @click="openDetail(row)">
              <span class="letter" :style="{ background: '#5b5bd6' }">{{ row.title.slice(0, 1).toUpperCase() }}</span>
              <span class="meta">
                <span class="name">{{ row.title }} <span v-if="row.pinned" class="pin">置顶</span></span>
                <span class="line">{{ kindLabel(row.kind) }} · {{ row.account || row.fingerprint || "—" }}</span>
              </span>
            </button>
            <p v-if="!visible.length" class="hint">没有条目。</p>
          </div>
        </div>
        <div class="tabs">
          <button class="tab on">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <rect x="3" y="4" width="18" height="16" rx="2.5" />
              <circle cx="12" cy="12" r="3.5" />
              <path d="M12 8.5v-1.5M12 17v-1.5M15.5 12H17M7 12h1.5" />
            </svg>
            <span>保险库</span>
          </button>
          <button class="tab" @click="openSettings">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.09a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.09a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
            </svg>
            <span>设置</span>
          </button>
        </div>
      </div>
      <button class="fab" @click="startCreate('website')">+</button>
    </template>

    <section v-else-if="page === 'detail' && selected" class="view">
      <div class="top"><button class="link" @click="page = 'vault'">返回</button><h1>{{ selected.title }}</h1><button class="link" @click="startEdit">编辑</button></div>
      <div class="scroll pad">
        <div class="kv">
          <div class="row"><span class="k">类型</span><span>{{ kindLabel(selected.kind) }}</span></div>
          <div class="row"><span class="k">账号</span><span>{{ selected.account || "—" }}</span></div>
          <div class="row"><span class="k">网址</span><span>{{ selected.url || "—" }}</span></div>
          <div class="row"><span class="k">修改</span><span>{{ selected.updated_at.slice(0, 16).replace("T", " ") }}</span></div>
        </div>
        <div class="secret">
          <div class="lbl">秘密</div>
          <div class="mask">{{ revealed || "••••••••" }}</div>
          <div class="actions">
            <button class="ghost" @click="reveal">显示</button>
            <button class="primary" @click="copy('secret')">复制</button>
          </div>
          <div class="actions" v-if="selected.has_totp"><button class="ghost" @click="copy('totp')">复制 TOTP</button></div>
          <p v-if="selected.kind === 'client_cert'" class="hint">私钥不显示、不复制。可以复制公开证书。</p>
        </div>
        <div v-if="fields.length" class="kv">
          <div v-for="(field, i) in fields" :key="`${field.label}-${i}`" class="row"><span class="k">{{ field.label }}</span><span>{{ field.value }}</span></div>
        </div>
        <p v-if="notes" class="hint">{{ notes }}</p>
        <div class="gap"></div>
        <button class="ghost" @click="togglePin">{{ selected.pinned ? "取消置顶" : "置顶" }}</button>
        <div class="gap"></div>
        <button v-if="!trash" class="danger" @click="moveTrash">移入回收站</button>
        <button v-else class="primary" @click="restoreSelected">恢复</button>
      </div>
    </section>

    <section v-else-if="page === 'edit'" class="view">
      <div class="top"><button class="link" @click="goBack">返回</button><h1>{{ editing ? "编辑" : "新建" }}</h1></div>
      <div class="scroll pad">
        <div v-if="!editing" class="kinds">
          <button v-for="item in KINDS" :key="item.id" class="kind" :class="{ on: form.kind === item.id }" @click="startCreate(item.id)"><b>{{ kindLabel(item.id) }}</b></button>
        </div>
        <div class="gap"></div>
        <div class="field"><label>键名</label><input v-model="form.title" /></div>
        <template v-if="form.kind === 'website'">
          <div class="field"><label>网址</label><input v-model="form.url" /></div>
          <div class="field"><label>用户名</label><input v-model="form.account" /></div>
          <div class="field"><label>密码</label><input v-model="form.password" type="password" /></div>
          <div class="field"><label>TOTP 密钥，可选</label><input v-model="form.totp" /></div>
        </template>
        <template v-else-if="form.kind === 'api_token'">
          <div class="field"><label>服务</label><input v-model="form.service" /></div>
          <div class="field"><label>账号</label><input v-model="form.account" /></div>
          <div class="field"><label>Token</label><textarea v-model="form.token"></textarea></div>
        </template>
        <template v-else-if="form.kind === 'ssh'">
          <div class="field"><label>私钥</label><textarea v-model="form.privateKey"></textarea></div>
          <div class="field"><label>口令，可选</label><input v-model="form.passphrase" type="password" /></div>
        </template>
        <template v-else-if="form.kind === 'mailbox' || form.kind === 'mail_auth'">
          <div class="field"><label>邮箱</label><input v-model="form.email" /></div>
          <div v-if="form.kind === 'mail_auth'" class="field"><label>服务商</label><input v-model="form.provider" /></div>
          <div v-if="form.kind === 'mailbox'" class="field"><label>密码</label><input v-model="form.password" type="password" /></div>
          <div v-else class="field"><label>授权码</label><input v-model="form.authCode" type="password" /></div>
        </template>
        <template v-else-if="form.kind === 'server' || form.kind === 'database'">
          <div v-if="form.kind === 'database'" class="field"><label>引擎</label><select v-model="form.engine" @change="changeConnectionType"><option v-for="option in engineOptions" :key="option.id" :value="option.id">{{ option.label }}</option></select></div>
          <div v-else class="field"><label>协议</label><select v-model="form.protocol" @change="changeConnectionType"><option v-for="option in protocolOptions" :key="option.id" :value="option.id">{{ option.label }}</option></select></div>
          <div v-if="form.kind === 'server' || dbFields.host" class="field"><label>主机</label><input v-model="form.host" /></div>
          <div v-if="form.kind === 'server' || dbFields.port" class="field"><label>端口</label><input v-model="form.port" type="number" min="0" max="65535" /></div>
          <div v-if="form.kind === 'database'" class="field"><label>{{ dbFields.databaseLabel }}</label><input v-model="form.database" /></div>
          <div v-if="form.kind === 'server' || dbFields.username" class="field"><label>{{ form.engine === 'redis' && form.kind === 'database' ? '用户名，可选' : '用户名' }}</label><input v-model="form.username" /></div>
          <div class="field"><label>密码</label><input v-model="form.password" type="password" /></div>
        </template>
        <template v-else>
          <div class="field"><label>证书文件</label><button class="ghost" @click="chooseCert('cert')">{{ certDocument?.name || '从系统文档选择证书' }}</button></div>
          <div class="field"><label>私钥文件</label><button class="ghost" @click="chooseCert('key')">{{ keyDocument?.name || '从系统文档选择私钥' }}</button></div>
          <div class="field"><label>私钥口令，可选；留空保留</label><input v-model="form.passphrase" type="password" :disabled="clearCertPassphrase" /></div>
          <label v-if="editing" class="set"><span>明确清除已保存口令</span><input v-model="clearCertPassphrase" type="checkbox" /></label>
          <p class="hint">私钥由原生端读取和校验，不回显。编辑时不选择替换文件则保留原证书及私钥。</p>
        </template>
        <div class="field"><label>文件夹</label>
          <select v-model="form.folderId"><option value="">未归类</option><option v-for="folder in folders" :key="folder.id" :value="folder.id">{{ folder.name }}</option></select>
        </div>
        <div class="field"><label>标签，逗号分隔</label><input v-model="form.tags" /></div>
        <div class="field"><label>备注</label><textarea v-model="form.notes"></textarea></div>
        <p v-if="error" class="error">{{ error }}</p>
        <button class="primary" @click="saveEntry">保存</button>
      </div>
    </section>

    <template v-else-if="page === 'settings'">
      <div class="view">
        <div class="top"><h1>设置</h1></div>
        <div class="scroll">
          <div class="group">
            <div class="set"><span class="t">空闲锁定<small>秒，切到后台也会锁定</small></span><input v-model="idleSecs" type="number" style="width:80px" /></div>
            <button class="set" @click="saveIdle"><span class="t">保存锁定时间</span></button>
            <button class="set" @click="toggleBiometry"><span class="t">指纹解锁<small>{{ biometryOn ? "已打开，包装只在这台手机" : "未打开" }}</small></span></button>
          </div>
          <p v-if="error" class="error" style="padding:0 18px">{{ error }}</p>
          <div class="group">
            <button class="set" @click="openManagement('password')"><span class="t">修改主密码<small>至少 10 位，完成后重新用主密码解锁</small></span><span>›</span></button>
            <button class="set" @click="openManagement('organization')"><span class="t">文件夹与标签<small>重命名、删除与合并，不删除条目</small></span><span>›</span></button>
            <button class="set" @click="openManagement('backup-export')"><span class="t">导出加密备份<small>完整金库 .svbak</small></span><span>›</span></button>
            <button class="set" @click="openManagement('backup-restore')"><span class="t">恢复加密备份<small>先校验预览，再选择恢复策略</small></span><span>›</span></button>
            <button class="set" @click="openManagement('csv-import')"><span class="t">CSV 网站导入<small>明文迁移，仅网站账号</small></span><span>›</span></button>
            <button class="set" @click="openManagement('csv-export')"><span class="t">CSV 网站导出<small>明文迁移，仅网站账号</small></span><span>›</span></button>
            <button class="set" @click="openSync"><span class="t">数据同步<small>WebDAV / S3</small></span><span>›</span></button>
            <button class="set" @click="lockNow"><span class="t">立即锁定</span></button>
          </div>
          <div class="group">
            <div class="set">
              <span class="t">当前版本<small>Android</small></span>
              <strong>v{{ appVersion || "…" }}</strong>
            </div>
            <button class="set" :disabled="updateStage === 'checking'" @click="onUpdateClick">
              <span class="t">检查更新<small>{{ aboutUpdateText }}</small></span>
              <span>›</span>
            </button>
          </div>
        </div>
        <div class="tabs">
          <button class="tab" @click="openVault">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <rect x="3" y="4" width="18" height="16" rx="2.5" />
              <circle cx="12" cy="12" r="3.5" />
              <path d="M12 8.5v-1.5M12 17v-1.5M15.5 12H17M7 12h1.5" />
            </svg>
            <span>保险库</span>
          </button>
          <button class="tab on">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.09a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.09a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
            </svg>
            <span>设置</span>
          </button>
        </div>
      </div>
    </template>

    <section v-else class="view">
      <div class="top"><button class="link" @click="page = 'settings'">返回</button><h1>数据同步</h1></div>
      <div class="scroll pad">
        <div class="chips" style="padding:0 0 12px">
          <button class="chip" :class="{ on: syncKind === 'webdav' }" @click="syncKind = 'webdav'">WebDAV</button>
          <button class="chip" :class="{ on: syncKind === 's3' }" @click="syncKind = 's3'">S3</button>
        </div>
        <div class="field"><label>{{ syncKind === 'webdav' ? 'WebDAV 地址' : 'S3 Endpoint' }}</label><input v-model="syncForm.endpoint" placeholder="https://" /></div>
        <div class="field"><label>{{ syncKind === 'webdav' ? '用户名' : 'Access Key' }}</label><input v-model="syncForm.username" /></div>
        <div class="field"><label>{{ syncKind === 'webdav' ? '密码或应用密码' : 'Secret Key' }}</label><input v-model="syncForm.secret" type="password" placeholder="至少 8 位，留空则不修改" /></div>
        <template v-if="syncKind === 's3'">
          <div class="field"><label>Bucket</label><input v-model="syncForm.bucket" /></div>
          <div class="field"><label>Region</label><input v-model="syncForm.region" /></div>
        </template>
        <div class="field"><label>路径前缀，可选</label><input v-model="syncForm.prefix" placeholder="sealbox/vault.sboxsync" /></div>
        <div class="group" style="margin:0 0 14px">
          <label class="set">
            <span class="t">定时自动同步<small>解锁后按间隔自动同步，默认 60 秒</small></span>
            <input v-model="syncForm.auto" type="checkbox" />
          </label>
          <div class="set">
            <span class="t">间隔（秒）</span>
            <input v-model.number="syncForm.autoSecs" type="number" min="15" max="86400" :disabled="!syncForm.auto" style="width:96px" />
          </div>
        </div>
        <p v-if="sync?.last_result" class="hint">上次：{{ sync.last_result }}</p>
        <p v-if="error" class="error">{{ error }}</p>
        <div class="actions">
          <button class="ghost" :disabled="busy" @click="saveSync(false)">仅保存</button>
          <button class="primary" :disabled="busy" @click="saveSync(true)">{{ busy ? "同步中" : "保存并同步" }}</button>
        </div>
        <div class="actions">
          <button class="ghost" type="button" :disabled="busy" @click="verifySync">验证安全同步</button>
          <button class="ghost" type="button" :disabled="busy" @click="previewSync">预览变更</button>
        </div>
        <div v-if="report" class="secret">
          <div class="row"><span class="k">拉取</span><span>{{ report.pulled }}</span></div>
          <div class="row"><span class="k">推送</span><span>{{ report.pushed }}</span></div>
          <div class="row"><span class="k">未变</span><span>{{ report.unchanged }}</span></div>
          <div class="row" v-if="report.removed"><span class="k">删除</span><span>{{ report.removed }}</span></div>
          <p v-if="report.blocked" class="error">{{ report.blocked }}</p>
          <p v-if="report.phase" class="hint">阶段：{{ report.phase }}</p>
        </div>
        <div v-for="item in syncConflicts" :key="item.id" class="secret">
          <div class="row"><span class="k">条目</span><span>{{ item.title }}</span></div>
          <p class="hint">{{ item.kind === 'edit_edit' ? '两边都改过' : '一边删除一边修改' }}</p>
          <div v-if="syncChoices[item.id]" class="chips flat">
            <button type="button" class="chip" :class="{ on: syncChoices[item.id].choice === 'local' }" @click="syncChoices[item.id].choice = 'local'">保留本机</button>
            <button type="button" class="chip" :class="{ on: syncChoices[item.id].choice === 'remote' }" @click="syncChoices[item.id].choice = 'remote'">采用远端</button>
            <button type="button" class="chip" :class="{ on: syncChoices[item.id].choice === 'both' }" @click="syncChoices[item.id].choice = 'both'">两边都保留</button>
          </div>
          <label v-if="item.kind === 'delete_edit' && syncChoices[item.id]" class="set">
            <span>我确认如何处理删除与修改</span>
            <input v-model="syncChoices[item.id].confirm_delete_edit" type="checkbox" />
          </label>
        </div>
        <div class="gap"></div>
        <button class="primary" type="button" :disabled="!syncCanCommit || busy" @click="commitSync">按选择同步</button>
        <p class="hint">远端只有加密快照。同步密钥解不开主密码。</p>
      </div>
    </section>
    <div v-if="updateDialogOpen && release" class="update-mask" @click.self="updateDialogOpen = false">
      <div class="update-dialog" role="dialog" aria-modal="true" aria-labelledby="update-dialog-title">
        <div class="update-badge" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 3.5v11" />
            <path d="M7.5 10.5 12 15l4.5-4.5" />
            <path d="M4.5 19.5h15" />
          </svg>
        </div>
        <h2 id="update-dialog-title">{{ updateStage === "ready" ? "更新已就绪" : "发现新版本" }}</h2>
        <p class="update-sub">Sealbox Android · v{{ appVersion || release.current_version }} → v{{ release.latest_version }}</p>
        <div class="update-versions">
          <span>当前版本</span>
          <strong>v{{ appVersion || release.current_version }}</strong>
          <template v-if="release.published_at">
            <span>发布时间</span>
            <strong>{{ formatWhen(release.published_at) }}</strong>
          </template>
        </div>
        <div v-if="updateStage === 'downloading' || updateStage === 'ready'" class="update-progress">
          <div class="update-progress-head">
            <span>{{ updateStage === "ready" ? "下载完成" : "正在下载更新" }}</span>
            <strong>{{ updateProgress === null ? "…" : `${updateProgress}%` }}</strong>
          </div>
          <div class="track"><span :style="{ width: `${updateProgress ?? 0}%` }"></span></div>
          <p class="hint">{{ formatBytes(downloadedBytes) }}<span v-if="downloadTotal"> / {{ formatBytes(downloadTotal) }}</span></p>
        </div>
        <p v-if="updateError" class="error update-dialog-error">{{ updateError }}</p>
        <p v-if="updateStage === 'downloading'" class="hint update-background-hint">关闭此窗口后下载会在后台继续</p>
        <div class="update-actions">
          <button v-if="updateStage === 'available'" class="primary" @click="downloadUpdate">立即更新</button>
          <button v-else-if="updateStage === 'error'" class="primary" @click="retryUpdate">重试下载</button>
          <button v-else-if="updateStage === 'ready'" class="primary" @click="installUpdate">立即安装</button>
          <button class="ghost" @click="updateDialogOpen = false">{{ updateStage === "downloading" ? "后台下载" : "稍后" }}</button>
        </div>
        <button class="link release-link" @click="openReleasePage">打开发布页</button>
      </div>
    </div>
    <div v-if="toast" class="toast">{{ toast }}</div>
  </div>
</template>
