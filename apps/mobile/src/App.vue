<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from "vue";
import { listen } from "@tauri-apps/api/event";
import { onBackButtonPress } from "@tauri-apps/api/app";
import type { PluginListener } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { authenticate, checkStatus, getData, hasData, removeData, setData } from "@choochmeque/tauri-plugin-biometry-api";
import { KINDS, api, kindLabel, type Counts, type EntryDto, type EntryKind, type Folder, type MobileRelease, type SyncReport, type SyncView } from "./api";

type Page = "lock" | "vault" | "detail" | "edit" | "settings" | "sync";
const page = ref<Page>("lock");
const initialized = ref(false);
const biometryOn = ref(false);
const biometryReady = ref(false);
const password = ref("");
const password2 = ref("");
const error = ref("");
const toast = ref("");
const counts = ref<Counts | null>(null);
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
const editing = ref(false);
const form = reactive(blankForm());
const sync = ref<SyncView | null>(null);
const report = ref<SyncReport | null>(null);
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
  if (page.value === "vault") return filtersOpen.value;
  return page.value === "detail" || page.value === "edit" || page.value === "settings" || page.value === "sync";
}

function goBack() {
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

watch([page, filtersOpen], syncBackListener);

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
  };
}

const visible = computed(() => {
  const text = query.value.trim().toLowerCase();
  return entries.value.filter((row) => {
    if (kind.value && row.kind !== kind.value) return false;
    if (!text) return true;
    return [row.title, row.account, row.url, row.fingerprint].join(" ").toLowerCase().includes(text);
  });
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

async function loadVault() {
  const [rows, folderRows, tagRows, countRows] = await Promise.all([
    api.entries({
      query: null,
      folder_id: folderId.value || null,
      uncategorized: uncategorized.value,
      tag: tag.value || null,
      trash: trash.value,
      sort: "updated",
    }),
    api.folders(),
    api.tags(),
    api.counts(),
  ]);
  entries.value = rows;
  folders.value = folderRows;
  tags.value = tagRows;
  counts.value = countRows;
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
    toast.value = "指纹解锁已打开，只在这台手机生效";
  } catch (caught) {
    showError(caught);
  }
}

async function openDetail(row: EntryDto) {
  selected.value = row;
  revealed.value = "";
  notes.value = (await api.notes(row.id)) ?? "";
  page.value = "detail";
}

async function reveal() {
  if (!selected.value) return;
  const payload = await api.reveal(selected.value.id);
  revealed.value = String(payload.password ?? payload.token ?? payload.private_key ?? payload.auth_code ?? "");
}

async function copy(field: string) {
  if (!selected.value) return;
  await api.copy(selected.value.id, field);
  toast.value = "已复制，约 20 秒后清空剪贴板";
  setTimeout(() => (toast.value = ""), 1600);
}

function startCreate(next: EntryKind) {
  Object.assign(form, blankForm());
  form.kind = next;
  editing.value = false;
  page.value = "edit";
}

async function startEdit() {
  if (!selected.value) return;
  const row = selected.value;
  Object.assign(form, blankForm());
  form.id = row.id;
  form.kind = row.kind;
  form.title = row.title;
  form.account = row.account ?? "";
  form.url = row.url ?? "";
  form.folderId = row.folder_id ?? "";
  form.tags = row.tags.join(", ");
  form.notes = notes.value;
  form.pinned = row.pinned;
  if (row.kind !== "client_cert") {
    const payload = await api.reveal(row.id);
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
  const port = form.port ? Number(form.port) : null;
  switch (form.kind) {
    case "website":
      return { type: "website", url: form.url || null, username: form.account || null, password: form.password, totp_secret: form.totp || null };
    case "api_token":
      return { type: "api_token", service: form.service || form.title, account: form.account || null, token: form.token };
    case "ssh":
      return { type: "ssh", key_type: "openssh", private_key: form.privateKey, passphrase: form.passphrase || null, public_fingerprint: null };
    case "mailbox":
      return { type: "mailbox", email: form.email, password: form.password, imap_host: null, imap_port: null, smtp_host: null, smtp_port: null };
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
    const saved = await api.save({
      id: form.id || null,
      kind: form.kind,
      title: form.title,
      account: form.account || form.email || form.username || null,
      url: form.url || null,
      folder_id: form.folderId || null,
      tags: form.tags.split(/[,，]/).map((item) => item.trim()).filter(Boolean),
      pinned: form.pinned,
      expires_at: null,
      notes: form.notes || null,
      secret: secretPayload(),
    });
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
    } else if (!auto) {
      toast.value = "已是最新版本";
      window.setTimeout(() => (toast.value = ""), 1800);
    }
  } catch (caught) {
    updateStage.value = "error";
    updateError.value = caught instanceof Error ? caught.message : String(caught);
    if (auto) {
      updateStage.value = "idle";
      updateError.value = "";
    } else {
      toast.value = `检查更新失败：${updateError.value}`;
      window.setTimeout(() => (toast.value = ""), 2400);
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
    toast.value = "已打开系统安装界面";
    window.setTimeout(() => (toast.value = ""), 1800);
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
  toast.value = "已保存";
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
      toast.value = "已保存";
      setTimeout(() => (toast.value = ""), 1600);
    }
    syncForm.secret = "";
  } catch (caught) {
    showError(caught);
  } finally {
    busy.value = false;
  }
}

async function lockNow() {
  await api.lock();
  page.value = "lock";
  updateDialogOpen.value = false;
  entries.value = [];
  selected.value = null;
}

onMounted(async () => {
  await refreshStatus();
  await listen("lock-now", () => {
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
    <section v-if="page === 'lock'" class="view lock">
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
    </section>

    <template v-else-if="page === 'vault'">
      <div class="view">
        <div class="searchbar">
          <input v-model="query" placeholder="搜索键名 / 账号 / 网址" />
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
              {{ item.label }} {{ counts?.[item.count] ?? 0 }}
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
      <button class="fab" @click="page = 'edit'; Object.assign(form, blankForm())">+</button>
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
        <p v-if="notes" class="hint">{{ notes }}</p>
        <div class="gap"></div>
        <button class="ghost" @click="togglePin">{{ selected.pinned ? "取消置顶" : "置顶" }}</button>
        <div class="gap"></div>
        <button v-if="!trash" class="danger" @click="moveTrash">移入回收站</button>
        <button v-else class="primary" @click="restoreSelected">恢复</button>
      </div>
    </section>

    <section v-else-if="page === 'edit'" class="view">
      <div class="top"><button class="link" @click="page = editing ? 'detail' : 'vault'">返回</button><h1>{{ editing ? "编辑" : "新建" }}</h1></div>
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
          <div v-if="form.kind === 'database'" class="field"><label>引擎</label><input v-model="form.engine" /></div>
          <div class="field"><label>主机</label><input v-model="form.host" /></div>
          <div class="field"><label>端口</label><input v-model="form.port" /></div>
          <div v-if="form.kind === 'database'" class="field"><label>库名</label><input v-model="form.database" /></div>
          <div class="field"><label>用户名</label><input v-model="form.username" /></div>
          <div class="field"><label>密码</label><input v-model="form.password" type="password" /></div>
        </template>
        <template v-else>
          <div class="field"><label>证书 PEM</label><textarea v-model="form.certPem"></textarea></div>
          <div class="field"><label>私钥 PEM</label><textarea v-model="form.keyPem"></textarea></div>
          <p class="hint">用粘贴，不从文件管理器导入。编辑已有证书时不回显私钥。</p>
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
        <div v-if="report" class="secret">
          <div class="row"><span class="k">拉取</span><span>{{ report.pulled }}</span></div>
          <div class="row"><span class="k">推送</span><span>{{ report.pushed }}</span></div>
          <div class="row"><span class="k">未变</span><span>{{ report.unchanged }}</span></div>
          <div class="row" v-if="report.removed"><span class="k">删除</span><span>{{ report.removed }}</span></div>
          <p v-if="report.conflicts.length" class="error">两端修改时间相同，已保留本机：{{ report.conflicts.join("、") }}</p>
        </div>
        <p class="hint">远端只有加密快照。同步密钥解不开主密码。</p>
      </div>
    </section>
    <div v-if="updateDialogOpen && release" class="sheet-mask" @click.self="updateDialogOpen = false">
      <div class="sheet update-sheet" role="dialog" aria-modal="true" aria-labelledby="update-sheet-title">
        <div class="sheet-head">
          <div>
            <h2 id="update-sheet-title">{{ updateStage === "ready" ? "更新已就绪" : "发现新版本" }}</h2>
            <p class="hint">Sealbox Android</p>
          </div>
          <span class="ver">v{{ release.latest_version }}</span>
        </div>
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
            <strong v-if="updateProgress !== null">{{ updateProgress }}%</strong>
          </div>
          <div class="track"><span :style="{ width: `${updateProgress ?? 0}%` }"></span></div>
          <p class="hint">{{ formatBytes(downloadedBytes) }}<span v-if="downloadTotal"> / {{ formatBytes(downloadTotal) }}</span></p>
        </div>
        <p v-if="updateError" class="error update-sheet-error">{{ updateError }}</p>
        <div class="sheet-actions">
          <button class="ghost" @click="updateDialogOpen = false">稍后</button>
          <button v-if="updateStage === 'available'" class="primary" @click="downloadUpdate">立即更新</button>
          <button v-else-if="updateStage === 'error'" class="primary" @click="retryUpdate">重试下载</button>
          <button v-else-if="updateStage === 'ready'" class="primary" @click="installUpdate">安装</button>
        </div>
        <button class="link release-link" @click="openReleasePage">打开发布页</button>
      </div>
    </div>
    <div v-if="toast" class="toast">{{ toast }}</div>
  </div>
</template>
