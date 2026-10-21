<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { listen } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import { authenticate, checkStatus, getData, hasData, removeData, setData } from "@choochmeque/tauri-plugin-biometry-api";
import { KINDS, api, kindLabel, type Counts, type EntryDto, type EntryKind, type Folder, type MobileRelease, type SyncReport, type SyncView } from "./api";

type Page = "lock" | "vault" | "query" | "detail" | "edit" | "settings" | "sync";
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
const selected = ref<EntryDto | null>(null);
const revealed = ref("");
const notes = ref("");
const editing = ref(false);
const form = reactive(blankForm());
const sync = ref<SyncView | null>(null);
const report = ref<SyncReport | null>(null);
const syncKind = ref<"webdav" | "s3">("webdav");
const syncForm = reactive({ endpoint: "", username: "", secret: "", bucket: "", region: "us-east-1", prefix: "" });
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
const updateProgress = computed(() => {
  if (!downloadTotal.value || downloadTotal.value <= 0) return null;
  return Math.min(100, Math.round((downloadedBytes.value / downloadTotal.value) * 100));
});

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
    await authenticate("用指纹打开印盒", {
      title: "印盒",
      subtitle: "验证指纹",
      cancelTitle: "取消",
      allowDeviceCredential: false,
      confirmationRequired: false,
    });
    const stored = await getData({ domain: DOMAIN, name: DEK_NAME, reason: "打开保险库" });
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
  await api.createFolder(name);
  folders.value = await api.folders();
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

async function checkForUpdates() {
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
    if (!found.update_available) toast.value = "已是最新版本";
  } catch (caught) {
    updateStage.value = "error";
    updateError.value = caught instanceof Error ? caught.message : String(caught);
  }
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
  } catch (caught) {
    updateStage.value = "error";
    updateError.value = caught instanceof Error ? caught.message : String(caught);
  } finally {
    stop();
  }
}

async function installUpdate() {
  if (!downloadedPath.value || !release.value) return;
  if (!window.confirm(`将打开系统安装界面安装 v${release.value.latest_version}。保险库数据不会被替换。`)) return;
  try {
    await api.installUpdate(downloadedPath.value);
    toast.value = "已打开系统安装界面";
  } catch (caught) {
    updateStage.value = "error";
    updateError.value = caught instanceof Error ? caught.message : String(caught);
  }
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
    });
    if (run) {
      report.value = await api.syncNow();
      sync.value = await api.syncStatus();
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
  entries.value = [];
  selected.value = null;
}

onMounted(async () => {
  await refreshStatus();
  await listen("lock-now", () => {
    page.value = "lock";
    entries.value = [];
  });
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
        <div class="chips">
          <button class="chip" :class="{ on: !kind && !trash }" @click="kind = ''; trash = false">全部 {{ counts?.total ?? 0 }}</button>
          <button v-for="item in KINDS" :key="item.id" class="chip" :class="{ on: kind === item.id }" @click="kind = item.id">
            {{ item.label }} {{ counts?.[item.count] ?? 0 }}
          </button>
          <span style="flex:1"></span>
          <button class="icon" title="查询" @click="page = 'query'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="6"/><path d="m20 20-3.2-3.2"/></svg>
          </button>
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
          <button class="tab on">保险库</button>
          <button class="tab" @click="openSettings">设置</button>
        </div>
      </div>
      <button class="fab" @click="page = 'edit'; Object.assign(form, blankForm())">+</button>
    </template>

    <section v-else-if="page === 'query'" class="view">
      <div class="top"><button class="link" @click="page = 'vault'">返回</button><h1>查询</h1></div>
      <div class="scroll pad">
        <div class="field"><label>关键字</label><input v-model="query" placeholder="键名、账号、网址" /></div>
        <div class="lbl">文件夹</div>
        <div class="chips" style="padding:0;flex-wrap:wrap">
          <button class="chip" :class="{ on: !folderId }" @click="folderId = ''; loadVault()">全部</button>
          <button class="chip" @click="folderId = ''; loadVault()">未归类</button>
          <button v-for="folder in folders" :key="folder.id" class="chip" :class="{ on: folderId === folder.id }" @click="folderId = folder.id; loadVault()">{{ folder.name }}</button>
          <button class="chip" @click="addFolder">新建</button>
        </div>
        <div class="gap"></div>
        <div class="lbl">标签</div>
        <div class="chips" style="padding:0;flex-wrap:wrap">
          <button class="chip" :class="{ on: !tag }" @click="tag = ''; loadVault()">全部</button>
          <button v-for="item in tags" :key="item" class="chip" :class="{ on: tag === item }" @click="tag = item; loadVault()">{{ item }}</button>
        </div>
        <div class="gap"></div>
        <button class="item" @click="trash = !trash; loadVault()">
          <span class="meta"><span class="name">回收站</span><span class="line">{{ counts?.trash ?? 0 }} 条 · 清空需要再次确认</span></span>
        </button>
        <div class="gap"></div>
        <button v-if="trash" class="danger" @click="api.emptyTrash().then(loadVault)">清空回收站</button>
        <p class="hint">删除没有墓碑。一台删掉而另一台还留着，下次同步会回来。想让删除传过去，放进回收站。</p>
      </div>
    </section>

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
            <div v-if="release" class="set">
              <span class="t">最新版本<small>{{ formatWhen(release.published_at) || "GitHub Releases" }}</small></span>
              <strong>v{{ release.latest_version }}</strong>
            </div>
            <p v-if="updateError" class="error update-note">{{ updateError }}</p>
            <p v-else-if="updateStage === 'checking'" class="hint update-note">正在检查 GitHub Releases…</p>
            <p v-else-if="updateStage === 'idle' && updateCheckedAt" class="hint update-note">已是最新版本 · {{ updateCheckedAt }} 检查</p>
            <p v-else-if="updateStage === 'available'" class="hint update-note">发现新版本，下载后由系统安装。</p>
            <div v-if="release?.notes" class="update-notes">
              <strong>更新说明</strong>
              <p>{{ release.notes }}</p>
            </div>
            <div v-if="updateStage === 'downloading' || updateStage === 'ready'" class="update-progress">
              <div class="update-progress-head">
                <span>{{ updateStage === 'ready' ? '下载完成' : '下载进度' }}</span>
                <strong v-if="updateProgress !== null">{{ updateProgress }}%</strong>
              </div>
              <div class="track"><span :style="{ width: `${updateProgress ?? 0}%` }"></span></div>
              <p class="hint">{{ formatBytes(downloadedBytes) }}<span v-if="downloadTotal"> / {{ formatBytes(downloadTotal) }}</span></p>
            </div>
            <div class="update-actions">
              <button class="primary" :disabled="updateStage === 'checking' || updateStage === 'downloading'" @click="checkForUpdates">
                {{ updateStage === 'checking' ? '检查中' : '检查更新' }}
              </button>
              <button v-if="updateStage === 'available' || (updateStage === 'error' && release?.update_available)" class="ghost" @click="downloadUpdate">下载更新</button>
              <button v-if="updateStage === 'ready'" class="primary" @click="installUpdate">安装</button>
              <button v-if="release" class="ghost" @click="openReleasePage">打开发布页</button>
            </div>
          </div>
        </div>
        <div class="tabs">
          <button class="tab" @click="openVault">保险库</button>
          <button class="tab on">设置</button>
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
        <p v-if="sync?.last_result" class="hint">上次：{{ sync.last_result }}</p>
        <p v-if="error" class="error">{{ error }}</p>
        <button class="primary" :disabled="busy" @click="saveSync(true)">{{ busy ? "同步中" : "保存并同步" }}</button>
        <div v-if="report" class="secret">
          <div class="row"><span class="k">拉取</span><span>{{ report.pulled }}</span></div>
          <div class="row"><span class="k">推送</span><span>{{ report.pushed }}</span></div>
          <div class="row"><span class="k">未变</span><span>{{ report.unchanged }}</span></div>
          <p v-if="report.conflicts.length" class="error">冲突保留了本机：{{ report.conflicts.join("、") }}</p>
        </div>
        <p class="hint">远端只有加密快照。同步密钥解不开主密码。</p>
      </div>
    </section>
    <div v-if="toast" class="toast">{{ toast }}</div>
  </div>
</template>
