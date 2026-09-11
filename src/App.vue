<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import { listen } from "@tauri-apps/api/event";
import {
  api,
  type AuditEvent,
  type EntryDto,
  type EntryKind,
  type FolderDto,
  type ListFilter,
  type SecretPayload,
  type Status,
  type UpsertEntry,
} from "./lib/tauri";

const status = ref<Status | null>(null);
type Page = "home" | "vault" | "audit" | "settings" | "mcp";
const page = ref<Page>("vault");
const history = ref<Page[]>(["vault"]);
const historyIndex = ref(0);
const password = ref("");
const password2 = ref("");
const error = ref("");
const toast = ref("");
const entries = ref<EntryDto[]>([]);
const folders = ref<FolderDto[]>([]);
const tags = ref<string[]>([]);
const audit = ref<AuditEvent[]>([]);
const selected = ref<Set<string>>(new Set());
const filter = reactive<ListFilter>({
  query: "",
  kind: null,
  folder_id: null,
  uncategorized: false,
  tag: null,
  trash: false,
  sort: "use_count",
});
const showForm = ref(false);
const editing = ref<EntryDto | null>(null);
const form = reactive({
  kind: "website" as EntryKind,
  title: "",
  account: "",
  url: "",
  folder_id: "" as string | "",
  tags: "",
  notes: "",
  pinned: false,
  expires_at: "",
  password: "",
  token: "",
  service: "github",
  private_key: "",
  totp: "",
  key_type: "ed25519",
  email: "",
  imap_host: "",
  imap_port: 993,
  smtp_host: "",
  smtp_port: 465,
  provider: "qq",
  auth_code: "",
  host: "",
  port: 22,
  protocol: "ssh",
});
const reveal = ref<SecretPayload | null>(null);
const revealFor = ref<string | null>(null);
const quickOpen = ref(false);
const quickQuery = ref("");
const quickIndex = ref(0);
const backupOpen = ref(false);
const backupMode = ref<"export" | "import">("export");
const backupPath = ref("");
const backupPassword = ref("");
const backupOverwrite = ref(false);

const quickHits = computed(() => {
  const q = quickQuery.value.toLowerCase();
  return entries.value.filter(
    (e) =>
      e.title.toLowerCase().includes(q) ||
      (e.account || "").toLowerCase().includes(q) ||
      (e.url || "").toLowerCase().includes(q),
  );
});

const crumb = computed(() => {
  if (page.value === "home") return "首页";
  if (page.value === "audit") return "审计";
  if (page.value === "settings") return "设置";
  if (page.value === "mcp") return "MCP";
  if (filter.trash) return "回收站";
  if (filter.kind === "website") return "网站账号";
  if (filter.kind === "api_token") return "API Token";
  if (filter.kind === "ssh") return "SSH";
  if (filter.kind === "mailbox") return "邮箱";
  if (filter.kind === "mail_auth") return "邮箱授权码";
  if (filter.kind === "server") return "服务器";
  return "全部凭据";
});

function letterColor(title: string) {
  const colors = ["#5b5bd6", "#0ea5e9", "#16a34a", "#f59e0b", "#e11d48", "#8b5cf6"];
  return colors[(title.charCodeAt(0) || 0) % colors.length];
}
function kindLabel(k: EntryKind) {
  switch (k) {
    case "website": return "网站账号";
    case "api_token": return "API Token";
    case "ssh": return "SSH";
    case "mailbox": return "邮箱";
    case "mail_auth": return "邮箱授权码";
    case "server": return "服务器";
  }
}
function showToast(msg: string) {
  toast.value = msg;
  setTimeout(() => (toast.value = ""), 1800);
}
function fmtTime(s: string | null) {
  if (!s) return "—";
  return s.replace("T", " ").slice(0, 16);
}

async function refreshStatus() {
  status.value = await api.status();
}
async function refreshVault() {
  entries.value = await api.list({ ...filter, query: filter.query || null });
  folders.value = await api.folders();
  tags.value = await api.tags();
  status.value = await api.status();
}

async function doSetup() {
  error.value = "";
  if (password.value !== password2.value) {
    error.value = "两次密码不一致";
    return;
  }
  try {
    await api.setup(password.value);
    password.value = "";
    password2.value = "";
    await refreshStatus();
    await refreshVault();
  } catch (e) {
    error.value = String(e);
  }
}
async function doUnlock() {
  error.value = "";
  try {
    await api.unlock(password.value);
    password.value = "";
    await refreshStatus();
    await refreshVault();
  } catch {
    error.value = "主密码不正确";
  }
}
async function doHello() {
  try {
    await api.unlockHello();
    await refreshStatus();
    await refreshVault();
  } catch (e) {
    error.value = String(e);
  }
}
async function doLock() {
  await api.lock();
  entries.value = [];
  await refreshStatus();
}
async function openAudit() {
  goPage("audit");
  audit.value = await api.audit();
}
async function togglePin(row: EntryDto) {
  await api.pin(row.id, !row.pinned);
  await refreshVault();
}
async function doEmptyTrash() {
  if (!confirm("彻底删除回收站中的全部条目？不可恢复。")) return;
  await api.emptyTrash();
  selected.value.clear();
  await refreshVault();
}

const mcp = ref<{ running: boolean; port: number; token: string; url: string; fill_token: string; fill_url: string } | null>(null);
const mcpSnippet = computed(() => {
  if (!mcp.value?.token) return "";
  return `{
  "mcpServers": {
    "sealbox": {
      "url": "${mcp.value.url}",
      "headers": {
        "Authorization": "Bearer ${mcp.value.token}"
      }
    }
  }
}`;
});
async function refreshMcp() {
  mcp.value = await api.mcpStatus();
}
async function startMcp() {
  mcp.value = await api.mcpStart();
  showToast("MCP 已在本机启动");
}
async function stopMcp() {
  mcp.value = await api.mcpStop();
  showToast("MCP 已停止");
}
async function rotateMcp() {
  if (!confirm("轮换 Token 后，Cursor / Claude Code 里的旧配置会失效，确定？")) return;
  mcp.value = await api.mcpRotate();
  showToast("已轮换 Token");
}
async function copyMcpSnippet() {
  await navigator.clipboard.writeText(mcpSnippet.value);
  showToast("配置已复制");
}
async function copyFillToken() {
  if (!mcp.value?.fill_token) return;
  await navigator.clipboard.writeText(mcp.value.fill_token);
  showToast("填表 Token 已复制");
}
async function rotateFill() {
  if (!confirm("轮换填表 Token 后，浏览器插件里的旧 Token 会失效，确定？")) return;
  mcp.value = await api.fillRotate();
  showToast("已轮换填表 Token");
}
async function openMcp() {
  goPage("mcp");
  await refreshMcp();
}

function goPage(next: Page) {
  if (page.value === next) return;
  history.value = history.value.slice(0, historyIndex.value + 1);
  history.value.push(next);
  historyIndex.value = history.value.length - 1;
  page.value = next;
}
function goBack() {
  if (historyIndex.value <= 0) return;
  historyIndex.value -= 1;
  page.value = history.value[historyIndex.value];
}
function goForward() {
  if (historyIndex.value >= history.value.length - 1) return;
  historyIndex.value += 1;
  page.value = history.value[historyIndex.value];
}
const passwordHint = computed(() => {
  const p = password.value;
  if (!p) return "";
  if (p.length < 10) return "太短（至少 10 位）";
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;
  if (p.length >= 14 && classes >= 3) return "强度：强";
  if (p.length >= 12 && classes >= 2) return "强度：中";
  return "强度：弱（可用，建议更长或加符号）";
});

function setFilter(partial: Partial<ListFilter>) {
  Object.assign(filter, {
    kind: null,
    folder_id: null,
    uncategorized: false,
    tag: null,
    trash: false,
    ...partial,
  });
  refreshVault();
}

function openCreate() {
  editing.value = null;
  Object.assign(form, {
    kind: "website",
    title: "",
    account: "",
    url: "",
    folder_id: "",
    tags: "",
    notes: "",
    pinned: false,
    expires_at: "",
    password: "",
    token: "",
    service: "github",
    private_key: "",
    totp: "",
    key_type: "ed25519",
    email: "",
    imap_host: "",
    imap_port: 993,
    smtp_host: "",
    smtp_port: 465,
    provider: "qq",
    auth_code: "",
    host: "",
    port: 22,
    protocol: "ssh",
  });
  showForm.value = true;
}
async function openEdit(row: EntryDto) {
  editing.value = row;
  const secret = await api.reveal(row.id);
  const notes = await api.notes(row.id);
  form.kind = row.kind;
  form.title = row.title;
  form.account = row.account || "";
  form.url = row.url || "";
  form.folder_id = row.folder_id || "";
  form.tags = row.tags.join(", ");
  form.notes = notes || "";
  form.pinned = row.pinned;
  form.expires_at = row.expires_at ? row.expires_at.slice(0, 10) : "";
  if (secret.type === "website") {
    form.password = secret.password;
    form.totp = secret.totp_secret || "";
    form.url = secret.url || form.url;
    form.account = secret.username || form.account;
  } else if (secret.type === "api_token") {
    form.token = secret.token;
    form.service = secret.service;
    form.account = secret.account || form.account;
  } else if (secret.type === "mailbox") {
    form.email = secret.email;
    form.password = secret.password;
    form.imap_host = secret.imap_host || "";
    form.imap_port = secret.imap_port || 993;
    form.smtp_host = secret.smtp_host || "";
    form.smtp_port = secret.smtp_port || 465;
    form.account = secret.email;
  } else if (secret.type === "mail_auth") {
    form.email = secret.email;
    form.provider = secret.provider;
    form.auth_code = secret.auth_code;
    form.account = secret.email;
  } else if (secret.type === "server") {
    form.host = secret.host;
    form.port = secret.port || 22;
    form.protocol = secret.protocol;
    form.account = secret.username;
    form.password = secret.password;
  } else {
    form.private_key = secret.private_key;
    form.key_type = secret.key_type;
  }
  showForm.value = true;
}

function buildSecret(): SecretPayload {
  if (form.kind === "website") {
    return {
      type: "website",
      url: form.url || null,
      username: form.account || null,
      password: form.password,
      totp_secret: form.totp || null,
    };
  }
  if (form.kind === "api_token") {
    return { type: "api_token", service: form.service, account: form.account || null, token: form.token };
  }
  if (form.kind === "mailbox") {
    return {
      type: "mailbox",
      email: form.email,
      password: form.password,
      imap_host: form.imap_host || null,
      imap_port: form.imap_port || null,
      smtp_host: form.smtp_host || null,
      smtp_port: form.smtp_port || null,
    };
  }
  if (form.kind === "mail_auth") {
    return { type: "mail_auth", email: form.email, provider: form.provider, auth_code: form.auth_code };
  }
  if (form.kind === "server") {
    return {
      type: "server",
      host: form.host,
      port: form.port || null,
      protocol: form.protocol,
      username: form.account,
      password: form.password,
    };
  }
  return {
    type: "ssh",
    key_type: form.key_type,
    private_key: form.private_key,
    passphrase: null,
    public_fingerprint: null,
  };
}

async function saveEntry() {
  const input: UpsertEntry = {
    id: editing.value?.id ?? null,
    kind: form.kind,
    title: form.title,
    account: form.account || null,
    url: form.url || null,
    folder_id: form.folder_id || null,
    tags: form.tags
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    pinned: form.pinned,
    expires_at: form.expires_at || null,
    notes: form.notes || null,
    secret: buildSecret(),
  };
  await api.create(input);
  showForm.value = false;
  showToast("已保存");
  await refreshVault();
}

async function copy(id: string, field = "secret") {
  await api.copy(id, field);
  showToast(field === "account" ? "已复制账号" : field === "totp" ? "已复制验证码" : "已复制，20 秒后清空剪贴板");
  await refreshVault();
}
async function revealRow(row: EntryDto) {
  reveal.value = await api.reveal(row.id);
  revealFor.value = row.id;
  setTimeout(() => {
    reveal.value = null;
    revealFor.value = null;
  }, 10000);
}
async function remove(ids: string[]) {
  if (!confirm("移入回收站？")) return;
  await api.remove(ids);
  selected.value.clear();
  await refreshVault();
}
async function restore(ids: string[]) {
  await api.restore(ids);
  await refreshVault();
}
async function gen() {
  form.password = await api.genPassword({ length: 20, upper: true, lower: true, digits: true, symbols: true });
}
async function newFolder() {
  const name = prompt("文件夹名称");
  if (!name) return;
  await api.createFolder(name);
  await refreshVault();
}
async function runBackup() {
  if (!backupPath.value || !backupPassword.value) {
    showToast("请填写路径和主密码");
    return;
  }
  try {
    if (backupMode.value === "export") {
      await api.exportBackup(backupPassword.value, backupPath.value);
      showToast("已导出备份");
    } else {
      const [n, skip] = await api.importBackup(backupPassword.value, backupPath.value, backupOverwrite.value);
      showToast(`导入 ${n} 条，跳过 ${skip} 条`);
      await refreshVault();
    }
    backupOpen.value = false;
    backupPassword.value = "";
  } catch (e) {
    showToast(String(e));
  }
}
async function openQuick() {
  if (!status.value?.unlocked) return;
  await refreshVault();
  quickQuery.value = "";
  quickIndex.value = 0;
  quickOpen.value = true;
}
async function pickQuick() {
  const hit = quickHits.value[quickIndex.value];
  if (!hit) return;
  await copy(hit.id);
  quickOpen.value = false;
}

const settingsIdle = ref(15);
const settingsClip = ref(20);
const settingsHotkey = ref("Ctrl+Shift+Space");
const oldMaster = ref("");
const newMaster = ref("");
const newMaster2 = ref("");
const recent = ref<EntryDto[]>([]);
const expiring = ref<EntryDto[]>([]);

async function loadSettings() {
  const s = await api.settingsGet();
  settingsIdle.value = Math.round(s.idle_secs / 60);
  settingsClip.value = s.clipboard_secs;
  settingsHotkey.value = s.hotkey;
}
async function saveSettings() {
  try {
    await api.settingsSet({
      idle_secs: settingsIdle.value * 60,
      clipboard_secs: settingsClip.value,
      hotkey: settingsHotkey.value,
    });
    showToast("设置已保存");
  } catch (e) {
    showToast("热键可能被占用：" + String(e));
  }
}
async function doChangeMaster() {
  if (newMaster.value.length < 10) {
    showToast("新主密码至少 10 位");
    return;
  }
  if (newMaster.value !== newMaster2.value) {
    showToast("两次新密码不一致");
    return;
  }
  try {
    await api.changeMaster(oldMaster.value, newMaster.value);
    oldMaster.value = "";
    newMaster.value = "";
    newMaster2.value = "";
    showToast("主密码已更新");
  } catch (e) {
    showToast(String(e));
  }
}
async function loadHome() {
  goPage("home");
  const h = await api.home();
  recent.value = h.recent;
  expiring.value = h.expiring;
  status.value = { ...(status.value as Status), counts: h.counts };
}
async function pickBackupFile(mode: "export" | "import") {
  const { save, open } = await import("@tauri-apps/plugin-dialog");
  if (mode === "export") {
    const p = await save({
      defaultPath: "sealbox.svbak",
      filters: [{ name: "Sealbox backup", extensions: ["svbak"] }],
    });
    if (p) backupPath.value = p;
  } else {
    const p = await open({
      multiple: false,
      filters: [{ name: "Sealbox backup", extensions: ["svbak"] }],
    });
    if (typeof p === "string") backupPath.value = p;
  }
}

function onKey(e: KeyboardEvent) {
  if (e.ctrlKey && e.key.toLowerCase() === "f" && status.value?.unlocked && !quickOpen.value) {
    const el = document.querySelector(".search") as HTMLInputElement | null;
    el?.focus();
  }
  if (quickOpen.value) {
    if (e.key === "Escape") quickOpen.value = false;
    if (e.key === "ArrowDown") quickIndex.value = Math.min(quickIndex.value + 1, Math.max(quickHits.value.length - 1, 0));
    if (e.key === "ArrowUp") quickIndex.value = Math.max(quickIndex.value - 1, 0);
    if (e.key === "Enter") pickQuick();
  }
}

onMounted(async () => {
  await refreshStatus();
  if (status.value?.unlocked) await refreshVault();
  await loadSettings();
  window.addEventListener("keydown", onKey);
  const unTick = await listen("tick", async () => {
    const locked = await api.tick();
    if (locked) {
      entries.value = [];
      quickOpen.value = false;
      await refreshStatus();
    }
  });
  const unLock = await listen("lock-now", () => doLock());
  const unQuick = await listen("quick-search", async () => {
    await refreshStatus();
    if (status.value?.unlocked) await openQuick();
    else {
      const el = document.querySelector(".unlock input") as HTMLInputElement | null;
      el?.focus();
    }
  });
  onUnmounted(() => {
    window.removeEventListener("keydown", onKey);
    unTick();
    unLock();
    unQuick();
  });
});
</script>

<template>
  <div class="app">
    <header class="titlebar" data-tauri-drag-region>
      <div class="drag" data-tauri-drag-region>
        <button class="nav-btn" :disabled="historyIndex <= 0" @click="goBack">←</button>
        <button class="nav-btn" :disabled="historyIndex >= history.length - 1" @click="goForward">→</button>
        <strong>Sealbox</strong>
        <span class="crumb">保险库 &gt; <strong>{{ crumb }}</strong></span>
        <span v-if="status?.unlocked" class="status-dot" />
        <span v-if="status?.unlocked" class="badge">{{ status.counts?.total ?? entries.length }} 凭据</span>
      </div>
      <button class="btn" v-if="status?.unlocked" @click="doLock">锁定</button>
      <div class="win-btns">
        <button @click="api.window('minimize')">—</button>
        <button @click="api.window('maximize')">□</button>
        <button class="close" @click="api.window('close')">×</button>
      </div>
    </header>

    <div class="body" v-if="!status">加载中…</div>

    <div class="body" v-else-if="!status.initialized">
      <div class="unlock">
        <h1>创建金库</h1>
        <p>主密码至少 10 位，请务必记住——备份和解锁都靠它。</p>
        <p v-if="error" class="error">{{ error }}</p>
        <input v-model="password" type="password" placeholder="主密码" />
        <p class="crumb" v-if="passwordHint">{{ passwordHint }}</p>
        <input v-model="password2" type="password" placeholder="再输入一次" @keyup.enter="doSetup" />
        <button class="btn primary" style="width:100%" @click="doSetup">创建</button>
        <button class="btn" style="width:100%;margin-top:8px" @click="backupMode = 'import'; backupOpen = true">从备份导入</button>
      </div>
    </div>

    <div class="body" v-else-if="!status.unlocked">
      <div class="unlock">
        <h1>解锁印盒</h1>
        <p>输入主密码，或使用 Windows Hello。</p>
        <p v-if="error" class="error">{{ error }}</p>
        <input v-model="password" type="password" placeholder="主密码" @keyup.enter="doUnlock" />
        <button class="btn primary" style="width:100%;margin-bottom:8px" @click="doUnlock">解锁</button>
        <button class="btn" style="width:100%" v-if="status.hello_enabled && status.hello_available" @click="doHello">
          Windows Hello
        </button>
      </div>
    </div>

    <div class="body" v-else>
      <nav class="rail">
        <button class="rail-btn" :class="{ active: page === 'home' }" @click="loadHome">
          <span class="icon">⌂</span><span>首页</span>
        </button>
        <button class="rail-btn" :class="{ active: page === 'vault' }" @click="goPage('vault')">
          <span class="icon">▣</span><span>保险库</span>
        </button>
        <button class="rail-btn" :class="{ active: page === 'audit' }" @click="openAudit">
          <span class="icon">≡</span><span>审计</span>
        </button>
        <button class="rail-btn" :class="{ active: page === 'mcp' }" @click="openMcp">
          <span class="icon">⬡</span><span>MCP</span>
        </button>
        <div class="spacer" />
        <button class="rail-btn" :class="{ active: page === 'settings' }" @click="goPage('settings')">
          <span class="icon">⚙</span><span>设置</span>
        </button>
      </nav>

      <section class="main" v-if="page === 'home'">
        <div class="content">
          <h2>概览</h2>
          <p>全部 {{ status.counts?.total ?? 0 }} · 网站 {{ status.counts?.website ?? 0 }} · Token {{ status.counts?.api_token ?? 0 }} · SSH {{ status.counts?.ssh ?? 0 }} · 邮箱 {{ status.counts?.mailbox ?? 0 }} · 授权码 {{ status.counts?.mail_auth ?? 0 }} · 服务器 {{ status.counts?.server ?? 0 }} · 回收站 {{ status.counts?.trash ?? 0 }}</p>
          <h3>最近使用</h3>
          <div class="table" v-if="recent.length">
            <table>
              <tbody>
                <tr v-for="row in recent" :key="row.id">
                  <td>{{ row.title }}</td>
                  <td>{{ row.account || "—" }}</td>
                  <td>{{ fmtTime(row.last_used_at) }}</td>
                  <td><button class="btn" @click="copy(row.id)">复制</button></td>
                </tr>
              </tbody>
            </table>
          </div>
          <p class="crumb" v-else>还没有使用记录</p>
          <h3>30 天内过期</h3>
          <div class="table" v-if="expiring.length">
            <table>
              <tbody>
                <tr v-for="row in expiring" :key="'e'+row.id">
                  <td>{{ row.title }}</td>
                  <td>{{ fmtTime(row.expires_at) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p class="crumb" v-else>没有即将过期的条目</p>
        </div>
      </section>

      <section class="main" v-else-if="page === 'vault'">
        <aside class="sidebar">
          <div class="side-label">分类</div>
          <button class="side-item" :class="{ active: !filter.kind && !filter.trash && !filter.folder_id && !filter.uncategorized && !filter.tag }" @click="setFilter({})">
            <span>全部凭据</span><span class="count">{{ status.counts?.total }}</span>
          </button>
          <div class="side-label">类型</div>
          <button class="side-item" :class="{ active: filter.kind === 'api_token' }" @click="setFilter({ kind: 'api_token' })">
            <span>API Token</span><span class="count">{{ status.counts?.api_token }}</span>
          </button>
          <button class="side-item" :class="{ active: filter.kind === 'website' }" @click="setFilter({ kind: 'website' })">
            <span>网站账号</span><span class="count">{{ status.counts?.website }}</span>
          </button>
          <button class="side-item" :class="{ active: filter.kind === 'ssh' }" @click="setFilter({ kind: 'ssh' })">
            <span>SSH</span><span class="count">{{ status.counts?.ssh }}</span>
          </button>
          <button class="side-item" :class="{ active: filter.kind === 'mailbox' }" @click="setFilter({ kind: 'mailbox' })">
            <span>邮箱</span><span class="count">{{ status.counts?.mailbox }}</span>
          </button>
          <button class="side-item" :class="{ active: filter.kind === 'mail_auth' }" @click="setFilter({ kind: 'mail_auth' })">
            <span>邮箱授权码</span><span class="count">{{ status.counts?.mail_auth }}</span>
          </button>
          <button class="side-item" :class="{ active: filter.kind === 'server' }" @click="setFilter({ kind: 'server' })">
            <span>服务器</span><span class="count">{{ status.counts?.server }}</span>
          </button>
          <div class="side-label" v-if="tags.length">标签</div>
          <button class="side-item" v-for="t in tags" :key="t" :class="{ active: filter.tag === t }" @click="setFilter({ tag: t })">{{ t }}</button>
          <div class="side-label">文件夹 <a href="#" @click.prevent="newFolder">新建</a></div>
          <button class="side-item" :class="{ active: filter.uncategorized }" @click="setFilter({ uncategorized: true })">未归类</button>
          <button class="side-item" v-for="f in folders" :key="f.id" :class="{ active: filter.folder_id === f.id }" @click="setFilter({ folder_id: f.id })">{{ f.name }}</button>
          <div class="side-label">其他</div>
          <button class="side-item" :class="{ active: filter.trash }" @click="setFilter({ trash: true })">
            回收站<span class="count">{{ status.counts?.trash }}</span>
          </button>
          <button class="side-item" @click="backupMode = 'export'; backupOpen = true">备份 / 还原</button>
        </aside>
        <div class="content">
          <div class="toolbar">
            <input class="search" v-model="filter.query" placeholder="搜索键名 / 账号 / 网址… (Ctrl+F)" @keyup.enter="refreshVault" />
            <select class="btn" v-model="filter.sort" @change="refreshVault">
              <option value="use_count">使用次数</option>
              <option value="updated">修改时间</option>
              <option value="title">键名</option>
            </select>
            <button class="btn primary" @click="openCreate">+ 新建凭据</button>
          </div>
          <div class="toolbar" v-if="selected.size">
            <button class="btn danger" @click="remove([...selected])">移入回收站 ({{ selected.size }})</button>
          </div>
          <div class="toolbar" v-if="filter.trash && entries.length">
            <button class="btn danger" @click="doEmptyTrash">清空回收站</button>
          </div>
          <div class="table">
            <table v-if="entries.length">
              <thead>
                <tr>
                  <th></th><th>键名</th><th>关联账号</th><th>类型</th><th>修改时间</th><th>次数</th><th>过期</th><th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in entries" :key="row.id">
                  <td><input type="checkbox" :checked="selected.has(row.id)" @change="selected.has(row.id) ? selected.delete(row.id) : selected.add(row.id)" /></td>
                  <td>
                    <span class="letter" :style="{ background: letterColor(row.title) }">{{ row.title.slice(0,1).toUpperCase() }}</span>
                    {{ row.title }}
                    <button v-if="!filter.trash" class="pin" :class="{ on: row.pinned }" @click="togglePin(row)">{{ row.pinned ? "📌" : "📍" }}</button>
                  </td>
                  <td>
                    {{ row.account || row.fingerprint || "—" }}
                    <div v-if="revealFor === row.id && reveal" style="font-size:12px;color:var(--muted);margin-top:4px;word-break:break-all">
                      <template v-if="reveal.type === 'website' || reveal.type === 'mailbox' || reveal.type === 'server'">{{ reveal.password }}</template>
                      <template v-else-if="reveal.type === 'api_token'">{{ reveal.token }}</template>
                      <template v-else-if="reveal.type === 'mail_auth'">{{ reveal.auth_code }}</template>
                      <template v-else>已显示私钥</template>
                    </div>
                  </td>
                  <td><span class="pill" :class="row.kind">{{ kindLabel(row.kind) }}</span></td>
                  <td>{{ fmtTime(row.updated_at) }}<div v-if="row.has_totp" style="color:var(--muted);font-size:12px">TOTP</div></td>
                  <td>{{ row.use_count }}</td>
                  <td>{{ row.expires_at ? fmtTime(row.expires_at) : "永不" }}</td>
                  <td class="row-actions">
                    <button title="复制" @click="copy(row.id)">复制</button>
                    <button title="复制账号" @click="copy(row.id, 'account')">账号</button>
                    <button v-if="row.has_totp" @click="copy(row.id, 'totp')">TOTP</button>
                    <button v-if="filter.trash" @click="restore([row.id])">还原</button>
                    <button v-else @click="revealRow(row)">显示</button>
                    <button v-if="!filter.trash" @click="openEdit(row)">编辑</button>
                    <button v-if="!filter.trash" class="danger" @click="remove([row.id])">删</button>
                  </td>
                </tr>
              </tbody>
            </table>
            <div class="empty" v-else>
              还没有凭据。
              <div style="margin-top:12px"><button class="btn primary" @click="openCreate">新建凭据</button></div>
            </div>
          </div>
        </div>
      </section>

      <section class="main" v-else-if="page === 'mcp'">
        <div class="content" style="max-width:640px">
          <h2>MCP 接入</h2>
          <p class="crumb">仅监听 127.0.0.1。模型只能看到凭据名称，发 HTTP 时由本机代签并脱敏。</p>
          <p>状态：{{ mcp?.running ? "运行中" : "已停止" }}　端口：{{ mcp?.port || "—" }}</p>
          <div style="display:flex;gap:8px;margin:12px 0">
            <button class="btn primary" v-if="!mcp?.running" @click="startMcp">启动</button>
            <button class="btn" v-else @click="stopMcp">停止</button>
            <button class="btn" @click="rotateMcp">轮换 Token</button>
          </div>
          <div class="field"><label>Bearer Token</label>
            <input :value="mcp?.token || ''" readonly />
          </div>
          <div class="field"><label>Cursor / Claude Code 配置片段</label>
            <textarea rows="12" readonly :value="mcpSnippet"></textarea>
          </div>
          <button class="btn" @click="copyMcpSnippet">复制配置</button>
          <h3 style="margin-top:28px">浏览器插件</h3>
          <p class="crumb">Chrome / Edge：打开 chrome://extensions → 加载已解压的扩展程序 → 选择仓库里的 extension 目录。把下面 Token 贴进插件弹窗。</p>
          <div class="field"><label>填表 Token</label>
            <div style="display:flex;gap:8px">
              <input :value="mcp?.fill_token || ''" readonly style="flex:1" />
              <button class="btn" @click="copyFillToken">复制</button>
              <button class="btn" @click="rotateFill">轮换</button>
            </div>
          </div>
          <p class="crumb">接口：{{ mcp?.fill_url || "http://127.0.0.1:17891/fill" }}。应用启动后自动监听本机端口。</p>
          <p class="crumb" style="margin-top:16px">MCP 工具：list_credentials、http_request、copy_secret。金库锁定时工具会失败并提示先解锁。</p>
        </div>
      </section>

      <section class="main" v-else-if="page === 'audit'">
        <div class="content">
          <h2>审计</h2>
          <div class="table">
            <table>
              <thead><tr><th>时间</th><th>动作</th><th>详情</th></tr></thead>
              <tbody>
                <tr v-for="a in audit" :key="a.id">
                  <td>{{ fmtTime(a.at) }}</td>
                  <td>{{ a.action }}</td>
                  <td>{{ a.detail }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section class="main" v-else>
        <div class="content" style="max-width:480px">
          <h2>设置</h2>
          <div class="field"><label>空闲锁定（分钟）</label><input type="number" v-model.number="settingsIdle" /></div>
          <div class="field"><label>剪贴板清空（秒）</label><input type="number" v-model.number="settingsClip" /></div>
          <div class="field"><label>全局热键</label><input v-model="settingsHotkey" placeholder="Ctrl+Shift+Space" /></div>
          <button class="btn primary" @click="saveSettings">保存</button>
          <div class="field" style="margin-top:24px">
            <label>Windows Hello</label>
            <button class="btn" @click="api.setHello(true).then(() => showToast('已开启'))">开启</button>
            <button class="btn" @click="api.setHello(false).then(() => showToast('已关闭'))">关闭</button>
          </div>
          <h3 style="margin-top:28px">修改主密码</h3>
          <div class="field"><label>当前主密码</label><input v-model="oldMaster" type="password" /></div>
          <div class="field"><label>新主密码</label><input v-model="newMaster" type="password" /></div>
          <div class="field"><label>确认新主密码</label><input v-model="newMaster2" type="password" /></div>
          <button class="btn" @click="doChangeMaster">更新主密码</button>
          <p class="crumb" style="margin-top:16px">关闭窗口进入托盘。全局热键默认 Ctrl+Shift+Space，即使窗口不在前台也能打开速查。</p>
        </div>
      </section>
    </div>

    <div class="dialog-mask" v-if="showForm" @click.self="showForm = false">
      <div class="dialog">
        <h3>{{ editing ? "编辑凭据" : "新建凭据" }}</h3>
        <div class="field"><label>类型</label>
          <select v-model="form.kind">
            <option value="website">网站账号</option>
            <option value="api_token">API Token</option>
            <option value="ssh">SSH 私钥</option>
            <option value="mailbox">邮箱</option>
            <option value="mail_auth">邮箱授权码</option>
            <option value="server">服务器账号</option>
          </select>
        </div>
        <div class="field"><label>键名</label><input v-model="form.title" /></div>
        <div class="field" v-if="form.kind !== 'ssh' && form.kind !== 'mailbox' && form.kind !== 'mail_auth'"><label>{{ form.kind === 'server' ? '用户名' : '账号' }}</label><input v-model="form.account" /></div>
        <div class="field" v-if="form.kind === 'website'"><label>网址</label><input v-model="form.url" /></div>
        <div class="field" v-if="form.kind === 'website' || form.kind === 'mailbox' || form.kind === 'server'"><label>密码</label>
          <div style="display:flex;gap:8px">
            <input v-model="form.password" type="password" style="flex:1" />
            <button class="btn" @click="gen">生成</button>
          </div>
        </div>
        <div class="field" v-if="form.kind === 'website'"><label>TOTP 密钥（可选）</label><input v-model="form.totp" /></div>
        <div class="field" v-if="form.kind === 'api_token'"><label>服务</label>
          <select v-model="form.service">
            <option value="github">GitHub</option>
            <option value="gitee">Gitee</option>
            <option value="gitlab">GitLab</option>
            <option value="custom">自定义</option>
          </select>
        </div>
        <div class="field" v-if="form.kind === 'api_token'"><label>Token</label><input v-model="form.token" /></div>
        <div class="field" v-if="form.kind === 'ssh'"><label>密钥类型</label><input v-model="form.key_type" /></div>
        <div class="field" v-if="form.kind === 'ssh'"><label>私钥</label><textarea v-model="form.private_key" rows="6" /></div>
        <div class="field" v-if="form.kind === 'mailbox' || form.kind === 'mail_auth'"><label>邮箱地址</label><input v-model="form.email" placeholder="name@example.com" /></div>
        <div class="field" v-if="form.kind === 'mailbox'"><label>IMAP 主机</label><input v-model="form.imap_host" placeholder="imap.example.com" /></div>
        <div class="field" v-if="form.kind === 'mailbox'"><label>IMAP 端口</label><input v-model.number="form.imap_port" type="number" /></div>
        <div class="field" v-if="form.kind === 'mailbox'"><label>SMTP 主机</label><input v-model="form.smtp_host" placeholder="smtp.example.com" /></div>
        <div class="field" v-if="form.kind === 'mailbox'"><label>SMTP 端口</label><input v-model.number="form.smtp_port" type="number" /></div>
        <div class="field" v-if="form.kind === 'mail_auth'"><label>服务商</label>
          <select v-model="form.provider">
            <option value="qq">QQ 邮箱</option>
            <option value="163">网易 163</option>
            <option value="gmail">Gmail</option>
            <option value="outlook">Outlook</option>
            <option value="custom">其他</option>
          </select>
        </div>
        <div class="field" v-if="form.kind === 'mail_auth'"><label>授权码</label><input v-model="form.auth_code" type="password" /></div>
        <div class="field" v-if="form.kind === 'server'"><label>协议</label>
          <select v-model="form.protocol">
            <option value="ssh">SSH</option>
            <option value="rdp">RDP</option>
            <option value="sftp">SFTP</option>
            <option value="ftp">FTP</option>
            <option value="vnc">VNC</option>
          </select>
        </div>
        <div class="field" v-if="form.kind === 'server'"><label>主机</label><input v-model="form.host" placeholder="192.168.1.10 或 example.com" /></div>
        <div class="field" v-if="form.kind === 'server'"><label>端口</label><input v-model.number="form.port" type="number" /></div>
        <div class="field"><label>文件夹</label>
          <select v-model="form.folder_id">
            <option value="">未归类</option>
            <option v-for="f in folders" :key="f.id" :value="f.id">{{ f.name }}</option>
          </select>
        </div>
        <div class="field"><label>标签（逗号分隔）</label><input v-model="form.tags" /></div>
        <div class="field"><label>过期日期（可空）</label><input v-model="form.expires_at" type="date" /></div>
        <div class="field"><label><input type="checkbox" v-model="form.pinned" /> 置顶</label></div>
        <div class="field"><label>备注</label><textarea v-model="form.notes" rows="3" /></div>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
          <button class="btn" @click="showForm = false">取消</button>
          <button class="btn primary" @click="saveEntry">保存</button>
        </div>
      </div>
    </div>
    <div class="dialog-mask" v-if="backupOpen" @click.self="backupOpen = false">
      <div class="dialog">
        <h3>备份 / 还原</h3>
        <div class="field">
          <label>操作</label>
          <select v-model="backupMode">
            <option value="export">导出加密备份</option>
            <option value="import">导入备份</option>
          </select>
        </div>
        <div class="field"><label>文件路径（.svbak）</label>
          <div style="display:flex;gap:8px">
            <input v-model="backupPath" placeholder="选择或输入路径" style="flex:1" />
            <button class="btn" @click="pickBackupFile(backupMode)">浏览</button>
          </div>
        </div>
        <div class="field"><label>主密码</label><input v-model="backupPassword" type="password" /></div>
        <div class="field" v-if="backupMode === 'import'">
          <label><input type="checkbox" v-model="backupOverwrite" /> 覆盖已有同 id 条目</label>
        </div>
        <div style="display:flex;gap:8px;justify-content:flex-end">
          <button class="btn" @click="backupOpen = false">取消</button>
          <button class="btn primary" @click="runBackup">确定</button>
        </div>
      </div>
    </div>
    <div class="dialog-mask" v-if="quickOpen" @click.self="quickOpen = false">
      <div class="dialog" style="width:420px">
        <input class="search" v-model="quickQuery" placeholder="搜索并回车复制…" autofocus />
        <div v-for="(row, i) in quickHits" :key="row.id" class="side-item" :class="{ active: i === quickIndex }" @click="quickIndex = i; pickQuick()">
          <span>{{ row.title }}</span>
          <span class="count">{{ kindLabel(row.kind) }}</span>
        </div>
        <p class="crumb" v-if="!quickHits.length">没有匹配</p>
      </div>
    </div>
    <div class="toast" v-if="toast">{{ toast }}</div>
  </div>
</template>
