<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, reactive, ref } from "vue";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  api,
  type AuditEvent,
  type Counts,
  type EntryDto,
  type EntryKind,
  type FolderDto,
  type ListFilter,
  type McpStatus,
  type SecretPayload,
  type Status,
  type UpsertEntry,
} from "./lib/tauri";

const status = ref<Status | null>(null);
type Page = "home" | "vault" | "audit" | "settings" | "mcp" | "plugin";
const page = ref<Page>("vault");
const history = ref<Page[]>(["vault"]);
const historyIndex = ref(0);
const password = ref("");
const password2 = ref("");
const error = ref("");
const toast = ref("");
const entries = ref<EntryDto[]>([]);
const scopedCounts = ref<Counts | null>(null);
const folders = ref<FolderDto[]>([]);
const tags = ref<string[]>([]);
const audit = ref<AuditEvent[]>([]);
const selected = ref<Set<string>>(new Set());
const filter = reactive<ListFilter>({
  query: "",
  kind: null,
  kinds: [],
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
  engine: "mysql",
  db_name: "",
});
const generatorOpen = ref(false);
const generatorBusy = ref(false);
const generator = reactive({
  mode: "password" as "password" | "passphrase",
  length: 20,
  upper: true,
  lower: true,
  digits: true,
  symbols: true,
  ensureEach: true,
  wordCount: 4,
  separator: "-",
});
const generatorNoClasses = computed(
  () => generator.mode === "password" && !generator.upper && !generator.lower && !generator.digits && !generator.symbols,
);
const reveal = ref<SecretPayload | null>(null);
const revealFor = ref<string | null>(null);
const backupOpen = ref(false);
const backupMode = ref<"export" | "import">("export");
const backupPath = ref("");
const backupPassword = ref("");
const backupOverwrite = ref(false);

const KIND_ITEMS: { id: EntryKind; label: string }[] = [
  { id: "website", label: "网站账号" },
  { id: "api_token", label: "API Token" },
  { id: "ssh", label: "SSH" },
  { id: "mailbox", label: "邮箱" },
  { id: "mail_auth", label: "邮箱授权码" },
  { id: "server", label: "服务器" },
  { id: "database", label: "数据库" },
];
const selectedKindIds = computed(() => {
  const ids = [...(filter.kinds ?? [])];
  if (filter.kind && !ids.includes(filter.kind)) ids.push(filter.kind);
  return ids;
});
const crumb = computed(() => {
  if (page.value === "home") return "首页";
  if (page.value === "audit") return "审计";
  if (page.value === "settings") return "设置";
  if (page.value === "mcp") return "MCP";
  if (page.value === "plugin") return "插件";
  if (filter.trash) return "回收站";
  const selectedKinds = selectedKindIds.value;
  if (selectedKinds.length === 1) {
    return KIND_ITEMS.find((item) => item.id === selectedKinds[0])?.label ?? "全部凭据";
  }
  if (selectedKinds.length > 1) return `已选 ${selectedKinds.length} 种类型`;
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
    case "database": return "数据库";
  }
}
function kindCount(k: EntryKind) {
  return scopedCounts.value?.[k] ?? 0;
}
const allFilterActive = computed(
  () => !filter.trash && !filter.folder_id && !filter.uncategorized && !filter.tag,
);
const DB_ENGINES: { id: string; label: string; port: number }[] = [
  { id: "mysql", label: "MySQL / MariaDB", port: 3306 },
  { id: "postgres", label: "PostgreSQL", port: 5432 },
  { id: "sqlserver", label: "SQL Server", port: 1433 },
  { id: "oracle", label: "Oracle", port: 1521 },
  { id: "mongodb", label: "MongoDB", port: 27017 },
  { id: "redis", label: "Redis", port: 6379 },
  { id: "sqlite", label: "SQLite", port: 0 },
  { id: "clickhouse", label: "ClickHouse", port: 8123 },
  { id: "elasticsearch", label: "Elasticsearch", port: 9200 },
  { id: "dameng", label: "达梦 DM", port: 5236 },
  { id: "custom", label: "其他", port: 0 },
];
function onEngineChange() {
  const e = DB_ENGINES.find((x) => x.id === form.engine);
  if (e && e.port) form.port = e.port;
}
function showToast(msg: string) {
  toast.value = msg;
  setTimeout(() => (toast.value = ""), 1800);
}
const REVEAL_HIDE_MS = 20_000;
let revealTimer: ReturnType<typeof setTimeout> | null = null;
function hideSecret() {
  reveal.value = null;
  revealFor.value = null;
  if (revealTimer) {
    clearTimeout(revealTimer);
    revealTimer = null;
  }
}
function scheduleRevealHide() {
  if (revealTimer) clearTimeout(revealTimer);
  revealTimer = setTimeout(hideSecret, REVEAL_HIDE_MS);
}
function resetGenerator() {
  Object.assign(generator, {
    mode: "password",
    length: 20,
    upper: true,
    lower: true,
    digits: true,
    symbols: true,
    ensureEach: true,
    wordCount: 4,
    separator: "-",
  });
  generatorOpen.value = false;
  generatorBusy.value = false;
}
function resetFormFields() {
  resetGenerator();
  Object.assign(form, {
    kind: "website" as EntryKind,
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
    engine: "mysql",
    db_name: "",
  });
}
function fmtTime(s: string | null) {
  if (!s) return "—";
  return s.replace("T", " ").slice(0, 16);
}

async function refreshStatus() {
  status.value = await api.status();
}
async function refreshVault() {
  const kinds = selectedKindIds.value;
  const scoped = {
    ...filter,
    query: filter.query || null,
    kinds,
    kind: kinds.length === 1 ? kinds[0] : null,
  };
  entries.value = await api.list(scoped);
  scopedCounts.value = await api.counts({
    ...scoped,
    kinds: [],
    kind: null,
  });
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

const mcp = ref<McpStatus | null>(null);
const pairing = ref<{ active: boolean; code: string | null; expires_in_secs: number; port: number } | null>(null);
const pairingError = ref("");
const pairingBusy = ref(false);
const revealedFillToken = ref("");
const revealedMcpToken = ref("");
const revealedMcpSnippet = ref("");
const httpLogs = ref<
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
>([]);
const openHttpLog = ref<string | null>(null);
const mcpTools = ref<{ name: string; description: string }[]>([]);
let pairingTimer: ReturnType<typeof setInterval> | null = null;
function hideBridgeTokens() {
  revealedFillToken.value = "";
  revealedMcpToken.value = "";
  revealedMcpSnippet.value = "";
}
async function refreshMcp() {
  hideBridgeTokens();
  mcp.value = await api.mcpStatus();
  try {
    mcpTools.value = await api.mcpTools();
  } catch {
    mcpTools.value = [];
  }
  try {
    httpLogs.value = await api.mcpHttpLogs();
  } catch {
    httpLogs.value = [];
  }
}
async function startMcp() {
  hideBridgeTokens();
  mcp.value = await api.mcpStart();
  showToast("MCP 已在本机启动");
}
async function stopMcp() {
  hideBridgeTokens();
  mcp.value = await api.mcpStop();
  showToast("MCP 已停止");
}
async function rotateMcp() {
  if (!confirm("轮换 Token 后，Cursor / Claude Code 里的旧配置会失效，确定？")) return;
  hideBridgeTokens();
  mcp.value = await api.mcpRotate();
  showToast("已轮换 Token");
}
async function copyMcpSnippet() {
  try {
    await api.copyMcpSnippet();
    showToast("配置已复制，将按剪贴板超时清空");
  } catch (e) {
    showToast(String(e));
  }
}
async function copyFillToken() {
  try {
    await api.copyFillToken();
    showToast("填表 Token 已复制，将按剪贴板超时清空");
  } catch (e) {
    showToast(String(e));
  }
}
async function copyMcpToken() {
  try {
    await api.copyMcpToken();
    showToast("MCP Token 已复制，将按剪贴板超时清空");
  } catch (e) {
    showToast(String(e));
  }
}
async function toggleMcpToken() {
  if (revealedMcpToken.value) {
    revealedMcpToken.value = "";
    revealedMcpSnippet.value = "";
    return;
  }
  try {
    revealedMcpToken.value = await api.revealMcpToken();
    revealedMcpSnippet.value = `{
  "mcpServers": {
    "sealbox": {
      "url": "${mcp.value?.url || ""}",
      "headers": {
        "Authorization": "Bearer ${revealedMcpToken.value}"
      }
    }
  }
}`;
  } catch (e) {
    showToast(String(e));
  }
}
async function toggleFillToken() {
  if (revealedFillToken.value) {
    revealedFillToken.value = "";
    return;
  }
  try {
    revealedFillToken.value = await api.revealFillToken();
  } catch (e) {
    showToast(String(e));
  }
}
async function rotateFill() {
  if (!confirm("轮换填表 Token 后，已配对的浏览器插件会失效，需要重新输入配对码。确定？")) return;
  hideBridgeTokens();
  mcp.value = await api.fillRotate();
  showToast("已轮换填表 Token");
}
function stopPairingTimer() {
  if (pairingTimer) {
    clearInterval(pairingTimer);
    pairingTimer = null;
  }
}
function pairingLabel(code: string | null | undefined) {
  const raw = String(code || "").replace(/[^A-Za-z0-9]/g, "").toUpperCase();
  if (raw.length < 4) return raw;
  return `${raw.slice(0, 4)} ${raw.slice(4)}`;
}
async function refreshPairing() {
  try {
    const next = await api.fillPairingStatus();
    if (next?.active && next.code) {
      pairing.value = next;
      pairingError.value = "";
      return;
    }
    pairing.value = null;
    stopPairingTimer();
  } catch {
    stopPairingTimer();
  }
}
async function openFillPairing() {
  if (pairingBusy.value) return;
  pairingBusy.value = true;
  pairingError.value = "";
  try {
    const next = await api.fillOpenPairing();
    const code = String(next?.code || "").trim();
    if (!code) {
      pairingError.value = "未能打开配对窗口，请确认金库已解锁，并重新启动一次 Sealbox。";
      showToast(pairingError.value);
      return;
    }
    pairing.value = {
      active: true,
      code,
      expires_in_secs: Number(next.expires_in_secs) || 60,
      port: next.port,
    };
    showToast("配对码已生成");
    stopPairingTimer();
    const openedAt = Date.now();
    const total = pairing.value.expires_in_secs;
    pairingTimer = setInterval(() => {
      const left = Math.max(0, total - Math.floor((Date.now() - openedAt) / 1000));
      if (left <= 0) {
        pairing.value = null;
        stopPairingTimer();
        return;
      }
      if (pairing.value) pairing.value = { ...pairing.value, expires_in_secs: left, active: true };
    }, 250);
    await nextTick();
    document.getElementById("pairing-code-box")?.scrollIntoView({ behavior: "smooth", block: "center" });
  } catch (e) {
    pairing.value = null;
    pairingError.value = String(e);
    showToast(pairingError.value);
  } finally {
    pairingBusy.value = false;
  }
}
async function copyPairingCode() {
  if (!pairing.value?.code) return;
  await navigator.clipboard.writeText(pairing.value.code);
  showToast("配对码已复制");
}
async function openMcp() {
  goPage("mcp");
  await refreshMcp();
}
async function openPlugin() {
  goPage("plugin");
  await refreshMcp();
  await refreshPairing();
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
    folder_id: null,
    uncategorized: false,
    tag: null,
    trash: false,
    ...partial,
  });
  refreshVault();
}

function toggleKind(kind: EntryKind) {
  const next = new Set(selectedKindIds.value);
  if (next.has(kind)) next.delete(kind);
  else next.add(kind);
  const kinds = KIND_ITEMS.map((item) => item.id).filter((id) => next.has(id));
  filter.kinds = kinds;
  filter.kind = kinds.length === 1 ? kinds[0] : null;
  refreshVault();
}

function isKindSelected(kind: EntryKind) {
  return selectedKindIds.value.includes(kind);
}

function closeForm() {
  showForm.value = false;
  editing.value = null;
  resetFormFields();
}
function openCreate() {
  editing.value = null;
  resetFormFields();
  showForm.value = true;
}
async function openEdit(row: EntryDto) {
  resetGenerator();
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
  } else if (secret.type === "database") {
    form.engine = secret.engine;
    form.host = secret.host;
    form.port = secret.port || 0;
    form.db_name = secret.database;
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
  if (form.kind === "database") {
    return {
      type: "database",
      engine: form.engine,
      host: form.host,
      port: form.port || null,
      database: form.db_name,
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
  closeForm();
  showToast("已保存");
  await refreshVault();
}

async function copy(id: string, field = "secret") {
  await api.copy(id, field);
  showToast(field === "account" ? "已复制账号" : field === "totp" ? "已复制验证码" : "已复制，20 秒后清空剪贴板");
  await refreshVault();
}
async function revealRow(row: EntryDto) {
  if (revealFor.value === row.id) {
    hideSecret();
    return;
  }
  reveal.value = await api.reveal(row.id);
  revealFor.value = row.id;
  scheduleRevealHide();
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
  if (generatorBusy.value) return;
  generator.length = Math.round(Math.min(128, Math.max(8, Number(generator.length) || 20)));
  generator.wordCount = Math.round(Math.min(8, Math.max(3, Number(generator.wordCount) || 4)));
  generator.separator = generator.separator || "-";
  generatorBusy.value = true;
  try {
    form.password = await api.genPassword({
      mode: generator.mode,
      length: generator.length,
      upper: generator.upper,
      lower: generator.lower,
      digits: generator.digits,
      symbols: generator.symbols,
      ensureEach: generator.ensureEach,
      wordCount: generator.wordCount,
      separator: generator.separator,
    });
  } catch (e) {
    showToast(`生成失败：${String(e)}`);
  } finally {
    generatorBusy.value = false;
  }
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
      if (backupOverwrite.value && !confirm("覆盖导入会替换同 id 的现有条目，且无法撤销。确定继续？")) {
        return;
      }
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
const settingsIdle = ref(15);
const settingsClip = ref(20);
const settingsHotkey = ref("Ctrl+Shift+Space");
const oldMaster = ref("");
const newMaster = ref("");
const newMaster2 = ref("");
const recent = ref<EntryDto[]>([]);
const expiring = ref<EntryDto[]>([]);

function hideVisibleSecrets() {
  hideSecret();
  closeForm();
  hideBridgeTokens();
}

function clearSecrets() {
  hideVisibleSecrets();
  closeForm();
  backupPassword.value = "";
  pairing.value = null;
  pairingError.value = "";
  stopPairingTimer();
  httpLogs.value = [];
  openHttpLog.value = null;
  oldMaster.value = "";
  newMaster.value = "";
  newMaster2.value = "";
}

function applyLockedUi() {
  clearSecrets();
  backupOpen.value = false;
  entries.value = [];
  scopedCounts.value = null;
  audit.value = [];
  recent.value = [];
  expiring.value = [];
  selected.value = new Set();
  mcp.value = null;
}

async function doLock() {
  applyLockedUi();
  try {
    await api.lock();
  } catch {
    /* already locked from tray / idle */
  }
  await refreshStatus();
}

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
  if (e.ctrlKey && e.key.toLowerCase() === "f" && status.value?.unlocked) {
    const el = document.querySelector(".search") as HTMLInputElement | null;
    el?.focus();
  }
}

function onVisibility() {
  if (document.visibilityState === "hidden") hideVisibleSecrets();
}

onMounted(async () => {
  await refreshStatus();
  if (status.value?.unlocked) await refreshVault();
  await loadSettings();
  window.addEventListener("keydown", onKey);
  document.addEventListener("visibilitychange", onVisibility);
  const unFocus = await getCurrentWindow().onFocusChanged((event) => {
    if (!event.payload) hideVisibleSecrets();
  });
  const unTick = await listen("tick", async () => {
    const locked = await api.tick();
    if (locked) {
      applyLockedUi();
      await refreshStatus();
    }
  });
  const unLock = await listen("lock-now", () => doLock());
  onUnmounted(() => {
    applyLockedUi();
    window.removeEventListener("keydown", onKey);
    document.removeEventListener("visibilitychange", onVisibility);
    unFocus();
    unTick();
    unLock();
    stopPairingTimer();
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
          <span class="icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="m3 10 9-7 9 7" />
              <path d="M5 9.5V21h14V9.5" />
              <path d="M9 21v-6h6v6" />
            </svg>
          </span>
          <span>首页</span>
        </button>
        <button class="rail-btn" :class="{ active: page === 'vault' }" @click="goPage('vault')">
          <span class="icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <rect x="4" y="3" width="16" height="18" rx="2" />
              <path d="M8 7h8M8 11h8M8 15h5" />
            </svg>
          </span>
          <span>保险库</span>
        </button>
        <button class="rail-btn" :class="{ active: page === 'audit' }" @click="openAudit">
          <span class="icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M4 19V5M4 19h16" />
              <path d="m7 15 3-3 3 2 6-7" />
              <path d="M16 7h3v3" />
            </svg>
          </span>
          <span>审计</span>
        </button>
        <button class="rail-btn" :class="{ active: page === 'mcp' }" @click="openMcp">
          <span class="icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="m12 3 8 4.5v9L12 21l-8-4.5v-9L12 3Z" />
              <path d="m8 9 4 2.25L16 9M12 11.25V16" />
            </svg>
          </span>
          <span>MCP</span>
        </button>
        <button class="rail-btn" :class="{ active: page === 'plugin' }" @click="openPlugin">
          <span class="icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 2v6" />
              <path d="M8 8h8" />
              <rect x="4" y="8" width="16" height="12" rx="2" />
              <path d="M8 14h.01M12 14h.01M16 14h.01" />
            </svg>
          </span>
          <span>插件</span>
        </button>
        <div class="spacer" />
        <button class="rail-btn" :class="{ active: page === 'settings' }" @click="goPage('settings')">
          <span class="icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.64 5.64l1.42 1.42M16.94 16.94l1.42 1.42M18.36 5.64l-1.42 1.42M7.06 16.94l-1.42 1.42" />
              <circle cx="12" cy="12" r="4" />
            </svg>
          </span>
          <span>设置</span>
        </button>
      </nav>

      <section class="main" v-if="page === 'home'">
        <div class="content">
          <h2>概览</h2>
          <p>全部 {{ status.counts?.total ?? 0 }} · 网站 {{ status.counts?.website ?? 0 }} · Token {{ status.counts?.api_token ?? 0 }} · SSH {{ status.counts?.ssh ?? 0 }} · 邮箱 {{ status.counts?.mailbox ?? 0 }} · 授权码 {{ status.counts?.mail_auth ?? 0 }} · 服务器 {{ status.counts?.server ?? 0 }} · 数据库 {{ status.counts?.database ?? 0 }} · 回收站 {{ status.counts?.trash ?? 0 }}</p>
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
          <div class="side-nav">
            <button class="side-item" :class="{ active: allFilterActive }" type="button" @click="setFilter({})">
              <span>全部凭据</span><span class="count">{{ status.counts?.total ?? 0 }}</span>
            </button>
          </div>
          <div class="side-scroll">
            <div class="side-section" v-if="tags.length">
              <div class="side-label">标签</div>
              <button
                class="side-item"
                v-for="t in tags"
                :key="t"
                type="button"
                :class="{ active: filter.tag === t }"
                :title="t"
                @click="setFilter({ tag: t })"
              >
                <span>{{ t }}</span>
              </button>
            </div>
            <div class="side-section">
              <div class="side-label">
                <span>文件夹</span>
                <button class="side-link" type="button" @click="newFolder">新建</button>
              </div>
              <button class="side-item" type="button" :class="{ active: filter.uncategorized }" @click="setFilter({ uncategorized: true })">
                <span>未归类</span>
              </button>
              <button
                class="side-item"
                v-for="f in folders"
                :key="f.id"
                type="button"
                :class="{ active: filter.folder_id === f.id }"
                :title="f.name"
                @click="setFilter({ folder_id: f.id })"
              >
                <span>{{ f.name }}</span>
              </button>
            </div>
          </div>
          <div class="side-foot">
            <button class="side-item" type="button" :class="{ active: filter.trash }" @click="setFilter({ trash: true })">
              <span>回收站</span><span class="count">{{ status.counts?.trash ?? 0 }}</span>
            </button>
            <button class="side-item" type="button" @click="backupMode = 'export'; backupOpen = true">
              <span>备份 / 还原</span>
            </button>
          </div>
        </aside>
        <div class="content vault-content">
          <div class="toolbar">
            <input class="search" v-model="filter.query" placeholder="搜索键名 / 账号 / 网址… (Ctrl+F)" @keyup.enter="refreshVault" />
            <select class="select" v-model="filter.sort" @change="refreshVault">
              <option value="use_count">使用次数</option>
              <option value="updated">修改时间</option>
              <option value="title">键名</option>
            </select>
            <button class="btn primary" type="button" @click="openCreate">新建凭据</button>
          </div>
          <div class="kind-filters" role="group" aria-label="按类型筛选">
            <button
              class="kind-chip"
              v-for="item in KIND_ITEMS"
              :key="item.id"
              type="button"
              :class="[item.id, { active: isKindSelected(item.id) }]"
              :aria-pressed="isKindSelected(item.id)"
              @click="toggleKind(item.id)"
            >
              <span>{{ item.label }}</span>
              <span class="count">{{ kindCount(item.id) }}</span>
            </button>
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
                    <div class="title-cell">
                      <span class="letter" :style="{ background: letterColor(row.title) }">{{ row.title.slice(0,1).toUpperCase() }}</span>
                      <span class="title-text" :title="row.title">{{ row.title }}</span>
                      <button
                        v-if="!filter.trash"
                        class="icon-btn pin"
                        type="button"
                        :class="{ on: row.pinned }"
                        :title="row.pinned ? '取消置顶' : '置顶'"
                        :aria-label="row.pinned ? '取消置顶' : '置顶'"
                        @click="togglePin(row)"
                      >
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                          <path d="M12 17v5" />
                          <path d="M9 3h6l-1 7h3l-5 6-5-6h3z" />
                        </svg>
                      </button>
                    </div>
                  </td>
                  <td>
                    {{ row.account || row.fingerprint || "—" }}
                    <div v-if="revealFor === row.id && reveal" style="font-size:12px;color:var(--muted);margin-top:4px;word-break:break-all">
                      <template v-if="reveal.type === 'website' || reveal.type === 'mailbox' || reveal.type === 'server' || reveal.type === 'database'">{{ reveal.password }}</template>
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
                    <button class="icon-btn" type="button" title="复制密码" aria-label="复制密码" @click="copy(row.id)">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <rect x="9" y="9" width="13" height="13" rx="2" />
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                      </svg>
                    </button>
                    <button class="icon-btn" type="button" title="复制账号" aria-label="复制账号" @click="copy(row.id, 'account')">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                        <circle cx="12" cy="7" r="4" />
                      </svg>
                    </button>
                    <button v-if="row.has_totp" class="icon-btn" type="button" title="复制 TOTP" aria-label="复制 TOTP" @click="copy(row.id, 'totp')">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <circle cx="12" cy="12" r="10" />
                        <polyline points="12 6 12 12 16 14" />
                      </svg>
                    </button>
                    <button v-if="filter.trash" class="icon-btn" type="button" title="还原" aria-label="还原" @click="restore([row.id])">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
                        <path d="M3 3v5h5" />
                      </svg>
                    </button>
                    <button
                      v-else
                      class="icon-btn"
                      type="button"
                      :class="{ on: revealFor === row.id }"
                      :title="revealFor === row.id ? '隐藏' : '显示'"
                      :aria-label="revealFor === row.id ? '隐藏' : '显示'"
                      :aria-pressed="revealFor === row.id"
                      @click="revealRow(row)"
                    >
                      <svg v-if="revealFor === row.id" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
                        <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
                        <path d="M14.12 14.12a3 3 0 1 1-4.24-4.24" />
                        <line x1="1" y1="1" x2="23" y2="23" />
                      </svg>
                      <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                        <circle cx="12" cy="12" r="3" />
                      </svg>
                    </button>
                    <button v-if="!filter.trash" class="icon-btn" type="button" title="编辑" aria-label="编辑" @click="openEdit(row)">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M12 20h9" />
                        <path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z" />
                      </svg>
                    </button>
                    <button v-if="!filter.trash" class="icon-btn danger" type="button" title="移入回收站" aria-label="移入回收站" @click="remove([row.id])">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <polyline points="3 6 5 6 21 6" />
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                      </svg>
                    </button>
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
        <div class="content content-page mcp-page">
          <div class="mcp-head">
            <div>
              <h2>MCP 接入</h2>
            </div>
            <div class="mcp-status">
              <span class="mcp-dot" :class="{ on: mcp?.running }" />
              <span>{{ mcp?.running ? "运行中" : "已停止" }} · {{ mcp?.port || "—" }}</span>
              <button class="btn primary" v-if="!mcp?.running" type="button" @click="startMcp">启动</button>
              <button class="btn" v-else type="button" @click="stopMcp">停止</button>
              <button class="btn" type="button" @click="rotateMcp">轮换 MCP Token</button>
            </div>
          </div>
          <div class="mcp-card">
            <h3>Cursor / Claude Code</h3>
            <p class="crumb">金库锁定时工具会失败并提示先解锁。</p>
            <div class="field">
              <label>Bearer Token</label>
              <div class="secret-row">
                <input :value="revealedMcpToken || '••••••••'" readonly />
                <button class="btn" type="button" :disabled="!mcp?.has_token" @click="toggleMcpToken">{{ revealedMcpToken ? "隐藏" : "显示" }}</button>
                <button class="btn" type="button" :disabled="!mcp?.has_token" @click="copyMcpToken">复制</button>
              </div>
            </div>
            <div class="field">
              <label>配置片段</label>
              <textarea class="mcp-snippet" rows="10" readonly :value="revealedMcpSnippet || '显示 Token 后才会填入配置片段。复制走后端剪贴板超时。'"></textarea>
            </div>
            <button class="btn" type="button" :disabled="!mcp?.has_token" @click="copyMcpSnippet">复制配置</button>
          </div>
          <div class="mcp-card">
            <h3>工具列表</h3>
            <p class="crumb">当前 MCP 对模型暴露的工具，与 tools/list 一致。</p>
            <div class="tool-list" v-if="mcpTools.length">
              <div class="tool-item" v-for="tool in mcpTools" :key="tool.name">
                <code class="tool-name">{{ tool.name }}</code>
                <p class="crumb">{{ tool.description }}</p>
              </div>
            </div>
            <p class="crumb" v-else>还没有读到工具定义。</p>
          </div>
          <div class="mcp-card mcp-logs">
            <h3>http_request 响应</h3>
            <p class="crumb">完整正文只在这里查看，锁定金库后清空。模型侧只有状态码、长度和 SHA256。</p>
            <button class="btn" style="margin:8px 0 12px" type="button" @click="refreshMcp">刷新日志</button>
            <div class="table" v-if="httpLogs.length">
              <table>
                <thead><tr><th>时间</th><th>方法</th><th>状态</th><th>网址</th><th></th></tr></thead>
                <tbody>
                  <tr v-for="log in httpLogs" :key="log.id">
                    <td>{{ fmtTime(log.at) }}</td>
                    <td>{{ log.method }}</td>
                    <td>{{ log.status }} / {{ log.bytes }} B</td>
                    <td>{{ log.url }}</td>
                    <td><button class="btn" type="button" @click="openHttpLog = openHttpLog === log.id ? null : log.id">{{ openHttpLog === log.id ? "收起" : "查看" }}</button></td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p class="crumb" v-else>还没有代发记录。</p>
            <div class="field" v-if="httpLogs.find((l) => l.id === openHttpLog)">
              <label>sha256 {{ httpLogs.find((l) => l.id === openHttpLog)?.sha256 }}</label>
              <textarea rows="10" readonly :value="httpLogs.find((l) => l.id === openHttpLog)?.body || ''"></textarea>
            </div>
          </div>
        </div>
      </section>

      <section class="main" v-else-if="page === 'plugin'">
        <div class="content content-page mcp-page">
          <div class="mcp-head">
            <div>
              <h2>插件</h2>
              <p class="crumb">Chrome / Edge 浏览器扩展。配对码一次性有效，填表 Token 与 MCP Token 分开。读取明文和写入条目都会按当前页面网址复核。</p>
            </div>
          </div>
          <div class="mcp-card" style="max-width:640px">
            <h3>浏览器扩展</h3>
            <p class="crumb">打开 <code>chrome://extensions</code>（Edge：<code>edge://extensions</code>），打开开发者模式，加载已解压的扩展，选择仓库里的 <code>extension</code> 目录。点配对后，60 秒内把一次性配对码填进扩展。</p>
            <div class="mcp-actions">
              <button class="btn primary" type="button" :disabled="pairingBusy" @click="openFillPairing">{{ pairingBusy ? "正在打开…" : "配对" }}</button>
              <button class="btn" type="button" @click="rotateFill">轮换填表 Token</button>
            </div>
            <p class="error" v-if="pairingError">{{ pairingError }}</p>
            <div id="pairing-code-box" class="pairing-box" v-if="pairing?.active && pairing.code">
              <div class="pairing-meta">
                <span>一次性配对码</span>
                <span>{{ pairing.expires_in_secs }} 秒后失效</span>
              </div>
              <div class="pairing-code-row">
                <div class="pairing-code" aria-label="配对码">{{ pairingLabel(pairing.code) }}</div>
                <button class="icon-btn" type="button" title="复制配对码" aria-label="复制配对码" @click="copyPairingCode">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <rect x="9" y="9" width="13" height="13" rx="2" />
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                  </svg>
                </button>
              </div>
              <p class="crumb" style="margin:8px 0 0;text-align:center">用过即作废。过期后会自动消失。</p>
            </div>
            <p class="crumb" v-else>当前没有开放的配对窗口。</p>
            <div class="field">
              <label>填表 Token</label>
              <div class="secret-row">
                <input :value="revealedFillToken || '••••••••'" readonly />
                <button class="btn" type="button" :disabled="!mcp?.has_fill_token" @click="toggleFillToken">{{ revealedFillToken ? "隐藏" : "显示" }}</button>
                <button class="btn" type="button" :disabled="!mcp?.has_fill_token" @click="copyFillToken">复制</button>
              </div>
            </div>
            <p class="crumb">{{ mcp?.fill_url || "http://127.0.0.1:17891/fill" }} · 只接受 Host 为 127.0.0.1 的本机请求</p>
          </div>
        </div>
      </section>

      <section class="main" v-else-if="page === 'audit'">
        <div class="content content-page">
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
        <div class="content content-page settings-page">
          <div class="mcp-head">
            <div>
              <h2>设置</h2>
              <p class="crumb">关闭窗口进入托盘。全局热键即使窗口不在前台也能打开速查。</p>
            </div>
          </div>
          <div class="settings-grid">
            <div class="mcp-card">
              <h3>锁定与快捷键</h3>
              <p class="crumb">空闲超时后自动锁库；复制秘密后按设定秒数清空剪贴板。</p>
              <div class="settings-fields">
                <div class="field">
                  <label>空闲锁定（分钟）</label>
                  <input type="number" min="1" v-model.number="settingsIdle" />
                </div>
                <div class="field">
                  <label>剪贴板清空（秒）</label>
                  <input type="number" min="5" max="120" v-model.number="settingsClip" />
                </div>
                <div class="field settings-span">
                  <label>全局热键</label>
                  <input v-model="settingsHotkey" placeholder="Ctrl+Shift+Space" />
                </div>
              </div>
              <button class="btn primary" type="button" @click="saveSettings">保存</button>
            </div>
            <div class="mcp-card">
              <h3>Windows Hello</h3>
              <p class="crumb">用本机生物识别作为第二把钥匙。备份文件仍只能用主密码解开。</p>
              <p class="hello-status">
                <span class="mcp-dot" :class="{ on: status.hello_enabled }" />
                <span v-if="!status.hello_available">当前设备不可用</span>
                <span v-else-if="status.hello_enabled">已开启</span>
                <span v-else>未开启</span>
              </p>
              <div class="mcp-actions">
                <button class="btn primary" type="button" :disabled="!status.hello_available" @click="api.setHello(true).then(() => { showToast('已开启'); refreshStatus(); })">开启</button>
                <button class="btn" type="button" @click="api.setHello(false).then(() => { showToast('已关闭'); refreshStatus(); })">关闭</button>
              </div>
            </div>
          </div>
          <div class="mcp-card settings-master">
            <h3>修改主密码</h3>
            <p class="crumb">至少 10 位。更新后，旧主密码立刻失效。</p>
            <div class="settings-fields">
              <div class="field">
                <label>当前主密码</label>
                <input v-model="oldMaster" type="password" />
              </div>
              <div class="field">
                <label>新主密码</label>
                <input v-model="newMaster" type="password" />
              </div>
              <div class="field">
                <label>确认新主密码</label>
                <input v-model="newMaster2" type="password" @keyup.enter="doChangeMaster" />
              </div>
            </div>
            <button class="btn primary" type="button" @click="doChangeMaster">更新主密码</button>
          </div>
        </div>
      </section>

      <div class="dialog-mask" v-if="showForm" @click.self="closeForm">
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
            <option value="database">数据库</option>
          </select>
        </div>
        <div class="field"><label>键名</label><input v-model="form.title" /></div>
        <div class="field" v-if="form.kind !== 'ssh' && form.kind !== 'mailbox' && form.kind !== 'mail_auth'"><label>{{ form.kind === 'server' || form.kind === 'database' ? '用户名' : '账号' }}</label><input v-model="form.account" /></div>
        <div class="field" v-if="form.kind === 'website'"><label>网址</label><input v-model="form.url" /></div>
        <div class="field" v-if="form.kind === 'website' || form.kind === 'mailbox' || form.kind === 'server' || form.kind === 'database'">
          <label>密码</label>
          <div class="secret-row generator-row">
            <input v-model="form.password" type="password" />
            <button class="btn" type="button" :disabled="generatorBusy" @click="gen">{{ generatorBusy ? '生成中…' : '生成' }}</button>
            <button class="btn generator-toggle" type="button" :aria-expanded="generatorOpen" @click="generatorOpen = !generatorOpen">
              {{ generatorOpen ? '收起选项' : '选项' }}
            </button>
          </div>
          <div v-if="generatorOpen" class="generator-panel">
            <div class="generator-head">
              <strong>生成器选项</strong>
              <span class="crumb">生成结果会覆盖当前密码</span>
            </div>
            <div class="generator-mode">
              <label class="check"><input v-model="generator.mode" type="radio" value="password" /> 随机密码</label>
              <label class="check"><input v-model="generator.mode" type="radio" value="passphrase" /> 口令短语</label>
            </div>
            <div v-if="generator.mode === 'password'" class="generator-options">
              <div class="field generator-length">
                <label for="generator-length">长度</label>
                <input id="generator-length" v-model.number="generator.length" type="number" min="8" max="128" />
              </div>
              <div class="generator-checks">
                <label class="check"><input v-model="generator.lower" type="checkbox" /> 小写字母</label>
                <label class="check"><input v-model="generator.upper" type="checkbox" /> 大写字母</label>
                <label class="check"><input v-model="generator.digits" type="checkbox" /> 数字</label>
                <label class="check"><input v-model="generator.symbols" type="checkbox" /> 符号</label>
                <label class="check generator-check-wide"><input v-model="generator.ensureEach" type="checkbox" /> 每类字符至少一个</label>
              </div>
              <p v-if="generatorNoClasses" class="generator-hint">未选择字符类别，将使用字母和数字作为安全回退。</p>
            </div>
            <div v-else class="generator-options">
              <div class="field generator-length">
                <label for="generator-word-count">词数</label>
                <input id="generator-word-count" v-model.number="generator.wordCount" type="number" min="3" max="8" />
              </div>
              <div class="field generator-separator">
                <label for="generator-separator">分隔符</label>
                <input id="generator-separator" v-model="generator.separator" maxlength="8" placeholder="-" />
              </div>
              <p class="generator-hint">使用内置英文词表生成易读的随机口令短语。</p>
            </div>
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
        <div class="field" v-if="form.kind === 'api_token'"><label>允许的网址（自定义服务必填）</label>
          <input v-model="form.url" placeholder="https://api.example.com" />
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
        <div class="field" v-if="form.kind === 'database'"><label>数据库类型</label>
          <select v-model="form.engine" @change="onEngineChange">
            <option v-for="e in DB_ENGINES" :key="e.id" :value="e.id">{{ e.label }}</option>
          </select>
        </div>
        <div class="field" v-if="form.kind === 'database' && form.engine !== 'sqlite'"><label>主机</label><input v-model="form.host" placeholder="127.0.0.1 或 db.example.com" /></div>
        <div class="field" v-if="form.kind === 'database' && form.engine !== 'sqlite'"><label>端口</label><input v-model.number="form.port" type="number" /></div>
        <div class="field" v-if="form.kind === 'database'"><label>{{ form.engine === 'sqlite' ? '文件路径' : form.engine === 'oracle' ? '服务名 / SID' : form.engine === 'redis' ? '库编号（可空）' : '库名' }}</label><input v-model="form.db_name" :placeholder="form.engine === 'sqlite' ? 'D:\\data\\app.db' : 'appdb'" /></div>
        <div class="field"><label>文件夹</label>
          <select v-model="form.folder_id">
            <option value="">未归类</option>
            <option v-for="f in folders" :key="f.id" :value="f.id">{{ f.name }}</option>
          </select>
        </div>
        <div class="field"><label>标签（逗号分隔）</label><input v-model="form.tags" /></div>
        <div class="field"><label>过期日期（可空）</label><input v-model="form.expires_at" type="date" /></div>
        <div class="field"><label>备注</label><textarea v-model="form.notes" rows="3" /></div>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
          <button class="btn" @click="closeForm">取消</button>
          <button class="btn primary" @click="saveEntry">保存</button>
        </div>
      </div>
    </div>
    </div>
    <div class="dialog-mask" v-if="backupOpen && status && (status.unlocked || !status.initialized)" @click.self="backupOpen = false">
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
          <label class="check">
            <input type="checkbox" v-model="backupOverwrite" />
            覆盖已有同 id 条目
          </label>
          <p class="crumb" v-if="backupOverwrite" style="margin:6px 0 0 23px">会替换本地同 id 条目。确定时还会再确认一次。</p>
        </div>
        <div style="display:flex;gap:8px;justify-content:flex-end">
          <button class="btn" @click="backupOpen = false">取消</button>
          <button class="btn primary" @click="runBackup">确定</button>
        </div>
      </div>
    </div>
    <div class="toast" v-if="toast">{{ toast }}</div>
  </div>
</template>
