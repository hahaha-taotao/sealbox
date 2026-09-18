<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, reactive, ref } from "vue";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  api,
  type AuditEvent,
  type AssistantChatResponse,
  type AssistantConfigView,
  type AssistantMessage,
  type AssistantMcpProbe,
  type AssistantToolTrace,
  type ClientCertInfo,
  type Counts,
  type EntryDto,
  type EntryKind,
  type ExtensionInstallStatus,
  type FolderDto,
  type GithubMcpPolicy,
  type ListFilter,
  type McpStatus,
  type McpToolInfo,
  type SecretPayload,
  type Status,
  type UpsertEntry,
  type ZoomkeyCandidates,
  type ZoomkeyMcpPolicy,
} from "./lib/tauri";

const status = ref<Status | null>(null);
  type Page = "home" | "vault" | "audit" | "settings" | "mcp" | "plugin" | "assistant";
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
  cert_pem: "",
  key_pem: "",
  cert_path: "",
  key_path: "",
  cert_passphrase: "",
});
const clientCertInfo = ref<ClientCertInfo | null>(null);
const certImportBusy = ref(false);
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
const certInfoFor = ref<string | null>(null);
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
  { id: "client_cert", label: "客户端证书" },
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
  if (page.value === "assistant") return "助手";
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
    case "client_cert": return "客户端证书";
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
  clientCertInfo.value = null;
  certInfoFor.value = null;
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
    cert_pem: "",
    key_pem: "",
    cert_path: "",
    key_path: "",
    cert_passphrase: "",
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
const extStatus = ref<ExtensionInstallStatus | null>(null);
const extError = ref("");
const extBusy = ref(false);
const revealedFillToken = ref("");
const revealedMcpToken = ref("");
const revealedMcpSnippet = ref("");
const mcpTools = ref<McpToolInfo[]>([]);
const githubPolicy = ref<GithubMcpPolicy>({ enabled: false });
const githubPolicyBusy = ref(false);
const zoomkeyPolicy = ref<ZoomkeyMcpPolicy | null>(null);
const zoomkeyCandidates = ref<ZoomkeyCandidates>({
  jira_credentials: [],
  crm_credentials: [],
  client_certs: [],
});
const zoomkeyBusy = ref(false);
const zoomkeyTestBusy = ref("");
const zoomkeyTestResult = ref<{ endpoint: string; ok: boolean; text: string } | null>(null);
const assistantConfig = ref<AssistantConfigView | null>(null);
const assistantModel = ref("gpt-4o-mini");
const assistantBaseUrl = ref("https://api.openai.com/v1");
const assistantApiKey = ref("");
const assistantClearApiKey = ref(false);
const assistantConfigBusy = ref(false);
const assistantProbeBusy = ref(false);
const assistantChatBusy = ref(false);
const assistantError = ref("");
const assistantInput = ref("");
const assistantMcp = ref<AssistantMcpProbe | null>(null);
const assistantMessages = ref<AssistantMessage[]>([]);
const assistantTraces = ref<AssistantToolTrace[]>([]);
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
    githubPolicy.value = await api.githubMcpPolicyGet();
  } catch {
    githubPolicy.value = { enabled: false };
  }
  try {
    zoomkeyPolicy.value = await api.zoomkeyPolicyGet();
    zoomkeyCandidates.value = await api.zoomkeyCandidates();
  } catch {
    zoomkeyPolicy.value = null;
  }
  try {
    mcpTools.value = await api.mcpTools();
  } catch {
    mcpTools.value = [];
  }
}

async function saveZoomkeyPolicy(opts: { toggling?: boolean } = {}) {
  if (!zoomkeyPolicy.value || zoomkeyBusy.value) return;
  const previousEnabled = zoomkeyPolicy.value.enabled;
  if (opts.toggling) {
    zoomkeyPolicy.value.enabled = !previousEnabled;
  }
  if (zoomkeyPolicy.value.enabled && (opts.toggling || !previousEnabled)) {
    const ok = confirm(
      "开启后，Sealbox 允许向白名单内的内网主机发起请求（携带金库里的客户端证书）。\n" +
        "请确认白名单里只有你信任的公司内网域名。配齐凭据的端点会自动出现在工具列表。继续？",
    );
    if (!ok) {
      if (opts.toggling) zoomkeyPolicy.value.enabled = previousEnabled;
      return;
    }
  }
  zoomkeyBusy.value = true;
  try {
    zoomkeyPolicy.value = await api.zoomkeyPolicySet(zoomkeyPolicy.value);
    mcpTools.value = await api.mcpTools();
    if (opts.toggling) {
      showToast(zoomkeyPolicy.value.enabled ? "ZoomKey MCP 已启用" : "ZoomKey MCP 已停用");
    } else {
      showToast("ZoomKey 策略已保存");
    }
  } catch (e) {
    if (opts.toggling) zoomkeyPolicy.value.enabled = previousEnabled;
    showToast(String(e));
  } finally {
    zoomkeyBusy.value = false;
  }
}

function toggleZoomkeyEnabled() {
  return saveZoomkeyPolicy({ toggling: true });
}

async function testZoomkey(endpoint: "jira" | "crm") {
  if (zoomkeyTestBusy.value) return;
  zoomkeyTestBusy.value = endpoint;
  zoomkeyTestResult.value = null;
  try {
    const text = await api.zoomkeyTest(endpoint);
    zoomkeyTestResult.value = { endpoint, ok: true, text };
  } catch (e) {
    zoomkeyTestResult.value = { endpoint, ok: false, text: String(e) };
  } finally {
    zoomkeyTestBusy.value = "";
  }
}

// CA bundle 是「验证服务端证书」的那份签发链，与凭据条目里的客户端证书/私钥是两个文件。
async function pickCaBundlePath(endpoint: "jira" | "crm") {
  try {
    const picked = await withNativeDialog(async () => {
      const { open } = await import("@tauri-apps/plugin-dialog");
      return open({
        multiple: false,
        title: "选择 CA bundle（含 Root + SubCA 的 PEM）",
        filters: [{ name: "PEM / certificate", extensions: ["pem", "crt", "cer"] }],
      });
    });
    if (typeof picked !== "string" || !zoomkeyPolicy.value) return;
    zoomkeyPolicy.value[endpoint].ca_bundle_path = picked;
  } catch (e) {
    showToast(`打开文件选择框失败：${String(e)}`);
  }
}

async function saveGithubPolicy() {
  if (githubPolicyBusy.value) return;
  const previous = githubPolicy.value.enabled;
  if (!previous) {
    const ok = confirm(
      "开启后，Cursor / Claude Code 可以使用 GitHub 只读 API，并在模型给出的本地路径上执行 git（含 commit / push / pull / clone）。Token 不会返回给模型。继续？",
    );
    if (!ok) return;
  }
  githubPolicyBusy.value = true;
  githubPolicy.value = { enabled: !previous };
  try {
    githubPolicy.value = await api.githubMcpPolicySet(githubPolicy.value);
    mcp.value = await api.mcpStatus();
    mcpTools.value = await api.mcpTools();
    showToast(githubPolicy.value.enabled ? "GitHub MCP 已启用" : "GitHub MCP 已停用");
  } catch (e) {
    githubPolicy.value = { enabled: previous };
    showToast(String(e));
  } finally {
    githubPolicyBusy.value = false;
  }
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
function extStatusText(s: ExtensionInstallStatus | null) {
  if (!s) return "尚未检查本机扩展。";
  if (!s.installed) return "尚未安装到本机";
  if (!s.outdated) return `已安装 · v${s.installed_version || s.bundled_version}`;
  if (s.installed_version && s.installed_version !== s.bundled_version) {
    return `已安装 · v${s.installed_version}，内置 v${s.bundled_version}，请更新后再到浏览器点刷新`;
  }
  return `已安装 · v${s.installed_version || s.bundled_version}，内置文件已更新，请重新安装后再到浏览器点刷新`;
}

async function refreshExtensionInstall() {
  try {
    extStatus.value = await api.extensionInstallStatus();
    extError.value = "";
  } catch (e) {
    extStatus.value = null;
    extError.value = String(e);
  }
}

async function installExtension() {
  if (extBusy.value) return;
  extBusy.value = true;
  extError.value = "";
  try {
    extStatus.value = await api.extensionInstall();
    showToast("已安装到本机并打开目录");
  } catch (e) {
    extError.value = String(e);
    showToast(extError.value);
  } finally {
    extBusy.value = false;
  }
}

async function openExtensionFolder() {
  extError.value = "";
  try {
    await api.extensionOpenFolder();
  } catch (e) {
    extError.value = String(e);
    showToast(extError.value);
  }
}

async function openExtensionBrowser(browser: "chrome" | "edge") {
  extError.value = "";
  try {
    const url = await api.extensionOpenBrowser(browser);
    showToast(`已打开 ${url}`);
  } catch (e) {
    extError.value = String(e);
    showToast(extError.value);
  }
}

async function copyExtensionPath() {
  if (!extStatus.value?.dest_path) return;
  await navigator.clipboard.writeText(extStatus.value.dest_path);
  showToast("扩展目录已复制");
}

async function openPlugin() {
  goPage("plugin");
  await refreshMcp();
  await refreshPairing();
  await refreshExtensionInstall();
}

async function refreshAssistantConfig() {
  assistantError.value = "";
  try {
    const config = await api.assistantConfigGet();
    assistantConfig.value = config;
    assistantModel.value = config.model;
    assistantBaseUrl.value = config.baseUrl;
    assistantApiKey.value = "";
    assistantClearApiKey.value = false;
  } catch (e) {
    assistantError.value = String(e);
  }
}

async function openAssistant() {
  goPage("assistant");
  await refreshAssistantConfig();
  if (!assistantMcp.value) await probeAssistantMcp();
}

async function saveAssistantConfig() {
  if (assistantConfigBusy.value) return;
  assistantConfigBusy.value = true;
  assistantError.value = "";
  try {
    const config = await api.assistantConfigSet({
      model: assistantModel.value,
      baseUrl: assistantBaseUrl.value,
      apiKey: assistantApiKey.value || undefined,
      clearApiKey: assistantClearApiKey.value,
    });
    assistantConfig.value = config;
    assistantApiKey.value = "";
    assistantClearApiKey.value = false;
    showToast("助手配置已保存");
  } catch (e) {
    assistantError.value = String(e);
    showToast(assistantError.value);
  } finally {
    assistantConfigBusy.value = false;
  }
}

async function probeAssistantMcp() {
  if (assistantProbeBusy.value) return;
  assistantProbeBusy.value = true;
  assistantError.value = "";
  try {
    assistantMcp.value = await api.assistantMcpProbe();
    showToast(`MCP 已连接，发现 ${assistantMcp.value.tools.length} 个只读工具`);
  } catch (e) {
    assistantMcp.value = null;
    assistantError.value = String(e);
    showToast(assistantError.value);
  } finally {
    assistantProbeBusy.value = false;
  }
}

function clearAssistantChat() {
  assistantMessages.value = [];
  assistantTraces.value = [];
  assistantInput.value = "";
  assistantError.value = "";
}

async function sendAssistantMessage() {
  const message = assistantInput.value.trim();
  if (!message || assistantChatBusy.value) return;
  assistantChatBusy.value = true;
  assistantError.value = "";
  assistantInput.value = "";
  const history = [...assistantMessages.value];
  assistantMessages.value.push({ role: "user", content: message });
  try {
    const response: AssistantChatResponse = await api.assistantChat({
      history,
      message,
    });
    assistantMessages.value.push({ role: "assistant", content: response.content });
    assistantTraces.value.push(...response.traces);
  } catch (e) {
    assistantError.value = String(e);
    assistantMessages.value.pop();
    assistantInput.value = message;
    showToast(assistantError.value);
  } finally {
    assistantChatBusy.value = false;
  }
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
  const notes = await api.notes(row.id);
  if (row.kind === "client_cert") {
    clientCertInfo.value = await api.clientCertInfo(row.id);
    form.kind = row.kind;
    form.title = row.title;
    form.account = row.account || "";
    form.url = row.url || "";
    form.folder_id = row.folder_id || "";
    form.tags = row.tags.join(", ");
    form.notes = notes || "";
    form.pinned = row.pinned;
    form.expires_at = row.expires_at ? row.expires_at.slice(0, 10) : "";
    showForm.value = true;
    return;
  }
  const secret = await api.reveal(row.id);
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
  } else if (secret.type === "ssh") {
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
  if (form.kind === "client_cert") {
    throw new Error("客户端证书请使用文件导入");
  }
  return {
    type: "ssh",
    key_type: form.key_type,
    private_key: form.private_key,
    passphrase: null,
    public_fingerprint: null,
  };
}

async function pickClientCertFile(kind: "cert" | "key") {
  try {
    const picked = await withNativeDialog(async () => {
      const { open } = await import("@tauri-apps/plugin-dialog");
      return open({
        multiple: false,
        title: kind === "cert" ? "选择证书 PEM 文件" : "选择私钥 PEM 文件",
        filters: [{ name: "PEM / certificate", extensions: ["pem", "crt", "cer", "key"] }],
      });
    });
    if (typeof picked !== "string") return;
    if (kind === "cert") form.cert_path = picked;
    else form.key_path = picked;
  } catch (e) {
    showToast(`打开文件选择框失败：${String(e)}`);
  }
}

async function saveEntry() {
  if (form.kind === "client_cert") {
    const hasCertPath = Boolean(form.cert_path);
    const hasKeyPath = Boolean(form.key_path);
    if (hasCertPath !== hasKeyPath || (!editing.value && (!hasCertPath || !hasKeyPath))) {
      showToast("请选择客户端证书和私钥文件，或都不选择");
      return;
    }
    certImportBusy.value = true;
    try {
      if (hasCertPath && hasKeyPath) {
        await api.importClientCert({
          id: editing.value?.id ?? null,
          title: form.title,
          certPath: form.cert_path,
          keyPath: form.key_path,
          passphrase: form.cert_passphrase || null,
          account: form.account || null,
          url: form.url || null,
          folderId: form.folder_id || null,
          tags: form.tags.split(",").map((s) => s.trim()).filter(Boolean),
          pinned: form.pinned,
          expiresAt: form.expires_at || null,
          notes: form.notes || null,
        });
      } else if (editing.value) {
        await api.updateClientCertMetadata({
          id: editing.value.id,
          title: form.title,
          account: form.account || null,
          url: form.url || null,
          folderId: form.folder_id || null,
          tags: form.tags.split(",").map((s) => s.trim()).filter(Boolean),
          pinned: form.pinned,
          expiresAt: form.expires_at || null,
          notes: form.notes || null,
        });
      }
      closeForm();
      showToast("客户端证书已保存");
      await refreshVault();
    } catch (e) {
      showToast(String(e));
    } finally {
      certImportBusy.value = false;
    }
    return;
  }
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
async function copyClientCertificate(id: string) {
  await api.copyClientCert(id);
  showToast("已复制公开证书，20 秒后清空剪贴板");
  await refreshVault();
}
async function showClientCertificateInfo(row: EntryDto) {
  if (certInfoFor.value === row.id) {
    certInfoFor.value = null;
    clientCertInfo.value = null;
    return;
  }
  clientCertInfo.value = await api.clientCertInfo(row.id);
  certInfoFor.value = row.id;
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

// 系统文件选择框是应用窗口的子窗口，弹出时会让窗口失焦。那种失焦不是「用户离开了」，
// 所以开着文件框的时候不能把表单关掉，否则选完路径表单已经没了（新建凭据 -> 选择证书）。
let nativeDialogDepth = 0;
let nativeDialogClosedAt = 0;
const NATIVE_DIALOG_GRACE_MS = 400;

async function withNativeDialog<T>(run: () => Promise<T>): Promise<T> {
  nativeDialogDepth += 1;
  try {
    return await run();
  } finally {
    nativeDialogDepth -= 1;
    nativeDialogClosedAt = Date.now();
  }
}

function nativeDialogInFlight() {
  return nativeDialogDepth > 0 || Date.now() - nativeDialogClosedAt < NATIVE_DIALOG_GRACE_MS;
}

function hideVisibleSecrets() {
  hideSecret();
  // 文件选择框（以及它的收尾事件）导致的失焦不算数，其余失焦照旧关表单。
  if (!nativeDialogInFlight()) closeForm();
  hideBridgeTokens();
}

function clearSecrets() {
  hideVisibleSecrets();
  clientCertInfo.value = null;
  certInfoFor.value = null;
  closeForm();
  backupPassword.value = "";
  assistantApiKey.value = "";
  assistantInput.value = "";
  assistantMessages.value = [];
  assistantTraces.value = [];
  assistantMcp.value = null;
  assistantError.value = "";
  pairing.value = null;
  pairingError.value = "";
  stopPairingTimer();
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
  try {
    if (mode === "export") {
      const picked = await withNativeDialog(async () => {
        const { save } = await import("@tauri-apps/plugin-dialog");
        return save({
          defaultPath: "sealbox.svbak",
          filters: [{ name: "Sealbox backup", extensions: ["svbak"] }],
        });
      });
      if (picked) backupPath.value = picked;
      return;
    }
    const picked = await withNativeDialog(async () => {
      const { open } = await import("@tauri-apps/plugin-dialog");
      return open({
        multiple: false,
        filters: [{ name: "Sealbox backup", extensions: ["svbak"] }],
      });
    });
    if (typeof picked === "string") backupPath.value = picked;
  } catch (e) {
    showToast(`打开文件选择框失败：${String(e)}`);
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
        <button class="rail-btn" :class="{ active: page === 'assistant' }" @click="openAssistant">
          <span class="icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M4 5.5A2.5 2.5 0 0 1 6.5 3h11A2.5 2.5 0 0 1 20 5.5v8a2.5 2.5 0 0 1-2.5 2.5H12l-4.5 4v-4h-1A2.5 2.5 0 0 1 4 13.5z" />
              <path d="M8 8h8M8 11h5" />
            </svg>
          </span>
          <span>助手</span>
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
          <p>全部 {{ status.counts?.total ?? 0 }} · 网站 {{ status.counts?.website ?? 0 }} · Token {{ status.counts?.api_token ?? 0 }} · SSH {{ status.counts?.ssh ?? 0 }} · 邮箱 {{ status.counts?.mailbox ?? 0 }} · 授权码 {{ status.counts?.mail_auth ?? 0 }} · 服务器 {{ status.counts?.server ?? 0 }} · 数据库 {{ status.counts?.database ?? 0 }} · 证书 {{ status.counts?.client_cert ?? 0 }} · 回收站 {{ status.counts?.trash ?? 0 }}</p>
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
                    <div v-if="certInfoFor === row.id && clientCertInfo" class="cert-row-info">
                      <span>指纹：{{ clientCertInfo.fingerprint || '—' }}</span>
                      <span>证书链：{{ clientCertInfo.certificateCount ?? '—' }} 张</span>
                      <span v-if="clientCertInfo.hasPassphrase">含私钥口令</span>
                    </div>
                    <div v-else-if="revealFor === row.id && reveal" style="font-size:12px;color:var(--muted);margin-top:4px;word-break:break-all">
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
                    <button v-if="!filter.trash && row.kind !== 'client_cert'" class="icon-btn" type="button" title="复制密码" aria-label="复制密码" @click="copy(row.id)">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <rect x="9" y="9" width="13" height="13" rx="2" />
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                      </svg>
                    </button>
                    <button v-if="!filter.trash" class="icon-btn" type="button" title="复制账号" aria-label="复制账号" @click="copy(row.id, 'account')">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                        <circle cx="12" cy="7" r="4" />
                      </svg>
                    </button>
                    <button v-if="!filter.trash && row.kind === 'client_cert'" class="icon-btn" type="button" :class="{ on: certInfoFor === row.id }" title="查看证书信息" aria-label="查看证书信息" @click="showClientCertificateInfo(row)">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <circle cx="12" cy="12" r="9" /><path d="M12 10v6M12 7h.01" />
                      </svg>
                    </button>
                    <button v-if="!filter.trash && row.kind === 'client_cert'" class="icon-btn" type="button" title="复制公开证书" aria-label="复制公开证书" @click="copyClientCertificate(row.id)">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M8 3h8a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z" />
                        <path d="M9 8h6M9 12h6M9 16h4" />
                      </svg>
                    </button>
                    <button v-if="!filter.trash && row.has_totp" class="icon-btn" type="button" title="复制 TOTP" aria-label="复制 TOTP" @click="copy(row.id, 'totp')">
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
                      v-else-if="row.kind !== 'client_cert'"
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
            <h3>GitHub MCP</h3>
            <p class="crumb">
              启用后开放 api.github.com 只读 GET 工具，以及本地 git 工具 github_git_*（status / diff / commit / push / pull / clone）。
              Agent 传入本机绝对路径；Token 只在 Rust 里注入，不会返回给模型。
            </p>
            <div class="mcp-actions">
              <button class="btn primary" type="button" :disabled="githubPolicyBusy" @click="saveGithubPolicy">
                {{ githubPolicyBusy ? "保存中…" : (githubPolicy.enabled ? "停用 GitHub MCP" : "启用 GitHub MCP") }}
              </button>
            </div>
            <p class="crumb">GitHub Token 在 GitHub 侧的实际权限仍由 GitHub 返回结果决定；Sealbox 不把 Token、请求头或任意请求体返回给模型。</p>
          </div>
          <div class="mcp-card">
            <h3>ZoomKey JIRA / CRM</h3>
            <p class="crumb">
              把众齐内网的 JIRA 与 CRM 查询能力开放给本机 MCP 客户端。两个站点都在 172.16.x.x 内网且强制双向 TLS；
              账号密码与客户端私钥都从金库取，不落磁盘明文，模型永远看不到明文。
            </p>
            <template v-if="zoomkeyPolicy">
              <div class="zoomkey-notice">
                启用后 Sealbox 只对下方白名单里的主机名放行，解析结果会被钉住再使用；
                回环、链路本地与云元数据地址（169.254.169.254 / 100.100.100.200）永远拒绝。
                配齐凭据、客户端证书和 CA bundle 的端点会自动出现在工具列表。
              </div>
              <div class="mcp-actions">
                <button class="btn primary" type="button" :disabled="zoomkeyBusy" @click="toggleZoomkeyEnabled">
                  {{ zoomkeyBusy ? "保存中…" : (zoomkeyPolicy.enabled ? "停用 ZoomKey MCP" : "启用 ZoomKey MCP") }}
                </button>
              </div>
              <div class="field">
                <label>允许的主机名（每行一个，精确匹配）</label>
                <textarea
                  rows="2"
                  :value="zoomkeyPolicy.allowed_hosts.join('\n')"
                  @change="zoomkeyPolicy.allowed_hosts = ($event.target as HTMLTextAreaElement).value.split('\n').map((s) => s.trim()).filter(Boolean)"
                />
              </div>

              <div class="zoomkey-endpoint">
                <div class="zoomkey-endpoint-head">
                  <strong>JIRA</strong>
                  <button class="btn" type="button" :disabled="!!zoomkeyTestBusy" @click="testZoomkey('jira')">
                    {{ zoomkeyTestBusy === 'jira' ? '测试中…' : '测试连接' }}
                  </button>
                </div>
                <div class="field"><label>站点地址</label><input v-model="zoomkeyPolicy.jira.base_url" /></div>
                <div class="field">
                  <label>金库凭据（API Token 条目，服务选「ZoomKey JIRA」，账号=用户名，密钥=密码）</label>
                  <select v-model="zoomkeyPolicy.jira.credential_id">
                    <option value="">未选择</option>
                    <option v-for="c in zoomkeyCandidates.jira_credentials" :key="c.id" :value="c.id">
                      {{ c.title }}{{ c.account ? ` · ${c.account}` : '' }}
                    </option>
                  </select>
                  <p class="crumb" v-if="!zoomkeyCandidates.jira_credentials.length">
                    还没有可用的 JIRA 凭据。请在保险库新建一条 API Token：服务选「ZoomKey JIRA」、账号填 JIRA 用户名、密钥填 JIRA 密码，保存后回到本页重新进入即可选中。
                  </p>
                </div>
                <div class="field">
                  <label>客户端证书（金库里的「客户端证书」条目）</label>
                  <select v-model="zoomkeyPolicy.jira.client_cert_id">
                    <option value="">未选择</option>
                    <option v-for="c in zoomkeyCandidates.client_certs" :key="c.id" :value="c.id">{{ c.title }}</option>
                  </select>
                  <p class="crumb" v-if="!zoomkeyCandidates.client_certs.length">
                    还没有客户端证书条目。请新建一条「客户端证书」，把 client-cert.pem 与 client-key.pem 贴进去。
                  </p>
                </div>
                <div class="field"><label>CA bundle 路径（含 Root + SubCA 的 PEM，用于验证服务端证书）</label>
                  <div class="path-row">
                    <input v-model="zoomkeyPolicy.jira.ca_bundle_path" placeholder="D:\...\zoomkey-ca-bundle.pem" />
                    <button class="btn" type="button" @click="pickCaBundlePath('jira')">浏览</button>
                  </div>
                  <p class="crumb">这不是凭据条目里选的客户端证书/私钥，而是签发服务端证书的那条链（公司自建 Root CA + SubCA）。</p>
                </div>
              </div>

              <div class="zoomkey-endpoint">
                <div class="zoomkey-endpoint-head">
                  <strong>CRM</strong>
                  <button class="btn" type="button" :disabled="!!zoomkeyTestBusy" @click="testZoomkey('crm')">
                    {{ zoomkeyTestBusy === 'crm' ? '测试中…' : '测试连接' }}
                  </button>
                </div>
                <div class="field">
                  <label>Webservice 地址</label>
                  <input v-model="zoomkeyPolicy.crm.base_url" placeholder="https://crm.zoomkey.com.cn/webservice.php" />
                  <p class="crumb">必须指向 Vtiger 的 webservice.php。填站点首页会拿到登录页 HTML，测试连接会失败。</p>
                </div>
                <div class="field">
                  <label>金库凭据（API Token 条目，服务选「ZoomKey CRM」，账号=用户名，密钥=AccessKey）</label>
                  <select v-model="zoomkeyPolicy.crm.credential_id">
                    <option value="">未选择</option>
                    <option v-for="c in zoomkeyCandidates.crm_credentials" :key="c.id" :value="c.id">
                      {{ c.title }}{{ c.account ? ` · ${c.account}` : '' }}
                    </option>
                  </select>
                  <p class="crumb" v-if="!zoomkeyCandidates.crm_credentials.length">
                    还没有可用的 CRM 凭据。请在保险库新建一条 API Token：服务选「ZoomKey CRM」、账号填 CRM 用户名、密钥填 AccessKey，保存后回到本页重新进入即可选中。
                  </p>
                </div>
                <div class="field">
                  <label>客户端证书</label>
                  <select v-model="zoomkeyPolicy.crm.client_cert_id">
                    <option value="">未选择</option>
                    <option v-for="c in zoomkeyCandidates.client_certs" :key="c.id" :value="c.id">{{ c.title }}</option>
                  </select>
                </div>
                <div class="field"><label>CA bundle 路径（含 Root + SubCA 的 PEM，用于验证服务端证书）</label>
                  <div class="path-row">
                    <input v-model="zoomkeyPolicy.crm.ca_bundle_path" placeholder="D:\...\zoomkey-ca-bundle.pem" />
                    <button class="btn" type="button" @click="pickCaBundlePath('crm')">浏览</button>
                  </div>
                </div>
              </div>

              <div class="mcp-actions">
                <button class="btn primary" type="button" :disabled="zoomkeyBusy" @click="saveZoomkeyPolicy">
                  {{ zoomkeyBusy ? "保存中…" : "保存 ZoomKey 策略" }}
                </button>
              </div>
              <div class="zoomkey-test" v-if="zoomkeyTestResult" :class="{ ok: zoomkeyTestResult.ok }">
                <strong>{{ zoomkeyTestResult.endpoint.toUpperCase() }} {{ zoomkeyTestResult.ok ? "连通正常" : "连接失败" }}</strong>
                <pre>{{ zoomkeyTestResult.text }}</pre>
              </div>
            </template>
            <p class="crumb" v-else>解锁金库后才能读取 ZoomKey 策略。</p>
          </div>
          <div class="mcp-card">
            <h3>工具列表</h3>
            <p class="crumb">当前 MCP 对模型暴露的工具，与 tools/list 一致。</p>
            <div class="tool-list" v-if="mcpTools.length">
              <div class="tool-item" v-for="tool in mcpTools" :key="tool.name">
                <div class="tool-heading">
                  <code class="tool-name">{{ tool.name }}</code>
                  <span class="tool-risk" :class="{ safe: tool.readOnly, danger: !tool.readOnly }">{{ tool.readOnly ? "只读" : tool.risk }}</span>
                </div>
                <p class="crumb">{{ tool.description }}</p>
              </div>
            </div>
            <p class="crumb" v-else>还没有读到工具定义。</p>
          </div>
        </div>
      </section>

      <section class="main" v-else-if="page === 'plugin'">
        <div class="content content-page mcp-page">
          <div class="mcp-head">
            <div>
              <h2>插件</h2>
            </div>
          </div>
          <div class="mcp-card" style="max-width:640px">
            <h3>安装扩展</h3>
            <p class="crumb">{{ extStatusText(extStatus) }}</p>
            <div class="field" v-if="extStatus?.dest_path">
              <label>本机目录</label>
              <div class="secret-row">
                <input class="plugin-path" :value="extStatus.dest_path" readonly />
                <button class="btn" type="button" @click="copyExtensionPath">复制</button>
              </div>
            </div>
            <p class="error" v-if="extError">{{ extError }}</p>
            <div class="mcp-actions">
              <button class="btn primary" type="button" :disabled="extBusy" @click="installExtension">
                {{ extBusy ? "正在安装…" : (extStatus && extStatus.installed && !extStatus.outdated ? "重新安装并打开目录" : "安装到本机并打开目录") }}
              </button>
              <button class="btn" type="button" :disabled="!extStatus?.installed" @click="openExtensionFolder">打开目录</button>
              <button class="btn" type="button" :disabled="!extStatus?.chrome.available" @click="openExtensionBrowser('chrome')">打开 Chrome 扩展页</button>
              <button class="btn" type="button" :disabled="!extStatus?.edge.available" @click="openExtensionBrowser('edge')">打开 Edge 扩展页</button>
            </div>
            <p class="crumb" v-if="extStatus && !extStatus.chrome.available">未检测到 Google Chrome</p>
            <p class="crumb" v-if="extStatus && !extStatus.edge.available">未检测到 Microsoft Edge</p>
            <ol class="plugin-steps">
              <li>打开开发者模式</li>
              <li>加载已解压的扩展</li>
              <li>选择上面这个文件夹</li>
            </ol>
            <p class="crumb">升级 Sealbox 后若提示更新，先点安装覆盖文件，再回扩展页点刷新。路径不要改。</p>

            <h3>配对</h3>
            <p class="crumb">扩展加载成功后，点配对，60 秒内把一次性配对码填进扩展。</p>
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
          </div>
        </div>
      </section>

      <section class="main" v-else-if="page === 'assistant'">
        <div class="content content-page assistant-page">
          <div class="mcp-head assistant-head">
            <div>
              <h2>助手</h2>
              <p class="crumb">用 OpenAI 兼容接口聊天，并通过本机 MCP 只读工具验证连通性。API Key 只保存在加密金库中。</p>
            </div>
            <div class="mcp-status">
              <span class="mcp-dot" :class="{ on: assistantConfig?.hasApiKey }" />
              <span>{{ assistantConfig?.hasApiKey ? "模型已配置" : "待配置模型" }}</span>
              <span class="assistant-connection" :class="{ connected: assistantMcp?.connected }">
                {{ assistantMcp?.connected ? `MCP · ${assistantMcp.tools.length} 工具` : "MCP 未测试" }}
              </span>
            </div>
          </div>
          <p class="error" v-if="assistantError">{{ assistantError }}</p>
          <div class="assistant-layout">
            <div class="assistant-side">
              <div class="mcp-card assistant-card">
                <div class="assistant-card-heading">
                  <div>
                    <h3>模型配置</h3>
                    <p class="crumb">兼容 Chat Completions 的服务均可使用。</p>
                  </div>
                  <span class="tool-risk" :class="{ safe: assistantConfig?.hasApiKey }">{{ assistantConfig?.hasApiKey ? "已配置" : "未配置" }}</span>
                </div>
                <div class="field">
                  <label>Base URL</label>
                  <input v-model="assistantBaseUrl" placeholder="https://api.openai.com/v1" />
                </div>
                <div class="field">
                  <label>模型</label>
                  <input v-model="assistantModel" placeholder="gpt-4o-mini" />
                </div>
                <div class="field">
                  <label>API Key <span class="crumb">（留空保持原值）</span></label>
                  <input v-model="assistantApiKey" type="password" autocomplete="off" placeholder="不会回显或返回前端" />
                </div>
                <label class="checkbox-row assistant-check">
                  <input v-model="assistantClearApiKey" type="checkbox" />
                  <span>清除已保存的 API Key</span>
                </label>
                <button class="btn primary" type="button" :disabled="assistantConfigBusy" @click="saveAssistantConfig">
                  {{ assistantConfigBusy ? "保存中…" : "保存配置" }}
                </button>
              </div>

              <div class="mcp-card assistant-card">
                <div class="assistant-card-heading">
                  <div>
                    <h3>MCP 连通性</h3>
                    <p class="crumb">助手会连接当前 Sealbox 的本机 MCP，不把 Token 交给网页。</p>
                  </div>
                  <span class="tool-risk" :class="{ safe: assistantMcp?.connected }">{{ assistantMcp?.connected ? "在线" : "待测试" }}</span>
                </div>
                <div class="assistant-endpoint" v-if="assistantMcp?.url || mcp?.url">{{ assistantMcp?.url || mcp?.url }}</div>
                <button class="btn" type="button" :disabled="assistantProbeBusy" @click="probeAssistantMcp">
                  {{ assistantProbeBusy ? "测试中…" : "测试 MCP" }}
                </button>
                <div class="tool-list assistant-tool-list" v-if="assistantMcp?.tools.length">
                  <div class="tool-item" v-for="tool in assistantMcp.tools" :key="tool.name">
                    <div class="tool-heading">
                      <code class="tool-name">{{ tool.name }}</code>
                      <span class="tool-risk safe">只读</span>
                    </div>
                    <p class="crumb">{{ tool.description }}</p>
                  </div>
                </div>
                <p class="crumb" v-else>点击“测试 MCP”发现当前可用工具。</p>
              </div>
            </div>

            <div class="mcp-card assistant-card assistant-chat-card">
              <div class="assistant-card-heading">
                <div>
                  <h3>对话</h3>
                  <p class="crumb">工具结果会标记为外部资料，不会改变助手权限。</p>
                </div>
                <div class="mcp-actions assistant-chat-actions">
                  <span class="crumb">助手只调用只读工具；git 写入需在 Cursor 里使用</span>
                  <button class="btn" type="button" :disabled="assistantChatBusy || !assistantMessages.length" @click="clearAssistantChat">清空</button>
                </div>
              </div>
              <div class="assistant-messages" aria-live="polite">
                <div class="assistant-empty" v-if="!assistantMessages.length">
                  <div class="assistant-empty-mark">✦</div>
                  <strong>开始一次 MCP 连通性测试</strong>
                  <p class="crumb">例如：“列出当前可用的 GitHub 工具”，或直接问一个普通问题。</p>
                </div>
                <div class="assistant-message" :class="message.role" v-for="(message, index) in assistantMessages" :key="`${index}-${message.role}`">
                  <span class="assistant-message-role">{{ message.role === 'user' ? '你' : '助手' }}</span>
                  <div class="assistant-message-content">{{ message.content }}</div>
                </div>
                <div class="assistant-thinking" v-if="assistantChatBusy"><span></span><span></span><span></span> 正在思考…</div>
              </div>
              <div class="assistant-traces" v-if="assistantTraces.length">
                <div class="assistant-trace-title">工具调用记录</div>
                <details class="assistant-tool-trace" v-for="(trace, index) in assistantTraces" :key="`${trace.name}-${index}`">
                  <summary>
                    <span class="assistant-trace-dot" :class="{ ok: trace.success }" />
                    <code>{{ trace.name }}</code>
                    <span>{{ trace.success ? "完成" : "失败" }}</span>
                  </summary>
                  <div class="assistant-trace-body">
                    <div><strong>参数</strong><pre>{{ trace.arguments }}</pre></div>
                    <div><strong>结果预览</strong><pre>{{ trace.resultPreview }}</pre></div>
                  </div>
                </details>
              </div>
              <form class="assistant-composer" @submit.prevent="sendAssistantMessage">
                <textarea v-model="assistantInput" rows="3" :disabled="assistantChatBusy" placeholder="输入消息，Enter 发送，Shift+Enter 换行" @keydown.enter.exact.prevent="sendAssistantMessage" />
                <div class="assistant-composer-foot">
                  <span class="crumb">助手不会调用 github_git_commit / push / pull / clone</span>
                  <button class="btn primary" type="submit" :disabled="assistantChatBusy || !assistantInput.trim()">{{ assistantChatBusy ? "发送中…" : "发送" }}</button>
                </div>
              </form>
            </div>
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
            <option value="client_cert">客户端证书</option>
          </select>
        </div>
        <div class="field"><label>键名</label><input v-model="form.title" /></div>
        <div class="field" v-if="form.kind !== 'ssh' && form.kind !== 'mailbox' && form.kind !== 'mail_auth' && form.kind !== 'client_cert'"><label>{{ form.kind === 'server' || form.kind === 'database' ? '用户名' : '账号' }}</label><input v-model="form.account" /></div>
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
            <option value="zoomkey-jira">ZoomKey JIRA（MCP 用）</option>
            <option value="zoomkey-crm">ZoomKey CRM（MCP 用）</option>
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
        <div class="field cert-import-panel" v-if="form.kind === 'client_cert'">
          <label>客户端证书与私钥</label>
          <p class="crumb">文件只在 Rust 侧读取并加密保存；不会把私钥内容回显到界面，也不会保存原始路径。</p>
          <div class="cert-file-row">
            <input :value="form.cert_path || '未选择证书 PEM 文件'" readonly />
            <button class="btn" type="button" @click="pickClientCertFile('cert')">选择证书</button>
          </div>
          <div class="cert-file-row">
            <input :value="form.key_path || '未选择私钥 PEM 文件'" readonly />
            <button class="btn" type="button" @click="pickClientCertFile('key')">选择私钥</button>
          </div>
          <div class="cert-meta" v-if="clientCertInfo">
            <span>指纹：{{ clientCertInfo.fingerprint || '—' }}</span>
            <span>证书链：{{ clientCertInfo.certificateCount ?? '—' }} 张</span>
            <span v-if="clientCertInfo.hasPassphrase">含私钥口令</span>
          </div>
          <p class="crumb" v-if="editing && !form.cert_path && !form.key_path">不选择新文件将保留当前加密证书，仅更新下方元数据。</p>
          <div class="field cert-passphrase"><label>私钥口令（可空）</label><input v-model="form.cert_passphrase" type="password" autocomplete="off" /></div>
        </div>
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
