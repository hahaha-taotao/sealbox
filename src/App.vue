<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, shallowRef } from "vue";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { openUrl } from "@tauri-apps/plugin-opener";
import packageJson from "../package.json";
import { DB_ENGINES } from "./lib/entry-options";
import { auditDateBounds, createAuditRequestGuard } from "./lib/audit-request";
import { buildResolutions, completeChoices, type SyncChoice } from "./lib/sync-choice.mjs";
import {
  checkForUpdate,
  download,
  install,
  RELEASE_PAGE_URL,
  type AvailableUpdate,
  type NormalizedDownloadEvent,
  type UpdaterMetadata,
} from "./lib/updater";
import {
  api,
  type AuditEvent,
  type ClientCertInfo,
  type BackupPreview,
  type Counts,
  type CsvPreview,
  type EntryDto,
  type EntryKind,
  type EntryProfile,
  type ExtensionInstallStatus,
  type FolderDto,
  type ListFilter,
  type McpStatus,
  type McpToolInfo,
  type SecretPayload,
  type Status,
  type SyncKind,
  type SyncPreview,
  type SyncReport,
  type SyncVerifyResult,
  type SyncView,
  type UpsertEntry,
  type WebsiteDuplicate,
  type ZoomkeyCandidates,
  type ZoomkeyMcpPolicy,
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
const auditTotal = ref(0);
const auditOffset = ref(0);
const auditLoading = ref(false);
const auditError = ref("");
const auditActions = ref<[string, string][]>([]);
const auditResults = ref<[string, string][]>([]);
const auditFilter = reactive({ keyword: "", action: "", result: "", from: "", to: "" });
const auditGuard = createAuditRequestGuard();
let auditApplied = { ...auditFilter };
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
const websiteDuplicates = ref<WebsiteDuplicate[]>([]);
const saveBusy = ref(false);
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
const backupIncludeSettings = ref(false);
const backupRestoreSettings = ref(false);
const backupBusy = ref(false);
const backupPreview = ref<BackupPreview | null>(null);
const backupNewPassword = ref("");
const backupNewPassword2 = ref("");
const backupExporting = computed(() => backupMode.value === "export" && Boolean(status.value?.initialized));
const csvImportOpen = ref(false);
const csvMode = ref<"import" | "export">("import");
const csvImportPath = ref("");
const csvImportPreview = ref<CsvPreview | null>(null);
const csvImportOverwrite = ref(false);
const csvImportBusy = ref(false);
const csvRiskConfirmed = ref(false);
const csvPassword = ref("");
const CSV_RISK_TEXT = "这是明文网站迁移，不含证书/SSH/服务器，不要用表格软件打开";
const organizationOpen = ref(false);
const organizationBusy = ref(false);
const organizationTab = ref<"folders" | "tags">("folders");
const folderDrafts = reactive<Record<string, string>>({});
const folderMergeTargets = reactive<Record<string, string>>({});
const tagDrafts = reactive<Record<string, string>>({});
const tagMergeTargets = reactive<Record<string, string>>({});

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
  const raw = s.trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) return raw;
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return raw.replace("T", " ").slice(0, 16);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

async function refreshStatus() {
  status.value = await api.status();
}
let vaultSeq = 0;
let vaultSearchTimer: ReturnType<typeof setTimeout> | null = null;
function clearVaultSearchTimer() {
  if (vaultSearchTimer) {
    clearTimeout(vaultSearchTimer);
    vaultSearchTimer = null;
  }
}
function scheduleVaultSearch() {
  clearVaultSearchTimer();
  vaultSearchTimer = setTimeout(() => {
    vaultSearchTimer = null;
    void refreshVault();
  }, 200);
}
function searchVaultNow() {
  clearVaultSearchTimer();
  void refreshVault();
}
async function refreshVault() {
  const seq = ++vaultSeq;
  const kinds = selectedKindIds.value;
  const scoped = {
    ...filter,
    query: filter.query || null,
    kinds,
    kind: kinds.length === 1 ? kinds[0] : null,
  };
  const [nextEntries, nextCounts, nextFolders, nextTags, nextStatus] = await Promise.all([
    api.list(scoped),
    api.counts({
      ...scoped,
      kinds: [],
      kind: null,
    }),
    api.folders(),
    api.tags(),
    api.status(),
  ]);
  if (seq !== vaultSeq) return;
  entries.value = nextEntries;
  scopedCounts.value = nextCounts;
  folders.value = nextFolders;
  tags.value = nextTags;
  status.value = nextStatus;
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
    void autoCheckUpdate();
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
    void autoCheckUpdate();
  } catch {
    error.value = "主密码不正确";
  }
}
async function openAudit() {
  goPage("audit");
  await queryAudit();
}
async function queryAudit(offset = 0, applyFilters = true) {
  if (!status.value?.unlocked) return;
  const request = auditGuard.begin();
  auditLoading.value = true;
  auditError.value = "";
  audit.value = [];
  auditTotal.value = 0;
  if (applyFilters) auditApplied = { ...auditFilter };
  try {
    const bounds = auditDateBounds(auditApplied.from, auditApplied.to);
    const result = await api.audit({
      keyword: auditApplied.keyword,
      actions: auditApplied.action ? [auditApplied.action] : [],
      result: auditApplied.result,
      ...bounds, limit: 50, offset,
    });
    if (!auditGuard.isCurrent(request)) return;
    audit.value = result.items;
    auditTotal.value = result.total;
    auditActions.value = result.actions;
    auditResults.value = result.results;
    auditOffset.value = offset;
  } catch (e) {
    if (auditGuard.isCurrent(request)) auditError.value = String(e);
  } finally {
    if (auditGuard.isCurrent(request)) auditLoading.value = false;
  }
}
function resetAudit() {
  Object.assign(auditFilter, { keyword: "", action: "", result: "", from: "", to: "" });
  void queryAudit();
}
function syncOpenDetail(id: string) {
  if (detail.value?.entry.id !== id) return;
  const row = entries.value.find((entry) => entry.id === id);
  if (row) detail.value = { ...detail.value, entry: row };
}
async function togglePin(row: EntryDto) {
  await api.pin(row.id, !row.pinned);
  await refreshVault();
  syncOpenDetail(row.id);
}
async function doEmptyTrash() {
  if (!confirm("彻底删除回收站中的全部条目？不可恢复。")) return;
  await api.emptyTrash();
  selected.value.clear();
  if (detailTrashed.value) closeDetail();
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
const zoomkeyPolicy = ref<ZoomkeyMcpPolicy | null>(null);
const zoomkeyCandidates = ref<ZoomkeyCandidates>({
  jira_credentials: [],
  crm_credentials: [],
  client_certs: [],
});
const zoomkeyBusy = ref(false);
const zoomkeyTestBusy = ref("");
const zoomkeyTestResult = ref<{ endpoint: string; ok: boolean; text: string } | null>(null);
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
      "开启后，Sealbox 会同时开放 GitHub 和 ZoomKey MCP 工具；ZoomKey 只会向白名单内的内网主机发起请求（携带金库里的客户端证书）。\n" +
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
      showToast(zoomkeyPolicy.value.enabled ? "MCP 已启用" : "MCP 已停用");
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
  try {
    await api.copyPairingCode();
    showToast("配对码已复制");
  } catch (e) {
    pairingError.value = String(e);
    showToast(pairingError.value);
  }
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
  try {
    await api.copyExtensionPath();
    showToast("扩展目录已复制");
  } catch (e) {
    extError.value = String(e);
    showToast(extError.value);
  }
}

async function openPlugin() {
  goPage("plugin");
  await refreshMcp();
  await refreshPairing();
  await refreshExtensionInstall();
}

function goPage(next: Page) {
  if (page.value === next) return;
  history.value = history.value.slice(0, historyIndex.value + 1);
  history.value.push(next);
  historyIndex.value = history.value.length - 1;
  page.value = next;
  if (next === "settings" && status.value?.unlocked) {
    loadSettings().catch(() => undefined);
    loadSync().catch(() => undefined);
  }
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

function clearWebsiteDuplicateState() {
  websiteDuplicates.value = [];
}
function editWebsiteDuplicate(entry: WebsiteDuplicate) {
  openEdit(entry);
}
async function continueWithWebsiteDuplicate() {
  try {
    const duplicates = await api.findWebsiteDuplicates(form.url, form.account, editing.value?.id ?? null);
    if (!duplicates.length) {
      clearWebsiteDuplicateState();
      await saveEntry();
      return;
    }
    websiteDuplicates.value = duplicates;
    await saveEntry(true);
  } catch (e) {
    showToast(String(e));
  }
}
function closeForm() {
  showForm.value = false;
  editing.value = null;
  clearWebsiteDuplicateState();
  resetFormFields();
}
const detailOpen = ref(false);
const detailTrashed = ref(false);
const detail = ref<EntryProfile | null>(null);
let detailSeq = 0;
function closeDetail() {
  detailSeq += 1;
  detailOpen.value = false;
  detailTrashed.value = false;
  detail.value = null;
  hideSecret();
}
function folderName(id: string | null) {
  if (!id) return "未归类";
  return folders.value.find((folder) => folder.id === id)?.name || "未归类";
}
function revealedSecretText() {
  const payload = reveal.value;
  if (!payload) return "";
  if (payload.type === "website" || payload.type === "mailbox" || payload.type === "server" || payload.type === "database") return payload.password;
  if (payload.type === "api_token") return payload.token;
  if (payload.type === "mail_auth") return payload.auth_code;
  if (payload.type === "ssh") return payload.private_key;
  return "";
}
async function openDetail(row: EntryDto, trashed = page.value === "vault" && Boolean(filter.trash)) {
  const seq = ++detailSeq;
  detailOpen.value = true;
  detailTrashed.value = trashed;
  detail.value = null;
  hideSecret();
  try {
    const profile = await api.profile(row.id);
    if (seq !== detailSeq) return;
    detail.value = profile;
  } catch (e) {
    if (seq !== detailSeq) return;
    closeDetail();
    showToast(String(e));
  }
}
async function refreshOpenDetail() {
  const id = detail.value?.entry.id;
  if (!detailOpen.value || !id) return;
  const seq = ++detailSeq;
  try {
    const profile = await api.profile(id);
    if (seq !== detailSeq) return;
    detail.value = profile;
  } catch {
    if (seq === detailSeq) closeDetail();
  }
}
function openOverview(kind: EntryKind | null, trash = false) {
  filter.kinds = kind ? [kind] : [];
  filter.kind = kind;
  setFilter(trash ? { trash: true } : {});
  goPage("vault");
}
function openCreate() {
  editing.value = null;
  clearWebsiteDuplicateState();
  resetFormFields();
  showForm.value = true;
}
async function openEdit(row: EntryDto) {
  resetGenerator();
  clearWebsiteDuplicateState();
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

async function saveEntry(allowWebsiteDuplicate = false) {
  if (saveBusy.value) return;
  saveBusy.value = true;
  if (form.kind === "website" && !allowWebsiteDuplicate) {
    try {
      const duplicates = await api.findWebsiteDuplicates(form.url, form.account, editing.value?.id ?? null);
      if (duplicates.length) {
        websiteDuplicates.value = duplicates;
        saveBusy.value = false;
        return;
      }
    } catch (e) {
      showToast(String(e));
      saveBusy.value = false;
      return;
    }
  }
  if (form.kind === "client_cert") {
    const hasCertPath = Boolean(form.cert_path);
    const hasKeyPath = Boolean(form.key_path);
    if (hasCertPath !== hasKeyPath || (!editing.value && (!hasCertPath || !hasKeyPath))) {
      showToast("请选择客户端证书和私钥文件，或都不选择");
      saveBusy.value = false;
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
      await refreshOpenDetail();
    } catch (e) {
      showToast(String(e));
    } finally {
      certImportBusy.value = false;
      saveBusy.value = false;
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
  try {
    await api.create(input, allowWebsiteDuplicate);
    closeForm();
    showToast("已保存");
    await refreshVault();
    await refreshOpenDetail();
  } catch (e) {
    const message = String(e);
    if (form.kind === "website" && message.includes("已有同站同账号")) {
      websiteDuplicates.value = await api.findWebsiteDuplicates(form.url, form.account, editing.value?.id ?? null).catch(() => []);
    }
    showToast(message);
  } finally {
    saveBusy.value = false;
  }
}

async function copy(id: string, field = "secret") {
  await api.copy(id, field);
  showToast(field === "account" ? "已复制账号" : field === "totp" ? "已复制验证码" : "已复制，20 秒后清空剪贴板");
  await refreshVault();
  syncOpenDetail(id);
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
  if (detail.value && ids.includes(detail.value.entry.id)) closeDetail();
  await refreshVault();
}
async function restore(ids: string[]) {
  await api.restore(ids);
  if (detail.value && ids.includes(detail.value.entry.id)) closeDetail();
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
  try {
    await api.createFolder(name);
    await refreshVault();
  } catch (e) {
    showToast(String(e));
  }
}
function openOrganization(tab: "folders" | "tags" = "folders") {
  organizationTab.value = tab;
  for (const folder of folders.value) {
    folderDrafts[folder.id] = folder.name;
    folderMergeTargets[folder.id] = "";
  }
  for (const tag of tags.value) {
    tagDrafts[tag] = tag;
    tagMergeTargets[tag] = "";
  }
  organizationOpen.value = true;
}
async function runOrganization(action: () => Promise<unknown>, success: string) {
  if (organizationBusy.value) return;
  organizationBusy.value = true;
  try {
    await action();
    await refreshVault();
    let filterChanged = false;
    if (filter.folder_id && !folders.value.some((folder) => folder.id === filter.folder_id)) {
      filter.folder_id = null;
      filterChanged = true;
    }
    if (filter.tag && !tags.value.includes(filter.tag)) {
      filter.tag = null;
      filterChanged = true;
    }
    if (filterChanged) await refreshVault();
    openOrganization(organizationTab.value);
    showToast(success);
  } catch (e) {
    showToast(String(e));
  } finally {
    organizationBusy.value = false;
  }
}
async function renameFolderFromManager(folder: FolderDto) {
  const name = folderDrafts[folder.id]?.trim() || "";
  if (name === folder.name) return;
  await runOrganization(() => api.renameFolder(folder.id, name), "文件夹已重命名");
}
async function deleteFolderFromManager(folder: FolderDto) {
  if (!confirm(`删除“${folder.name}”？其中的凭据会移到未归类，不会删除凭据。`)) return;
  await runOrganization(() => api.deleteFolder(folder.id), "文件夹已删除");
}
async function mergeFolderFromManager(folder: FolderDto) {
  const targetId = folderMergeTargets[folder.id];
  const target = folders.value.find((item) => item.id === targetId);
  if (!target) {
    showToast("请选择合并目标");
    return;
  }
  if (!confirm(`将“${folder.name}”合并到“${target.name}”？其中的凭据会归入目标文件夹。`)) return;
  await runOrganization(() => api.mergeFolders(folder.id, target.id), "文件夹已合并");
}
async function renameTagFromManager(tag: string) {
  const name = tagDrafts[tag]?.trim() || "";
  if (name === tag) return;
  await runOrganization(() => api.renameTag(tag, name), "标签已重命名");
}
async function deleteTagFromManager(tag: string) {
  if (!confirm(`删除标签“${tag}”？只会解除标签关联，不会删除凭据。`)) return;
  await runOrganization(() => api.deleteTag(tag), "标签已删除");
}
async function mergeTagFromManager(tag: string) {
  const target = tagMergeTargets[tag];
  if (!target) {
    showToast("请选择合并目标");
    return;
  }
  if (!confirm(`将标签“${tag}”合并到“${target}”？重复关联会自动去重。`)) return;
  await runOrganization(() => api.mergeTags(tag, target), "标签已合并");
}
function resetBackupPreview() {
  backupPreview.value = null;
  backupRestoreSettings.value = false;
  backupNewPassword.value = "";
  backupNewPassword2.value = "";
}

function closeBackup() {
  backupOpen.value = false;
  backupPassword.value = "";
  backupNewPassword.value = "";
  backupNewPassword2.value = "";
  backupPreview.value = null;
}

function openBackup(mode: "export" | "import") {
  backupMode.value = status.value?.initialized ? mode : "import";
  backupPassword.value = "";
  backupIncludeSettings.value = false;
  backupOverwrite.value = false;
  resetBackupPreview();
  backupOpen.value = true;
}

async function inspectBackup() {
  if (backupBusy.value) return;
  if (!backupPath.value || !backupPassword.value) {
    showToast("请填写路径和备份密码");
    return;
  }
  backupBusy.value = true;
  resetBackupPreview();
  try {
    backupPreview.value = await api.backupInspect({ path: backupPath.value, backupPassword: backupPassword.value });
    backupPassword.value = "";
  } catch (e) {
    showToast(String(e));
  } finally {
    backupBusy.value = false;
  }
}

async function runBackupExport() {
  if (backupBusy.value) return;
  if (!status.value?.unlocked) {
    showToast("请先解锁再导出");
    return;
  }
  if (!backupPath.value || !backupPassword.value) {
    showToast("请填写路径和主密码");
    return;
  }
  backupBusy.value = true;
  try {
    await api.backupExport({
      path: backupPath.value,
      password: backupPassword.value,
      includeSettings: backupIncludeSettings.value,
    });
    showToast("已导出备份");
    closeBackup();
  } catch (e) {
    showToast(String(e));
  } finally {
    backupBusy.value = false;
    backupPassword.value = "";
  }
}

async function runBackupRestore() {
  if (backupBusy.value) return;
  const preview = backupPreview.value;
  if (!preview) {
    showToast("请先校验并查看备份摘要");
    return;
  }
  const initialized = Boolean(status.value?.initialized);
  if (initialized && backupOverwrite.value && !confirm("覆盖导入会替换同 id 的现有条目，且无法撤销。确定继续？")) {
    return;
  }
  if (!initialized) {
    if (backupNewPassword.value.length < 10) {
      showToast("新主密码至少 10 位");
      return;
    }
    if (backupNewPassword.value !== backupNewPassword2.value) {
      showToast("两次新主密码不一致");
      return;
    }
  }
  const restoreSettings = Boolean(preview.summary.includes_settings && backupRestoreSettings.value);
  backupBusy.value = true;
  try {
    const result = initialized
      ? await api.backupRestore({ token: preview.token, overwrite: backupOverwrite.value, restoreSettings })
      : await api.backupRestoreNew({ token: preview.token, newPassword: backupNewPassword.value, restoreSettings });
    showToast(`导入 ${result.imported} 条，跳过 ${result.skipped} 条`);
    closeBackup();
    await refreshStatus();
    if (status.value?.unlocked) {
      await refreshVault();
      await loadSettings().catch(() => undefined);
    }
  } catch (e) {
    backupPreview.value = null;
    showToast(String(e));
  } finally {
    backupBusy.value = false;
    backupPassword.value = "";
    backupNewPassword.value = "";
    backupNewPassword2.value = "";
  }
}
const settingsIdle = ref(15);
const settingsClip = ref(20);
const settingsHotkey = ref("Ctrl+Shift+Space");
const oldMaster = ref("");
const newMaster = ref("");
const newMaster2 = ref("");
const syncKind = ref<SyncKind>("webdav");
const syncEndpoint = ref("");
const syncUsername = ref("");
const syncSecret = ref("");
const syncBucket = ref("");
const syncRegion = ref("us-east-1");
const syncPrefix = ref("");
const syncView = ref<SyncView | null>(null);
const syncBusy = ref(false);
const syncReport = ref<SyncReport | null>(null);
const syncAuto = ref(true);
const syncAutoSecs = ref(60);
const syncToken = ref("");
const syncExpiresSecs = ref(0);
const syncChoices = reactive<Record<string, SyncChoice>>({});
const syncVerifyResult = ref<SyncVerifyResult | null>(null);
const syncConflicts = computed(() => syncReport.value?.conflict_details ?? []);
const syncCanCommit = computed(() => {
  const phase = syncReport.value?.phase;
  if (!syncToken.value) return false;
  if (phase === "local_pending") return true;
  return (phase === "preview" || phase === "conflicts") && completeChoices(syncConflicts.value, syncChoices);
});

async function loadSync() {
  syncView.value = await api.syncStatus();
  if (!syncView.value.configured) return;
  syncKind.value = syncView.value.kind ?? "webdav";
  syncEndpoint.value = syncView.value.endpoint;
  syncUsername.value = syncView.value.username;
  syncBucket.value = syncView.value.bucket;
  syncRegion.value = syncView.value.region || "us-east-1";
  syncPrefix.value = syncView.value.prefix;
  syncAuto.value = syncView.value.auto_sync;
  syncAutoSecs.value = syncView.value.auto_sync_secs;
}

function clearSyncChoices() {
  for (const id of Object.keys(syncChoices)) delete syncChoices[id];
}

function clearSyncPreview() {
  syncToken.value = "";
  syncExpiresSecs.value = 0;
  clearSyncChoices();
}

function adoptSyncPreview(result: SyncPreview) {
  clearSyncChoices();
  syncToken.value = result.token;
  syncExpiresSecs.value = result.expires_in_secs;
  syncReport.value = result.report;
  for (const item of result.report.conflict_details ?? []) {
    syncChoices[item.id] = { choice: "", confirm_delete_edit: false };
  }
}

function syncPhaseLabel(phase: string | undefined) {
  switch (phase) {
    case "preview": return "预览";
    case "conflicts": return "待解决冲突";
    case "committed": return "已提交";
    case "local_pending": return "本地待完成";
    case "blocked": return "已阻塞";
    default: return "未知";
  }
}

async function fetchSyncPreview() {
  clearSyncPreview();
  const result = await api.syncPreview();
  adoptSyncPreview(result);
  return result;
}

async function previewSync() {
  if (syncBusy.value) return null;
  syncBusy.value = true;
  try {
    return await fetchSyncPreview();
  } catch (e) {
    showToast(String(e));
    return null;
  } finally {
    syncBusy.value = false;
  }
}

async function saveSync() {
  syncBusy.value = true;
  try {
    syncView.value = await api.syncSave({
      kind: syncKind.value,
      endpoint: syncEndpoint.value,
      username: syncUsername.value,
      secret: syncSecret.value || null,
      bucket: syncBucket.value || null,
      region: syncRegion.value || null,
      prefix: syncPrefix.value || null,
      auto_sync: syncAuto.value,
      auto_sync_secs: Number(syncAutoSecs.value) || 60,
    });
    syncSecret.value = "";
    clearSyncPreview();
    syncReport.value = null;
    showToast("同步配置已保存");
  } catch (e) {
    showToast(String(e));
  } finally {
    syncBusy.value = false;
  }
}

async function commitSync() {
  if (syncBusy.value || !syncCanCommit.value || !syncToken.value) return;
  syncBusy.value = true;
  const token = syncToken.value;
  const pendingLocal = syncReport.value?.phase === "local_pending";
  try {
    const resolutions = pendingLocal && !completeChoices(syncConflicts.value, syncChoices)
      ? []
      : buildResolutions(syncConflicts.value, syncChoices);
    const report = await api.syncCommit({ token, resolutions });
    syncReport.value = report;
    if (report.phase === "local_pending") {
      showToast(report.blocked || "远端已写入，本地尚未完成。请重试提交，不要重新预览。");
      return;
    }
    clearSyncPreview();
    syncReport.value = report;
    if (report.phase === "committed") {
      await loadSync();
      await refreshVault();
      const removed = report.removed ? `，删除 ${report.removed}` : "";
      showToast(`已同步：拉取 ${report.pulled}，推送 ${report.pushed}${removed}`);
      return;
    }
    showToast(report.blocked || "同步未提交，正在重新预览");
    try {
      await fetchSyncPreview();
    } catch (again) {
      showToast(String(again));
    }
  } catch (e) {
    const message = String(e);
    showToast(message);
    if (pendingLocal || message.includes("sync_local_retry_pending")) return;
    clearSyncPreview();
    try {
      await fetchSyncPreview();
    } catch (again) {
      showToast(String(again));
    }
  } finally {
    syncBusy.value = false;
  }
}

async function runSync() {
  if (syncReport.value?.phase === "local_pending" && syncToken.value) {
    await commitSync();
    return;
  }
  const result = await previewSync();
  if (!result) return;
  if (result.report.phase === "blocked") {
    showToast(result.report.blocked || "同步已阻塞");
    return;
  }
  if (result.report.phase === "local_pending") {
    showToast(result.report.blocked || "本地尚未完成，请重试提交");
    return;
  }
  if (result.report.conflict_details.length > 0 || result.report.phase === "conflicts") {
    showToast(`有 ${result.report.conflict_details.length} 条冲突，请逐条选择后再提交`);
    return;
  }
  await commitSync();
}

async function verifySync() {
  if (syncBusy.value) return;
  syncBusy.value = true;
  try {
    syncVerifyResult.value = await api.syncVerifyConditional();
    showToast(syncVerifyResult.value.verified ? "安全条件写入已验证" : "服务端未通过安全验证");
  } catch (e) {
    syncVerifyResult.value = null;
    showToast(String(e));
  } finally {
    syncBusy.value = false;
  }
}

async function clearSync() {
  if (!confirm("清除这台设备上的同步配置和同步密钥？远端文件不会删除。")) return;
  try {
    await api.syncClear();
    syncView.value = null;
    syncSecret.value = "";
    syncReport.value = null;
    syncVerifyResult.value = null;
    clearSyncPreview();
    showToast("已清除同步配置");
  } catch (e) {
    showToast(String(e));
  }
}
const appVersion = ref(String(packageJson.version));
const update = shallowRef<AvailableUpdate | null>(null);
const updateMetadata = ref<UpdaterMetadata | null>(null);
const updateBusy = ref(false);
const updateError = ref("");
const updateCheckedAt = ref("");
const updateStage = ref<"idle" | "checking" | "available" | "downloading" | "ready" | "installing" | "error">("idle");
const updateDownloadedBytes = ref(0);
const updateContentLength = ref<number | null>(null);
const updateDownloadFinished = ref(false);
const updateDialogOpen = ref(false);
let updateAutoChecked = false;
const updateProgress = computed(() => {
  if (!updateContentLength.value || updateContentLength.value <= 0) return null;
  return Math.min(100, Math.round((updateDownloadedBytes.value / updateContentLength.value) * 100));
});
const aboutUpdateText = computed(() => {
  switch (updateStage.value) {
    case "checking": return "正在检查更新…";
    case "available": return `发现新版本 v${updateMetadata.value?.latestVersion ?? ""}`;
    case "downloading": return updateProgress.value === null ? "正在下载更新…" : `正在下载更新… ${updateProgress.value}%`;
    case "ready": return "更新已下载，等待安装";
    case "installing": return "正在安装更新…";
    case "error": return "更新未完成，可重试";
    default: return updateCheckedAt.value ? `已是最新版本 · ${updateCheckedAt.value} 检查` : "使用 GitHub Releases 检查更新";
  }
});
const aboutUpdateAction = computed(() => {
  if (updateStage.value === "checking") return "检查中…";
  return update.value || updateStage.value === "downloading" || updateStage.value === "ready" || updateStage.value === "installing"
    ? "查看更新"
    : "检查更新";
});
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
  if (!nativeDialogInFlight()) {
    closeForm();
    closeDetail();
  }
  hideBridgeTokens();
}

function clearSecrets() {
  hideVisibleSecrets();
  clientCertInfo.value = null;
  certInfoFor.value = null;
  closeForm();
  backupPassword.value = "";
  backupNewPassword.value = "";
  backupNewPassword2.value = "";
  backupPreview.value = null;
  csvImportOpen.value = false;
  csvImportPath.value = "";
  csvImportPreview.value = null;
  csvImportOverwrite.value = false;
  csvRiskConfirmed.value = false;
  csvPassword.value = "";
  syncReport.value = null;
  syncVerifyResult.value = null;
  clearSyncPreview();
  pairing.value = null;
  pairingError.value = "";
  stopPairingTimer();
  oldMaster.value = "";
  newMaster.value = "";
  newMaster2.value = "";
}

function applyLockedUi() {
  if (status.value) status.value = { ...status.value, unlocked: false };
  clearVaultSearchTimer();
  vaultSeq += 1;
  clearSecrets();
  backupOpen.value = false;
  updateDialogOpen.value = false;
  entries.value = [];
  scopedCounts.value = null;
  auditGuard.invalidate();
  audit.value = [];
  auditTotal.value = 0;
  auditOffset.value = 0;
  auditLoading.value = false;
  auditError.value = "";
  Object.assign(auditFilter, { keyword: "", action: "", result: "", from: "", to: "" });
  auditApplied = { ...auditFilter };
  recent.value = [];
  expiring.value = [];
  selected.value = new Set();
  mcp.value = null;
}

async function lockVault(strict: boolean) {
  applyLockedUi();
  try {
    await api.lock();
  } catch (e) {
    await refreshStatus().catch(() => undefined);
    if (strict) throw e;
  }
  await refreshStatus();
}

async function doLock() {
  await lockVault(false);
}

async function lockForUpdate() {
  await lockVault(true);
}

async function loadSettings() {
  const s = await api.settingsGet();
  settingsIdle.value = Math.max(1, Math.round(s.idle_secs / 60));
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
    const message = String(e);
    showToast(message.includes("解锁") ? message : "热键可能被占用：" + message);
    await loadSettings().catch(() => undefined);
  }
}
function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${Math.ceil(bytes / 1024)} KB`;
  return `${Math.ceil(bytes)} B`;
}

function applyDownloadEvent(event: NormalizedDownloadEvent) {
  updateDownloadedBytes.value = event.downloadedBytes;
  updateContentLength.value = event.contentLength;
  updateDownloadFinished.value = event.phase === "finished";
}

async function checkForUpdates(auto = false) {
  if (updateBusy.value) return;
  updateBusy.value = true;
  updateError.value = "";
  if (!auto) updateStage.value = "checking";
  try {
    const result = await checkForUpdate();
    updateCheckedAt.value = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    if (!result) {
      update.value = null;
      updateMetadata.value = null;
      updateStage.value = "idle";
      if (!auto) showToast("已是最新版本");
      return;
    }
    update.value = result;
    updateMetadata.value = result.metadata;
    appVersion.value = result.metadata.currentVersion;
    updateStage.value = "available";
    if (status.value?.unlocked) updateDialogOpen.value = true;
  } catch (e) {
    if (auto) {
      updateStage.value = "idle";
    } else {
      updateStage.value = "error";
      updateError.value = String(e);
    }
  } finally {
    updateBusy.value = false;
  }
}

async function autoCheckUpdate() {
  if (updateAutoChecked) return;
  updateAutoChecked = true;
  await checkForUpdates(true);
}

function onAboutUpdateClick() {
  if (update.value) {
    updateDialogOpen.value = true;
    return;
  }
  void checkForUpdates();
}

async function downloadUpdate() {
  if (!update.value || updateBusy.value) return;
  updateBusy.value = true;
  updateError.value = "";
  updateStage.value = "downloading";
  updateDownloadedBytes.value = 0;
  updateContentLength.value = null;
  updateDownloadFinished.value = false;
  try {
    await download(update.value, applyDownloadEvent);
    updateDownloadFinished.value = true;
    updateStage.value = "ready";
    if (status.value?.unlocked) updateDialogOpen.value = true;
  } catch (e) {
    updateStage.value = "error";
    updateError.value = String(e);
  } finally {
    updateBusy.value = false;
  }
}

async function installUpdate() {
  if (!update.value || updateBusy.value || !updateDownloadFinished.value) return;
  updateBusy.value = true;
  updateError.value = "";
  updateStage.value = "installing";
  try {
    await lockForUpdate();
    await install(update.value);
  } catch (e) {
    updateStage.value = "error";
    updateError.value = String(e);
  } finally {
    updateBusy.value = false;
  }
}

function retryUpdate() {
  if (update.value) void downloadUpdate();
  else void checkForUpdates();
}

async function openUpdateUrl(url: string) {
  try {
    await openUrl(url);
  } catch (e) {
    showToast(`无法打开发布页面：${String(e)}`);
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
function closeCsv() {
  csvImportOpen.value = false;
  csvPassword.value = "";
  csvRiskConfirmed.value = false;
  csvImportPreview.value = null;
}

function openCsv(mode: "import" | "export") {
  csvMode.value = mode;
  csvImportPath.value = "";
  csvImportPreview.value = null;
  csvImportOverwrite.value = false;
  csvRiskConfirmed.value = false;
  csvPassword.value = "";
  csvImportOpen.value = true;
}

async function pickCsvImportFile() {
  try {
    const picked = await withNativeDialog(async () => {
      const { open, save } = await import("@tauri-apps/plugin-dialog");
      if (csvMode.value === "export") {
        return save({
          defaultPath: "sealbox-websites.csv",
          filters: [{ name: "CSV", extensions: ["csv"] }],
        });
      }
      return open({
        multiple: false,
        title: "选择 CSV 文件",
        filters: [{ name: "CSV", extensions: ["csv"] }],
      });
    });
    if (typeof picked !== "string" || !picked) return;
    csvImportPath.value = picked;
    csvImportPreview.value = null;
    csvPassword.value = "";
    if (csvMode.value !== "import") return;
    csvImportBusy.value = true;
    try {
      csvImportPreview.value = await api.csvPreview({ path: picked });
    } catch (e) {
      showToast(String(e));
    } finally {
      csvImportBusy.value = false;
    }
  } catch (e) {
    showToast(`打开文件选择框失败：${String(e)}`);
  }
}

function csvRiskReady() {
  return csvRiskConfirmed.value && csvPassword.value.length > 0;
}

async function runCsvImport() {
  if (!csvImportPreview.value || csvImportBusy.value) return;
  if (!csvRiskReady()) {
    showToast("请勾选明文迁移确认，并再次输入主密码");
    return;
  }
  csvImportBusy.value = true;
  try {
    const result = await api.csvCommit({
      token: csvImportPreview.value.token,
      password: csvPassword.value,
      riskConfirmed: true,
      overwrite: csvImportOverwrite.value,
    });
    const skipped = result.skipped_existing + result.skipped_invalid;
    showToast(`导入 ${result.inserted + result.updated} 条，跳过 ${skipped} 条`);
    closeCsv();
    csvImportPath.value = "";
    csvImportOverwrite.value = false;
    await refreshVault();
  } catch (e) {
    showToast(String(e));
  } finally {
    csvImportBusy.value = false;
    csvPassword.value = "";
  }
}

async function runCsvExport() {
  if (csvImportBusy.value) return;
  if (!csvImportPath.value || !csvRiskReady()) {
    showToast("请选择路径、勾选明文迁移确认，并再次输入主密码");
    return;
  }
  csvImportBusy.value = true;
  try {
    await api.csvExport({
      path: csvImportPath.value,
      password: csvPassword.value,
      riskConfirmed: true,
    });
    showToast("已导出 CSV。这是明文网站数据，用完请删除，不要用表格软件打开。");
    closeCsv();
    csvImportPath.value = "";
  } catch (e) {
    showToast(String(e));
  } finally {
    csvImportBusy.value = false;
    csvPassword.value = "";
  }
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
      if (picked) {
        backupPath.value = picked;
        resetBackupPreview();
      }
      return;
    }
    const picked = await withNativeDialog(async () => {
      const { open } = await import("@tauri-apps/plugin-dialog");
      return open({
        multiple: false,
        filters: [{ name: "Sealbox backup", extensions: ["svbak"] }],
      });
    });
    if (typeof picked === "string") {
      backupPath.value = picked;
      resetBackupPreview();
    }
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
  if (status.value?.unlocked) {
    await refreshVault();
    void autoCheckUpdate();
  }
  await loadSettings();
  window.addEventListener("keydown", onKey);
  document.addEventListener("visibilitychange", onVisibility);
  const unFocus = await getCurrentWindow().onFocusChanged((event) => {
    if (!event.payload) hideVisibleSecrets();
  });
  const unLock = await listen("lock-now", () => doLock());
  const unUnlock = await listen("vault-unlocked", async () => {
    if (status.value?.unlocked) return;
    await refreshStatus();
    if (status.value?.unlocked) {
      await refreshVault();
      await loadSettings();
      void autoCheckUpdate();
    }
  });
  const unSync = await listen<{ ok: boolean; error: string | null; report: SyncReport | null }>(
    "sync-finished",
    async (event) => {
      if (!status.value?.unlocked) return;
      const report = event.payload.report;
      if (report) {
        const keepLocalToken = syncReport.value?.phase === "local_pending" && Boolean(syncToken.value) && report.phase === "local_pending";
        if (!keepLocalToken) clearSyncPreview();
        syncReport.value = report;
        if (report.phase === "committed") {
          if (report.pulled > 0 || report.removed > 0) await refreshVault();
        } else if (report.phase === "local_pending") {
          showToast(report.blocked || "自动同步的本地提交尚未完成");
        } else if (report.phase === "blocked") {
          showToast(report.blocked || "自动同步已阻塞");
        } else if (report.phase === "conflicts" || (report.conflict_details?.length ?? 0) > 0) {
          showToast("自动同步因冲突暂停。请重新预览并逐条选择，不能沿用旧结果。");
        } else if (report.pulled > 0 || report.removed > 0) {
          await refreshVault();
        }
      }
      if (!syncView.value) return;
      try {
        const fresh = await api.syncStatus();
        syncView.value.last_sync_at = fresh.last_sync_at;
        syncView.value.last_result = fresh.last_result;
      } catch {
        // Vault locked between the event and the refresh; nothing to show.
      }
    },
  );
  onUnmounted(() => {
    clearVaultSearchTimer();
    vaultSeq += 1;
    applyLockedUi();
    window.removeEventListener("keydown", onKey);
    document.removeEventListener("visibilitychange", onVisibility);
    unFocus();
    unLock();
    unUnlock();
    unSync();
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
        <button class="btn" style="width:100%;margin-top:8px" @click="openBackup('import')">从备份导入</button>
      </div>
    </div>

    <div class="body" v-else-if="!status.unlocked">
      <div class="unlock">
        <h1>解锁印盒</h1>
        <p>输入主密码。</p>
        <p v-if="error" class="error">{{ error }}</p>
        <input v-model="password" type="password" placeholder="主密码" @keyup.enter="doUnlock" />
        <button class="btn primary" style="width:100%" @click="doUnlock">解锁</button>
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
          <div class="overview-counts">
            <button type="button" @click="openOverview(null)">全部<strong>{{ status.counts?.total ?? 0 }}</strong></button>
            <button type="button" @click="openOverview('website')">网站<strong>{{ status.counts?.website ?? 0 }}</strong></button>
            <button type="button" @click="openOverview('api_token')">Token<strong>{{ status.counts?.api_token ?? 0 }}</strong></button>
            <button type="button" @click="openOverview('ssh')">SSH<strong>{{ status.counts?.ssh ?? 0 }}</strong></button>
            <button type="button" @click="openOverview('mailbox')">邮箱<strong>{{ status.counts?.mailbox ?? 0 }}</strong></button>
            <button type="button" @click="openOverview('mail_auth')">授权码<strong>{{ status.counts?.mail_auth ?? 0 }}</strong></button>
            <button type="button" @click="openOverview('server')">服务器<strong>{{ status.counts?.server ?? 0 }}</strong></button>
            <button type="button" @click="openOverview('database')">数据库<strong>{{ status.counts?.database ?? 0 }}</strong></button>
            <button type="button" @click="openOverview('client_cert')">证书<strong>{{ status.counts?.client_cert ?? 0 }}</strong></button>
            <button type="button" @click="openOverview(null, true)">回收站<strong>{{ status.counts?.trash ?? 0 }}</strong></button>
          </div>
          <h3>最近使用</h3>
          <div class="table" v-if="recent.length">
            <table>
              <tbody>
                <tr v-for="row in recent" :key="row.id" class="home-row" @click="openDetail(row)">
                  <td>{{ row.title }}</td>
                  <td>{{ row.account || "—" }}</td>
                  <td>{{ fmtTime(row.last_used_at) }}</td>
                  <td>
                    <button class="btn" type="button" @click.stop="row.kind === 'client_cert' ? copyClientCertificate(row.id) : copy(row.id)">复制</button>
                    <button class="btn" type="button" @click.stop="openEdit(row)">编辑</button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <p class="crumb" v-else>还没有使用记录</p>
          <h3>30 天内过期</h3>
          <div class="table" v-if="expiring.length">
            <table>
              <tbody>
                <tr v-for="row in expiring" :key="'e'+row.id" class="home-row" @click="openDetail(row)">
                  <td>{{ row.title }}</td>
                  <td>{{ fmtTime(row.expires_at) }}</td>
                  <td>
                    <button class="btn" type="button" @click.stop="row.kind === 'client_cert' ? copyClientCertificate(row.id) : copy(row.id)">复制</button>
                    <button class="btn" type="button" @click.stop="openEdit(row)">编辑</button>
                  </td>
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
              <div class="side-label">
                <span>标签</span>
                <button class="side-link" type="button" @click="openOrganization('tags')">管理</button>
              </div>
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
                <span class="side-actions">
                  <button class="side-link" type="button" @click="newFolder">新建</button>
                  <button class="side-link" type="button" @click="openOrganization('folders')">管理</button>
                </span>
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
            <button class="side-item" type="button" @click="openBackup('export')">
              <span>备份 / 还原</span>
            </button>
            <button class="side-item" type="button" :disabled="!status?.unlocked" @click="openCsv('import')">
              <span>从 CSV 导入</span>
            </button>
            <button class="side-item" type="button" :disabled="!status?.unlocked" @click="openCsv('export')">
              <span>导出 CSV</span>
            </button>
          </div>
        </aside>
        <div class="content vault-content">
          <div class="toolbar">
            <input class="search" v-model="filter.query" placeholder="搜索键名 / 账号 / 网址 / 标签 / 备注… (Ctrl+F)" @input="scheduleVaultSearch" @keyup.enter="searchVaultNow" />
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
            <table v-if="entries.length" class="vault-table">
              <colgroup>
                <col class="vault-select-col" />
                <col class="vault-title-col" />
                <col class="vault-account-col" />
                <col class="vault-kind-col" />
                <col class="vault-updated-col" />
                <col class="vault-count-col" />
                <col class="vault-expires-col" />
                <col class="vault-actions-col" />
              </colgroup>
              <thead>
                <tr>
                  <th></th><th>键名</th><th class="vault-account-col">关联账号</th><th>类型</th><th>修改时间</th><th>次数</th><th>过期</th><th class="vault-actions-col">操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in entries" :key="row.id">
                  <td><input type="checkbox" :checked="selected.has(row.id)" @change="selected.has(row.id) ? selected.delete(row.id) : selected.add(row.id)" /></td>
                  <td>
                    <div class="title-cell">
                      <span class="letter" :style="{ background: letterColor(row.title) }">{{ row.title.slice(0,1).toUpperCase() }}</span>
                      <button class="title-link title-text" type="button" :title="row.title" @click.stop="openDetail(row)">{{ row.title }}</button>
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
                  <td class="vault-account-cell">
                    <span class="account-text" :title="row.account || row.fingerprint || '—'">{{ row.account || row.fingerprint || "—" }}</span>
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
                    <div class="row-actions-inner">
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
                    </div>
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
              <button
                class="btn primary"
                type="button"
                :disabled="zoomkeyBusy || !zoomkeyPolicy"
                @click="toggleZoomkeyEnabled"
              >
                {{ zoomkeyBusy ? "保存中…" : (zoomkeyPolicy?.enabled ? "停用 MCP" : "启用 MCP") }}
              </button>
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
            <h3>ZoomKey JIRA / CRM</h3>
            <template v-if="zoomkeyPolicy">
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
                <button class="btn primary" type="button" :disabled="zoomkeyBusy" @click="() => saveZoomkeyPolicy()">
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

      <section class="main" v-else-if="page === 'audit'">
        <div class="content content-page">
          <h2>审计</h2>
          <form class="audit-filters" @submit.prevent="queryAudit()">
            <label class="audit-keyword">关键词<input v-model="auditFilter.keyword" placeholder="如：复制 动态验证码" maxlength="500" /></label>
            <label class="audit-select">操作类型<select v-model="auditFilter.action"><option value="">全部操作</option><option v-for="[key, label] in auditActions" :key="key" :value="key">{{ label }}</option></select></label>
            <label class="audit-select">结果<select v-model="auditFilter.result"><option value="">全部结果</option><option v-for="[key, label] in auditResults" :key="key" :value="key">{{ label }}</option></select></label>
            <label class="audit-date">起始日期<input v-model="auditFilter.from" type="date" /></label>
            <label class="audit-date">结束日期<input v-model="auditFilter.to" type="date" /></label>
            <div class="audit-filter-actions">
              <button class="btn primary" type="submit">查询</button>
              <button class="btn" type="button" @click="resetAudit">重置</button>
            </div>
          </form>
          <p v-if="auditLoading" role="status">正在查询历史记录…</p>
          <p v-else-if="auditError" class="audit-error" role="alert">{{ auditError }}</p>
          <p v-else-if="!audit.length">{{ auditTotal ? '此页已无记录，请重新查询。' : '没有符合条件的记录。' }}</p>
          <div v-if="audit.length" class="table audit-table">
            <table>
              <thead><tr><th>时间</th><th>操作</th><th>结果</th><th>详情</th><th>原始记录</th></tr></thead>
              <tbody>
                <tr v-for="a in audit" :key="a.id">
                  <td>{{ fmtTime(a.at) }}</td>
                  <td>{{ a.operation }}</td>
                  <td>{{ a.result_label }}</td>
                  <td>{{ a.description }}<div v-if="a.entry_id" class="crumb">条目 ID：{{ a.entry_id }}</div></td>
                  <td><details><summary>展开</summary><pre>{{ JSON.stringify({ id: a.id, at: a.at, action: a.action, entry_id: a.entry_id, detail: a.detail }, null, 2) }}</pre></details></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="audit-pagination">
            <span>共 {{ auditTotal }} 条 · 每页 50 条 · 第 {{ Math.floor(auditOffset / 50) + 1 }} 页</span>
            <button class="btn" :disabled="auditLoading || auditOffset === 0" @click="queryAudit(auditOffset - 50, false)">上一页</button>
            <button class="btn" :disabled="auditLoading || auditOffset + 50 >= auditTotal" @click="queryAudit(auditOffset + 50, false)">下一页</button>
          </div>
          <p class="crumb">“已记录”不代表已验证成功；“未获准”不推断为用户拒绝。新增日志可能使分页位置变化，重新查询可刷新。</p>
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
                <div class="field">
                  <label>全局热键</label>
                  <input v-model="settingsHotkey" placeholder="Ctrl+Shift+Space" />
                </div>
              </div>
              <button class="btn primary" type="button" @click="saveSettings">保存</button>
            </div>
          </div>
          <div class="mcp-card settings-master">
            <h3>数据同步</h3>
            <p class="crumb">支持 WebDAV 和 S3。上传的是用同步密钥再加密的快照，服务器看不到明文，也解不开主密码。有冲突时必须逐条选择保留本地、采用远端或两者都留；删除与编辑冲突要单独确认后才能提交。不会因为修改时间相同就自动保留某一边。冲突或阻塞之后会重新预览，不能沿用旧令牌。本地尚未落盘时只重试提交。解锁后按设定间隔自动同步，默认 60 秒；改完点「保存配置」生效。</p>
            <div class="settings-fields">
              <div class="field">
                <label>类型</label>
                <select v-model="syncKind">
                  <option value="webdav">WebDAV</option>
                  <option value="s3">S3</option>
                </select>
              </div>
              <div class="field">
                <label>{{ syncKind === 'webdav' ? 'WebDAV 地址' : 'S3 Endpoint' }}</label>
                <input v-model="syncEndpoint" placeholder="https://" />
              </div>
              <div class="field">
                <label>{{ syncKind === 'webdav' ? '用户名' : 'Access Key' }}</label>
                <input v-model="syncUsername" autocomplete="off" />
              </div>
              <div class="field">
                <label>{{ syncKind === 'webdav' ? '密码或应用密码' : 'Secret Key' }}</label>
                <input v-model="syncSecret" type="password" autocomplete="new-password" :placeholder="syncView?.has_secret ? '已保存，留空则不修改' : '至少 8 位'" />
              </div>
              <template v-if="syncKind === 's3'">
                <div class="field">
                  <label>Bucket</label>
                  <input v-model="syncBucket" />
                </div>
                <div class="field">
                  <label>Region</label>
                  <input v-model="syncRegion" placeholder="us-east-1" />
                </div>
              </template>
              <div class="field settings-span">
                <label>路径前缀（可选）</label>
                <input v-model="syncPrefix" placeholder="留空则使用 sealbox/vault.sboxsync" />
              </div>
              <div class="field">
                <label class="check"><input v-model="syncAuto" type="checkbox" /><span>定时自动同步</span></label>
              </div>
              <div class="field">
                <label>自动同步间隔（秒）</label>
                <input v-model.number="syncAutoSecs" type="number" min="15" max="86400" :disabled="!syncAuto" />
              </div>
            </div>
            <p v-if="syncView?.last_sync_at" class="crumb">上次同步 {{ fmtTime(syncView.last_sync_at) }}<span v-if="syncView.last_result"> · {{ syncView.last_result }}</span></p>
            <div v-if="syncReport" class="crumb">
              <p>阶段：{{ syncPhaseLabel(syncReport.phase) }}</p>
              <p>阻塞：{{ syncReport.blocked || "无" }}</p>
              <p>可重试：{{ syncReport.retryable ? "是" : "否" }}</p>
              <p v-if="syncToken">本次预览约 {{ syncExpiresSecs }} 秒内有效。</p>
              <p v-if="syncReport.phase === 'committed'">拉取 {{ syncReport.pulled }}，推送 {{ syncReport.pushed }}，未变 {{ syncReport.unchanged }}<span v-if="syncReport.removed">，删除 {{ syncReport.removed }}</span></p>
            </div>
            <div v-if="syncVerifyResult" class="crumb">
              安全同步：{{ syncVerifyResult.verified ? "已验证" : "未通过" }}；探测对象已清理：{{ syncVerifyResult.probe_cleaned ? "是" : "否" }}。{{ syncVerifyResult.scope }}
            </div>
            <template v-if="syncToken && syncConflicts.length">
              <div class="field" v-for="item in syncConflicts" :key="item.id">
                <template v-if="syncChoices[item.id]">
                  <label>{{ item.title || item.id }}</label>
                  <p class="crumb">{{ item.kind === 'delete_edit' ? '删除与编辑' : '两端都已修改' }}<span v-if="item.local_deleted"> · 本地已删</span><span v-if="item.remote_deleted"> · 远端已删</span></p>
                  <label class="check"><input type="radio" :name="'sync-choice-' + item.id" value="local" v-model="syncChoices[item.id].choice" /> 保留本地</label>
                  <label class="check"><input type="radio" :name="'sync-choice-' + item.id" value="remote" v-model="syncChoices[item.id].choice" /> 采用远端</label>
                  <label class="check"><input type="radio" :name="'sync-choice-' + item.id" value="both" v-model="syncChoices[item.id].choice" /> 两者都留</label>
                  <label v-if="item.kind === 'delete_edit'" class="check">
                    <input type="checkbox" v-model="syncChoices[item.id].confirm_delete_edit" />
                    确认处理这条删除与编辑冲突
                  </label>
                </template>
              </div>
            </template>
            <div class="mcp-actions">
              <button class="btn primary" type="button" :disabled="syncBusy" @click="saveSync">保存配置</button>
              <button class="btn" type="button" :disabled="syncBusy || !syncView?.configured" @click="runSync">{{ syncBusy ? '同步中…' : '立即同步' }}</button>
              <button class="btn primary" type="button" :disabled="syncBusy || !syncCanCommit" @click="commitSync">{{ syncReport?.phase === 'local_pending' ? '重试本地提交' : '提交选择' }}</button>
              <button class="btn" type="button" :disabled="syncBusy || !syncView?.configured" @click="verifySync">验证安全同步</button>
              <button class="btn" type="button" :disabled="syncBusy || !syncView?.configured" @click="clearSync">清除配置</button>
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
          <div class="mcp-card about-card">
            <div class="about-heading">
              <div>
                <h3>关于 Sealbox</h3>
                <p class="crumb">本地凭据金库，数据保存在本机。</p>
              </div>
              <span class="version-badge">v{{ appVersion }}</span>
            </div>
            <div class="about-update">
              <div class="about-update-text">
                <span>{{ aboutUpdateText }}</span>
                <p v-if="updateError" class="error">{{ updateError }}</p>
              </div>
              <button class="btn" type="button" :disabled="updateStage === 'checking'" @click="onAboutUpdateClick">{{ aboutUpdateAction }}</button>
            </div>
          </div>
        </div>
      </section>

      <div class="dialog-mask" v-if="detailOpen" @click.self="closeDetail">
        <div class="dialog detail-dialog" role="dialog" aria-modal="true" aria-labelledby="detail-title">
          <p v-if="!detail" class="crumb">正在读取…</p>
          <template v-else>
          <div class="dialog-heading">
            <div>
              <h3 id="detail-title">{{ detail.entry.title }}</h3>
              <p class="crumb">{{ kindLabel(detail.entry.kind) }} · {{ folderName(detail.entry.folder_id) }}</p>
            </div>
            <button class="nav-btn" type="button" @click="closeDetail">×</button>
          </div>
          <dl class="detail-fields">
            <template v-for="field in detail.fields" :key="field.label">
              <dt>{{ field.label }}</dt>
              <dd>{{ field.value }}</dd>
            </template>
            <dt>标签</dt>
            <dd>{{ detail.entry.tags.length ? detail.entry.tags.join("、") : "—" }}</dd>
            <dt>过期</dt>
            <dd>{{ detail.entry.expires_at ? fmtTime(detail.entry.expires_at) : "永不" }}</dd>
            <dt>使用次数</dt>
            <dd>{{ detail.entry.use_count }}</dd>
          </dl>
          <p v-if="detail.notes" class="detail-notes">{{ detail.notes }}</p>
          <p v-else class="crumb">没有备注</p>
          <div v-if="detail.entry.kind !== 'client_cert'" class="detail-secret">
            <span>秘密</span>
            <code>{{ revealFor === detail.entry.id ? revealedSecretText() : "••••••••" }}</code>
          </div>
          <p v-else class="crumb">私钥不在详情里显示。可以复制公开证书，或进入编辑查看证书信息。</p>
          <div class="detail-actions">
            <button v-if="detail.entry.kind !== 'client_cert'" class="btn" type="button" @click="copy(detail.entry.id)">复制密码</button>
            <button class="btn" type="button" @click="copy(detail.entry.id, 'account')">复制账号</button>
            <button v-if="detail.entry.has_totp" class="btn" type="button" @click="copy(detail.entry.id, 'totp')">复制 TOTP</button>
            <button v-if="detail.entry.kind === 'client_cert'" class="btn" type="button" @click="copyClientCertificate(detail.entry.id)">复制公开证书</button>
            <button v-if="detail.entry.kind !== 'client_cert'" class="btn" type="button" @click="revealRow(detail.entry)">{{ revealFor === detail.entry.id ? "隐藏" : "显示" }}</button>
            <button v-if="!detailTrashed" class="btn" type="button" @click="togglePin(detail.entry)">{{ detail.entry.pinned ? "取消置顶" : "置顶" }}</button>
            <button v-if="!detailTrashed" class="btn" type="button" @click="openEdit(detail.entry)">编辑</button>
            <button v-if="!detailTrashed" class="btn danger" type="button" @click="remove([detail.entry.id])">移入回收站</button>
            <button v-else class="btn" type="button" @click="restore([detail.entry.id])">还原</button>
            <button class="btn" type="button" @click="closeDetail">关闭</button>
          </div>
          </template>
        </div>
      </div>
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
        <div class="field" v-if="form.kind !== 'ssh' && form.kind !== 'mailbox' && form.kind !== 'mail_auth' && form.kind !== 'client_cert'"><label>{{ form.kind === 'server' || form.kind === 'database' ? '用户名' : '账号' }}</label><input v-model="form.account" @input="form.kind === 'website' && clearWebsiteDuplicateState()" /></div>
        <div class="field" v-if="form.kind === 'website'"><label>网址</label><input v-model="form.url" @input="clearWebsiteDuplicateState" /></div>
        <div v-if="form.kind === 'website' && websiteDuplicates.length" class="duplicate-warning">
          <strong>已有 {{ websiteDuplicates.length }} 条同站同账号</strong>
          <p class="crumb">不会自动覆盖。请选择已有条目，或明确确认仍然新建。</p>
          <div v-for="entry in websiteDuplicates" :key="entry.id" class="duplicate-row">
            <div>
              <strong>{{ entry.title || '未命名' }}</strong>
              <span class="duplicate-meta">{{ entry.url || '—' }} · 更新于 {{ fmtTime(entry.updated_at) }} · 使用 {{ entry.use_count }} 次</span>
            </div>
            <button class="btn" type="button" @click="editWebsiteDuplicate(entry)">编辑</button>
          </div>
          <div class="duplicate-actions">
            <button class="btn" type="button" @click="clearWebsiteDuplicateState">取消</button>
            <button class="btn danger" type="button" @click="continueWithWebsiteDuplicate">仍然新建</button>
          </div>
        </div>
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
        <div class="field" v-if="form.kind === 'website'"><label>TOTP 密钥（可选）</label><input v-model="form.totp" placeholder="Base32 或 otpauth://totp/..." /></div>
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
          <button class="btn" type="button" @click="closeForm">取消</button>
          <button class="btn primary" type="button" :disabled="saveBusy" @click="saveEntry()">{{ saveBusy ? '保存中…' : '保存' }}</button>
        </div>
      </div>
    </div>
    </div>
    <div class="dialog-mask" v-if="backupOpen && status && (status.unlocked || !status.initialized)" @click.self="closeBackup">
      <div class="dialog">
        <h3>备份 / 还原</h3>
        <div class="field" v-if="status.initialized">
          <label>操作</label>
          <select v-model="backupMode" @change="backupPassword = ''; resetBackupPreview()">
            <option value="export">导出加密备份</option>
            <option value="import">导入备份</option>
          </select>
        </div>
        <p class="crumb" v-else>金库尚未创建。校验通过后直接从备份建立新库，不会先建空库。</p>
        <div class="field"><label>文件路径（.svbak）</label>
          <div style="display:flex;gap:8px">
            <input v-model="backupPath" placeholder="选择或输入路径" style="flex:1" @input="resetBackupPreview()" />
            <button class="btn" type="button" @click="pickBackupFile(backupExporting ? 'export' : 'import')">浏览</button>
          </div>
        </div>
        <template v-if="backupExporting">
          <div class="field"><label>主密码</label><input v-model="backupPassword" type="password" /></div>
          <div class="field">
            <label class="check">
              <input type="checkbox" v-model="backupIncludeSettings" />
              包含本机设置（空闲锁定、剪贴板）
            </label>
          </div>
          <div style="display:flex;gap:8px;justify-content:flex-end">
            <button class="btn" type="button" @click="closeBackup">取消</button>
            <button class="btn primary" type="button" :disabled="backupBusy" @click="runBackupExport">{{ backupBusy ? "导出中…" : "导出" }}</button>
          </div>
        </template>
        <template v-else>
          <div class="field"><label>备份密码</label><input v-model="backupPassword" type="password" /></div>
          <div style="display:flex;gap:8px;justify-content:flex-end">
            <button class="btn" type="button" :disabled="backupBusy" @click="inspectBackup">{{ backupBusy ? "校验中…" : "校验并查看摘要" }}</button>
          </div>
          <template v-if="backupPreview">
            <p class="crumb">
              版本 {{ backupPreview.summary.version }}；条目 {{ backupPreview.summary.entries }}；回收站 {{ backupPreview.summary.trash }}；
              文件夹 {{ backupPreview.summary.folders }}；标签 {{ backupPreview.summary.tags }}；墓碑 {{ backupPreview.summary.tombstones }}；
              含设置 {{ backupPreview.summary.includes_settings ? "是" : "否" }}。
            </p>
            <p class="crumb" v-if="!backupPreview.summary.warnings.length">警告：无</p>
            <p class="error" v-for="(warning, index) in backupPreview.summary.warnings" :key="index">{{ warning }}</p>
            <div class="field" v-if="status.initialized">
              <label class="check">
                <input type="checkbox" v-model="backupOverwrite" />
                覆盖已有同 id 条目
              </label>
              <p class="crumb" v-if="backupOverwrite">会替换本地同 id 条目。确定时还会再确认一次。</p>
            </div>
            <div class="field">
              <label class="check">
                <input type="checkbox" v-model="backupRestoreSettings" :disabled="!backupPreview.summary.includes_settings" />
                恢复备份中的设置
              </label>
            </div>
            <template v-if="!status.initialized">
              <div class="field"><label>新主密码</label><input v-model="backupNewPassword" type="password" /></div>
              <div class="field"><label>确认新主密码</label><input v-model="backupNewPassword2" type="password" /></div>
              <p class="crumb">至少 10 位。用它创建金库，不会先建空库；可以与备份密码相同。</p>
            </template>
            <div style="display:flex;gap:8px;justify-content:flex-end">
              <button class="btn" type="button" @click="closeBackup">取消</button>
              <button class="btn primary" type="button" :disabled="backupBusy" @click="runBackupRestore">{{ backupBusy ? "恢复中…" : "恢复" }}</button>
            </div>
          </template>
          <div v-else style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
            <button class="btn" type="button" @click="closeBackup">取消</button>
          </div>
        </template>
      </div>
    </div>
    <div class="dialog-mask" v-if="organizationOpen && status?.unlocked" @click.self="organizationOpen = false">
      <div class="dialog organization-dialog">
        <div class="dialog-heading">
          <div>
            <h3>管理分类</h3>
            <p class="crumb">重命名会保留关联；删除不会删除凭据。</p>
          </div>
          <button class="nav-btn" type="button" @click="organizationOpen = false">×</button>
        </div>
        <div class="organization-tabs">
          <button class="btn" :class="{ primary: organizationTab === 'folders' }" type="button" @click="openOrganization('folders')">文件夹</button>
          <button class="btn" :class="{ primary: organizationTab === 'tags' }" type="button" @click="openOrganization('tags')">标签</button>
        </div>
        <template v-if="organizationTab === 'folders'">
          <div class="organization-list" v-if="folders.length">
            <div class="organization-row" v-for="folder in folders" :key="folder.id">
              <input v-model="folderDrafts[folder.id]" :disabled="organizationBusy" aria-label="文件夹名称" />
              <button class="btn" type="button" :disabled="organizationBusy || !folderDrafts[folder.id]?.trim() || folderDrafts[folder.id]?.trim() === folder.name" @click="renameFolderFromManager(folder)">保存</button>
              <select v-model="folderMergeTargets[folder.id]" :disabled="organizationBusy">
                <option value="">合并到…</option>
                <option v-for="target in folders.filter((item) => item.id !== folder.id)" :key="target.id" :value="target.id">{{ target.name }}</option>
              </select>
              <button class="btn" type="button" :disabled="organizationBusy || !folderMergeTargets[folder.id]" @click="mergeFolderFromManager(folder)">合并</button>
              <button class="btn danger" type="button" :disabled="organizationBusy" @click="deleteFolderFromManager(folder)">删除</button>
            </div>
          </div>
          <p class="crumb" v-else>还没有文件夹。</p>
        </template>
        <template v-else>
          <div class="organization-list" v-if="tags.length">
            <div class="organization-row" v-for="tag in tags" :key="tag">
              <input v-model="tagDrafts[tag]" :disabled="organizationBusy" aria-label="标签名称" />
              <button class="btn" type="button" :disabled="organizationBusy || !tagDrafts[tag]?.trim() || tagDrafts[tag]?.trim() === tag" @click="renameTagFromManager(tag)">保存</button>
              <select v-model="tagMergeTargets[tag]" :disabled="organizationBusy">
                <option value="">合并到…</option>
                <option v-for="target in tags.filter((item) => item !== tag)" :key="target" :value="target">{{ target }}</option>
              </select>
              <button class="btn" type="button" :disabled="organizationBusy || !tagMergeTargets[tag]" @click="mergeTagFromManager(tag)">合并</button>
              <button class="btn danger" type="button" :disabled="organizationBusy" @click="deleteTagFromManager(tag)">删除</button>
            </div>
          </div>
          <p class="crumb" v-else>还没有正在使用的标签。</p>
        </template>
      </div>
    </div>
    <div class="dialog-mask" v-if="csvImportOpen && status?.unlocked" @click.self="closeCsv">
      <div class="dialog">
        <h3>{{ csvMode === 'export' ? '导出 CSV' : '从 CSV 导入' }}</h3>
        <p class="crumb">只迁移网站账号，不含证书、SSH 或服务器。预览不显示密码或 TOTP 密钥。</p>
        <div class="field">
          <label>CSV 文件</label>
          <div style="display:flex;gap:8px">
            <input :value="csvImportPath || (csvMode === 'export' ? '请选择导出路径' : '请选择 CSV 文件')" readonly style="flex:1" />
            <button class="btn" type="button" :disabled="csvImportBusy" @click="pickCsvImportFile">浏览</button>
          </div>
        </div>
        <p class="crumb" v-if="csvImportBusy && csvMode === 'import'">正在读取并预览…</p>
        <template v-if="csvMode === 'import' && csvImportPreview">
          <p class="crumb">
            格式：{{ csvImportPreview.summary.format }}；共 {{ csvImportPreview.summary.total }} 条；可导入 {{ csvImportPreview.summary.importable }} 条；
            已有 {{ csvImportPreview.summary.skipped_existing }} 条；无效 {{ csvImportPreview.summary.skipped_invalid }} 条。
          </p>
          <div class="table" v-if="csvImportPreview.summary.sample.length">
            <table>
              <thead><tr><th>名称</th><th>网址</th><th>账号</th><th>有密码</th><th>有 TOTP</th></tr></thead>
              <tbody>
                <tr v-for="(row, index) in csvImportPreview.summary.sample.slice(0, 20)" :key="`${row.title}-${index}`">
                  <td>{{ row.title }}</td><td>{{ row.url }}</td><td>{{ row.username }}</td>
                  <td>{{ row.has_password ? '有' : '无' }}</td><td>{{ row.has_totp ? '有' : '无' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p class="crumb" v-else>没有可预览的有效条目。</p>
          <div class="field">
            <label class="check">
              <input type="checkbox" v-model="csvImportOverwrite" />
              覆盖已有同站同账号
            </label>
          </div>
        </template>
        <div class="field" v-if="csvMode === 'export' || csvImportPreview">
          <label class="check">
            <input type="checkbox" v-model="csvRiskConfirmed" />
            <span style="min-width:0;white-space:normal">{{ CSV_RISK_TEXT }}</span>
          </label>
        </div>
        <div class="field" v-if="csvMode === 'export' || csvImportPreview">
          <label>再次输入主密码</label>
          <input v-model="csvPassword" type="password" autocomplete="current-password" />
        </div>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
          <button class="btn" type="button" @click="closeCsv">取消</button>
          <button
            v-if="csvMode === 'import'"
            class="btn primary"
            type="button"
            :disabled="csvImportBusy || !csvRiskConfirmed || !csvPassword || !csvImportPreview || (csvImportPreview.summary.importable === 0 && !(csvImportOverwrite && csvImportPreview.summary.skipped_existing > 0))"
            @click="runCsvImport"
          >
            {{ csvImportBusy ? "导入中…" : "确认导入" }}
          </button>
          <button
            v-else
            class="btn primary"
            type="button"
            :disabled="csvImportBusy || !csvRiskConfirmed || !csvPassword || !csvImportPath"
            @click="runCsvExport"
          >
            {{ csvImportBusy ? "导出中…" : "确认导出" }}
          </button>
        </div>
      </div>
    </div>
    <div class="dialog-mask" v-if="updateDialogOpen && updateMetadata" @click.self="updateDialogOpen = false">
      <div class="dialog update-dialog" role="dialog" aria-modal="true" aria-labelledby="update-dialog-title">
        <div class="update-dialog-head">
          <div>
            <h3 id="update-dialog-title">{{ updateStage === "ready" ? "更新已就绪" : "发现新版本" }}</h3>
            <p class="crumb">Sealbox 桌面版</p>
          </div>
          <span class="version-badge">v{{ updateMetadata.latestVersion }}</span>
        </div>
        <div class="update-versions">
          <span>当前版本</span>
          <strong>v{{ appVersion }}</strong>
          <template v-if="updateMetadata.publishedAt">
            <span>发布时间</span>
            <strong>{{ fmtTime(updateMetadata.publishedAt) }}</strong>
          </template>
        </div>
        <div v-if="updateStage === 'downloading' || updateStage === 'ready'" class="update-progress">
          <div class="update-progress-head">
            <span>{{ updateStage === "ready" ? "下载完成" : "正在下载更新" }}</span>
            <strong v-if="updateProgress !== null">{{ updateProgress }}%</strong>
            <strong v-else>下载中</strong>
          </div>
          <div class="update-progress-track" role="progressbar" :aria-valuenow="updateProgress ?? undefined" aria-valuemin="0" aria-valuemax="100">
            <span :style="{ width: `${updateProgress ?? 0}%` }" />
          </div>
          <p class="crumb about-download">{{ formatBytes(updateDownloadedBytes) }}<span v-if="updateContentLength"> / {{ formatBytes(updateContentLength) }}</span></p>
        </div>
        <p v-if="updateError" class="error update-dialog-error">{{ updateError }}</p>
        <div class="update-dialog-actions">
          <button class="btn" type="button" @click="openUpdateUrl(RELEASE_PAGE_URL)">打开发布页</button>
          <span class="update-dialog-spacer" />
          <button class="btn" type="button" @click="updateDialogOpen = false">稍后</button>
          <button v-if="updateStage === 'available'" class="btn primary" type="button" :disabled="updateBusy" @click="downloadUpdate">立即更新</button>
          <button v-else-if="updateStage === 'error'" class="btn primary" type="button" :disabled="updateBusy" @click="retryUpdate">重试下载</button>
          <button v-else-if="updateStage === 'ready'" class="btn primary" type="button" :disabled="updateBusy" @click="installUpdate">安装并重启</button>
        </div>
      </div>
    </div>
    <div class="toast" v-if="toast">{{ toast }}</div>
  </div>
</template>
