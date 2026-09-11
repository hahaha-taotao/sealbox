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
const page = ref<"home" | "vault" | "audit" | "settings">("vault");
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
  if (filter.trash) return "回收站";
  if (filter.kind === "website") return "网站账号";
  if (filter.kind === "api_token") return "API Token";
  if (filter.kind === "ssh") return "SSH";
  return "全部凭据";
});

function letterColor(title: string) {
  const colors = ["#5b5bd6", "#0ea5e9", "#16a34a", "#f59e0b", "#e11d48", "#8b5cf6"];
  return colors[(title.charCodeAt(0) || 0) % colors.length];
}
function kindLabel(k: EntryKind) {
  return k === "website" ? "网站账号" : k === "api_token" ? "API Token" : "SSH";
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
  page.value = "audit";
  audit.value = await api.audit();
}

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
async function loadSettings() {
  const s = await api.settingsGet();
  settingsIdle.value = Math.round(s.idle_secs / 60);
  settingsClip.value = s.clipboard_secs;
}
async function saveSettings() {
  await api.settingsSet({
    idle_secs: settingsIdle.value * 60,
    clipboard_secs: settingsClip.value,
    hotkey: "Ctrl+Shift+Space",
  });
  showToast("设置已保存");
}

function onKey(e: KeyboardEvent) {
  if (e.ctrlKey && e.shiftKey && e.code === "Space") {
    e.preventDefault();
    openQuick();
  }
  if (e.ctrlKey && e.key.toLowerCase() === "f" && status.value?.unlocked) {
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
  onUnmounted(() => {
    window.removeEventListener("keydown", onKey);
    unTick();
    unLock();
  });
});
</script>

<template>
  <div class="app">
    <header class="titlebar" data-tauri-drag-region>
      <div class="drag" data-tauri-drag-region>
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
        <input v-model="password2" type="password" placeholder="再输入一次" @keyup.enter="doSetup" />
        <button class="btn primary" style="width:100%" @click="doSetup">创建</button>
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
        <button class="rail-btn" :class="{ active: page === 'home' }" @click="page = 'home'">
          <span class="icon">⌂</span><span>首页</span>
        </button>
        <button class="rail-btn" :class="{ active: page === 'vault' }" @click="page = 'vault'">
          <span class="icon">▣</span><span>保险库</span>
        </button>
        <button class="rail-btn" :class="{ active: page === 'audit' }" @click="openAudit">
          <span class="icon">≡</span><span>审计</span>
        </button>
        <div class="spacer" />
        <button class="rail-btn" :class="{ active: page === 'settings' }" @click="page = 'settings'">
          <span class="icon">⚙</span><span>设置</span>
        </button>
      </nav>

      <section class="main" v-if="page === 'home'">
        <div class="content">
          <h2>概览</h2>
          <p>全部 {{ status.counts?.total ?? 0 }} · 网站 {{ status.counts?.website ?? 0 }} · Token {{ status.counts?.api_token ?? 0 }} · SSH {{ status.counts?.ssh ?? 0 }}</p>
          <p class="crumb">回收站 {{ status.counts?.trash ?? 0 }} 条</p>
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
                  </td>
                  <td>
                    {{ row.account || row.fingerprint || "—" }}
                    <div v-if="revealFor === row.id && reveal" style="font-size:12px;color:var(--muted);margin-top:4px;word-break:break-all">
                      <template v-if="reveal.type === 'website'">{{ reveal.password }}</template>
                      <template v-else-if="reveal.type === 'api_token'">{{ reveal.token }}</template>
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
          <button class="btn primary" @click="saveSettings">保存</button>
          <div class="field" style="margin-top:24px">
            <label>Windows Hello</label>
            <button class="btn" @click="api.setHello(true).then(() => showToast('已开启'))">开启</button>
            <button class="btn" @click="api.setHello(false).then(() => showToast('已关闭'))">关闭</button>
          </div>
          <p class="crumb" style="margin-top:16px">全局速查：窗口聚焦时 Ctrl+Shift+Space。关闭窗口会藏到托盘。</p>
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
            <option value="ssh">SSH</option>
          </select>
        </div>
        <div class="field"><label>键名</label><input v-model="form.title" /></div>
        <div class="field" v-if="form.kind !== 'ssh'"><label>账号</label><input v-model="form.account" /></div>
        <div class="field" v-if="form.kind === 'website'"><label>网址</label><input v-model="form.url" /></div>
        <div class="field" v-if="form.kind === 'website'"><label>密码</label>
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
        <div class="field"><label>文件夹</label>
          <select v-model="form.folder_id">
            <option value="">未归类</option>
            <option v-for="f in folders" :key="f.id" :value="f.id">{{ f.name }}</option>
          </select>
        </div>
        <div class="field"><label>标签（逗号分隔）</label><input v-model="form.tags" /></div>
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
        <div class="field"><label>文件路径（.svbak）</label><input v-model="backupPath" placeholder="D:\sealbox.svbak" /></div>
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
