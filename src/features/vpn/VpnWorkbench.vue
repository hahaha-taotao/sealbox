<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { openUrl } from "@tauri-apps/plugin-opener";
import { api, type VpnConnection, type VpnPortal, type VpnWorkbench as Store } from "../../lib/tauri";

const view = ref<Awaited<ReturnType<typeof api.vpnGet>> | null>(null);
const error = ref("");
const message = ref("");
const askAccount = ref("");
const pending = ref<{ portalId: string; sessionId: number } | null>(null);
const query = ref("");

const clients = [
  { id: "atrust", label: "aTrust" },
  { id: "easy_connect", label: "EasyConnect" },
  { id: "open_vpn_connect", label: "OpenVPN Connect" },
  { id: "clash", label: "Clash" },
  { id: "tailscale", label: "Tailscale" },
] as const;

const accounts = computed(() => view.value?.accounts ?? []);
const filteredAccounts = computed(() => {
  const q = query.value.trim().toLowerCase();
  return accounts.value.filter((item) => !q || `${item.title} ${item.account ?? ""}`.toLowerCase().includes(q));
});

async function load() {
  error.value = "";
  view.value = await api.vpnGet();
}

onMounted(() => {
  load().catch((err) => (error.value = String(err)));
});

function blankConnection(): VpnConnection {
  return { id: crypto.randomUUID(), client: "atrust", label: "办公 VPN", gateway: "" };
}
function blankPortal(): VpnPortal {
  return {
    id: crypto.randomUUID(),
    name: "新入口",
    target_kind: "url",
    target: "https://",
    connection_id: view.value?.workbench.connections[0]?.id ?? "",
    account_ids: [],
    default_account_id: null,
    ask_each_time: false,
    auto_submit: false,
  };
}

async function save() {
  if (!view.value) return;
  error.value = "";
  message.value = "";
  try {
    const workbench: Store = {
      connections: view.value.workbench.connections,
      portals: view.value.workbench.portals.map((portal) => ({ ...portal, auto_submit: false })),
    };
    view.value.workbench = await api.vpnSave(workbench);
    message.value = "入口设置已保存";
    await load();
  } catch (err) {
    error.value = String(err);
  }
}

function accountTitle(id: string) {
  return accounts.value.find((item) => item.id === id)?.title ?? `已失效 ${id.slice(0, 8)}`;
}

function toggleAccount(portal: VpnPortal, id: string) {
  if (portal.account_ids.includes(id)) {
    portal.account_ids = portal.account_ids.filter((item) => item !== id);
    if (portal.default_account_id === id) portal.default_account_id = null;
  } else {
    portal.account_ids.push(id);
  }
}

async function openPortal(portal: VpnPortal, explicitSwitch: boolean) {
  error.value = "";
  message.value = "";
  const plan = await api.vpnPlan(portal.id, false, explicitSwitch);
  if (plan.includes("OpenDirect")) {
    if (portal.target_kind === "url") await openUrl(portal.target);
    message.value = "目标按当前网络打开。这不表示已经用某个 VPN 账号登录。";
    return;
  }
  if (plan.includes("NoAccount")) {
    const started = await api.vpnConnect(portal.connection_id);
    pending.value = { portalId: portal.id, sessionId: started.session_id };
    message.value = `${started.message} 未绑定账号，使用客户端自身登录或现有网络。`;
    return;
  }
  if (plan.includes("DefaultUnavailable")) {
    error.value = "默认账号已失效，不会自动改用其他账号。请重新选择。";
    return;
  }
  if (plan.includes("Ask")) {
    askAccount.value = portal.id;
    return;
  }
  const match = plan.match(/UseAccount\("([^"]+)"\)/);
  if (match) await connectAs(portal, match[1]);
}

async function connectAs(portal: VpnPortal, accountId: string) {
  askAccount.value = "";
  const started = await api.vpnConnect(portal.connection_id);
  pending.value = { portalId: portal.id, sessionId: started.session_id };
  const name = accountTitle(accountId);
  message.value = `${started.message} 本次选择「${name}」。扩展不能安全绑定到指定标签页，请在官方页面手动登录，完成后点「登录完成后打开」。`;
}

async function finish() {
  if (!pending.value || !view.value) return;
  const portal = view.value.workbench.portals.find((item) => item.id === pending.value?.portalId);
  try {
    await api.vpnFinishOpen(pending.value.sessionId);
    if (portal?.target_kind === "url") await openUrl(portal.target);
    message.value = portal?.target_kind === "url" ? "已打开目标。" : "本机应用目标需你在客户端里继续。";
    pending.value = null;
  } catch (err) {
    error.value = String(err);
  }
}

async function cancel() {
  if (!pending.value) return;
  await api.vpnCancel(pending.value.sessionId);
  pending.value = null;
  message.value = "已取消，不会继续打开目标。";
}
</script>

<template>
  <div class="vpn-page" v-if="view">
    <header class="vpn-head">
      <div>
        <h2>VPN</h2>
        <p>{{ view.fill_note }}</p>
      </div>
      <button class="btn primary" type="button" @click="save">保存入口设置</button>
    </header>
    <p v-if="!view.windows" class="vpn-note">此平台只读写 VPN 条目和入口设置，不启动客户端。</p>
    <p v-if="error" class="error">{{ error }}</p>
    <p v-if="message" class="vpn-note">{{ message }}</p>
    <div v-if="pending" class="vpn-note">
      <button class="btn" type="button" @click="finish">登录完成后打开</button>
      <button class="btn" type="button" @click="cancel">取消</button>
    </div>

    <section>
      <div class="vpn-head">
        <h3>连接</h3>
        <button class="btn" type="button" @click="view.workbench.connections.push(blankConnection())">添加连接</button>
      </div>
      <article v-for="item in view.workbench.connections" :key="item.id" class="vpn-card">
        <input v-model="item.label" placeholder="名称" />
        <select v-model="item.client">
          <option v-for="client in clients" :key="client.id" :value="client.id">{{ client.label }}</option>
        </select>
        <input v-model="item.gateway" placeholder="网关或已导入配置名，不含密码" />
        <span class="crumb">{{ view.clients.find((client) => client.client === item.client)?.installed ? "已检测到客户端" : "未检测到客户端" }}</span>
      </article>
    </section>

    <section>
      <div class="vpn-head">
        <h3>入口</h3>
        <button class="btn" type="button" @click="view.workbench.portals.push(blankPortal())">添加入口</button>
      </div>
      <article v-for="portal in view.workbench.portals" :key="portal.id" class="vpn-card">
        <input v-model="portal.name" placeholder="入口名称" />
        <select v-model="portal.target_kind">
          <option value="url">网页</option>
          <option value="app">本机应用</option>
        </select>
        <input v-model="portal.target" placeholder="https:// 或应用标识" />
        <select v-model="portal.connection_id">
          <option value="">选择连接</option>
          <option v-for="item in view.workbench.connections" :key="item.id" :value="item.id">{{ item.label }}</option>
        </select>
        <label><input type="checkbox" v-model="portal.ask_each_time" /> 每次询问</label>
        <p class="crumb">自动提交已关闭。不会把 VPN 密码交给普通自动填充。</p>
        <input v-model="query" placeholder="搜索标题或账号" />
        <label v-for="account in filteredAccounts" :key="account.id">
          <input type="checkbox" :checked="portal.account_ids.includes(account.id)" @change="toggleAccount(portal, account.id)" />
          {{ account.title }} · {{ account.account || "无账号" }}
        </label>
        <p v-for="id in portal.account_ids.filter((id) => !accounts.some((account) => account.id === id))" :key="id" class="error">
          {{ accountTitle(id) }}
          <button class="btn" type="button" @click="toggleAccount(portal, id)">移除</button>
        </p>
        <label>默认账号
          <select v-model="portal.default_account_id">
            <option :value="null">无</option>
            <option v-for="id in portal.account_ids" :key="id" :value="id">{{ accountTitle(id) }}</option>
          </select>
        </label>
        <div>
          <span class="crumb">访问使用已保存的设置，且不做目标可达探测。</span>
          <button class="btn primary" type="button" @click="openPortal(portal, false)">访问</button>
          <button class="btn" type="button" @click="openPortal(portal, true)">使用其他账号</button>
        </div>
        <div v-if="askAccount === portal.id">
          <button v-for="id in portal.account_ids" :key="id" class="btn" type="button" @click="connectAs(portal, id)">{{ accountTitle(id) }}</button>
        </div>
      </article>
    </section>
  </div>
</template>

<style scoped>
.vpn-page { display: grid; gap: 16px; padding: 20px 24px 40px; max-width: 880px; }
.vpn-head, .vpn-card { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.vpn-card { border: 1px solid var(--line, #e6e6ea); border-radius: 12px; padding: 12px; margin-top: 8px; }
.vpn-note { color: var(--muted, #666); }
input, select { min-height: 32px; }
</style>
