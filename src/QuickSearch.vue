<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { listen } from "@tauri-apps/api/event";
import { api, type EntryDto, type EntryKind, type FolderDto, type Status } from "./lib/tauri";

const status = ref<Status | null>(null);
const query = ref("");
const index = ref(0);
const entries = ref<EntryDto[]>([]);
const folders = ref<FolderDto[]>([]);
const password = ref("");
const error = ref("");
const toast = ref("");
const win = getCurrentWindow();

const hits = computed(() => {
  const q = query.value.toLowerCase();
  return entries.value.filter(
    (e) =>
      e.title.toLowerCase().includes(q) ||
      (e.account || "").toLowerCase().includes(q) ||
      (e.url || "").toLowerCase().includes(q) ||
      folderName(e.folder_id).toLowerCase().includes(q),
  ).filter((e) => e.kind !== "client_cert");
});

function kindLabel(k: EntryKind) {
  switch (k) {
    case "website": return "网站";
    case "api_token": return "Token";
    case "ssh": return "SSH";
    case "mailbox": return "邮箱";
    case "mail_auth": return "授权码";
    case "server": return "服务器";
    case "database": return "数据库";
    case "client_cert": return "客户端证书";
  }
}

function folderName(folderId: string | null) {
  return folders.value.find((folder) => folder.id === folderId)?.name || "未归类";
}

async function hide() {
  query.value = "";
  index.value = 0;
  password.value = "";
  error.value = "";
  await win.hide();
}

async function refresh() {
  status.value = await api.status();
  if (!status.value.unlocked) {
    entries.value = [];
    folders.value = [];
    return;
  }
  try {
    [entries.value, folders.value] = await Promise.all([
      api.list({
      query: null,
      kind: null,
      kinds: [],
      folder_id: null,
      uncategorized: false,
      tag: null,
      trash: false,
      sort: "use_count",
      }),
      api.folders(),
    ]);
    error.value = "";
  } catch (e) {
    entries.value = [];
    error.value = String(e);
  }
}

async function unlock() {
  if (!status.value?.initialized) return;
  error.value = "";
  try {
    await api.unlock(password.value);
    password.value = "";
    await refresh();
  } catch (e) {
    const msg = String(e);
    error.value = msg.includes("not initialized") ? "尚未创建金库" : "主密码不正确";
  }
}

async function copyHit(row: EntryDto) {
  if (row.kind === "client_cert") {
    toast.value = "客户端证书不能通过速查复制";
    setTimeout(() => (toast.value = ""), 800);
    return;
  }
  await api.copy(row.id, "secret");
  toast.value = `已复制 ${row.title}`;
  setTimeout(() => (toast.value = ""), 800);
  await hide();
}

function onKey(e: KeyboardEvent) {
  if (e.key === "Escape") {
    e.preventDefault();
    hide();
    return;
  }
  if (!status.value?.initialized) {
    return;
  }
  if (!status.value.unlocked) {
    if (e.key === "Enter") unlock();
    return;
  }
  if (e.key === "ArrowDown") {
    e.preventDefault();
    index.value = Math.min(index.value + 1, Math.max(hits.value.length - 1, 0));
  }
  if (e.key === "ArrowUp") {
    e.preventDefault();
    index.value = Math.max(index.value - 1, 0);
  }
  if (e.key === "Enter") {
    e.preventDefault();
    const hit = hits.value[index.value];
    if (hit) copyHit(hit);
  }
}

onMounted(async () => {
  window.addEventListener("keydown", onKey);
  await refresh();
  const un = await listen("quick-search", async () => {
    await refresh();
    query.value = "";
    index.value = 0;
    setTimeout(() => {
      const el = document.querySelector("input") as HTMLInputElement | null;
      el?.focus();
    }, 30);
  });
  const unLock = await listen("lock-now", async () => {
    entries.value = [];
    password.value = "";
    await refresh();
  });
  onUnmounted(() => {
    window.removeEventListener("keydown", onKey);
    un();
    unLock();
  });
});
</script>

<template>
  <div class="quick-win">
    <div class="quick-head" data-tauri-drag-region>
      <strong>Sealbox 速查</strong>
      <button class="nav-btn" @click="hide">×</button>
    </div>

    <div v-if="!status" class="quick-body crumb">加载中…</div>

    <div v-else-if="!status.initialized" class="quick-body">
      <p class="crumb">尚未创建金库</p>
      <p class="crumb">请先打开主窗口完成初始化，不要在此输入密码。</p>
    </div>

    <div v-else-if="!status.unlocked" class="quick-body">
      <p class="crumb">金库已锁定</p>
      <p v-if="error" class="error">{{ error }}</p>
      <input v-model="password" type="password" placeholder="主密码，回车解锁" autofocus />
      <button class="btn primary" style="width:100%;margin-top:8px" @click="unlock">解锁</button>
    </div>

    <div v-else class="quick-body">
      <input v-model="query" class="search" placeholder="搜索后回车复制…" autofocus @input="index = 0" />
      <p v-if="error" class="error">{{ error }}</p>
      <div class="quick-list">
        <button
          v-for="(row, i) in hits"
          :key="row.id"
          class="side-item"
          :class="{ active: i === index }"
          @mouseenter="index = i"
          @click="copyHit(row)"
        >
          <span class="quick-item-main">
            <span class="quick-item-title">{{ row.title }}<small v-if="row.account"> · {{ row.account }}</small></span>
            <small class="quick-item-folder">文件夹：{{ folderName(row.folder_id) }}</small>
          </span>
          <span class="count">{{ kindLabel(row.kind) }}</span>
        </button>
        <p class="crumb" v-if="!hits.length">没有匹配</p>
      </div>
    </div>
    <div class="toast" v-if="toast">{{ toast }}</div>
  </div>
</template>
