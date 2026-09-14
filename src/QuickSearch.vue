<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { listen } from "@tauri-apps/api/event";
import { api, type EntryDto, type EntryKind, type Status } from "./lib/tauri";

const status = ref<Status | null>(null);
const query = ref("");
const index = ref(0);
const entries = ref<EntryDto[]>([]);
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
      (e.url || "").toLowerCase().includes(q),
  );
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
  }
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
    return;
  }
  try {
    entries.value = await api.list({
      query: null,
      kind: null,
      folder_id: null,
      uncategorized: false,
      tag: null,
      trash: false,
      sort: "use_count",
    });
    error.value = "";
  } catch (e) {
    entries.value = [];
    error.value = String(e);
  }
}

async function unlock() {
  error.value = "";
  try {
    await api.unlock(password.value);
    password.value = "";
    await refresh();
  } catch {
    error.value = "主密码不正确";
  }
}

async function copyHit(row: EntryDto) {
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
  if (!status.value?.unlocked) {
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
  onUnmounted(() => {
    window.removeEventListener("keydown", onKey);
    un();
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
          <span>{{ row.title }}<small v-if="row.account"> · {{ row.account }}</small></span>
          <span class="count">{{ kindLabel(row.kind) }}</span>
        </button>
        <p class="crumb" v-if="!hits.length">没有匹配</p>
      </div>
    </div>
    <div class="toast" v-if="toast">{{ toast }}</div>
  </div>
</template>
