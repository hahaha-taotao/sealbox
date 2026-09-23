<script setup lang="ts">
import { nextTick, onMounted, onUnmounted, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

type Field = { label: string; value: string };
type Payload = { title: string; prompt: string; fields: Field[] };

const title = ref("写操作审批");
const prompt = ref("");
const fields = ref<Field[]>([]);
const error = ref("");
const busy = ref(false);
const loaded = ref(false);
const allowBtn = ref<HTMLButtonElement | null>(null);

async function respond(allow: boolean) {
  if (busy.value) return;
  busy.value = true;
  try {
    await invoke("confirm_respond", { allow });
  } catch (e) {
    error.value = String(e);
    busy.value = false;
  }
}

async function apply(payload: Payload | null) {
  if (!payload) return;
  error.value = "";
  busy.value = false;
  title.value = payload.title;
  prompt.value = payload.prompt;
  fields.value = payload.fields;
  loaded.value = true;
  await nextTick();
  allowBtn.value?.focus();
}

async function load() {
  try {
    await apply(await invoke<Payload | null>("confirm_payload"));
  } catch (e) {
    error.value = String(e);
    loaded.value = true;
  }
}

function onKey(e: KeyboardEvent) {
  if (e.key === "Escape") {
    e.preventDefault();
    void respond(false);
  }
}

onMounted(async () => {
  window.addEventListener("keydown", onKey);
  const unOpen = await listen<Payload>("confirm-open", (event) => {
    void apply(event.payload);
  });
  await load();
  onUnmounted(() => {
    window.removeEventListener("keydown", onKey);
    unOpen();
  });
});
</script>

<template>
  <div class="confirm-win">
    <div class="confirm-head" data-tauri-drag-region>
      <strong>Sealbox 审批</strong>
      <button class="nav-btn" type="button" :disabled="busy" @click="respond(false)">×</button>
    </div>
    <div class="confirm-body">
      <div v-if="!loaded" class="crumb">等待审批请求…</div>
      <template v-else>
        <div class="confirm-title">
          <span class="confirm-mark" aria-hidden="true">!</span>
          <div>
            <h3>{{ title }}</h3>
            <p class="crumb">{{ prompt }}</p>
          </div>
        </div>
        <p v-if="error" class="error">{{ error }}</p>
        <div v-if="fields.length" class="confirm-fields">
          <div v-for="field in fields" :key="field.label" class="confirm-field">
            <span>{{ field.label }}</span>
            <strong>{{ field.value }}</strong>
          </div>
        </div>
        <div class="confirm-actions">
          <button class="btn" type="button" :disabled="busy" @click="respond(false)">拒绝</button>
          <button ref="allowBtn" class="btn primary" type="button" :disabled="busy" @click="respond(true)">允许</button>
        </div>
      </template>
    </div>
  </div>
</template>
