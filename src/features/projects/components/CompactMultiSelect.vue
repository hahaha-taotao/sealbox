<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from "vue";

export interface MsOption {
  value: string;
  label: string;
  htmlLabel?: boolean;
}

const props = withDefaults(
  defineProps<{
    id: string;
    label: string;
    allLabel: string;
    options: MsOption[];
    modelValue: string[];
    formatOne?: (value: string) => string;
  }>(),
  {
    formatOne: (value: string) => value,
  },
);

const emit = defineEmits<{
  "update:modelValue": [value: string[]];
  change: [value: string[]];
}>();

const open = ref(false);
const rootRef = ref<HTMLElement | null>(null);
const menuRef = ref<HTMLElement | null>(null);

const selectedSet = computed(() => new Set(props.modelValue));

const summary = computed(() => {
  const selected = props.modelValue;
  if (!selected.length) return props.allLabel;
  if (selected.length === 1) return props.formatOne(selected[0]);
  if (selected.length <= 2) return selected.map(props.formatOne).join("、");
  return `已选 ${selected.length} 项`;
});

function toggleOpen() {
  if (open.value) close();
  else void openMenu();
}

async function openMenu() {
  open.value = true;
  await nextTick();
  const first = menuRef.value?.querySelector<HTMLInputElement>("input[type=checkbox]");
  first?.focus();
}

function close() {
  open.value = false;
}

function clear() {
  emit("update:modelValue", []);
  emit("change", []);
}

function onToggle(value: string, checked: boolean) {
  const next = checked
    ? [...props.modelValue, value]
    : props.modelValue.filter((item) => item !== value);
  // Keep menu open while checking (design §2.6 / Q-08).
  emit("update:modelValue", next);
  emit("change", next);
}

function onDocClick(event: MouseEvent) {
  if (!open.value) return;
  const target = event.target as Node | null;
  if (rootRef.value && target && !rootRef.value.contains(target)) close();
}

function onKeydown(event: KeyboardEvent) {
  if (event.key === "Escape" && open.value) {
    event.preventDefault();
    close();
    rootRef.value?.querySelector<HTMLButtonElement>(".pq-ms-trigger")?.focus();
    return;
  }
  if (!open.value || !menuRef.value) return;
  const boxes = [...menuRef.value.querySelectorAll<HTMLInputElement>("input[type=checkbox]")];
  if (!boxes.length) return;
  const active = document.activeElement as HTMLInputElement | null;
  const index = boxes.indexOf(active as HTMLInputElement);
  if (event.key === "ArrowDown") {
    event.preventDefault();
    boxes[(index + 1 + boxes.length) % boxes.length]?.focus();
  } else if (event.key === "ArrowUp") {
    event.preventDefault();
    boxes[(index - 1 + boxes.length) % boxes.length]?.focus();
  } else if (event.key === "Home") {
    event.preventDefault();
    boxes[0]?.focus();
  } else if (event.key === "End") {
    event.preventDefault();
    boxes[boxes.length - 1]?.focus();
  }
}

function onTriggerKey(event: KeyboardEvent) {
  if (event.key === "ArrowDown" || event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    void openMenu();
  }
}

onMounted(() => {
  document.addEventListener("click", onDocClick);
  document.addEventListener("keydown", onKeydown);
});
onBeforeUnmount(() => {
  document.removeEventListener("click", onDocClick);
  document.removeEventListener("keydown", onKeydown);
});
</script>

<template>
  <div ref="rootRef" class="pq-ms" :data-ms="id" :data-ms-label="label">
    <button
      type="button"
      class="pq-ms-trigger"
      :id="`${id}-trigger`"
      aria-haspopup="listbox"
      :aria-expanded="open"
      :aria-controls="`${id}-menu`"
      :aria-label="label"
      @click.stop="toggleOpen"
      @keydown="onTriggerKey"
    >
      <span class="pq-ms-label">{{ summary }}</span>
      <span class="pq-ms-caret" aria-hidden="true">▾</span>
    </button>
    <button
      v-if="modelValue.length"
      type="button"
      class="pq-ms-clear"
      :aria-label="`清空${label}`"
      @click.stop="clear"
    >
      ×
    </button>
    <div
      v-show="open"
      ref="menuRef"
      class="pq-ms-menu"
      :id="`${id}-menu`"
      role="listbox"
      aria-multiselectable="true"
      :aria-label="label"
      @click.stop
    >
      <template v-if="options.length">
        <label v-for="opt in options" :key="opt.value" class="pq-ms-option">
          <input
            type="checkbox"
            :value="opt.value"
            :checked="selectedSet.has(opt.value)"
            @change="onToggle(opt.value, ($event.target as HTMLInputElement).checked)"
          />
          <span>{{ opt.label }}</span>
        </label>
      </template>
      <div v-else class="pq-ms-empty">暂无可选项</div>
    </div>
  </div>
</template>
