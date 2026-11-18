<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";

const props = defineProps<{
  open: boolean;
  title: string;
  confirmLabel?: string;
  danger?: boolean;
}>();

const emit = defineEmits<{
  close: [];
  confirm: [];
}>();

const cancelBtn = ref<HTMLButtonElement | null>(null);

watch(
  () => props.open,
  async (open) => {
    if (open) {
      await nextTick();
      cancelBtn.value?.focus();
    }
  },
);

function onKey(event: KeyboardEvent) {
  if (!props.open) return;
  if (event.key === "Escape") {
    event.preventDefault();
    emit("close");
  }
}

onMounted(() => window.addEventListener("keydown", onKey));
onBeforeUnmount(() => window.removeEventListener("keydown", onKey));
</script>

<template>
  <div
    v-if="open"
    class="pq-modal-mask"
    role="presentation"
    @click.self="emit('close')"
  >
    <div
      class="pq-modal"
      role="dialog"
      aria-modal="true"
      :aria-labelledby="'pq-dialog-title'"
    >
      <form
        @submit.prevent="confirmLabel ? emit('confirm') : emit('close')"
      >
        <div class="pq-modal-head">
          <h3 id="pq-dialog-title">{{ title }}</h3>
        </div>
        <div class="pq-modal-body">
          <slot />
        </div>
        <div class="pq-modal-foot">
          <button ref="cancelBtn" class="btn" type="button" @click="emit('close')">
            {{ confirmLabel ? "取消" : "关闭" }}
          </button>
          <button
            v-if="confirmLabel"
            class="btn"
            :class="danger ? 'danger' : 'primary'"
            type="submit"
          >
            {{ confirmLabel }}
          </button>
        </div>
      </form>
    </div>
  </div>
</template>
