<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { ProjectSummaryDto } from "../../../lib/project-api";

const props = defineProps<{
  projects: ProjectSummaryDto[];
  selectedId: string | null;
  query: string;
}>();

const emit = defineEmits<{
  "update:query": [value: string];
  select: [id: string];
}>();

/** Collapsed customer group ids when not searching. */
const collapsed = ref(new Set<string>());
const searching = computed(() => Boolean(props.query.trim()));

interface CustomerGroup {
  customerId: string;
  customerName: string;
  members: ProjectSummaryDto[];
}

const groups = computed<CustomerGroup[]>(() => {
  const map = new Map<string, ProjectSummaryDto[]>();
  for (const project of props.projects) {
    const customerId = project.contractCustomerId || "";
    if (!map.has(customerId)) map.set(customerId, []);
    map.get(customerId)!.push(project);
  }
  return [...map.entries()].map(([customerId, members]) => ({
    customerId,
    customerName: members[0]?.contractCustomerName || customerId || "未填写签约客户",
    members,
  }));
});

function isOpen(customerId: string): boolean {
  if (searching.value) return true;
  return !collapsed.value.has(customerId);
}

function onToggle(customerId: string, event: Event) {
  if (searching.value) return;
  const details = event.target as HTMLDetailsElement;
  // details fires toggle after open state flips
  const next = new Set(collapsed.value);
  if (details.open) next.delete(customerId);
  else next.add(customerId);
  collapsed.value = next;
}

watch(
  () => props.query,
  (q, prev) => {
    // Clearing search restores prior collapse state (kept in `collapsed`).
    if (prev?.trim() && !q.trim()) {
      // no-op — collapsed set already holds state
    }
  },
);
</script>

<template>
  <aside class="pq-card pq-rail" aria-label="项目列表">
    <div class="pq-rail-head">
      <div class="pq-row pq-between">
        <h3>项目列表</h3>
        <span class="pq-pill" aria-live="polite">{{ projects.length }} 个</span>
      </div>
      <input
        class="pq-search"
        type="search"
        aria-label="查询客户或项目"
        placeholder="客户、项目名称或编号"
        :value="query"
        @input="emit('update:query', ($event.target as HTMLInputElement).value)"
      />
      <small>精确匹配基线；本原型仅含已核实的一条项目</small>
    </div>
    <div class="pq-project-list" :data-searching="String(searching)">
      <template v-if="groups.length">
        <details
          v-for="group in groups"
          :key="group.customerId || '__none__'"
          class="pq-customer-group"
          :data-customer-id="group.customerId"
          :open="isOpen(group.customerId)"
          @toggle="onToggle(group.customerId, $event)"
        >
          <summary>
            <span class="pq-customer-group-name">{{ group.customerName }}</span>
            <span class="pq-pill">{{ group.members.length }} 个</span>
          </summary>
          <div class="pq-customer-group-projects">
            <button
              v-for="project in group.members"
              :key="project.crmId"
              class="pq-project"
              type="button"
              :aria-pressed="project.id === selectedId"
              @click="emit('select', project.id)"
            >
              <span class="pq-row pq-between">
                <small class="pq-mono">{{ project.id }}</small>
                <span class="pq-pill live">{{ project.stage }}</span>
              </span>
              <strong>{{ project.title }}</strong>
              <small>项目经理 · {{ project.owner }}</small>
            </button>
          </div>
        </details>
      </template>
      <div v-else class="pq-empty">没有匹配的项目</div>
    </div>
    <div class="pq-rail-foot">
      <small>快照读取 · 2026-11-18 · ERP Project / Hour / JIRATask</small>
    </div>
  </aside>
</template>
