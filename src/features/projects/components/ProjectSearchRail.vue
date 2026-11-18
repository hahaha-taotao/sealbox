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
  bind: [];
  create: [];
}>();

const collapsed = ref(new Set<string>());
const searching = computed(() => Boolean(props.query.trim()));

interface CustomerGroup {
  customerId: string;
  customerName: string;
  members: ProjectSummaryDto[];
}

const filtered = computed(() => {
  const q = props.query.trim().toLowerCase();
  if (!q) return props.projects;
  return props.projects.filter((p) =>
    [p.id, p.crmId, p.title, p.owner, p.contractCustomerName || "", p.shortName]
      .join(" ")
      .toLowerCase()
      .includes(q),
  );
});

const groups = computed<CustomerGroup[]>(() => {
  const map = new Map<string, ProjectSummaryDto[]>();
  for (const project of filtered.value) {
    const customerId = project.contractCustomerId || (project.crmId ? "__erp__" : "__local__");
    if (!map.has(customerId)) map.set(customerId, []);
    map.get(customerId)!.push(project);
  }
  return [...map.entries()].map(([customerId, members]) => ({
    customerId,
    customerName:
      members[0]?.contractCustomerName ||
      (customerId === "__local__" ? "本地关注" : customerId === "__erp__" ? "已绑定 ERP" : customerId) ||
      "未填写签约客户",
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
  const next = new Set(collapsed.value);
  if (details.open) next.delete(customerId);
  else next.add(customerId);
  collapsed.value = next;
}

watch(
  () => props.query,
  () => {},
);
</script>

<template>
  <aside class="pq-card pq-rail" aria-label="我的项目">
    <div class="pq-rail-head">
      <div class="pq-row pq-between">
        <h3>我的项目</h3>
        <span class="pq-pill" aria-live="polite">{{ filtered.length }} 个</span>
      </div>
      <div class="pq-row pq-wrap" style="gap: 6px; margin-bottom: 8px">
        <button class="btn primary" type="button" @click="emit('bind')">绑定 ERP</button>
        <button class="btn" type="button" @click="emit('create')">新建关注</button>
      </div>
      <input
        class="pq-search"
        type="search"
        aria-label="筛选我的项目"
        placeholder="筛选已关注的项目"
        :value="query"
        @input="emit('update:query', ($event.target as HTMLInputElement).value)"
      />
      <small>只显示你关注的项目；绑定 ERP 后才会拉实时详情</small>
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
              :key="project.localProjectId || project.id"
              class="pq-project"
              type="button"
              :aria-pressed="project.id === selectedId"
              @click="emit('select', project.id)"
            >
              <span class="pq-row pq-between">
                <small class="pq-mono">{{ project.crmId || project.id }}</small>
                <span class="pq-pill live">{{ project.stage || "关注" }}</span>
              </span>
              <strong>{{ project.title }}</strong>
              <small v-if="project.owner">项目经理 · {{ project.owner }}</small>
            </button>
          </div>
        </details>
      </template>
      <div v-else class="pq-empty">还没有关注的项目<br />点击上方绑定 ERP 或新建关注</div>
    </div>
    <div class="pq-rail-foot">
      <small>左侧仅本地关注列表 · 详情按需刷新 ERP</small>
    </div>
  </aside>
</template>
