<script setup lang="ts">
import { computed, ref, watch } from "vue";
import CompactMultiSelect, { type MsOption } from "./CompactMultiSelect.vue";
import {
  JIRA_VIEW_LABELS,
  effectiveRangeKeys,
  mergeProjectTasks,
  normalizeShort,
  projectTaskCount,
  rangeEntries,
  type JiraTaskDto,
  type JiraView,
  type ProjectDetailDto,
} from "../../../lib/project-api";
import { taskColumns } from "../fixtures/proj3733";

const props = defineProps<{
  detail: ProjectDetailDto;
  jiraView: JiraView;
}>();

const emit = defineEmits<{
  "update:jiraView": [view: JiraView];
  "apply-short": [shortName: string];
  "choose-range": [];
  "remove-range": [key: string];
  "exact-issue": [];
  issue: [task: JiraTaskDto];
}>();

const views = Object.entries(JIRA_VIEW_LABELS) as [JiraView, string][];

const taskQuery = ref("");
const selectedProjects = ref<string[]>([]);
const selectedStatuses = ref<string[]>([]);
const shortDraft = ref(props.detail.shortName);

watch(
  () => props.detail.shortName,
  (v) => {
    shortDraft.value = v;
  },
);

const ranges = computed(() =>
  rangeEntries(props.detail.shortName, props.detail.manualRanges, props.detail.jiraCatalog),
);

const rangeKeySet = computed(
  () =>
    new Set(
      effectiveRangeKeys(
        props.detail.shortName,
        props.detail.manualRanges,
        props.detail.jiraCatalog,
      ),
    ),
);

const allTasks = computed(() => mergeProjectTasks(props.detail));
const totalCount = computed(() => projectTaskCount(props.detail));

function availableStatuses(projectFilter: string[]): string[] {
  const filter = new Set(projectFilter);
  const fromTasks = allTasks.value
    .filter((t) => !filter.size || filter.has(t.jiraProjectKey))
    .map((t) => t.status)
    .filter(Boolean);
  return [...new Set([...props.detail.jiraStatusDefaults, ...fromTasks])];
}

function sanitizeFilters() {
  const nextProjects = selectedProjects.value.filter((key) => rangeKeySet.value.has(key));
  if (nextProjects.length !== selectedProjects.value.length) {
    selectedProjects.value = nextProjects;
  }
  const available = new Set(availableStatuses(selectedProjects.value));
  const nextStatuses = selectedStatuses.value.filter((s) => available.has(s));
  if (nextStatuses.length !== selectedStatuses.value.length) {
    selectedStatuses.value = nextStatuses;
  }
}

watch(
  () => [props.detail.shortName, props.detail.manualRanges.slice()] as const,
  () => sanitizeFilters(),
  { deep: true },
);

const filteredTasks = computed(() => {
  const projectFilter = new Set(selectedProjects.value);
  const statusFilter = new Set(selectedStatuses.value);
  const q = taskQuery.value.trim().toLowerCase();
  return allTasks.value.filter((task) => {
    if (projectFilter.size && !projectFilter.has(task.jiraProjectKey)) return false;
    if (statusFilter.size && !statusFilter.has(task.status)) return false;
    if (q) {
      const hay = `${task.key} ${task.title}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
});

const projectOptions = computed<MsOption[]>(() =>
  ranges.value.map((entry) => ({
    value: entry.key,
    label: `${entry.key} · ${entry.name}${entry.status !== "verified" ? " · 待验证" : ""}`,
  })),
);

const statusOptions = computed<MsOption[]>(() =>
  availableStatuses(selectedProjects.value).map((status) => ({
    value: status,
    label: status,
  })),
);

function onProjectFilterChange(next: string[]) {
  const prevStatuses = [...selectedStatuses.value];
  selectedProjects.value = next;
  const available = new Set(availableStatuses(next));
  selectedStatuses.value = prevStatuses.filter((s) => available.has(s));
}

function onStatusFilterChange(next: string[]) {
  selectedStatuses.value = next;
}

function applyShort() {
  emit("apply-short", shortDraft.value);
}
</script>

<template>
  <div class="pq-jira-shell">
    <nav class="pq-jira-nav" aria-label="Jira 子视图">
      <button
        v-for="[key, label] in views"
        :key="key"
        type="button"
        :aria-pressed="key === jiraView"
        @click="emit('update:jiraView', key)"
      >
        {{ label }}{{ key === "project" ? ` · ${totalCount}` : "" }}
      </button>
    </nav>

    <div class="pq-jira-pane">
      <!-- 项目任务 -->
      <template v-if="jiraView === 'project'">
        <div class="pq-toolbar">
          <input
            class="pq-search"
            type="search"
            aria-label="筛选任务"
            placeholder="Issue 编号或标题"
            v-model="taskQuery"
          />
          <CompactMultiSelect
            id="project-task-jira"
            label="筛选 Jira 项目"
            all-label="全部项目"
            :options="projectOptions"
            :model-value="selectedProjects"
            @update:model-value="onProjectFilterChange"
          />
          <CompactMultiSelect
            id="project-task-status"
            label="筛选任务状态"
            all-label="全部状态"
            :options="statusOptions"
            :model-value="selectedStatuses"
            @update:model-value="onStatusFilterChange"
          />
          <button class="btn" type="button" @click="emit('exact-issue')">
            按 key 精确补充
          </button>
          <small aria-live="polite">
            {{ filteredTasks.length }} 项 · 项目任务合计 {{ totalCount }}
          </small>
        </div>

        <div class="pq-table-wrap" tabindex="0" role="region" aria-label="项目任务表">
          <table>
            <thead>
              <tr>
                <th v-for="col in taskColumns" :key="col" scope="col">{{ col }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="task in filteredTasks" :key="task.key">
                <td>
                  <button
                    class="pq-link pq-mono"
                    type="button"
                    @click="emit('issue', task)"
                  >
                    {{ task.key }}
                  </button>
                  <small>{{ task.title }}</small>
                </td>
                <td>{{ task.jiraProjectKey }}</td>
                <td>
                  <span
                    class="pq-pill"
                    :class="task.origin === 'erp' ? 'live' : 'warn'"
                  >
                    {{ task.status }}
                  </span>
                </td>
                <td>{{ task.priority }}</td>
                <td>{{ task.batch }}</td>
                <td>{{ task.dueDate }}</td>
                <td>{{ task.assignee }}</td>
              </tr>
              <tr v-if="!filteredTasks.length">
                <td :colspan="taskColumns.length" class="pq-empty">
                  没有满足筛选条件的项目任务
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="pq-footnote">任务字段来自 Jira 快照。— 表示当前快照未取得对应值。</p>
      </template>

      <!-- 范围配置 -->
      <template v-else>
        <section class="pq-task-block">
          <div class="pq-section-head">
            <h3>范围配置</h3>
            <p>
              有效范围 = 简称自动匹配 ∪ 手动补充；空简称只走手动。范围只影响「范围内候选」筛选，不改写项目任务。
            </p>
          </div>
          <div class="pq-short-box">
            <label>
              项目简称
              <input
                class="pq-search"
                type="text"
                spellcheck="false"
                v-model="shortDraft"
                placeholder="例如 XKRL；留空=仅手动"
                aria-label="项目简称"
                @keydown.enter.prevent="applyShort"
              />
            </label>
            <button class="btn primary" type="button" @click="applyShort">应用简称</button>
            <small class="pq-muted">
              匹配规则：trim 后转大写，对 Jira 项目 key 做 substring 包含。当前规范化：
              <span class="pq-mono">{{ normalizeShort(shortDraft) || "（空）" }}</span>
            </small>
          </div>

          <div class="pq-range-list" style="margin-top: 12px">
            <template v-if="ranges.length">
              <span v-for="entry in ranges" :key="entry.key" class="pq-range">
                <strong class="pq-mono">{{ entry.key }}</strong>
                {{ entry.name }}
                <span
                  v-for="src in entry.sources"
                  :key="src"
                  class="pq-pill"
                  :class="src === 'auto' ? 'blue' : 'live'"
                >
                  {{ src === "auto" ? "自动匹配" : "手动补充" }}
                </span>
                <span
                  v-if="entry.status === 'example'"
                  class="pq-pill warn"
                >规则示例 · 待验证</span>
                <span
                  v-else-if="entry.status === 'pending'"
                  class="pq-pill warn"
                >待验证</span>
                <small v-if="entry.sources.includes('auto') && entry.sources.includes('manual')">
                  自动+手动
                </small>
                <small v-else-if="entry.sources.includes('auto')">简称命中</small>
                <small v-else>仅手动</small>
                <button
                  v-if="entry.sources.includes('manual')"
                  class="pq-link remove"
                  type="button"
                  @click="emit('remove-range', entry.key)"
                >
                  移除手动
                </button>
              </span>
            </template>
            <span v-else class="pq-muted">
              当前无有效范围。可填写简称自动匹配，或手动添加项目。
            </span>
          </div>

          <div class="pq-actions" style="margin-top: 12px">
            <button class="btn" type="button" @click="emit('choose-range')">
              添加手动范围
            </button>
            <small class="pq-muted">
              已核实有任务：XKRL、XKRLWXM。XKRLWXV 为规则示例/待验证，无任务。正式版须解析到已授权项目
              ID。移除范围不会增删 ERP 关联或本地补充。
            </small>
          </div>
        </section>
        <p class="pq-footnote">
          搜索、状态筛选、范围内候选与「按 key 精确补充」已统一到「项目任务」子页，避免两处重复列出同一任务。
        </p>
      </template>
    </div>
  </div>
</template>
