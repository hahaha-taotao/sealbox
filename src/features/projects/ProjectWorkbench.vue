<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import ProjectSearchRail from "./components/ProjectSearchRail.vue";
import OverviewTab from "./components/OverviewTab.vue";
import CostTab from "./components/CostTab.vue";
import PeopleTab from "./components/PeopleTab.vue";
import JiraTab from "./components/JiraTab.vue";
import ProjectModal from "./components/ProjectModal.vue";
import {
  ROLE_LABELS,
  TAB_LABELS,
  adoptProject,
  addManualJiraRange,
  autoRangeKeys,
  bindLocalCustomer,
  catalogMeta,
  formatMoney,
  getProjectDetail,
  listClients,
  listProjectSources,
  normalizeShort,
  projectTaskCount,
  removeLocalIssue,
  removeManualJiraRange,
  searchProjects,
  setProjectShortName,
  supplementIssueByKey,
  unbindLocalCustomer,
  type CostView,
  type CustomerRole,
  type ErpClientDto,
  type JiraTaskDto,
  type JiraView,
  type LocalCustomerBinding,
  type ProjectDetailDto,
  type ProjectStaffDto,
  type ProjectSummaryDto,
  type ProjectTab,
  type SourceBindingSummaryDto,
} from "../../lib/project-api";
import "./styles.css";

const query = ref("");
const projects = ref<ProjectSummaryDto[]>([]);
const selectedId = ref<string | null>(null);
const detail = ref<ProjectDetailDto | null>(null);
const tab = ref<ProjectTab>("cost");
const costView = ref<CostView>("budget");
const jiraView = ref<JiraView>("project");
const loading = ref(false);
const toastMsg = ref("");
let toastTimer: ReturnType<typeof setTimeout> | null = null;

const clients = ref<ErpClientDto[]>([]);
const sources = ref<SourceBindingSummaryDto[]>([]);
const searchWarnings = ref<string[]>([]);

const dataMode = computed<"live" | "fixture">(() => {
  if (detail.value?.dataSource === "live") return "live";
  if (detail.value?.dataSource === "fixture") return "fixture";
  const crm = sources.value.find((s) => s.platform === "zoomkey_crm");
  return crm && !crm.isFixture ? "live" : "fixture";
});

const modeBanner = computed(() =>
  dataMode.value === "live"
    ? "实时 ERP · 使用 ZoomKey CRM/Jira 凭据"
    : "离线夹具 · PROJ3733 演示数据（未绑定 ZoomKey 凭据时）",
);

// Modal state
type ModalKind =
  | null
  | "bind-customer"
  | "unbind-customer"
  | "person"
  | "issue"
  | "exact-issue"
  | "choose-range"
  | "remove-range"
  | "unbind-issue";

const modalKind = ref<ModalKind>(null);
const modalRole = ref<CustomerRole>("contract");
const modalStaff = ref<ProjectStaffDto | null>(null);
const modalTask = ref<JiraTaskDto | null>(null);
const modalRangeKey = ref("");
const bindMode = ref<"erp" | "manual">("erp");
const bindClientId = ref("");
const bindManualName = ref("");
const exactKeyInput = ref("");
const rangeSelect = ref("");
const rangeCustom = ref("");

const tabs = Object.entries(TAB_LABELS) as [ProjectTab, string][];

const taskCount = computed(() => (detail.value ? projectTaskCount(detail.value) : 0));

function toast(message: string) {
  toastMsg.value = message;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toastMsg.value = "";
  }, 3800);
}

async function refreshSources() {
  try {
    sources.value = await listProjectSources();
  } catch {
    sources.value = [];
  }
}

async function refreshList() {
  const page = await searchProjects(query.value);
  projects.value = page.items;
  searchWarnings.value = page.warnings ?? [];
}

async function openProject(id: string) {
  selectedId.value = id;
  tab.value = "cost";
  costView.value = "budget";
  jiraView.value = "project";
  loading.value = true;
  try {
    detail.value = await getProjectDetail(id);
  } catch (e) {
    detail.value = null;
    toast(String(e));
  } finally {
    loading.value = false;
  }
}

async function reloadDetail() {
  if (!selectedId.value) return;
  try {
    detail.value = await getProjectDetail(selectedId.value);
  } catch (e) {
    toast(String(e));
  }
  await refreshList();
}

async function refreshAll() {
  loading.value = true;
  try {
    await refreshSources();
    await refreshList();
    if (selectedId.value) {
      try {
        detail.value = await getProjectDetail(selectedId.value);
      } catch (e) {
        toast(String(e));
      }
    } else if (projects.value.length) {
      await openProject(projects.value[0].id);
    }
  } finally {
    loading.value = false;
  }
}

watch(query, () => {
  void refreshList();
});

onMounted(async () => {
  clients.value = await listClients();
  await refreshSources();
  await refreshList();
  if (projects.value.length) {
    await openProject(projects.value[0].id);
  }
});

onBeforeUnmount(() => {
  if (toastTimer) clearTimeout(toastTimer);
});

function closeModal() {
  modalKind.value = null;
  modalStaff.value = null;
  modalTask.value = null;
  modalRangeKey.value = "";
  exactKeyInput.value = "";
  rangeSelect.value = "";
  rangeCustom.value = "";
  bindClientId.value = "";
  bindManualName.value = "";
  bindMode.value = "erp";
}

async function onAdopt() {
  if (!detail.value) return;
  const result = await adoptProject(detail.value.crmId);
  await reloadDetail();
  toast(
    result.created
      ? `已纳入我的项目（本地 ID ${result.localProjectId.slice(0, 8)}…）`
      : `已在我的项目中（本地 ID ${result.localProjectId.slice(0, 8)}…）`,
  );
}

function openBind(role: CustomerRole) {
  if (!detail.value) return;
  modalRole.value = role;
  const local = detail.value.local[role];
  if (local.kind === "manual") {
    bindMode.value = "manual";
    bindManualName.value = local.name || "";
    bindClientId.value = "";
  } else {
    bindMode.value = "erp";
    bindClientId.value = local.clientId || "";
    bindManualName.value = "";
  }
  modalKind.value = "bind-customer";
}

function openUnbind(role: CustomerRole) {
  modalRole.value = role;
  modalKind.value = "unbind-customer";
}

async function confirmBind() {
  if (!detail.value) return;
  let binding: LocalCustomerBinding;
  if (bindMode.value === "manual") {
    const name = bindManualName.value.trim();
    if (!name) {
      toast("请输入手工客户名称");
      return;
    }
    binding = { kind: "manual", name };
  } else {
    if (!bindClientId.value) {
      toast("请选择客户");
      return;
    }
    const client = clients.value.find((c) => c.id === bindClientId.value);
    binding = {
      kind: "erp",
      clientId: bindClientId.value,
      name: client?.name,
    };
  }
  detail.value = await bindLocalCustomer(detail.value.crmId, modalRole.value, binding);
  await refreshList();
  closeModal();
  toast(`已保存${ROLE_LABELS[modalRole.value]}本地绑定`);
}

async function confirmUnbind() {
  if (!detail.value) return;
  detail.value = await unbindLocalCustomer(detail.value.crmId, modalRole.value);
  await refreshList();
  closeModal();
  toast(`已取消${ROLE_LABELS[modalRole.value]}本地绑定`);
}

function openPerson(staff: ProjectStaffDto) {
  modalStaff.value = staff;
  modalKind.value = "person";
}

function openIssue(task: JiraTaskDto) {
  modalTask.value = task;
  modalKind.value = "issue";
}

async function confirmRemoveLocalIssue() {
  if (!detail.value || !modalTask.value) return;
  try {
    detail.value = await removeLocalIssue(detail.value.crmId, modalTask.value.key);
    closeModal();
    toast(`已移除 ${modalTask.value.key} 的本地补充`);
  } catch (e) {
    toast(String(e));
  }
}

function openExactIssue() {
  exactKeyInput.value = "";
  modalKind.value = "exact-issue";
}

async function confirmExactIssue() {
  if (!detail.value) return;
  try {
    const { detail: next, message } = await supplementIssueByKey(
      detail.value.crmId,
      exactKeyInput.value,
    );
    detail.value = next;
    jiraView.value = "project";
    closeModal();
    toast(message);
  } catch (e) {
    toast(String(e));
  }
}

function openChooseRange() {
  rangeSelect.value = "";
  rangeCustom.value = "";
  modalKind.value = "choose-range";
}

async function confirmChooseRange() {
  if (!detail.value) return;
  const key = normalizeShort(rangeCustom.value) || normalizeShort(rangeSelect.value);
  try {
    const { detail: next, message } = await addManualJiraRange(detail.value.crmId, key);
    detail.value = next;
    closeModal();
    toast(message);
  } catch (e) {
    toast(String(e));
  }
}

function openRemoveRange(key: string) {
  modalRangeKey.value = key;
  modalKind.value = "remove-range";
}

async function confirmRemoveRange() {
  if (!detail.value) return;
  const { detail: next, message } = await removeManualJiraRange(
    detail.value.crmId,
    modalRangeKey.value,
  );
  detail.value = next;
  closeModal();
  toast(message);
}

async function onApplyShort(shortName: string) {
  if (!detail.value) return;
  detail.value = await setProjectShortName(detail.value.crmId, shortName);
  const normalized = normalizeShort(shortName);
  const auto = autoRangeKeys(detail.value.shortName, detail.value.jiraCatalog);
  toast(
    normalized
      ? `已应用简称 ${normalized} · 自动命中 ${auto.join("、") || "无"}`
      : "简称已清空 · 仅保留手动范围",
  );
}

function localBindingLabel(role: CustomerRole): string {
  if (!detail.value) return "—";
  const local = detail.value.local[role];
  if (local.kind === "erp") return `${local.name || ""} · ${local.clientId || ""}`;
  if (local.kind === "manual") return `${local.name}（手工录入）`;
  return "未绑定";
}

function factLabel(role: CustomerRole): string {
  if (!detail.value) return "ERP 未提供";
  const id = detail.value.fact[role];
  if (!id) return "ERP 未提供";
  const client = clients.value.find((c) => c.id === id);
  return `${client?.name || id} · ${id}`;
}

const removeRangeStillAuto = computed(() => {
  if (!detail.value || !modalRangeKey.value) return false;
  return autoRangeKeys(detail.value.shortName, detail.value.jiraCatalog).includes(
    normalizeShort(modalRangeKey.value),
  );
});

const rangeCatalogOptions = computed(() => {
  if (!detail.value) return [];
  const auto = new Set(autoRangeKeys(detail.value.shortName, detail.value.jiraCatalog));
  const manual = new Set(detail.value.manualRanges.map(normalizeShort));
  return Object.entries(detail.value.jiraCatalog).map(([key, meta]) => {
    const tags: string[] = [];
    if (auto.has(key)) tags.push("已自动命中");
    if (manual.has(key)) tags.push("已手动");
    if (meta.status === "example") tags.push("规则示例");
    return {
      key,
      label: `${key} · ${meta.name}${tags.length ? `（${tags.join(" · ")}）` : ""}`,
    };
  });
});
</script>

<template>
  <div class="pq-page">
    <div class="pq-pagehead">
      <div class="pq-row pq-between pq-wrap">
        <div>
          <h1>项目查询</h1>
          <p class="pq-muted">
            核对 ERP 项目事实、预算与成本分项、工时来源及 Jira 任务。本地关联写入加密项目库，桌面端刷新后仍保留。
          </p>
        </div>
        <button class="btn" type="button" :disabled="loading" @click="refreshAll">
          {{ loading ? "刷新中…" : "刷新" }}
        </button>
      </div>
      <p :class="dataMode === 'live' ? 'pq-info' : 'pq-notice'" style="margin-top: 10px">
        {{ modeBanner }}
      </p>
      <ul v-if="searchWarnings.length" class="pq-notice" style="margin-top: 8px; list-style: disc; padding-left: 1.4em">
        <li v-for="(w, i) in searchWarnings" :key="i">{{ w }}</li>
      </ul>
      <ul
        v-if="detail?.warnings?.length"
        class="pq-notice"
        style="margin-top: 8px; list-style: disc; padding-left: 1.4em"
      >
        <li v-for="(w, i) in detail.warnings" :key="`d-${i}`">{{ w }}</li>
      </ul>
    </div>

    <div class="pq-workspace">
      <ProjectSearchRail
        :projects="projects"
        :selected-id="selectedId"
        :query="query"
        @update:query="query = $event"
        @select="openProject"
      />

      <section class="pq-detail" aria-label="项目详情">
        <template v-if="detail">
          <div class="pq-card pq-identity">
            <div class="pq-row pq-between pq-wrap">
              <div class="pq-row pq-wrap">
                <span class="pq-mono pq-muted">{{ detail.id }}</span>
                <span class="pq-pill live">{{ detail.stage }}</span>
                <span class="pq-pill ghost">{{ detail.crmId }}</span>
                <span v-if="detail.adopted" class="pq-pill blue">已纳入</span>
                <span class="pq-pill" :class="dataMode === 'live' ? 'blue' : 'ghost'">
                  {{ dataMode === "live" ? "实时 ERP" : "离线夹具" }}
                </span>
              </div>
              <div class="pq-row">
                <span class="pq-pill blue">快照 · {{ detail.snapshotDate }}</span>
                <button class="btn primary" type="button" @click="onAdopt">
                  {{ detail.adopted ? "打开我的项目" : "纳入我的项目" }}
                </button>
              </div>
            </div>
            <h2>{{ detail.title }}</h2>
            <div class="pq-identity-meta">
              <div>
                <small>签约客户</small>
                <strong>{{
                  clients.find((c) => c.id === detail!.fact.contract)?.name ||
                  detail.fact.contract ||
                  "—"
                }}</strong>
              </div>
              <div>
                <small>实际使用方</small>
                <strong>{{
                  clients.find((c) => c.id === detail!.fact.user)?.name ||
                  detail.fact.user ||
                  "—"
                }}</strong>
              </div>
              <div>
                <small>计划交付</small>
                <strong>{{ detail.planDelivery }}</strong>
              </div>
            </div>
          </div>

          <div class="pq-card">
            <div class="pq-kpis">
              <div class="pq-kpi accent">
                <small>项目合同额</small>
                <strong>{{ formatMoney(detail.amounts.contractAmount) }}</strong>
                <small>金额（ERP）</small>
              </div>
              <div class="pq-kpi">
                <small>项目预算</small>
                <strong>{{ formatMoney(detail.amounts.budgetTotal) }}</strong>
                <small>金额（ERP）· 分项齐全</small>
              </div>
              <div class="pq-kpi">
                <small>总成本</small>
                <strong>{{ formatMoney(detail.amounts.costTotal) }}</strong>
                <small>金额（ERP）</small>
              </div>
            </div>
          </div>

          <div class="pq-card pq-panel-card">
            <nav class="pq-tabs" aria-label="项目详情视图">
              <button
                v-for="[key, label] in tabs"
                :key="key"
                type="button"
                :aria-pressed="key === tab"
                @click="tab = key"
              >
                {{ label }}{{ key === "tasks" ? ` · ${taskCount}` : "" }}
              </button>
            </nav>
            <div class="pq-panel-body">
              <OverviewTab
                v-if="tab === 'overview'"
                :detail="detail"
                :clients="clients"
                @bind="openBind"
                @unbind="openUnbind"
              />
              <CostTab
                v-else-if="tab === 'cost'"
                :detail="detail"
                :cost-view="costView"
                @update:cost-view="costView = $event"
              />
              <PeopleTab
                v-else-if="tab === 'people'"
                :detail="detail"
                @person="openPerson"
              />
              <JiraTab
                v-else
                :detail="detail"
                :jira-view="jiraView"
                @update:jira-view="jiraView = $event"
                @apply-short="onApplyShort"
                @choose-range="openChooseRange"
                @remove-range="openRemoveRange"
                @exact-issue="openExactIssue"
                @issue="openIssue"
              />
            </div>
          </div>
        </template>
        <div v-else-if="loading" class="pq-empty">加载中…</div>
        <div v-else class="pq-empty">选择左侧项目查看详情</div>
      </section>
    </div>

    <!-- Bind customer -->
    <ProjectModal
      :open="modalKind === 'bind-customer'"
      :title="`${detail?.local[modalRole].kind !== 'none' ? '修改' : '绑定'}${ROLE_LABELS[modalRole]}`"
      confirm-label="保存绑定"
      @close="closeModal"
      @confirm="confirmBind"
    >
      <dl class="pq-facts">
        <dt>当前项目</dt>
        <dd>{{ detail?.title }}</dd>
        <dt>ERP 事实</dt>
        <dd>{{ factLabel(modalRole) }}</dd>
        <dt>说明</dt>
        <dd>可从本项目已查到的客户中选择，或手工录入本地名称；保存只更新本地关联</dd>
      </dl>
      <label class="pq-field">
        绑定方式
        <select class="pq-search" v-model="bindMode">
          <option value="erp">关联 ERP 客户</option>
          <option value="manual">手工录入</option>
        </select>
      </label>
      <label v-if="bindMode === 'erp'" class="pq-field">
        本地关联客户
        <select class="pq-search" v-model="bindClientId" required>
          <option value="">请选择</option>
          <option v-for="c in clients" :key="c.id" :value="c.id">
            {{ c.name }} · {{ c.id }}
          </option>
        </select>
      </label>
      <label v-else class="pq-field">
        手工名称
        <input
          class="pq-search"
          type="text"
          v-model="bindManualName"
          placeholder="本地查看用名称"
          required
        />
      </label>
      <small class="pq-muted">ERP 列保持只读事实；本地列与 ERP 已关联事实相互独立。</small>
    </ProjectModal>

    <!-- Unbind customer -->
    <ProjectModal
      :open="modalKind === 'unbind-customer'"
      :title="`取消${ROLE_LABELS[modalRole]}本地绑定`"
      confirm-label="确认移除"
      danger
      @close="closeModal"
      @confirm="confirmUnbind"
    >
      <dl class="pq-facts">
        <dt>当前项目</dt>
        <dd>{{ detail?.title }}</dd>
        <dt>本地关联客户</dt>
        <dd>{{ localBindingLabel(modalRole) }}</dd>
      </dl>
      <p class="pq-muted">仅清除该角色的本地关联。ERP 事实与另一角色绑定均保留。</p>
    </ProjectModal>

    <!-- Person hours -->
    <ProjectModal
      :open="modalKind === 'person'"
      :title="`人员来源 · ${modalStaff?.name || ''}`"
      @close="closeModal"
    >
      <dl v-if="modalStaff" class="pq-facts">
        <dt>项目角色</dt>
        <dd>{{ modalStaff.role }}</dd>
        <dt>来源</dt>
        <dd>{{ modalStaff.source }}</dd>
        <dt>成员工时</dt>
        <dd>{{ modalStaff.hours }} h</dd>
        <dt>参与状态</dt>
        <dd>{{ modalStaff.status }}</dd>
        <dt>起始</dt>
        <dd>{{ modalStaff.start }}</dd>
        <dt>数据性质</dt>
        <dd>ERP Members 真实快照</dd>
      </dl>
    </ProjectModal>

    <!-- Issue detail -->
    <ProjectModal
      :open="modalKind === 'issue'"
      :title="
        modalTask
          ? `${modalTask.key} · ${modalTask.title}`
          : '任务详情'
      "
      :confirm-label="modalTask?.origin === 'local' ? '移除本地补充' : undefined"
      :danger="modalTask?.origin === 'local'"
      @close="closeModal"
      @confirm="confirmRemoveLocalIssue"
    >
      <dl v-if="modalTask" class="pq-facts">
        <dt>数据来源</dt>
        <dd>
          {{
            modalTask.origin === "erp"
              ? `ERP 既有关联 · ${catalogMeta(modalTask.jiraProjectKey, detail?.jiraCatalog).name}`
              : "本地补充 · 原型无正文快照"
          }}
        </dd>
        <dt>状态</dt>
        <dd>{{ modalTask.status }}</dd>
        <template v-if="modalTask.origin === 'erp'">
          <dt>工时</dt>
          <dd>{{ modalTask.hours }} h</dd>
          <dt>金额（ERP）</dt>
          <dd>{{ formatMoney(modalTask.amount) }}</dd>
          <dt>归类</dt>
          <dd>{{ modalTask.kind || "—" }}</dd>
          <dt>ERP 关联</dt>
          <dd>已关联 · 不重复绑定</dd>
          <dt>快照日期</dt>
          <dd>{{ modalTask.snapshotDate }}</dd>
        </template>
        <dt>本地补充</dt>
        <dd>{{ modalTask.origin === "local" ? "是" : "否" }}</dd>
      </dl>
    </ProjectModal>

    <!-- Exact key supplement -->
    <ProjectModal
      :open="modalKind === 'exact-issue'"
      title="按 Issue key 精确补充"
      confirm-label="补充到项目"
      @close="closeModal"
      @confirm="confirmExactIssue"
    >
      <dl class="pq-facts">
        <dt>说明</dt>
        <dd>用于 ERP 未挂但属于本项目的任务。已在 ERP 关联中的 key 不会重复绑定。</dd>
        <dt>正式版</dt>
        <dd>必须解析到当前授权来源的稳定 issue ID</dd>
      </dl>
      <label class="pq-field">
        Issue key
        <input
          class="pq-search"
          type="text"
          v-model="exactKeyInput"
          spellcheck="false"
          placeholder="例如 XKRL-999"
          aria-label="Issue key"
          required
        />
      </label>
      <small class="pq-muted">原型不编造任务正文；补充后仅在项目任务列表显示 key，并可移除。</small>
    </ProjectModal>

    <!-- Choose range -->
    <ProjectModal
      :open="modalKind === 'choose-range'"
      title="添加手动 Jira 范围"
      confirm-label="添加手动范围"
      @close="closeModal"
      @confirm="confirmChooseRange"
    >
      <dl class="pq-facts">
        <dt>当前简称</dt>
        <dd>
          {{
            detail
              ? normalizeShort(detail.shortName) || "（空 · 仅手动）"
              : "—"
          }}
        </dd>
        <dt>说明</dt>
        <dd>与自动命中重合时幂等；来源可同时标自动+手动。正式版须解析到已授权项目 ID。</dd>
      </dl>
      <label class="pq-field">
        从目录选择
        <select class="pq-search" v-model="rangeSelect">
          <option value="">请选择（可改用手输）</option>
          <option
            v-for="opt in rangeCatalogOptions"
            :key="opt.key"
            :value="opt.key"
          >
            {{ opt.label }}
          </option>
        </select>
      </label>
      <label class="pq-field">
        或手输项目 key（原型记为待验证，可移除）
        <input
          class="pq-search"
          type="text"
          v-model="rangeCustom"
          spellcheck="false"
          placeholder="例如 DEMO"
          aria-label="手输 Jira 项目 key"
        />
      </label>
      <small class="pq-muted">
        XKRLWXV 无本样本任务，仅演示匹配规则。手输未知 key 不会编造任务。
      </small>
    </ProjectModal>

    <!-- Remove range -->
    <ProjectModal
      :open="modalKind === 'remove-range'"
      title="移除手动 Jira 范围"
      confirm-label="确认移除"
      danger
      @close="closeModal"
      @confirm="confirmRemoveRange"
    >
      <dl class="pq-facts">
        <dt>当前项目</dt>
        <dd>{{ detail?.title }}</dd>
        <dt>手动范围</dt>
        <dd>
          {{ modalRangeKey }} ·
          {{ catalogMeta(modalRangeKey, detail?.jiraCatalog).name }}
        </dd>
        <dt>简称是否仍命中</dt>
        <dd>
          {{
            removeRangeStillAuto
              ? `是（${normalizeShort(detail?.shortName)}）`
              : "否"
          }}
        </dd>
      </dl>
      <p class="pq-muted">
        {{
          removeRangeStillAuto
            ? "将移除手动标记；因简称仍命中，该项目会留在自动范围。本地补充任务不受影响。"
            : "移除后该项目退出有效范围。已有本地补充仍可在项目任务中查看。"
        }}
      </p>
    </ProjectModal>

    <div v-if="toastMsg" class="pq-toast" role="status" aria-live="polite">
      {{ toastMsg }}
    </div>
  </div>
</template>
