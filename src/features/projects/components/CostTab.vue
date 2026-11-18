<script setup lang="ts">
import { computed } from "vue";
import {
  COST_VIEW_LABELS,
  formatMoney,
  issueKeyProject,
  type CostView,
  type ProjectDetailDto,
} from "../../../lib/project-api";

const props = defineProps<{
  detail: ProjectDetailDto;
  costView: CostView;
}>();

const emit = defineEmits<{
  "update:costView": [view: CostView];
}>();

const views = Object.entries(COST_VIEW_LABELS) as [CostView, string][];

interface CompareRow {
  label: string;
  budget: number | null;
  cost: number | null;
  delta: number | null;
  budgetSrc: string;
  costSrc: string;
}

const compareRows = computed<CompareRow[]>(() => {
  const budgetMap = Object.fromEntries(
    props.detail.amounts.budgetItems.map((i) => [i.key, i]),
  );
  const costMap = Object.fromEntries(
    props.detail.amounts.costItems.map((i) => [i.key, i]),
  );
  const pairs: [string, string][] = [
    ["实施", "实施"],
    ["研发", "开发"],
    ["差旅", "差旅"],
    ["管理", "管理"],
    ["外采", "硬件外采"],
    ["税费", "税费"],
  ];
  return pairs.map(([bKey, cKey]) => {
    const b = budgetMap[bKey];
    const c = costMap[cKey];
    const delta =
      b?.amount != null && c?.amount != null ? b.amount - c.amount : null;
    return {
      label: `${bKey} → ${cKey}`,
      budget: b?.amount ?? null,
      cost: c?.amount ?? null,
      delta,
      budgetSrc: b?.source || "",
      costSrc: c?.source || "",
    };
  });
});

interface JiraCostGroup {
  key: string;
  name: string;
  hours: number;
  amount: number;
}

const jiraGroups = computed(() => {
  const groups = new Map<string, JiraCostGroup>();
  let totalHours = 0;
  let totalAmount = 0;
  for (const task of props.detail.devTasks) {
    const key = issueKeyProject(task.key);
    const group = groups.get(key) || { key, name: task.project, hours: 0, amount: 0 };
    // Fixed-point cents to avoid float drift (matches prototype).
    const hours = Math.round(task.hours * 100);
    const amount = Math.round(task.amount * 100);
    group.hours += hours;
    group.amount += amount;
    totalHours += hours;
    totalAmount += amount;
    groups.set(key, group);
  }
  return {
    rows: [...groups.values()].map((g) => ({
      ...g,
      hours: g.hours / 100,
      amount: g.amount / 100,
    })),
    totalHours: totalHours / 100,
    totalAmount: totalAmount / 100,
  };
});
</script>

<template>
  <div class="pq-cost-shell">
    <nav class="pq-cost-nav" aria-label="成本子视图">
      <button
        v-for="[key, label] in views"
        :key="key"
        type="button"
        :aria-pressed="key === costView"
        @click="emit('update:costView', key)"
      >
        {{ label }}
      </button>
    </nav>

    <div class="pq-cost-pane">
      <!-- 预算与成本 -->
      <template v-if="costView === 'budget'">
        <div class="pq-section-head">
          <h3>预算与成本分项对照</h3>
          <p>金额源未单独返回币种，统一按「金额（ERP）」展示，不假设货币单位。</p>
        </div>

        <div class="pq-metrics-row">
          <div class="pq-metric-card">
            <small>预算减总成本（界面计算）</small>
            <strong>{{ formatMoney(detail.amounts.budgetDiff) }}</strong>
            <small
              >{{ formatMoney(detail.amounts.budgetTotal) }} −
              {{ formatMoney(detail.amounts.costTotal) }}</small
            >
          </div>
          <div class="pq-metric-card">
            <small>项目预算毛利润（cf_9758 原值）</small>
            <strong>{{ formatMoney(detail.amounts.budgetProfit) }}</strong>
            <small>与预算差额不是同一字段，禁止互相替代</small>
          </div>
        </div>

        <div class="pq-table-wrap" tabindex="0" role="region" aria-label="预算成本对照表">
          <table>
            <thead>
              <tr>
                <th scope="col">分项（预算 → 成本）</th>
                <th scope="col" class="pq-num">预算</th>
                <th scope="col" class="pq-num">成本</th>
                <th scope="col" class="pq-num">差额</th>
                <th scope="col">字段来源</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in compareRows" :key="row.label">
                <td>{{ row.label }}</td>
                <td class="pq-num">
                  {{ row.budget === null ? "—" : formatMoney(row.budget) }}
                </td>
                <td class="pq-num">{{ formatMoney(row.cost) }}</td>
                <td class="pq-num">
                  <span v-if="row.delta === null" class="pq-muted">—</span>
                  <span
                    v-else
                    :class="row.delta >= 0 ? 'pq-delta-pos' : 'pq-delta-neg'"
                  >
                    {{ row.delta >= 0 ? "+" : "" }}{{ formatMoney(row.delta) }}
                  </span>
                </td>
                <td>
                  <small>{{ row.budgetSrc }}</small>
                  <small>{{ row.costSrc }}</small>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="pq-footnote">
          合计：预算 {{ formatMoney(detail.amounts.budgetTotal) }} · 成本
          {{ formatMoney(detail.amounts.costTotal) }} · 差额
          {{ formatMoney(detail.amounts.budgetDiff) }}（界面计算）。税费预算字段暂无值显示为
          —，不按 0 处理。
        </p>

        <div class="pq-task-block" style="margin-top: 16px">
          <div class="pq-section-head">
            <h3>经营指标（收入口径，独立展示）</h3>
            <p>合同额 / 回款 / 回款毛利润不与预算成本混算。</p>
          </div>
          <dl class="pq-facts">
            <dt>合同额 cf_1486</dt>
            <dd>{{ formatMoney(detail.amounts.operating.contractAmount) }}</dd>
            <dt>总回款 cf_2932</dt>
            <dd>{{ formatMoney(detail.amounts.operating.totalPayment) }}</dd>
            <dt>回款毛利润 cf_1488</dt>
            <dd>{{ formatMoney(detail.amounts.operating.paymentProfit) }}</dd>
          </dl>
        </div>
      </template>

      <!-- Jira 项目成本 -->
      <template v-else-if="costView === 'dev'">
        <div class="pq-section-head">
          <h3>Jira 项目成本</h3>
          <p>按 Jira 项目汇总当前 ERP 项目已关联任务的研发工时和开发成本。</p>
        </div>
        <div class="pq-table-wrap" tabindex="0" role="region" aria-label="Jira 项目成本表">
          <table>
            <thead>
              <tr>
                <th scope="col">Jira 项目</th>
                <th scope="col" class="pq-num">研发工时（小时）</th>
                <th scope="col" class="pq-num">开发成本（ERP）</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in jiraGroups.rows" :key="row.key">
                <td>
                  {{ row.name }}
                  <small class="pq-mono">{{ row.key }}</small>
                </td>
                <td class="pq-num">{{ formatMoney(row.hours) }}</td>
                <td class="pq-num">{{ formatMoney(row.amount) }}</td>
              </tr>
              <tr v-if="jiraGroups.rows.length">
                <td><strong>合计</strong></td>
                <td class="pq-num">{{ formatMoney(jiraGroups.totalHours) }}</td>
                <td class="pq-num">{{ formatMoney(jiraGroups.totalAmount) }}</td>
              </tr>
              <tr v-if="!jiraGroups.rows.length">
                <td colspan="3" class="pq-empty">暂无项目成本</td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>

      <!-- 工时与出差 -->
      <template v-else>
        <div class="pq-section-head">
          <h3>工时与出差 · 两来源并列</h3>
          <p>Project 汇总与 Hour 明细并存；出差量 5 天 vs 明细 3 人天，差异路径待核。</p>
        </div>
        <div class="pq-split">
          <div class="pq-source-card">
            <h3>ERP Project 汇总</h3>
            <div class="pq-metric">{{ formatMoney(detail.hours.summary.total) }} h</div>
            <p class="pq-muted">
              实施 {{ formatMoney(detail.hours.summary.impl) }} + 开发
              {{ formatMoney(detail.hours.summary.dev) }} · 出差量
              {{ detail.hours.summary.travelDays }} 天
            </p>
          </div>
          <div class="pq-source-card">
            <h3>ERP Hour 明细合计</h3>
            <div class="pq-metric">{{ formatMoney(detail.hours.detailSum.hours) }} h</div>
            <p class="pq-muted">
              {{ detail.hours.rows.length }} 笔 · 实施工时
              {{ formatMoney(detail.hours.detailSum.hours) }} · 出差
              {{ detail.hours.detailSum.days }} 人天
            </p>
          </div>
        </div>
        <p class="pq-notice" style="margin-top: 12px">
          待核：Project 出差量 5 天 ≠ Hour 明细出差合计 3 人天；Project 总工时含开发
          6.60，Hour 明细仅覆盖实施 55。
        </p>
        <div class="pq-task-block" style="margin-top: 12px">
          <div
            class="pq-hour-scroll"
            tabindex="0"
            role="region"
            aria-label="工时明细表"
          >
            <table>
              <thead>
                <tr>
                  <th scope="col">日期</th>
                  <th scope="col">工时单号</th>
                  <th scope="col" class="pq-num">工时</th>
                  <th scope="col" class="pq-num">出差人天</th>
                  <th scope="col">成员</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in detail.hours.rows" :key="row.id">
                  <td>{{ row.date }}</td>
                  <td><span class="pq-mono">{{ row.id }}</span></td>
                  <td class="pq-num">{{ formatMoney(row.hours) }}</td>
                  <td class="pq-num">{{ formatMoney(row.days) }}</td>
                  <td>{{ row.member }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p class="pq-footnote">
            {{ detail.hours.rows.length }} 笔明细在局部列表内滚动；成本子导航保持可达，不锁整页高度。
          </p>
        </div>
      </template>
    </div>
  </div>
</template>
