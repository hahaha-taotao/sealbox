<script setup lang="ts">
import {
  ROLE_LABELS,
  normalizeShort,
  type CustomerRole,
  type ErpClientDto,
  type LocalCustomerBinding,
  type ProjectDetailDto,
} from "../../../lib/project-api";

const props = defineProps<{
  detail: ProjectDetailDto;
  clients: ErpClientDto[];
}>();

defineEmits<{
  bind: [role: CustomerRole];
  unbind: [role: CustomerRole];
}>();

const roleKeys: CustomerRole[] = ["contract", "user"];

function factName(role: CustomerRole): string {
  const id = props.detail.fact[role];
  if (!id) return "";
  return props.clients.find((c) => c.id === id)?.name ?? id;
}

function localLabel(binding: LocalCustomerBinding): string {
  if (binding.kind === "erp") return binding.name || binding.clientId || "—";
  if (binding.kind === "manual") return `${binding.name || "—"}`;
  return "";
}

function localSub(binding: LocalCustomerBinding): string {
  if (binding.kind === "erp") return binding.clientId || "";
  if (binding.kind === "manual") return "手工录入";
  return "";
}
</script>

<template>
  <div>
    <p class="pq-info">
      ERP 已关联事实来自 Project 字段；本地关联初始为空，下方操作为原型模拟编辑，不代表已有真实本地绑定证据。
    </p>

    <div class="pq-section-head">
      <h3>客户关系</h3>
      <p>签约 / 实际使用方两列独立：左侧只读事实，右侧本地模拟。</p>
    </div>

    <div class="pq-table-wrap" tabindex="0" role="region" aria-label="客户关系数据表">
      <table>
        <thead>
          <tr>
            <th scope="col">角色</th>
            <th scope="col">ERP 项目事实 · 只读</th>
            <th scope="col">本地项目关联</th>
            <th scope="col">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="role in roleKeys" :key="role">
            <td>{{ ROLE_LABELS[role] }}</td>
            <td>
              <template v-if="detail.fact[role]">
                {{ factName(role) }}
                <small class="pq-mono">{{ detail.fact[role] }}</small>
              </template>
              <span v-else class="pq-muted">ERP 未提供</span>
            </td>
            <td>
              <template v-if="detail.local[role].kind !== 'none'">
                {{ localLabel(detail.local[role]) }}
                <small class="pq-mono">{{ localSub(detail.local[role]) }}</small>
              </template>
              <span v-else class="pq-pill ghost">未绑定 · 初始态</span>
            </td>
            <td>
              <div class="pq-actions">
                <button class="pq-link" type="button" @click="$emit('bind', role)">
                  {{ detail.local[role].kind !== "none" ? "修改绑定" : "绑定客户" }}
                </button>
                <button
                  v-if="detail.local[role].kind !== 'none'"
                  class="pq-link remove"
                  type="button"
                  @click="$emit('unbind', role)"
                >
                  取消绑定
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="pq-task-block" style="margin-top: 17px">
      <div class="pq-section-head">
        <h3>项目记录</h3>
        <p>来源 ERP Project · 实际结束未填</p>
      </div>
      <dl class="pq-facts">
        <dt>ERP 编号</dt>
        <dd class="pq-mono">{{ detail.id }} / {{ detail.crmId }}</dd>
        <dt>状态</dt>
        <dd>{{ detail.stage }}</dd>
        <dt>开始日期</dt>
        <dd>{{ detail.start }}</dd>
        <dt>计划上线</dt>
        <dd>{{ detail.planOnline }}</dd>
        <dt>计划交付</dt>
        <dd>{{ detail.planDelivery }}</dd>
        <dt>实际结束</dt>
        <dd>
          <span v-if="detail.actualEnd">{{ detail.actualEnd }}</span>
          <span v-else class="pq-muted">ERP 未填</span>
        </dd>
        <dt>项目经理</dt>
        <dd>{{ detail.owner }}</dd>
        <dt>Jira 简称</dt>
        <dd class="pq-mono">
          {{ normalizeShort(detail.shortName) || "（空 · 仅手动范围）" }}
        </dd>
      </dl>
    </div>

    <div class="pq-task-block">
      <div class="pq-section-head">
        <h3>不计入成本的口径</h3>
        <p>合同 / 回款属收入口径，不与预算成本混算。</p>
      </div>
      <p class="pq-notice">
        已排除：合同额 / 回款 {{ detail.amounts.operating.contractAmount }}、回款毛利润
        {{ detail.amounts.operating.paymentProfit }}。预算毛利润原值
        {{ detail.amounts.budgetProfit }} 与预算差额不是同一字段，本页不展示。
      </p>
    </div>
  </div>
</template>
