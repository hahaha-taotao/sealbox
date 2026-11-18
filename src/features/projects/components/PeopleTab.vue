<script setup lang="ts">
import type { ProjectDetailDto, ProjectStaffDto } from "../../../lib/project-api";

defineProps<{
  detail: ProjectDetailDto;
}>();

const emit = defineEmits<{
  person: [staff: ProjectStaffDto, index: number];
}>();
</script>

<template>
  <div>
    <div class="pq-section-head">
      <h3>人员与来源</h3>
      <p>ERP Members · 参与状态与起始日期沿用来源记录。</p>
    </div>
    <div class="pq-table-wrap" tabindex="0" role="region" aria-label="人员数据表">
      <table>
        <thead>
          <tr>
            <th scope="col">姓名</th>
            <th scope="col">项目角色</th>
            <th scope="col">来源</th>
            <th scope="col" class="pq-num">成员工时</th>
            <th scope="col">参与状态</th>
            <th scope="col">起始</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(row, index) in detail.staff" :key="`${row.name}-${index}`">
            <td>{{ row.name }}</td>
            <td>{{ row.role }}</td>
            <td>{{ row.source }}</td>
            <td class="pq-num">
              <button
                class="pq-link pq-mono"
                type="button"
                @click="emit('person', row, index)"
              >
                {{ row.hours }} h
              </button>
            </td>
            <td><span class="pq-pill live">{{ row.status }}</span></td>
            <td>{{ row.start }}</td>
          </tr>
          <tr v-if="!detail.staff.length">
            <td colspan="6" class="pq-empty">暂无成员</td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="pq-footnote">
      成员工时为 ERP 成员记录字段，与 Project 总工时 / Hour 明细为不同口径。
    </p>
  </div>
</template>
