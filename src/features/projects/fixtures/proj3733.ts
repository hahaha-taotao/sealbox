/**
 * Offline snapshot extracted from docs/superpowers/specs/project-query-prototype.html
 * Sealbox 2026-11-18 · PROJ3733 / 30x564318
 */

export type CatalogStatus = "verified" | "example" | "pending";

export interface FixtureClient {
  id: string;
  name: string;
}

export interface FixtureStaff {
  name: string;
  role: string;
  source: string;
  hours: string;
  status: string;
  start: string;
}

export interface FixtureProject {
  id: string;
  crmId: string;
  title: string;
  stage: string;
  owner: string;
  start: string;
  planOnline: string;
  planDelivery: string;
  actualEnd: string | null;
  fact: { contract: string | null; user: string | null };
  /** Local bind: ERP client id, or `manual:<name>` for hand-entered names. */
  local: { contract: string | null; user: string | null };
  shortName: string;
  manualRanges: string[];
  /** Local supplement issue keys (ERP keys live in crmIssues). */
  issues: string[];
  staff: FixtureStaff[];
}

export interface MoneyItem {
  key: string;
  amount: number | null;
  source: string;
}

export interface DevTask {
  key: string;
  title: string;
  project: string;
  hours: number;
  amount: number;
  kind: string;
}

export interface HourRow {
  date: string;
  id: string;
  hours: number;
  days: number;
  member: string;
}

export interface JiraCatalogEntry {
  name: string;
  status: CatalogStatus;
}

/** CRM issue tuple: key, title, status, unused, date, hours, amount */
export type CrmIssueRow = [string, string, string, string, string, number, number];

export interface JiraIssueFields {
  assignee?: string;
  priority?: string;
  batch?: string;
  dueDate?: string;
}

export const FIXTURE_SNAPSHOT_DATE = "2026-11-18";

export const clients: Record<string, string> = {
  "11x148029": "江苏徐矿热力有限公司",
  "11x564023": "江苏徐矿城南热力有限公司",
};

export const clientList: FixtureClient[] = Object.entries(clients).map(([id, name]) => ({ id, name }));

export const roles = { contract: "签约客户", user: "实际使用方" } as const;

export function createInitialProjects(): FixtureProject[] {
  return [
    {
      id: "PROJ3733",
      crmId: "30x564318",
      title: "2026-徐矿-新增子公司-城南分公司",
      stage: "启动",
      owner: "张文宇",
      start: "2026-08-24",
      planOnline: "2026-09-15",
      planDelivery: "2026-10-31",
      actualEnd: null,
      fact: { contract: "11x148029", user: "11x564023" },
      local: { contract: null, user: null },
      shortName: "XKRL",
      manualRanges: [],
      issues: [],
      staff: [
        {
          name: "张文宇",
          role: "项目经理",
          source: "ERP Members",
          hours: "55.00",
          status: "参与中",
          start: "2026-08-19",
        },
        {
          name: "曹惠峰",
          role: "研发工程师",
          source: "ERP Members",
          hours: "0.00",
          status: "参与中",
          start: "2026-08-19",
        },
      ],
    },
  ];
}

export const budgetItems: MoneyItem[] = [
  { key: "实施", amount: 7500, source: "ERP Project · 实施预算" },
  { key: "研发", amount: 6000, source: "ERP Project · 研发预算" },
  { key: "差旅", amount: 2000, source: "ERP Project · 差旅预算" },
  { key: "管理", amount: 9600, source: "ERP Project · 管理预算" },
  { key: "外采", amount: 0, source: "ERP Project · 外采预算" },
  { key: "税费", amount: null, source: "ERP Project · 税费预算字段暂无值" },
];

export const costItems: MoneyItem[] = [
  { key: "实施", amount: 8594, source: "ERP Project · 实施成本" },
  { key: "开发", amount: 1353.13, source: "ERP Project · 开发成本" },
  { key: "差旅", amount: 1972, source: "ERP Project · 差旅成本" },
  { key: "管理", amount: 9593.6, source: "ERP Project · 管理成本" },
  { key: "硬件外采", amount: 40, source: "ERP Project · 硬件外采成本" },
  { key: "税费", amount: 0, source: "ERP Project · 税费成本" },
];

/** ERP Project · 项目合同额 cf_9778 */
export const projectContractAmount = 60000;
export const budgetTotal = 25100;
export const costTotal = 21552.73;
/** 界面定点计算：预算 − 总成本 */
export const budgetDiff = 3547.27;
/** ERP Project · 项目预算毛利润 cf_9758 */
export const budgetProfit = 3580.87;
/** 经营指标 */
export const operatingMetrics = {
  contractAmount: 60000, // cf_1486
  totalPayment: 60000, // cf_2932
  paymentProfit: 38447.27, // cf_1488
};

export const devTasks: DevTask[] = [
  {
    key: "XKRLWXM-56",
    title: "新增城南子公司走银联支付接口",
    project: "【微信管理】徐矿热力",
    hours: 5,
    amount: 1093.75,
    kind: "合同内定制",
  },
  {
    key: "XKRL-269",
    title: "城南公司收据底图替换",
    project: "徐矿热力",
    hours: 0.5,
    amount: 78.13,
    kind: "合同内定制",
  },
  {
    key: "XKRL-270",
    title: "新增城南子公司合同章",
    project: "徐矿热力",
    hours: 1,
    amount: 156.25,
    kind: "合同内定制",
  },
  {
    key: "XKRL-271",
    title: "技术日志文件未授权访问漏洞修复",
    project: "徐矿热力",
    hours: 0.1,
    amount: 25,
    kind: "产品缺陷",
  },
];

export const hourSummary = { total: 61.6, impl: 55, dev: 6.6, travelDays: 5 };
export const hourDetailSum = { hours: 55, days: 3 };

export const hourRows: HourRow[] = [
  { date: "2026-08-28", id: "HO15473", hours: 5, days: 0, member: "张文宇" },
  { date: "2026-09-04", id: "HO15562", hours: 10, days: 0, member: "张文宇" },
  { date: "2026-09-11", id: "HO15619", hours: 8, days: 0, member: "张文宇" },
  { date: "2026-09-18", id: "HO15680", hours: 8, days: 0, member: "张文宇" },
  { date: "2026-09-26", id: "HO15829", hours: 4, days: 0, member: "张文宇" },
  { date: "2026-10-04", id: "HO15920", hours: 3, days: 0, member: "张文宇" },
  { date: "2026-10-10", id: "HO16277", hours: 0, days: 0, member: "张文宇" },
  { date: "2026-10-18", id: "HO16381", hours: 0, days: 0, member: "张文宇" },
  { date: "2026-10-25", id: "HO16454", hours: 0, days: 0, member: "张文宇" },
  { date: "2026-11-01", id: "HO16523", hours: 0, days: 0, member: "张文宇" },
  { date: "2026-11-08", id: "HO16584", hours: 16, days: 3, member: "张文宇" },
  { date: "2026-11-15", id: "HO16633", hours: 1, days: 0, member: "张文宇" },
];

export const jiraCatalog: Record<string, JiraCatalogEntry> = {
  XKRLWXM: { name: "【微信管理】徐矿热力", status: "verified" },
  XKRL: { name: "徐矿热力", status: "verified" },
  XKRLWXV: { name: "徐矿热力·规则示例（待验证，无任务）", status: "example" },
};

export const crmIssues: CrmIssueRow[] = [
  ["XKRLWXM-56", "新增城南子公司走银联支付接口", "已关闭", "—", "2026-11-18", 5, 1093.75],
  ["XKRL-269", "城南公司收据底图替换", "已关闭", "—", "2026-11-18", 0.5, 78.13],
  ["XKRL-270", "新增城南子公司合同章", "已关闭", "—", "2026-11-18", 1, 156.25],
  ["XKRL-271", "技术日志文件未授权访问漏洞修复", "已关闭", "—", "2026-11-18", 0.1, 25],
];

export const jiraIssueFields: Record<string, JiraIssueFields> = {
  "XKRLWXM-56": { assignee: "王 子沐" },
  "XKRL-269": { assignee: "曹 惠峰" },
  "XKRL-270": { assignee: "曹 惠峰" },
  "XKRL-271": { assignee: "杨 依逵" },
};

/** Offline preset from Sealbox Jira adapter. */
export const jiraStatusDefaults = [
  "开放",
  "已优选",
  "待开发设计",
  "需求设计完成",
  "需求设计未通过",
  "待开发",
  "处理中",
  "重新打开",
  "开发完成",
  "未通过开发评审",
  "待测试",
  "测试未通过",
  "提测退回",
  "待验证",
  "验证未通过",
  "待合并",
  "待交付客户",
  "已关闭",
  "Done",
  "Closed",
];

export const taskColumns = ["Issue / 标题", "Jira 项目", "状态", "优先级", "批次", "到期日", "经办人"] as const;
