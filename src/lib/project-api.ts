/**
 * Project workbench typed DTOs + invoke wrappers.
 *
 * When running inside Tauri, calls `project_*` commands (encrypted local store +
 * fixture remote adapter). Pure browser / `npm run mobile:dev` keeps the
 * in-memory fixture store so the UI stays usable without a vault runtime.
 */

import { invoke } from "@tauri-apps/api/core";
import {
  budgetDiff,
  budgetItems,
  budgetProfit,
  budgetTotal,
  clients,
  clientList,
  costItems,
  costTotal,
  createInitialProjects,
  crmIssues,
  devTasks,
  FIXTURE_SNAPSHOT_DATE,
  hourDetailSum,
  hourRows,
  hourSummary,
  jiraCatalog,
  jiraIssueFields,
  jiraStatusDefaults,
  operatingMetrics,
  projectContractAmount,
  roles,
  type CatalogStatus,
  type CrmIssueRow,
  type DevTask,
  type FixtureProject,
  type HourRow,
  type JiraIssueFields,
  type MoneyItem,
} from "../features/projects/fixtures/proj3733";

/** True when the Tauri IPC bridge is present (desktop app), false in plain browser. */
function canInvoke(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

// ─── DTOs ────────────────────────────────────────────────────────────────────

export type CustomerRole = "contract" | "user";
export type ProjectTab = "overview" | "cost" | "people" | "tasks";
export type CostView = "budget" | "dev" | "hours";
export type JiraView = "project" | "scope";
export type RangeSource = "auto" | "manual";

export interface ErpClientDto {
  id: string;
  name: string;
}

export interface LocalCustomerBinding {
  /** ERP client id, or null when unbound. Manual names use kind=manual. */
  kind: "erp" | "manual" | "none";
  clientId?: string;
  name?: string;
}

export interface ProjectSummaryDto {
  id: string;
  crmId: string;
  title: string;
  stage: string;
  owner: string;
  contractCustomerId: string | null;
  contractCustomerName: string | null;
  userCustomerId: string | null;
  userCustomerName: string | null;
  shortName: string;
  adopted: boolean;
  localProjectId: string | null;
}

export interface ProjectStaffDto {
  name: string;
  role: string;
  source: string;
  hours: string;
  status: string;
  start: string;
}

export interface ProjectAmountsDto {
  contractAmount: number;
  budgetTotal: number;
  costTotal: number;
  budgetDiff: number;
  budgetProfit: number;
  operating: {
    contractAmount: number;
    totalPayment: number;
    paymentProfit: number;
  };
  budgetItems: MoneyItem[];
  costItems: MoneyItem[];
}

export interface ProjectHoursDto {
  summary: { total: number; impl: number; dev: number; travelDays: number };
  detailSum: { hours: number; days: number };
  rows: HourRow[];
}

export interface JiraRangeEntryDto {
  key: string;
  name: string;
  status: CatalogStatus;
  sources: RangeSource[];
}

export interface JiraTaskDto {
  key: string;
  title: string;
  jiraProjectKey: string;
  status: string;
  priority: string;
  batch: string;
  dueDate: string;
  assignee: string;
  origin: "erp" | "local";
  hours?: number;
  amount?: number;
  kind?: string;
  snapshotDate?: string;
}

export interface SourceBindingSummaryDto {
  id: string;
  platform: string;
  site: string;
  accountScope: string;
  status: string;
  credentialEntryId: string;
  isFixture: boolean;
}

export interface ProjectDetailDto {
  id: string;
  crmId: string;
  title: string;
  stage: string;
  owner: string;
  start: string;
  planOnline: string;
  planDelivery: string;
  actualEnd: string | null;
  shortName: string;
  fact: { contract: string | null; user: string | null };
  local: { contract: LocalCustomerBinding; user: LocalCustomerBinding };
  manualRanges: string[];
  localIssues: string[];
  staff: ProjectStaffDto[];
  amounts: ProjectAmountsDto;
  hours: ProjectHoursDto;
  jiraCatalog: Record<string, { name: string; status: CatalogStatus }>;
  jiraStatusDefaults: string[];
  erpIssues: JiraTaskDto[];
  devTasks: DevTask[];
  snapshotDate: string;
  adopted: boolean;
  localProjectId: string | null;
  revision: number;
  /** "live" | "fixture" */
  dataSource: string;
  warnings: string[];
}

export interface AdoptResultDto {
  localProjectId: string;
  remoteId: string;
  created: boolean;
}

export interface AdoptInput {
  remoteId: string;
  remoteKey?: string;
  remoteName?: string;
  owner?: string;
  shortName?: string;
  stage?: string;
}

export interface LocalProjectDto {
  localProjectId: string;
  remoteId: string;
  title: string;
  shortName: string;
  revision: number;
}

// ─── Fixture store (in-memory; reset on module reload) ───────────────────────

interface AdoptedProject {
  localProjectId: string;
  remoteId: string;
  shortName: string;
  revision: number;
}

function cloneProjects(): FixtureProject[] {
  return structuredClone(createInitialProjects());
}

const fixtureStore = {
  projects: cloneProjects(),
  adopted: new Map<string, AdoptedProject>(),
};

function resetFixtureStore() {
  fixtureStore.projects = cloneProjects();
  fixtureStore.adopted.clear();
}

/** Test / lock helper — clears mutable fixture state. */
export function resetProjectFixtures() {
  resetFixtureStore();
}

function parseLocal(raw: string | null): LocalCustomerBinding {
  if (!raw) return { kind: "none" };
  if (raw.startsWith("manual:")) {
    return { kind: "manual", name: raw.slice("manual:".length) };
  }
  return { kind: "erp", clientId: raw, name: clients[raw] ?? raw };
}

function encodeLocal(binding: LocalCustomerBinding): string | null {
  if (binding.kind === "none") return null;
  if (binding.kind === "manual") return `manual:${binding.name ?? ""}`;
  return binding.clientId ?? null;
}

function clientName(id: string | null | undefined): string | null {
  if (!id) return null;
  return clients[id] ?? id;
}

function toSummary(project: FixtureProject): ProjectSummaryDto {
  const adopted = fixtureStore.adopted.get(project.crmId) ?? null;
  return {
    id: project.id,
    crmId: project.crmId,
    title: project.title,
    stage: project.stage,
    owner: project.owner,
    contractCustomerId: project.fact.contract,
    contractCustomerName: clientName(project.fact.contract),
    userCustomerId: project.fact.user,
    userCustomerName: clientName(project.fact.user),
    shortName: project.shortName,
    adopted: Boolean(adopted),
    localProjectId: adopted?.localProjectId ?? null,
  };
}

function issueProjectKey(issue: string): string {
  return issue.includes("-") ? issue.slice(0, issue.lastIndexOf("-")) : issue;
}

function erpTaskFromRow(row: CrmIssueRow): JiraTaskDto {
  const [key, title, status, , date, hours, amount] = row;
  const fields: JiraIssueFields = jiraIssueFields[key] ?? {};
  const meta = devTasks.find((t) => t.key === key);
  return {
    key,
    title,
    jiraProjectKey: issueProjectKey(key),
    status,
    priority: fields.priority ?? "—",
    batch: fields.batch ?? "—",
    dueDate: fields.dueDate ?? "—",
    assignee: fields.assignee ?? "—",
    origin: "erp",
    hours,
    amount,
    kind: meta?.kind,
    snapshotDate: date,
  };
}

function toDetail(project: FixtureProject): ProjectDetailDto {
  const adopted = fixtureStore.adopted.get(project.crmId) ?? null;
  return {
    id: project.id,
    crmId: project.crmId,
    title: project.title,
    stage: project.stage,
    owner: project.owner,
    start: project.start,
    planOnline: project.planOnline,
    planDelivery: project.planDelivery,
    actualEnd: project.actualEnd,
    shortName: project.shortName,
    fact: { ...project.fact },
    local: {
      contract: parseLocal(project.local.contract),
      user: parseLocal(project.local.user),
    },
    manualRanges: [...project.manualRanges],
    localIssues: [...project.issues],
    staff: project.staff.map((s) => ({ ...s })),
    amounts: {
      contractAmount: projectContractAmount,
      budgetTotal,
      costTotal,
      budgetDiff,
      budgetProfit,
      operating: { ...operatingMetrics },
      budgetItems: budgetItems.map((i) => ({ ...i })),
      costItems: costItems.map((i) => ({ ...i })),
    },
    hours: {
      summary: { ...hourSummary },
      detailSum: { ...hourDetailSum },
      rows: hourRows.map((r) => ({ ...r })),
    },
    jiraCatalog: { ...jiraCatalog },
    jiraStatusDefaults: [...jiraStatusDefaults],
    erpIssues: crmIssues.map(erpTaskFromRow),
    devTasks: devTasks.map((t) => ({ ...t })),
    snapshotDate: FIXTURE_SNAPSHOT_DATE,
    adopted: Boolean(adopted),
    localProjectId: adopted?.localProjectId ?? null,
    revision: adopted?.revision ?? 0,
    dataSource: "fixture",
    warnings: [],
  };
}

function findProject(remoteOrNumber: string): FixtureProject | undefined {
  return fixtureStore.projects.find(
    (p) => p.id === remoteOrNumber || p.crmId === remoteOrNumber,
  );
}

function matchValue(value: unknown, query: string): boolean {
  return String(value ?? "")
    .toLowerCase()
    .includes(query.trim().toLowerCase());
}

// ─── Pure helpers (shared with UI) ───────────────────────────────────────────

export function normalizeShort(value: unknown): string {
  return String(value ?? "").trim().toUpperCase();
}

export function autoRangeKeys(
  shortName: string,
  catalog: Record<string, { name: string; status: CatalogStatus }> = jiraCatalog,
): string[] {
  const needle = normalizeShort(shortName);
  if (!needle) return [];
  return Object.keys(catalog).filter((key) => key.toUpperCase().includes(needle));
}

export function catalogMeta(
  key: string,
  catalog: Record<string, { name: string; status: CatalogStatus }> = jiraCatalog,
): { name: string; status: CatalogStatus } {
  return catalog[key] ?? { name: "待验证项目（原型可移除）", status: "pending" };
}

export function rangeEntries(
  shortName: string,
  manualRanges: string[],
  catalog: Record<string, { name: string; status: CatalogStatus }> = jiraCatalog,
): JiraRangeEntryDto[] {
  const auto = new Set(autoRangeKeys(shortName, catalog));
  const manual = new Set(manualRanges.map(normalizeShort).filter(Boolean));
  return [...new Set([...auto, ...manual])].sort().map((key) => {
    const meta = catalogMeta(key, catalog);
    const sources: RangeSource[] = [];
    if (auto.has(key)) sources.push("auto");
    if (manual.has(key)) sources.push("manual");
    return { key, name: meta.name, status: meta.status, sources };
  });
}

export function effectiveRangeKeys(
  shortName: string,
  manualRanges: string[],
  catalog?: Record<string, { name: string; status: CatalogStatus }>,
): string[] {
  return rangeEntries(shortName, manualRanges, catalog).map((e) => e.key);
}

export function issueKeyProject(issue: string): string {
  return issueProjectKey(issue);
}

export function formatMoney(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  return new Intl.NumberFormat("zh-CN", {
    minimumFractionDigits: 0,
    maximumFractionDigits: 2,
  }).format(n);
}

export const ROLE_LABELS = roles;

export const TAB_LABELS: Record<ProjectTab, string> = {
  overview: "概览",
  cost: "成本",
  people: "人员",
  tasks: "Jira",
};

export const COST_VIEW_LABELS: Record<CostView, string> = {
  budget: "预算与成本",
  dev: "Jira 项目成本",
  hours: "工时与出差",
};

export const JIRA_VIEW_LABELS: Record<JiraView, string> = {
  project: "项目任务",
  scope: "范围配置",
};

// ─── API (Tauri invoke with fixture fallback) ────────────────────────────────

export interface RemoteSearchPage {
  items: ProjectSummaryDto[];
  nextCursor: string | null;
  complete: boolean;
  fetchedAt: string;
  sourceBindingId: string;
  warnings: string[];
}

async function stubDelay<T>(value: T): Promise<T> {
  return value;
}

/** List CRM/Jira source bindings (marks fixture vs live). */
export async function listProjectSources(): Promise<SourceBindingSummaryDto[]> {
  if (canInvoke()) {
    return invoke<SourceBindingSummaryDto[]>("project_sources_list");
  }
  return stubDelay([
    {
      id: "fixture-crm",
      platform: "zoomkey_crm",
      site: "https://fixture.sealbox.local/zoomkey-crm",
      accountScope: "fixture-readonly",
      status: "active",
      credentialEntryId: "fixture:proj3733",
      isFixture: true,
    },
    {
      id: "fixture-jira",
      platform: "zoomkey_jira",
      site: "https://fixture.sealbox.local/zoomkey-jira",
      accountScope: "fixture-readonly",
      status: "active",
      credentialEntryId: "fixture:proj3733",
      isFixture: true,
    },
  ]);
}

/** Search ERP projects (includes warnings from live/fixture adapters). */
export async function searchProjects(query = ""): Promise<RemoteSearchPage> {
  if (canInvoke()) {
    return invoke<RemoteSearchPage>("project_search_remote", {
      request: { keyword: query },
    });
  }
  const q = query.trim();
  const results = fixtureStore.projects.filter((project) => {
    if (!q) return true;
    const haystack = [
      project.id,
      project.crmId,
      project.title,
      project.shortName,
      project.owner,
      project.fact.contract,
      project.fact.user,
      project.local.contract,
      project.local.user,
      clientName(project.fact.contract),
      clientName(project.fact.user),
    ];
    return haystack.some((v) => matchValue(v, q));
  });
  return stubDelay({
    items: results.map(toSummary),
    nextCursor: null,
    complete: true,
    fetchedAt: new Date().toISOString(),
    sourceBindingId: "fixture-crm",
    warnings: ["remote adapter: fixture PROJ3733 (offline fallback)"],
  });
}

/** Load full project detail by number (PROJ3733) or CRM id (30x564318). */
export async function getProjectDetail(remoteOrNumber: string): Promise<ProjectDetailDto | null> {
  if (canInvoke()) {
    return invoke<ProjectDetailDto | null>("project_get", {
      request: { id: remoteOrNumber },
    });
  }
  const project = findProject(remoteOrNumber);
  if (!project) return stubDelay(null);
  return stubDelay(toDetail(project));
}

/** Idempotent adopt: one local project per remote CRM id. */
export async function adoptProject(input: string | AdoptInput): Promise<AdoptResultDto> {
  const req: AdoptInput = typeof input === "string" ? { remoteId: input } : input;
  if (canInvoke()) {
    return invoke<AdoptResultDto>("project_adopt", {
      request: {
        remoteId: req.remoteId,
        remoteKey: req.remoteKey ?? null,
        remoteName: req.remoteName ?? null,
        owner: req.owner ?? null,
        shortName: req.shortName ?? null,
        stage: req.stage ?? null,
      },
    });
  }
  const project = findProject(req.remoteId);
  if (!project) throw new Error(`项目不存在：${req.remoteId}`);
  const existing = fixtureStore.adopted.get(project.crmId);
  if (existing) {
    return stubDelay({
      localProjectId: existing.localProjectId,
      remoteId: existing.remoteId,
      created: false,
    });
  }
  const localProjectId = `local-${project.crmId}`;
  fixtureStore.adopted.set(project.crmId, {
    localProjectId,
    remoteId: project.crmId,
    shortName: project.shortName || "XKRL",
    revision: 1,
  });
  return stubDelay({ localProjectId, remoteId: project.crmId, created: true });
}

/** List locally adopted projects. */

/** Followed projects only (ERP-bound + local shells). */
export async function listMyProjects(): Promise<ProjectSummaryDto[]> {
  if (canInvoke()) {
    return invoke<ProjectSummaryDto[]>("project_list");
  }
  const adopted = [...fixtureStore.adopted.values()];
  return stubDelay(
    adopted
      .map((a) => {
        const project = findProject(a.remoteId);
        return project ? toSummary(project) : null;
      })
      .filter((x): x is ProjectSummaryDto => Boolean(x)),
  );
}

export async function createLocalProject(title: string, shortName?: string): Promise<AdoptResultDto> {
  if (canInvoke()) {
    return invoke<AdoptResultDto>("project_create_local", {
      request: { title, shortName: shortName || null },
    });
  }
  const id = `local-${Date.now()}`;
  return stubDelay({ localProjectId: id, remoteId: "", created: true });
}

export async function listLocalProjects(): Promise<LocalProjectDto[]> {
  if (canInvoke()) {
    return invoke<LocalProjectDto[]>("project_list_local");
  }
  return stubDelay(
    [...fixtureStore.adopted.values()].map((a) => {
      const project = findProject(a.remoteId);
      return {
        localProjectId: a.localProjectId,
        remoteId: a.remoteId,
        title: project?.title ?? a.remoteId,
        shortName: project?.shortName ?? a.shortName ?? "",
        revision: a.revision ?? 0,
      };
    }),
  );
}

export async function listClients(): Promise<ErpClientDto[]> {
  // Remote client catalog — still fixture until CRM structured adapter lands.
  return stubDelay(clientList.map((c) => ({ ...c })));
}

export async function bindLocalCustomer(
  remoteId: string,
  role: CustomerRole,
  binding: LocalCustomerBinding,
): Promise<ProjectDetailDto> {
  if (canInvoke()) {
    return invoke<ProjectDetailDto>("project_bind_customer", {
      request: { id: remoteId, role, binding },
    });
  }
  const project = findProject(remoteId);
  if (!project) throw new Error(`项目不存在：${remoteId}`);
  project.local[role] = encodeLocal(binding);
  bumpRevision(project.crmId);
  return stubDelay(toDetail(project));
}

export async function unbindLocalCustomer(
  remoteId: string,
  role: CustomerRole,
): Promise<ProjectDetailDto> {
  if (canInvoke()) {
    return invoke<ProjectDetailDto>("project_unbind_customer", {
      request: { id: remoteId, role },
    });
  }
  return bindLocalCustomer(remoteId, role, { kind: "none" });
}

export async function setProjectShortName(
  remoteId: string,
  shortName: string,
): Promise<ProjectDetailDto> {
  if (canInvoke()) {
    return invoke<ProjectDetailDto>("project_set_short_name", {
      request: { id: remoteId, shortName },
    });
  }
  const project = findProject(remoteId);
  if (!project) throw new Error(`项目不存在：${remoteId}`);
  project.shortName = shortName.trim();
  bumpRevision(project.crmId);
  return stubDelay(toDetail(project));
}

export async function addManualJiraRange(
  remoteId: string,
  keyInput: string,
): Promise<{ detail: ProjectDetailDto; message: string }> {
  if (canInvoke()) {
    return invoke<{ detail: ProjectDetailDto; message: string }>("project_add_jira_range", {
      request: { id: remoteId, key: keyInput },
    });
  }
  const project = findProject(remoteId);
  if (!project) throw new Error(`项目不存在：${remoteId}`);
  const key = normalizeShort(keyInput);
  if (!key) throw new Error("请选择或输入 Jira 项目 key");
  const alreadyManual = project.manualRanges.map(normalizeShort).includes(key);
  const alreadyAuto = autoRangeKeys(project.shortName).includes(key);
  if (alreadyManual) {
    return stubDelay({
      detail: toDetail(project),
      message:
        `${key} 已在手动范围中（幂等）` +
        (alreadyAuto ? "；同时由简称自动命中，故仍在范围内" : ""),
    });
  }
  project.manualRanges.push(key);
  bumpRevision(project.crmId);
  const meta = catalogMeta(key);
  const suffix =
    meta.status === "pending"
      ? " · 待验证（原型可移除）"
      : meta.status === "example"
        ? " · 规则示例，无任务"
        : "";
  const message = alreadyAuto
    ? `已记录 ${key} 为手动补充；该项目同时由简称自动命中，仍在范围内（未重复建项）`
    : `已添加手动范围 ${key}${suffix}`;
  return stubDelay({ detail: toDetail(project), message });
}

export async function removeManualJiraRange(
  remoteId: string,
  keyInput: string,
): Promise<{ detail: ProjectDetailDto; message: string; stillAuto: boolean }> {
  if (canInvoke()) {
    const result = await invoke<{
      detail: ProjectDetailDto;
      message: string;
      stillAuto?: boolean | null;
    }>("project_remove_jira_range", {
      request: { id: remoteId, key: keyInput },
    });
    return {
      detail: result.detail,
      message: result.message,
      stillAuto: Boolean(result.stillAuto),
    };
  }
  const project = findProject(remoteId);
  if (!project) throw new Error(`项目不存在：${remoteId}`);
  const norm = normalizeShort(keyInput);
  const stillAuto = autoRangeKeys(project.shortName).includes(norm);
  project.manualRanges = project.manualRanges.filter((item) => normalizeShort(item) !== norm);
  bumpRevision(project.crmId);
  const message = stillAuto
    ? `已移除 ${norm} 的手动标记；因简称仍命中，保留在自动范围`
    : `已移除手动范围 ${norm}`;
  return stubDelay({ detail: toDetail(project), message, stillAuto });
}

export async function supplementIssueByKey(
  remoteId: string,
  issueKey: string,
): Promise<{ detail: ProjectDetailDto; message: string }> {
  if (canInvoke()) {
    return invoke<{ detail: ProjectDetailDto; message: string }>("project_add_jira_issue", {
      request: { id: remoteId, issueKey },
    });
  }
  const project = findProject(remoteId);
  if (!project) throw new Error(`项目不存在：${remoteId}`);
  const key = String(issueKey || "").trim().toUpperCase();
  if (!key) throw new Error("请输入 Issue key");
  if (crmIssues.some((row) => row[0] === key)) {
    return stubDelay({
      detail: toDetail(project),
      message: `${key} 已由 ERP 关联，无需重复绑定`,
    });
  }
  if (project.issues.includes(key)) {
    return stubDelay({
      detail: toDetail(project),
      message: `${key} 已在本地补充中（幂等）`,
    });
  }
  project.issues.push(key);
  bumpRevision(project.crmId);
  return stubDelay({
    detail: toDetail(project),
    message: `已本地补充 ${key}（模拟 · 无正文快照）`,
  });
}

export async function removeLocalIssue(
  remoteId: string,
  issueKey: string,
): Promise<ProjectDetailDto> {
  if (canInvoke()) {
    return invoke<ProjectDetailDto>("project_unbind_jira_issue", {
      request: { id: remoteId, issueKey },
    });
  }
  const project = findProject(remoteId);
  if (!project) throw new Error(`项目不存在：${remoteId}`);
  if (crmIssues.some((row) => row[0] === issueKey) && !project.issues.includes(issueKey)) {
    throw new Error(`${issueKey} 为 ERP 既有关联，不能通过本地解绑移除`);
  }
  project.issues = project.issues.filter((item) => item !== issueKey);
  bumpRevision(project.crmId);
  return stubDelay(toDetail(project));
}

function bumpRevision(crmId: string) {
  const adopted = fixtureStore.adopted.get(crmId);
  if (adopted) adopted.revision += 1;
}

/** Merge ERP ∪ local supplement tasks (deduped by key). */
export function mergeProjectTasks(detail: ProjectDetailDto): JiraTaskDto[] {
  const map = new Map<string, JiraTaskDto>();
  for (const task of detail.erpIssues) map.set(task.key, task);
  for (const key of detail.localIssues) {
    if (map.has(key)) continue;
    map.set(key, {
      key,
      title: "本地补充任务（原型无正文快照）",
      jiraProjectKey: issueProjectKey(key),
      status: "待验证",
      priority: "—",
      batch: "—",
      dueDate: "—",
      assignee: "—",
      origin: "local",
    });
  }
  return [...map.values()];
}

export function projectTaskCount(detail: ProjectDetailDto): number {
  return mergeProjectTasks(detail).length;
}
