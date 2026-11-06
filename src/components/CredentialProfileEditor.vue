<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import type { CredentialOperation, CredentialProfile, CredentialProfileApi, EntryKind } from "../lib/tauri";

const props = defineProps<{
  credentialId: string;
  kind: EntryKind;
  originHint?: string | null;
  platform: "desktop" | "mobile";
  api: CredentialProfileApi;
}>();
const emit = defineEmits<{ saved: [profile: CredentialProfile | null] }>();
const METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const ADAPTERS = ["http", "github", "zoomkey_jira", "zoomkey_crm"];
const availableAuth = computed(() => props.kind === "client_cert"
  ? [{ value: "mtls", label: "mTLS · 使用金库客户端证书" }]
  : props.kind === "api_token"
    ? [{ value: "bearer", label: "Bearer · 使用本凭据 Token" }, { value: "basic", label: "Basic · 使用本凭据账号/密码" }, { value: "header", label: "自定义 Header · 使用本凭据秘密" }]
    : [{ value: "basic", label: "Basic · 使用本凭据账号/密码" }]);
const SCHEMA_KEYS = new Set(["type", "title", "description", "default", "enum", "properties", "required", "additionalProperties", "minLength", "maxLength", "minimum", "maximum", "items", "minItems", "maxItems"]);
const loading = ref(true);
const busy = ref(false);
const loadFailed = ref(false);
const configured = ref(false);
const mode = ref<"form" | "json">("form");
const error = ref("");
const notice = ref("");
const raw = ref("");
const profile = ref<CredentialProfile>(template());
const methods = ref("GET");
const prefixes = ref("/api");
let nextKey = 0;
interface OperationDraft {
  key: number;
  name: string;
  description: string;
  method: string;
  path_template: string;
  params: string;
  query: string;
  body: string;
  fixed_query: string;
  fixed_body: string;
  risk: CredentialOperation["risk"];
  read_only: boolean;
}
const operations = ref<OperationDraft[]>([]);
const baseline = ref("");
let requestSeq = 0;

function pretty(value: unknown) { return JSON.stringify(value, null, 2); }
function list(value: string) { return value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean); }
function isObject(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function sampleOperation(post = false): CredentialOperation {
  return {
    name: post ? "create_item" : "list_items",
    description: post ? "新增一个条目；title 是条目的显示名称" : "按关键词查找条目；q 是搜索词，留空列出条目",
    method: post ? "POST" : "GET",
    path_template: "/api/items",
    params: {
      type: "object",
      properties: post
        ? { title: { type: "string", description: "条目名称，例如：本周工作", minLength: 1, maxLength: 200 } }
        : { q: { type: "string", description: "搜索关键词，例如：待办", maxLength: 200 } },
      required: post ? ["title"] : [],
      additionalProperties: false,
    },
    query_params: post ? [] : ["q"],
    body_params: post ? ["title"] : [],
    fixed_query: {},
    fixed_body: {},
    risk: post ? "medium" : "low",
    read_only: !post,
  };
}
function template(post = false): CredentialProfile {
  let origin = "";
  try {
    const parsed = new URL(props.originHint || "");
    if (parsed.protocol === "https:") origin = parsed.origin;
  } catch { /* A recipe origin is entered separately when the entry has no HTTPS URL. */ }
  return {
    version: 1, adapter: "http", service: "custom", origin,
    auth: {
      kind: props.kind === "client_cert" ? "mtls" : props.kind === "api_token" ? "bearer" : "basic",
      client_cert_id: props.kind === "client_cert" ? props.credentialId : null,
    },
    allowed_methods: [post ? "POST" : "GET"], allowed_path_prefixes: ["/api"], operations: [sampleOperation(post)],
  };
}
function loadDraft(value: CredentialProfile) {
  profile.value = JSON.parse(JSON.stringify(value)) as CredentialProfile;
  methods.value = value.allowed_methods.join(", ");
  prefixes.value = value.allowed_path_prefixes.join("\n");
  operations.value = value.operations.map((op) => ({
    key: ++nextKey, name: op.name, description: op.description, method: op.method, path_template: op.path_template,
    params: pretty(op.params), query: op.query_params.join(", "), body: op.body_params.join(", "),
    fixed_query: pretty(op.fixed_query), fixed_body: pretty(op.fixed_body), risk: op.risk, read_only: op.read_only,
  }));
  raw.value = pretty(value);
}
function parse(text: string, label: string): unknown {
  try { return JSON.parse(text); }
  catch { throw new Error(`${label}：JSON 格式错误，请检查双引号、逗号和括号。`); }
}
function formValue(): CredentialProfile {
  const auth = profile.value.auth;
  return {
    ...profile.value,
    service: profile.value.service.trim(), origin: profile.value.origin.trim(),
    auth: {
      kind: auth.kind,
      header_name: auth.kind === "header" ? auth.header_name?.trim() || null : null,
      prefix: auth.kind === "header" ? auth.prefix ?? null : null,
      client_cert_id: auth.client_cert_id?.trim() || null,
      ca_bundle_path: auth.ca_bundle_path?.trim() || null,
    },
    allowed_methods: list(methods.value), allowed_path_prefixes: list(prefixes.value),
    operations: operations.value.map((op, i) => ({
      name: op.name.trim(), description: op.description.trim(), method: op.method, path_template: op.path_template.trim(),
      params: parse(op.params, `操作 ${i + 1} 的参数 schema`) as Record<string, unknown>,
      query_params: list(op.query), body_params: list(op.body),
      fixed_query: parse(op.fixed_query, `操作 ${i + 1} 的固定 query`) as Record<string, string>,
      fixed_body: parse(op.fixed_body, `操作 ${i + 1} 的固定 body`) as Record<string, unknown>,
      risk: op.risk, read_only: op.read_only,
    })),
  };
}
const snapshot = computed(() => JSON.stringify({ mode: mode.value, raw: mode.value === "json" ? raw.value : undefined,
  profile: mode.value === "form" ? profile.value : undefined, methods: methods.value, prefixes: prefixes.value,
  operations: mode.value === "form" ? operations.value : undefined }));
const dirty = computed(() => !loading.value && snapshot.value !== baseline.value);
function markClean() { baseline.value = snapshot.value; }
function canDiscard() { return !busy.value && (!dirty.value || window.confirm("放弃尚未保存的凭据 profile 修改？")); }
defineExpose({ canDiscard });

// Convenience validation only. The native executor remains the security boundary.
function validateSchema(value: unknown, at: string, issues: string[], depth = 0) {
  if (!isObject(value)) { issues.push(`${at} 必须是 JSON Schema 对象。`); return; }
  if (depth > 12) { issues.push(`${at} 嵌套过深。`); return; }
  for (const key of Object.keys(value)) if (!SCHEMA_KEYS.has(key)) issues.push(`${at}.${key} 不受支持（不支持 $ref、oneOf、pattern、format）。`);
  const type = value.type;
  if (!["object", "string", "integer", "number", "boolean", "array"].includes(String(type))) issues.push(`${at}.type 请选择 object/string/integer/number/boolean/array。`);
  for (const key of ["title", "description"]) if (value[key] !== undefined && typeof value[key] !== "string") issues.push(`${at}.${key} 必须是文字。`);
  if (value.enum !== undefined && (!Array.isArray(value.enum) || !value.enum.length)) issues.push(`${at}.enum 必须是非空数组。`);
  if (type === "object") {
    if (value.additionalProperties !== false) issues.push(`${at} 必须设置 additionalProperties: false（封闭参数）。`);
    if (!isObject(value.properties)) issues.push(`${at}.properties 必须是对象。`);
    else {
      for (const [name, schema] of Object.entries(value.properties)) validateSchema(schema, `${at}.properties.${name}`, issues, depth + 1);
      if (value.required !== undefined && (!Array.isArray(value.required) || value.required.some((name) => typeof name !== "string" || !Object.prototype.hasOwnProperty.call(value.properties as object, name)))) issues.push(`${at}.required 只能包含 properties 中的参数名。`);
    }
  }
  if (type === "array") {
    validateSchema(value.items, `${at}.items`, issues, depth + 1);
    if (value.maxItems !== undefined && (typeof value.maxItems !== "number" || value.maxItems > 100)) issues.push(`${at}.maxItems 必须是 0–100 的整数（默认 100）。`);
  }
  for (const key of ["minLength", "maxLength", "minItems", "maxItems"]) if (value[key] !== undefined && (typeof value[key] !== "number" || !Number.isInteger(value[key]) || Number(value[key]) < 0)) issues.push(`${at}.${key} 必须是非负整数。`);
  if (typeof value.maxLength === "number" && value.maxLength > 65536) issues.push(`${at}.maxLength 不能超过 65536（默认 8192）。`);
  for (const key of ["minimum", "maximum"]) if (value[key] !== undefined && typeof value[key] !== "number") issues.push(`${at}.${key} 必须是数值。`);
  for (const [min, max] of [["minLength", "maxLength"], ["minItems", "maxItems"], ["minimum", "maximum"]]) if (typeof value[min] === "number" && typeof value[max] === "number" && Number(value[min]) > Number(value[max])) issues.push(`${at}.${min} 不能大于 ${max}。`);
}
function validate(value: unknown): string[] {
  const issues: string[] = [];
  if (!isObject(value)) return ["profile 必须是 JSON 对象，不是数组或 null；清除配置请用下方重置按钮。"];
  const known = new Set(["version", "adapter", "service", "origin", "auth", "allowed_methods", "allowed_path_prefixes", "operations"]);
  for (const key of Object.keys(value)) if (!known.has(key)) issues.push(`未知 profile 字段：${key}。不要在 profile 中保存 Token、密码或私钥。`);
  if (value.version !== 1) issues.push("version 必须为 1。");
  if (!ADAPTERS.includes(String(value.adapter))) issues.push("adapter 请选择 http/github/zoomkey_jira/zoomkey_crm。");
  if (typeof value.service !== "string" || !value.service.trim()) issues.push("请填写服务标识 service，例如 my_company_api；可以使用新平台名称。");
  try {
    if (typeof value.origin !== "string" || !/^https:\/\/[^/?#]+$/.test(value.origin)) throw new Error();
    const url = new URL(value.origin);
    if (url.username || url.password || url.protocol !== "https:") throw new Error();
  } catch { issues.push("origin 必须是固定 HTTPS 主机（可带端口），如 https://api.example.com；不要带末尾 /、路径、查询或账号密码。"); }
  if (value.adapter === "github" && value.origin !== "https://api.github.com") issues.push("GitHub adapter 的 origin 必须是 https://api.github.com。");
  if (!isObject(value.auth)) issues.push("auth 必须是认证方式对象；秘密从金库读取。");
  else {
    for (const key of Object.keys(value.auth)) if (!["kind", "header_name", "prefix", "client_cert_id", "ca_bundle_path"].includes(key)) issues.push(`未知 auth 字段 ${key}；不能填写认证值或秘密。`);
    if (!["bearer", "basic", "header", "mtls"].includes(String(value.auth.kind))) issues.push("auth.kind 请选择 bearer/basic/header/mtls。");
    else if (!availableAuth.value.map((option) => option.value).includes(String(value.auth.kind))) issues.push("认证方式与本凭据类型不匹配：API Token 支持 bearer/basic/header，密码型凭据支持 basic，客户端证书支持 mtls。");
    for (const key of ["header_name", "prefix", "client_cert_id", "ca_bundle_path"]) if (value.auth[key] != null && typeof value.auth[key] !== "string") issues.push(`auth.${key} 必须是文字或 null。`);
    if (value.auth.kind === "header" && (typeof value.auth.header_name !== "string" || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value.auth.header_name))) issues.push("自定义头必须填写合法 header_name，例如 X-API-Key；不是 Token 的值。");
    if (typeof value.auth.prefix === "string" && /[\r\n]/.test(value.auth.prefix)) issues.push("认证前缀不能包含换行。");
  }
  const stringArray = (item: unknown, label: string): item is string[] => {
    if (!Array.isArray(item) || item.some((s) => typeof s !== "string" || !s.trim())) { issues.push(`${label} 必须是非空文字组成的数组。`); return false; }
    if (new Set(item).size !== item.length) issues.push(`${label} 不能重复。`);
    return true;
  };
  if (stringArray(value.allowed_methods, "allowed_methods")) {
    if (!value.allowed_methods.length) issues.push("至少允许一个 HTTP 方法。");
    if (value.allowed_methods.some((method) => !METHODS.includes(method))) issues.push("HTTP 方法必须是大写 GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS。");
  }
  const safePath = (path: unknown): path is string => typeof path === "string" && path.startsWith("/") && !path.startsWith("//") && !/[?#\\\r\n]/.test(path) && !path.split("/").some((part) => part === "." || part === "..");
  if (stringArray(value.allowed_path_prefixes, "allowed_path_prefixes")) {
    if (!value.allowed_path_prefixes.length) issues.push("至少填写一个允许的路径前缀。");
    if (value.allowed_path_prefixes.some((path) => !safePath(path) || /[{}]/.test(path))) issues.push("路径前缀必须是固定绝对路径，如 /api；不能带查询、占位符或 ..。");
  }
  if (!Array.isArray(value.operations)) issues.push("operations 必须是操作数组。");
  else {
    const names = new Set<string>();
    value.operations.forEach((op: unknown, i: number) => {
      const at = `操作 ${i + 1}`;
      if (!isObject(op)) { issues.push(`${at} 必须是对象。`); return; }
      for (const key of Object.keys(op)) if (!["name", "description", "method", "path_template", "params", "query_params", "body_params", "fixed_query", "fixed_body", "risk", "read_only"].includes(key)) issues.push(`${at} 含未知字段 ${key}。`);
      if (typeof op.name !== "string" || !/^[A-Za-z_][A-Za-z0-9_./-]{0,63}$/.test(op.name)) issues.push(`${at} 的 name 须为 1–64 个 ASCII 字符，字母或下划线开头，后续可用字母、数字、_、-、.、/，如 list_items。`);
      else if (names.has(op.name)) issues.push(`${at} 的操作名 ${op.name} 重复。`);
      else names.add(op.name);
      if (typeof op.description !== "string" || !op.description.trim()) issues.push(`${at} 请填写操作和参数用途说明，供 vault_describe 返回。`);
      if (!Array.isArray(value.allowed_methods) || !value.allowed_methods.includes(op.method)) issues.push(`${at} 的 method 必须属于 allowed_methods。`);
      if (!safePath(op.path_template)) issues.push(`${at} 的 path_template 必须是绝对路径，如 /api/items/{id}；不能带 URL、查询或 ..。`);
      else if (Array.isArray(value.allowed_path_prefixes) && !value.allowed_path_prefixes.some((prefix: unknown) => typeof prefix === "string" && (prefix === "/" || op.path_template === prefix || (op.path_template as string).startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`)))) issues.push(`${at} 的路径不在允许的前缀内。`);
      validateSchema(op.params, `${at}.params`, issues);
      if (isObject(op.params) && op.params.type !== "object") issues.push(`${at}.params 顶层必须是 object。`);
      const properties = isObject(op.params) && isObject(op.params.properties) ? op.params.properties : {};
      const pathParams = typeof op.path_template === "string" ? [...op.path_template.matchAll(/\{([^{}]+)\}/g)].map((match) => match[1]) : [];
      if (typeof op.path_template === "string" && op.path_template.split("/").some((segment) => /[{}]/.test(segment) && !/^\{[A-Za-z_][A-Za-z0-9_.-]*\}$/.test(segment))) issues.push(`${at} 的路径占位符必须独占一个路径段，例如 /api/items/{id}，不能写 item-{id}。`);
      for (const name of pathParams) {
        if (!Object.prototype.hasOwnProperty.call(properties, name)) issues.push(`${at} 的路径参数 ${name} 必须在 params.properties 中声明。`);
        if (!isObject(op.params) || !Array.isArray(op.params.required) || !op.params.required.includes(name)) issues.push(`${at} 的路径参数 ${name} 必须列入 schema.required。`);
      }
      for (const key of ["query_params", "body_params"]) if (stringArray(op[key], `${at}.${key}`)) for (const name of op[key] as string[]) if (!Object.prototype.hasOwnProperty.call(properties, name)) issues.push(`${at}.${key} 中的 ${name} 未在参数 schema 中声明。`);
      for (const key of ["fixed_query", "fixed_body"]) if (!isObject(op[key])) issues.push(`${at}.${key} 必须是 JSON 对象，留空用 {}。`);
      if (isObject(op.fixed_query) && Object.values(op.fixed_query).some((item) => typeof item !== "string")) issues.push(`${at}.fixed_query 的值必须都是文字。`);
      if (!["low", "medium", "high"].includes(String(op.risk))) issues.push(`${at}.risk 请选择 low/medium/high。`);
      if (typeof op.read_only !== "boolean") issues.push(`${at}.read_only 必须是 true 或 false。`);
      if (op.read_only === true && !["GET", "HEAD", "OPTIONS"].includes(String(op.method))) issues.push(`${at} 的写入方法不能标记为 read_only。`);
    });
  }
  return issues;
}
function checkedValue(): CredentialProfile {
  const value: unknown = mode.value === "json" ? parse(raw.value, "完整 profile") : formValue();
  const issues = validate(value);
  if (issues.length) throw new Error(issues.slice(0, 16).join("\n") + (issues.length > 16 ? `\n另有 ${issues.length - 16} 项错误。` : ""));
  return value as CredentialProfile;
}
async function load() {
  const seq = ++requestSeq;
  loading.value = true; loadFailed.value = false; error.value = ""; notice.value = "";
  try {
    const value = await props.api.get(props.credentialId);
    if (seq !== requestSeq) return;
    configured.value = value !== null;
    mode.value = "form";
    loadDraft(value ?? template());
    markClean();
  } catch (caught) {
    if (seq !== requestSeq) return;
    error.value = String(caught); loadFailed.value = true;
  } finally { if (seq === requestSeq) loading.value = false; }
}
function switchMode() {
  error.value = ""; notice.value = "";
  const wasDirty = dirty.value;
  try {
    if (mode.value === "form") { raw.value = pretty(formValue()); mode.value = "json"; }
    else { const value = checkedValue(); loadDraft(value); mode.value = "form"; }
    if (!wasDirty) markClean();
  } catch (caught) { error.value = String(caught); }
}
function useTemplate(post = false) {
  if (!canDiscard()) return;
  mode.value = "form"; loadDraft(template(post)); error.value = ""; notice.value = "示例尚未保存，请先填写真实 origin 和服务标识，再按需要调整。";
}
function addOperation(post = false) {
  const op = sampleOperation(post);
  let name = op.name; let suffix = 2;
  while (operations.value.some((item) => item.name === name)) name = `${op.name}_${suffix++}`;
  operations.value.push({ key: ++nextKey, name, description: op.description, method: op.method, path_template: op.path_template,
    params: pretty(op.params), query: op.query_params.join(", "), body: op.body_params.join(", "),
    fixed_query: "{}", fixed_body: "{}", risk: op.risk, read_only: op.read_only });
  if (!list(methods.value).includes(op.method)) methods.value = [...list(methods.value), op.method].join(", ");
}
function setMethod(op: OperationDraft) { if (!["GET", "HEAD", "OPTIONS"].includes(op.method)) { op.read_only = false; if (op.risk === "low") op.risk = "medium"; } }
async function save() {
  if (busy.value || loading.value || loadFailed.value) return;
  error.value = ""; notice.value = "";
  let value: CredentialProfile;
  try { value = checkedValue(); } catch (caught) { error.value = String(caught); return; }
  busy.value = true;
  const seq = requestSeq;
  try {
    const saved = await props.api.set(props.credentialId, value);
    if (seq !== requestSeq) return;
    configured.value = saved !== null; loadDraft(saved ?? template()); markClean();
    notice.value = "profile 已保存。新增操作通过 vault_describe 发现，由 http_call 调用，不增加 MCP 工具名。";
    emit("saved", saved);
  } catch (caught) { if (seq === requestSeq) error.value = String(caught); }
  finally { if (seq === requestSeq) busy.value = false; }
}
async function reset() {
  if (busy.value || !window.confirm(props.platform === "desktop"
    ? "清除该凭据的显式 profile 并重新加载内置配置？没有内置配置时将不再暴露 HTTP 操作。尚未保存的编辑会丢失。"
    : "清除该凭据保存的 profile？移动端不加载桌面内置配置。尚未保存的编辑会丢失。")) return;
  busy.value = true; error.value = ""; notice.value = "";
  const seq = requestSeq;
  try {
    const value = await props.api.reset(props.credentialId);
    if (seq !== requestSeq) return;
    configured.value = value !== null; mode.value = "form"; loadDraft(value ?? template()); markClean();
    notice.value = value ? "显式配置已清除，已重新加载内置 profile。" : "显式配置已清除。当前展示的是未保存的 HTTP 示例。";
    emit("saved", value);
  } catch (caught) { if (seq === requestSeq) error.value = String(caught); }
  finally { if (seq === requestSeq) busy.value = false; }
}
function check() { error.value = ""; notice.value = ""; try { checkedValue(); notice.value = "前端格式检查通过；保存和调用仍须通过后端安全校验。"; } catch (caught) { error.value = String(caught); } }
watch(() => props.credentialId, () => { busy.value = false; void load(); }, { immediate: true });
onBeforeUnmount(() => { requestSeq += 1; });
</script>

<template>
  <section class="cp-editor" aria-label="凭据 HTTP profile 编辑器">
    <header class="cp-heading"><h4>HTTP 操作 profile</h4><span>{{ dirty ? '有未保存修改' : configured ? (platform === 'desktop' ? '当前生效配置（可能含内置）' : '已保存配置') : '未配置 · 以下为未保存示例' }}</span></header>
    <p class="cp-help">固定六个工具适用于所有平台。先由 <code>vault_list</code> 找凭据，<code>vault_describe</code> 读操作和参数，再由 <code>http_call</code> 调用；新增操作不会新增工具名。</p>
    <p class="cp-warning">这里只填写请求配方，绝不填写 Token、密码、私钥或认证头的值。运行时从本条金库凭据注入认证；固定 query/body 也不能放秘密。此编辑器不读秘密、不写本地 storage，前端检查不替代后端安全校验。</p>
    <p v-if="loading" class="cp-help" role="status">正在读取 profile…</p>
    <div v-else-if="loadFailed"><p class="cp-error" role="alert">{{ error }}</p><button type="button" @click="load">重新读取</button></div>
    <template v-else>
      <div class="cp-actions">
        <button type="button" :disabled="busy" @click="switchMode">{{ mode === 'form' ? '高级：完整 JSON' : '返回表单' }}</button>
        <button type="button" :disabled="busy" @click="useTemplate(false)">GET 查询模板</button>
        <button type="button" :disabled="busy" @click="useTemplate(true)">POST 创建模板</button>
      </div>
      <fieldset :disabled="busy" class="cp-fields">
        <template v-if="mode === 'form'">
          <div class="cp-grid">
            <label>服务标识 service<input v-model="profile.service" placeholder="my_company_api（可自由填写）" autocomplete="off" /></label>
            <label>适配器<select v-model="profile.adapter"><option value="http">HTTP（新平台首选）</option><option value="github">GitHub（内置裁剪）</option><option value="zoomkey_jira">ZoomKey Jira</option><option value="zoomkey_crm">ZoomKey CRM</option></select></label>
          </div>
          <label>固定 origin<input v-model="profile.origin" placeholder="https://api.example.com" autocomplete="off" spellcheck="false" /></label>
          <p class="cp-help">只填写 HTTPS 协议、主机和可选端口，不带末尾 / 或路径；操作路径另填。GitHub 适配器必须使用 https://api.github.com。</p>
          <div class="cp-grid">
            <label>认证方式<select v-model="profile.auth.kind"><option v-for="option in availableAuth" :key="option.value" :value="option.value">{{ option.label }}</option></select></label>
            <label>客户端证书 ID（可选）<input v-model="profile.auth.client_cert_id" placeholder="金库客户端证书条目 ID，不是 PEM" autocomplete="off" /></label>
          </div>
          <div v-if="profile.auth.kind === 'header'" class="cp-grid">
            <label>认证头名称<input v-model="profile.auth.header_name" placeholder="X-API-Key（只填名称）" autocomplete="off" /></label>
            <label>非秘密前缀（可选）<input v-model="profile.auth.prefix" placeholder="如 Bearer 后带空格；不填认证值" autocomplete="off" /></label>
          </div>
          <label>CA bundle 路径（可选，仅元数据）<input v-model="profile.auth.ca_bundle_path" placeholder="用于验证服务端证书的本机 CA 文件路径" autocomplete="off" /></label>
          <p class="cp-help">mTLS 只引用金库里的证书条目；也可为 Basic/Bearer/Header 附加客户端证书。mtls 认证的证书 ID 留空时使用本条证书。当前凭据 ID：<code>{{ credentialId }}</code>（非秘密，可用于引用）。路径依赖设备，手机上不要填写桌面文件路径。此处不输入证书、私钥、Token 或密码。</p>
          <div class="cp-grid">
            <label>允许的方法（逗号分隔）<input v-model="methods" placeholder="GET, POST" /></label>
            <label>允许的路径前缀（每行一个）<textarea v-model="prefixes" rows="2" placeholder="/api" spellcheck="false"></textarea></label>
          </div>
          <div class="cp-heading"><h4>具名操作（{{ operations.length }}）</h4><div class="cp-actions"><button type="button" @click="addOperation(false)">+ GET 操作</button><button type="button" @click="addOperation(true)">+ POST 操作</button></div></div>
          <p v-if="!operations.length" class="cp-help">暂无操作；保存空操作列表后，这条凭据不提供 HTTP 操作。可用上方按钮新增。</p>
          <article v-for="(op, index) in operations" :key="op.key" class="cp-operation">
            <div class="cp-heading"><strong>操作 {{ index + 1 }} · {{ op.name || '未命名' }}</strong><button type="button" class="cp-danger" @click="operations.splice(index, 1)">删除操作</button></div>
            <div class="cp-grid"><label>操作名 name<input v-model="op.name" placeholder="list_items" spellcheck="false" /></label><label>HTTP 方法<select v-model="op.method" @change="setMethod(op)"><option v-for="method in METHODS" :key="method">{{ method }}</option></select></label></div>
            <label>操作与参数用途说明<textarea v-model="op.description" rows="2" placeholder="供模型阅读的操作说明；说明每个参数的用途"></textarea></label>
            <label>路径模板 path_template<input v-model="op.path_template" placeholder="/api/items 或 /api/items/{id}" spellcheck="false" /></label>
            <p class="cp-help">路径参数写为独占路径段的 {id}，并在 schema.properties 和 required 中声明。模型不能自行改 origin、请求头或认证。</p>
            <label>参数 schema（封闭 JSON Schema）<textarea v-model="op.params" class="cp-json" rows="10" spellcheck="false" autocomplete="off"></textarea></label>
            <details class="cp-guide"><summary>参数填写说明与调用示例</summary><p>顶层必须是 object，声明 properties，并设置 additionalProperties: false。required 列出必填参数；每个参数的 description 供 vault_describe 说明用途。支持 string/integer/number/boolean/array 和嵌套封闭 object，以及 enum/default、数值 minimum/maximum、长度与数量限制；不支持 $ref、oneOf、pattern 或 format。</p><p>字符串建议填写 maxLength（默认 8192，上限 65536）；数组填写 items、maxItems（默认及上限 100）。参数放进 URL 查询或 JSON 请求体，须在下面对应名单中列出；路径参数不用加入名单。</p><p>GET 模板的 q 是可选搜索词：<code>http_call({ credential_id: "本条凭据ID", op: "list_items", params: { q: "待办" } })</code>，生成 <code>GET /api/items?q=待办</code>。不要在参数默认值、固定参数或示例里填真实秘密。</p></details>
            <div class="cp-grid"><label>query 参数名单（逗号分隔）<input v-model="op.query" placeholder="q, page" /></label><label>body 参数名单（逗号分隔）<input v-model="op.body" placeholder="title, content" /></label></div>
            <details class="cp-guide"><summary>固定 query / body（非秘密常量）</summary><div class="cp-grid"><label>fixed_query（值只能是字符串）<textarea v-model="op.fixed_query" class="cp-json" rows="4" spellcheck="false"></textarea></label><label>fixed_body（JSON 对象）<textarea v-model="op.fixed_body" class="cp-json" rows="4" spellcheck="false"></textarea></label></div><p>固定参数是每次自动附带的非秘密常量；留空写 {}。认证仅由后端注入，不能在这里填密码、Token 或 Authorization。</p></details>
            <div class="cp-grid"><label>风险<select v-model="op.risk"><option value="low">low · 低风险</option><option value="medium">medium · 中风险</option><option value="high">high · 高风险</option></select></label><label class="cp-check"><input v-model="op.read_only" type="checkbox" :disabled="!['GET', 'HEAD', 'OPTIONS'].includes(op.method)" /> read_only · 只读（写操作仍按后端规则确认）</label></div>
          </article>
        </template>
        <template v-else><label>完整 profile JSON<textarea v-model="raw" class="cp-json cp-full-json" rows="26" spellcheck="false" autocomplete="off"></textarea></label><p class="cp-help">包含 version、adapter、service、origin、auth、allowed_methods、allowed_path_prefixes 和 operations。可使用模板后修改 JSON；只填配方与非秘密元数据。返回表单时会校验结构并显示具体错误。</p></template>
      </fieldset>
      <p v-if="error" class="cp-error" role="alert">{{ error }}</p><p v-if="notice" class="cp-notice" role="status">{{ notice }}</p>
      <div class="cp-actions cp-footer"><button class="cp-primary" type="button" :disabled="busy" @click="save">{{ busy ? '处理中…' : '保存 profile' }}</button><button type="button" :disabled="busy" @click="check">验证配置</button><button class="cp-danger" type="button" :disabled="busy" @click="reset">{{ platform === 'desktop' ? '清除显式配置 / 恢复内置' : '清除保存的 profile' }}</button></div>
      <p class="cp-help">{{ platform === 'desktop' ? '桌面显示当前生效 profile（含内置）。清除显式配置后重新加载内置；没有内置则无操作。' : '移动端只编辑已保存 profile，不在手机加载桌面内置适配。同步到桌面后仍由桌面 MCP 后端验证执行。' }} 没有 profile 的新平台不会退回任意 URL 代理。</p>
    </template>
  </section>
</template>

<style scoped>
.cp-editor { margin: 18px 0; padding: 16px; border: 1px solid #dce0ec; border-radius: 12px; background: #fafbff; color: #202334; font-size: 13px; text-align: left; min-width: 0; }
.cp-heading { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; margin: 8px 0; }
.cp-heading h4 { font-size: 15px; margin: 0; }.cp-heading > span { color: #626a80; font-size: 12px; }
.cp-help, .cp-guide p { color: #626a80; font-size: 12px; line-height: 1.65; margin: 8px 0; overflow-wrap: anywhere; }
.cp-warning { padding: 10px 12px; border-radius: 8px; background: #fff7e5; color: #805716; line-height: 1.65; font-size: 12px; }
.cp-fields { min-width: 0; border: 0; padding: 0; margin: 12px 0; }.cp-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 14px; }
.cp-editor label { display: flex; flex-direction: column; gap: 6px; margin: 10px 0; color: #41485e; font-size: 12px; min-width: 0; }
.cp-editor input, .cp-editor select, .cp-editor textarea { width: 100%; box-sizing: border-box; min-width: 0; border: 1px solid #d6dbe8; border-radius: 7px; padding: 9px 10px; font: inherit; background: #fff; color: #202334; height: auto; }
.cp-editor textarea { resize: vertical; line-height: 1.5; }.cp-editor input:focus, .cp-editor textarea:focus, .cp-editor select:focus { outline: 2px solid #b5b5f2; outline-offset: 1px; }
.cp-editor button { width: auto; min-height: 34px; border: 1px solid #d6dbe8; border-radius: 7px; padding: 7px 11px; background: #fff; color: #41485e; cursor: pointer; font: inherit; font-size: 12px; }
.cp-editor button:hover:not(:disabled) { border-color: #7777d9; }.cp-editor button:disabled { opacity: .55; cursor: wait; }.cp-editor .cp-primary { background: #5b5bd6; border-color: #5b5bd6; color: #fff; }.cp-editor .cp-danger { color: #b43c45; }
.cp-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }.cp-footer { padding-top: 10px; border-top: 1px solid #dce0ec; }
.cp-operation { padding: 12px; border: 1px solid #dce0ec; border-radius: 10px; background: #fff; margin: 12px 0; min-width: 0; }
.cp-editor .cp-json { font: 12px/1.55 ui-monospace, SFMono-Regular, Consolas, monospace; tab-size: 2; }.cp-full-json { min-height: 360px; }
.cp-editor .cp-check { flex-direction: row; align-items: center; line-height: 1.5; }.cp-check input { width: 16px; height: 16px; flex: 0 0 16px; }
.cp-guide { padding: 8px 10px; margin: 8px 0; background: #f4f5fb; border-radius: 7px; }.cp-guide summary { cursor: pointer; color: #5151b7; font-size: 12px; }.cp-guide code { white-space: normal; overflow-wrap: anywhere; }
.cp-error { color: #ad2638; white-space: pre-wrap; overflow-wrap: anywhere; padding: 10px; background: #fff0f2; border: 1px solid #f2c3cc; border-radius: 8px; line-height: 1.6; }.cp-notice { color: #1c754b; padding: 9px; background: #edf8f1; line-height: 1.6; overflow-wrap: anywhere; }
@media (max-width: 640px) { .cp-editor { padding: 12px; }.cp-grid { grid-template-columns: minmax(0, 1fr); gap: 0; }.cp-operation { padding: 10px; }.cp-editor input, .cp-editor select, .cp-editor textarea { font-size: 14px; }.cp-editor .cp-json { font-size: 12px; }.cp-actions button { min-height: 40px; } }
</style>
