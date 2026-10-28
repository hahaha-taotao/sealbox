/**
 * 邮件正文渲染工具：纯函数、无第三方依赖，浏览器与 node 都能直接运行。
 *
 * 这里是密码管理器里的只读邮件视图，安全是硬要求：
 * - 正文渲染在 sandbox="allow-same-origin" 的 iframe 中（不给 allow-scripts / allow-popups）；
 * - 文档级 CSP 只放行 data: 图片和内联样式，屏蔽远程图片、追踪像素、外部样式与脚本；
 * - 清洗阶段再剥掉能执行代码或带出网络请求的标签与属性。
 */

const DROP_WITH_CONTENT = new Set([
  "script",
  "noscript",
  "template",
  "iframe",
  "frame",
  "frameset",
  "object",
  "applet",
]);

const DROP_TAG_ONLY = new Set([
  "embed",
  "link",
  "base",
  "meta",
  "form",
  "input",
  "button",
  "select",
  "optgroup",
  "option",
  "textarea",
]);

const DROP_ATTRIBUTES = new Set(["srcdoc", "ping", "http-equiv", "formaction", "manifest"]);

const URL_ATTRIBUTES = new Set([
  "href",
  "src",
  "action",
  "poster",
  "background",
  "cite",
  "longdesc",
  "lowsrc",
  "dynsrc",
  "codebase",
  "profile",
  "data",
]);

const ALLOWED_DATA_IMAGE = /^data:image\/(?:png|jpe?g|gif|webp|bmp|x-icon)(?:[;,]|$)/i;

const TAG_PATTERN = /<([a-zA-Z][a-zA-Z0-9:_-]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>/g;

const ATTRIBUTE_PATTERN = /([^\s=/>]+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s"'=<>`]+))?/g;

const STYLE_PATTERN = /<style\b[^>]*>[\s\S]*?<\/style\s*>/gi;

const NAMED_ENTITIES: Record<string, string | undefined> = {
  colon: ":",
  tab: "\t",
  newline: "\n",
  lpar: "(",
  rpar: ")",
  sol: "/",
  nbsp: " ",
  amp: "&",
  quot: '"',
  apos: "'",
};

const BASE_STYLE = [
  ":root { color-scheme: light; }",
  "html, body { margin: 0; padding: 0; background: #ffffff; }",
  "body { padding: 14px 16px; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", \"Microsoft YaHei\", \"PingFang SC\", \"Hiragino Sans GB\", sans-serif; font-size: 14px; line-height: 1.7; color: #1f2328; word-break: break-word; overflow-wrap: anywhere; }",
  "p { margin: 0 0 12px; }",
  "img { max-width: 100%; height: auto; }",
  "table { max-width: 100%; border-collapse: collapse; }",
  "td, th { max-width: 100%; word-break: break-word; vertical-align: top; }",
  "a { color: #2563eb; text-decoration: underline; }",
  "blockquote { margin: 0 0 12px 12px; padding-left: 12px; border-left: 3px solid #e5e7eb; color: #57606a; }",
  "pre { white-space: pre-wrap; overflow-wrap: anywhere; margin: 0 0 12px; }",
].join("\n");

function decodeEntities(value: string): string {
  return value.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);?/g, (match: string, body: string): string => {
    if (body.charAt(0) === "#") {
      const hexadecimal = body.charAt(1) === "x" || body.charAt(1) === "X";
      const digits = hexadecimal ? body.slice(2) : body.slice(1);
      const code = Number.parseInt(digits, hexadecimal ? 16 : 10);
      if (!Number.isFinite(code) || code <= 0 || code > 0x10ffff) return match;
      return String.fromCodePoint(code);
    }
    return NAMED_ENTITIES[body.toLowerCase()] ?? match;
  });
}

function stripQuotes(value: string): string {
  const first = value.charAt(0);
  if ((first === '"' || first === "'") && value.length > 1 && value.charAt(value.length - 1) === first) {
    return value.slice(1, -1);
  }
  return value;
}

/** 判断一个 URL 属性值是否会执行代码或加载可执行的 data: 文档。 */
function urlIsDangerous(value: string): boolean {
  const compact = decodeEntities(value)
    .replace(/[\u0000-\u0020\u007f-\u00a0\u2000-\u200f\u2028\u2029]/g, "")
    .toLowerCase();
  if (compact === "") return false;
  if (/^(?:javascript|vbscript|livescript|mocha|about|file):/.test(compact)) return true;
  if (compact.startsWith("data:")) return !ALLOWED_DATA_IMAGE.test(compact);
  return false;
}

function cssIsDangerous(value: string): boolean {
  const compact = decodeEntities(value).toLowerCase();
  return (
    compact.includes("expression(") ||
    compact.includes("javascript:") ||
    compact.includes("vbscript:") ||
    compact.includes("-moz-binding") ||
    compact.includes("behavior:")
  );
}

/** 清洗单个属性，返回 null 表示丢弃该属性。 */
function sanitizeAttribute(name: string, rawValue: string | undefined): string | null {
  const lower = name.toLowerCase();
  if (lower.startsWith("on")) return null;
  if (DROP_ATTRIBUTES.has(lower)) return null;
  if (rawValue === undefined) return name;
  const plain = stripQuotes(rawValue);
  if (URL_ATTRIBUTES.has(lower) && urlIsDangerous(plain)) return null;
  if (lower === "srcset" || lower === "imagesrcset") {
    const candidates = plain.split(",").map((candidate) => candidate.trim().split(/\s+/)[0] ?? "");
    if (candidates.some((candidate) => candidate !== "" && urlIsDangerous(candidate))) return null;
  }
  if (lower === "style" && cssIsDangerous(plain)) return null;
  return `${name}=${rawValue}`;
}

function sanitizeAttributes(source: string): string {
  const parts: string[] = [];
  ATTRIBUTE_PATTERN.lastIndex = 0;
  let match = ATTRIBUTE_PATTERN.exec(source);
  while (match !== null) {
    const cleaned = sanitizeAttribute(match[1], match[2]);
    if (cleaned !== null) parts.push(cleaned);
    match = ATTRIBUTE_PATTERN.exec(source);
  }
  return parts.length === 0 ? "" : ` ${parts.join(" ")}`;
}

function sanitizeTag(name: string, attributeSource: string): string {
  const lower = name.toLowerCase();
  if (DROP_WITH_CONTENT.has(lower) || DROP_TAG_ONLY.has(lower)) return "";
  let attributes = sanitizeAttributes(attributeSource);
  if (lower === "a" && /(^|\s)href\s*=/i.test(attributes)) {
    // sandbox 没有 allow-popups，链接点不动；target/rel 只是兜底，防止将来放宽 sandbox。
    attributes = attributes.replace(/\s(?:target|rel)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'>]+)/gi, "");
    attributes += ' target="_blank" rel="noopener noreferrer"';
  }
  return `<${name}${attributes}>`;
}

function runSanitize(html: string): string {
  let output = html.replace(/<!--[\s\S]*?-->/g, "").replace(/<!--[\s\S]*$/g, "");
  for (const name of DROP_WITH_CONTENT) {
    const paired = new RegExp(`<${name}\\b[^>]*>[\\s\\S]*?<\\/${name}\\s*>`, "gi");
    let previous = "";
    while (previous !== output) {
      previous = output;
      output = output.replace(paired, "");
    }
  }
  output = output.replace(TAG_PATTERN, (_match: string, rawName: string, attributeSource: string): string =>
    sanitizeTag(rawName, attributeSource),
  );
  output = output.replace(/<\/(?:script|noscript|template|iframe|frame|frameset|object|applet|embed|link|base|meta|form|input|button|select|optgroup|option|textarea)\s*>/gi, "");
  output = output.replace(/(<style\b[^>]*>)([\s\S]*?)(<\/style\s*>)/gi, (_match: string, open: string, css: string, close: string): string => {
    // 外部样式由 CSP 拦下，这里再兜一层 @import。
    return `${open}${css.replace(/@import[^;]*;?/gi, "")}${close}`;
  });
  return output.trim();
}

/**
 * 清洗邮件 HTML：去掉可执行 / 可发请求的标签、on* 事件属性与危险链接，保留 <style>。
 * 对畸形输入不抛异常，最坏情况返回空字符串。
 */
export function sanitizeMailHtml(html: string): string {
  if (typeof html !== "string" || html.trim() === "") return "";
  try {
    return runSanitize(html);
  } catch {
    return "";
  }
}

function extractDocumentParts(content: string): { body: string; headStyles: string[] } {
  const isDocument = /<(?:html|head|body)[\s>]/i.test(content);
  if (!isDocument) return { body: content, headStyles: [] };
  const headStyles: string[] = [];
  const bodyStart = content.search(/<body[\s>]/i);
  const headSection = bodyStart >= 0 ? content.slice(0, bodyStart) : content;
  STYLE_PATTERN.lastIndex = 0;
  let styleMatch = STYLE_PATTERN.exec(headSection);
  while (styleMatch !== null) {
    headStyles.push(styleMatch[0]);
    styleMatch = STYLE_PATTERN.exec(headSection);
  }
  if (bodyStart < 0) {
    // 只有 <html>/<head>：整段当正文，但样式已经在 headStyles 里，避免重复。
    const body = content
      .replace(/<\/?(?:html|head|body)\b[^>]*>/gi, "")
      .replace(STYLE_PATTERN, "")
      .trim();
    return { body, headStyles };
  }
  const openEnd = content.indexOf(">", bodyStart);
  const afterOpen = openEnd >= 0 ? content.slice(openEnd + 1) : "";
  const closeIndex = afterOpen.search(/<\/body\s*>/i);
  const raw = closeIndex >= 0 ? afterOpen.slice(0, closeIndex) : afterOpen;
  return { body: raw.replace(/<\/?(?:html|body)\b[^>]*>/gi, "").trim(), headStyles };
}

function contentSecurityPolicy(allowRemoteImages: boolean): string {
  const imageSources = allowRemoteImages ? "img-src data: https: http:" : "img-src data:";
  return `default-src 'none'; ${imageSources}; style-src 'unsafe-inline'`;
}

function wrapDocument(body: string, headStyles: string[], allowRemoteImages: boolean): string {
  return [
    "<!DOCTYPE html>",
    '<html lang="zh-CN">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="referrer" content="no-referrer">',
    `<meta http-equiv="Content-Security-Policy" content="${contentSecurityPolicy(allowRemoteImages)}">`,
    `<style>${BASE_STYLE}</style>`,
    ...headStyles,
    "</head>",
    "<body>",
    body,
    "</body>",
    "</html>",
  ].join("\n");
}

export interface MailDocumentOptions {
  /** 只有用户在提示条上点了「显示图片」才放开远程图片，默认仍只允许 data: 图片。 */
  allowRemoteImages?: boolean;
}

/**
 * 把邮件 HTML 片段包装成可放进 sandbox iframe srcdoc 的完整文档。
 * 完整文档（带 <html>/<body>）会抽出 body 内容并合并 head 里的 <style>。
 * 没有可显示内容时返回空字符串，调用方据此退回纯文本。
 * 对畸形输入不抛异常。
 */
export function buildMailDocument(html: string, options: MailDocumentOptions = {}): string {
  const allowRemoteImages = options.allowRemoteImages === true;
  const safe = sanitizeMailHtml(html);
  if (safe === "") return "";
  try {
    const parts = extractDocumentParts(safe);
    if (parts.body.trim() === "") return "";
    return wrapDocument(parts.body, parts.headStyles, allowRemoteImages);
  } catch {
    return wrapDocument(safe, [], allowRemoteImages);
  }
}

function isRemoteImageUrl(value: string): boolean {
  const trimmed = decodeEntities(value).trim();
  // 协议相对地址（//host/x.png）同样是远程图片。
  return /^(?:https?:)?\/\//i.test(trimmed);
}

function srcsetHasRemoteImage(value: string): boolean {
  return value.split(",").some((candidate) => {
    const url = candidate.trim().split(/\s+/)[0] ?? "";
    return url !== "" && isRemoteImageUrl(url);
  });
}

// CSS 里的 url(https://…)/url(//cdn/…) 同样受 img-src 管辖（营销邮件的铺底图常用它）。
const CSS_REMOTE_URL_PATTERN = /url\(\s*['"]?\s*(?:https?:)?\/\//i;

/**
 * @import 的样式表与 @font-face 的字体都不受 img-src 管辖（点了「显示图片」也不会生效），
 * 先把它们剥掉，避免凭空多出一条假提示。未闭合的 @font-face 按 CSS 恢复规则吃到结尾。
 */
function stripNonImageCssRules(css: string): string {
  return css
    .replace(/@import\b[^;]*;?/gi, " ")
    .replace(/@font-face\b[^{]*\{[^}]*\}/gi, " ")
    .replace(/@font-face\b[\s\S]*$/i, " ");
}

function cssHasRemoteImage(css: string): boolean {
  return CSS_REMOTE_URL_PATTERN.test(stripNonImageCssRules(decodeEntities(css)));
}

function tagHasRemoteImage(tagName: string, attributeSource: string): boolean {
  const isImageTag = tagName === "img" || tagName === "image";
  ATTRIBUTE_PATTERN.lastIndex = 0;
  let match = ATTRIBUTE_PATTERN.exec(attributeSource);
  while (match !== null) {
    const name = match[1].toLowerCase();
    const rawValue = match[2];
    if (rawValue !== undefined) {
      const plain = stripQuotes(rawValue);
      if ((name === "background" || name === "poster") && isRemoteImageUrl(plain)) return true;
      if (name === "style" && cssHasRemoteImage(plain)) return true;
      if (isImageTag && (name === "src" || name === "href" || name === "xlink:href") && isRemoteImageUrl(plain)) return true;
      if (isImageTag && (name === "srcset" || name === "imagesrcset") && srcsetHasRemoteImage(plain)) return true;
    }
    match = ATTRIBUTE_PATTERN.exec(attributeSource);
  }
  return false;
}

function styleBlockHasRemoteImage(html: string): boolean {
  const stylePattern = /<style\b[^>]*>([\s\S]*?)<\/style\s*>/gi;
  let match = stylePattern.exec(html);
  while (match !== null) {
    if (cssHasRemoteImage(match[1] ?? "")) return true;
    match = stylePattern.exec(html);
  }
  return false;
}

/**
 * 正文里是否存在 http(s) 来源的图片引用：img 的 src/srcset、任意标签的 background/poster，
 * 以及 style 属性与 <style> 块里的 url(http…)/url(//…)。
 * data:、cid:、相对路径与 url(#id) 不算远程图片。对畸形输入不抛异常。
 */
export function hasRemoteImages(html: string): boolean {
  if (typeof html !== "string" || html === "") return false;
  try {
    const tagPattern = /<([a-zA-Z][a-zA-Z0-9:_-]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>/g;
    let match = tagPattern.exec(html);
    while (match !== null) {
      if (tagHasRemoteImage(match[1].toLowerCase(), match[2])) return true;
      match = tagPattern.exec(html);
    }
    return styleBlockHasRemoteImage(html);
  } catch {
    return false;
  }
}
