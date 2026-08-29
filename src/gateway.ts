// 登录网关：劫持 dsh 访问入口
//   用户访问网关端口 → 未认证则渲染登录页（dsh 风格 + 动画）
//   → 登录成功 Set-Cookie(JWT, HttpOnly) → 302 回到原始 URL（重定向兼容层）
//   → 已认证请求反向代理到上游 dsh（HTTP + WebSocket，Host 改写为上游地址）
import http, { type IncomingMessage, type IncomingHttpHeaders } from 'node:http';
import https from 'node:https';
import { createSecureContext } from 'node:tls';
import { readFileSync, createReadStream, realpathSync, openSync, fstatSync, closeSync, constants as fsConstants } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { type Duplex, Transform } from 'node:stream';
import zlib from 'node:zlib';
import { URL, fileURLToPath } from 'node:url';
import dns from 'node:dns';
import { createRequire } from 'node:module';
import express, { type Request, type Response } from 'express';

const require = createRequire(import.meta.url);
export const DEFAULT_USER_REQUEST_BODY_BYTES = 64 * 1024 * 1024;
export const ADMIN_REQUEST_BODY_BYTES = 300 * 1024 * 1024;

export function requestBodyLimitFor(role: 'admin' | 'user', allowLargeBody: boolean): number {
  return role === 'admin' || allowLargeBody ? ADMIN_REQUEST_BODY_BYTES : DEFAULT_USER_REQUEST_BODY_BYTES;
}

const WebSocket = require('ws') as {
  OPEN: number;
  WebSocketServer: new (options: { noServer: true }) => {
    handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer, callback: (client: any) => void): void;
  };
};
import type { PlatformConfig } from './config.js';
import { hardenSecretsAfterSetup } from './config.js';
import { AuthService, AuthError, type RequestMeta } from './auth.js';
import { Database, type UserPermissionsRow, type MessageRow } from './db.js';
import {
  folderAllowed,
  normalizePath,
  isWorkspaceRestricted,
  isUploadRequest,
  isGitRequest,
  isAdminOnlyPluginEndpoint,
  isAdminOnlySidebarEndpoint,
  isAionuiFileRead,
  isAionuiFileWrite,
  isAionuiPanel,
  aionuiRootFrom,
  isWorkspaceWrite,
  isWorkspaceCreate,
  isWorkspaceDirectoryCreate,
  isWorkspaceDeleteOrRename,
  extractWorkspaceRenamePaths,
  isStaticAsset,
  isPollingRequest,
  isUsageAnchorRequest,
  WORKSPACE_ENDPOINT_RE,
  extractPathFromBody,
  filterByPathField,
  filterByPathFieldWithPredicate,
  collectIdPathPairs,
  collectSessionCwd,
  collectSessionCwdFromWorkspaces,
  extractWorkspaceId,
  findStringField,
  SESSION_SCOPED_RE,
  extractSessionId,
  collectSessionIds,
  replaceArchivedSessionSnapshot,
  collectArchivedSessionIds,
  filterArchivedSessionIds,
  filterOwnedSessionIds,
  filterSessionItems,
  sandboxPresetRank,
  permissionPresetFromCommand,
  presetFromSettingsMutate,
  forceRejectApproval,
  clampSessionHistorySandbox,
  SANDBOX_RANK,
  isPrivateHost,
  isDangerousUploadName,
  sanitizeText,
  sanitizeHiddenUnicode,
  todayLocal,
  webSocketAccessForPath,
} from './permissions.js';
import { findDshRoot, applyRemotePatch, restartDshWeb } from './patch.js';
import { t, resolveGatewayLang, type Lang } from './i18n.js';
import type { UpdateEngine } from './update.js';

/** 网关内部扩展请求：权限执行时把用户/权限附在 req 上，供后续中间件与代理读取 */
type Req = Request & {
  dshpwUser?: number;
  dshpwPerms?: UserPermissionsRow;
  /** 会话目录白名单校验用：本次请求判定出的目标工作区路径（session.create/fork 时）；
   *  由 needsFolderCheck 写入，供 session.create 响应回调记录 sessionId→cwd 缓存 */
  dshpwSessionCwd?: string;
  /** fork 的源会话已通过逐会话授权校验，响应中的新会话可登记到当前用户快照。 */
  dshpwForkAuthorized?: boolean;
  /** 工作区管理请求通过白名单校验后的目标路径。 */
  dshpwWorkspacePath?: string;
  dshpwWorkspaceCreate?: boolean;
  dshpwWorkspaceOldPath?: string;
  dshpwWorkspaceNewPath?: string;
  dshpwIsAdmin?: boolean;
  /** 当前 create/fork 请求已验证的 agent preset，供成功响应登记。 */
  dshpwAgentPreset?: string;
  dshpwSelectedSessionId?: string;
};

const COOKIE_NAME = 'dsh_gateway_token';
/** 语言偏好 cookie（用户在登录页手动切换后持久化） */
const LANG_COOKIE = 'dshpw_lang';

/** 解析页面语言：?lang → cookie → dsh 设置(locale.preference) → 浏览器语言 → zh */
function langOf(req: Request): Lang {
  return resolveGatewayLang({
    queryLang: req.query.lang,
    cookieLang: readCookie(req.headers.cookie, LANG_COOKIE),
    acceptLanguage: req.headers['accept-language'],
  });
}

/**
 * 注入 dsh HTML 的兼容脚本：
 * crypto.randomUUID 是 Web Crypto API，只在安全上下文（HTTPS / localhost）
 * 存在；明文 HTTP 部署下 dsh 前端的 RPC id 生成（如加载 Agent 预设）会报
 * "crypto.randomUUID is not a function"。这里用 getRandomValues（HTTP 下
 * 可用）实现 UUID v4 补齐。
 */
const INJECT_SCRIPT = `<script>
(function () {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID !== 'function' && typeof crypto.getRandomValues === 'function') {
    crypto.randomUUID = function () {
      var b = crypto.getRandomValues(new Uint8Array(16));
      b[6] = (b[6] & 15) | 64;
      b[8] = (b[8] & 63) | 128;
      var h = Array.prototype.map.call(b, function (x) {
        return x.toString(16).padStart(2, '0');
      }).join('');
      return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
    };
  }
})();
</script>`;

function readCookie(cookieHeader: string | undefined, name: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    // Cookie Chaos 加固（P3）：之前 part.trim() 按 JS Unicode 空白语义裁剪 cookie 名，
    // 导致带 Unicode 空白前缀（U+00A0/U+3000/U+2000/U+0085 等）的“伪同名”cookie 在
    // 单字节 latin1 编码下会被 trim 归一化成目标名读入（行为不一致、依赖编码变异）。
    // 现在只剥离 RFC 6265 允许的 OWS（ASCII SP/HTAB，来自 "; " 分隔符或 cookie-pair
    // 前 OWS），cookie 名其余字符必须与目标精确相等——任何非 ASCII 前缀（含 Unicode
    // 空白与单字节 latin1 变体）都不再可能被归一化匹配，一律 fail-closed。
    const trimmed = part.replace(/^[ \t]+/, '');
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq);
    if (key !== name) continue;
    const value = trimmed.slice(eq + 1);
    if (value === '') continue;
    try {
      return decodeURIComponent(value);
    } catch {
      // 畸形百分号编码（如 %zz）：返回原值，JWT 校验自然失败，不抛 URIError 500
      return value;
    }
  }
  return null;
}

/**
 * 防开放重定向：next 只允许站内路径。
 * 拒绝一切浏览器可能解析成跨域的形式：
 *   - 反斜杠（浏览器按 '/' 解析：/\evil.com → //evil.com 协议相对跳转）
 *   - 解码后以 // 开头（%2F%2F 解码后成 //）
 *   - 非 / 开头、控制字符/空白
 */
function safeNext(next: string | undefined): string {
  if (!next) return '/';
  let decoded: string;
  try {
    decoded = decodeURIComponent(next);
  } catch {
    return '/';
  }
  if (decoded.includes('\\')) return '/';
  if (!decoded.startsWith('/') || decoded.startsWith('//')) return '/';
  if (/[\u0000-\u0020\u007f]/.test(decoded)) return '/';
  return decoded;
}

/**
 * 同源判定（浏览器 Origin vs 请求 Host），网关写路由与登出共用同一口径。
 * 跨源攻击的本质是跨主机（攻击者无法在受害者主机名上托管内容），因此只比
 * 主机:端口、不比协议——否则 nginx/caddy 在 80/443 终结 TLS 的反代部署
 * （网关收到明文 HTTP、req.protocol=http，浏览器 Origin=https）会全部误判。
 * Host 只信直接对端：仅当对端是本机回环（受信本地反代）才采纳 X-Forwarded-Host，
 * 公网直连请求不能带伪造头绕过。无 Origin（非浏览器/旧客户端）返回 true，
 * 由 HttpOnly+SameSite Cookie 兜底。
 */
type OriginRequest = {
  headers: {
    origin?: string | string[];
    host?: string | string[];
    'x-forwarded-host'?: string | string[];
  };
  socket: { remoteAddress?: string | null };
};

function firstHeader(value: string | string[] | undefined): string {
  return Array.isArray(value) ? value[0] ?? '' : value ?? '';
}

function originHostMatches(req: OriginRequest): boolean {
  const originRaw = firstHeader(req.headers.origin);
  if (originRaw === '') return true;
  try {
    const origin = new URL(originRaw);
    if (origin.origin === 'null') return false;
    const peer = req.socket.remoteAddress ?? '';
    const trustedProxy = peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1';
    const forwardedHost = firstHeader(req.headers['x-forwarded-host']).split(',')[0].trim();
    const effectiveHost = trustedProxy && forwardedHost !== '' ? forwardedHost : firstHeader(req.headers.host);
    return origin.host === effectiveHost;
  } catch {
    return false;
  }
}

// ── CSRF（double-submit token）────────────────────────────────
// 登录/配置表单：GET 渲染时下发 Cookie + 表单隐藏域同一随机值，
// POST 时恒定时间比对。无服务端会话也能防跨站表单伪造。
const CSRF_COOKIE = 'dsh_csrf';

function newCsrfToken(secret: string): string {
  // 签名双重提交：token 随机 + HMAC 签名。攻击者即使能自选 cookie 值
  // （子域 cookie tossing 等），不知道密钥也伪造不出合法签名。
  const token = randomBytes(16).toString('hex');
  const sig = createHmac('sha256', secret).update(token).digest('hex').slice(0, 32);
  return `${token}.${sig}`;
}

function csrfMatches(secret: string, cookieValue: string | null, fieldValue: string): boolean {
  if (!cookieValue || !fieldValue) return false;
  const cookie = cookieValue.split('.');
  const field = fieldValue.split('.');
  if (cookie.length !== 2 || field.length !== 2) return false;
  const [cookieToken, cookieSig] = cookie as [string, string];
  const [fieldToken, fieldSig] = field as [string, string];
  // 双重提交：cookie 与表单的 token 必须一致，且签名必须等于服务端 HMAC
  if (cookieToken.length === 0 || cookieToken !== fieldToken) return false;
  const expected = createHmac('sha256', secret).update(cookieToken).digest('hex').slice(0, 32);
  if (expected.length !== cookieSig.length || expected.length !== fieldSig.length) return false;
  return (
    timingSafeEqual(Buffer.from(cookieSig), Buffer.from(fieldSig)) &&
    timingSafeEqual(Buffer.from(cookieSig), Buffer.from(expected))
  );
}

function setCsrfCookie(res: Response, token: string, secure: boolean): void {
  res.setHeader(
    'Set-Cookie',
    `${CSRF_COOKIE}=${token}; Path=/gateway; HttpOnly; SameSite=Lax; Max-Age=3600${
      secure ? '; Secure' : ''
    }`,
  );
}

// ── 主题同步：合理化跟随 dsh 主题 ─────────────────────────────
// dsh 的主题偏好持久化在 <dsh home>/settings.yaml 的 ui-theme.preference
// （light|dark|system，默认 system）。网关在渲染登录/配置页时读取该文件，
// 注入引导脚本在浏览器端解析（system 走 prefers-color-scheme，与 dsh 的
// boot-theme 逻辑一致）。文件不可读时回退 system；可用 MCP_DSH_SETTINGS_FILE
// 显式指定 dsh 设置文件路径（网关与 dsh 不同机时用）。
type ThemePreference = 'light' | 'dark' | 'system';

// 主题偏好每 5 秒最多读一次 settings.yaml：登录/配置页每次渲染都调用本函数，
// 同步磁盘 IO 不应成为每个页面 GET 的固定开销。用户切主题后最多延迟 5 秒生效。
let themePreferenceCache: { value: ThemePreference; at: number } | null = null;
const THEME_CACHE_TTL_MS = 5_000;

function readDshThemePreference(): ThemePreference {
  const now = Date.now();
  if (themePreferenceCache !== null && now - themePreferenceCache.at < THEME_CACHE_TTL_MS) {
    return themePreferenceCache.value;
  }
  const explicit = process.env.MCP_DSH_SETTINGS_FILE?.trim();
  const dshHome = process.env.DSH_HOME?.trim();
  const candidates: string[] = explicit
    ? [explicit]
    : [
        ...(dshHome ? [path.join(dshHome, 'settings.yaml')] : []),
        path.join(os.homedir(), '.dsh', 'settings.yaml'),
      ];
  let value: ThemePreference = 'system';
  for (const file of candidates) {
    try {
      const text = readFileSync(file, 'utf8');
      // settings.yaml 为扁平结构：顶层命名空间键 + 缩进字段（注释可跟在行尾）
      const block = text.match(/^ui-theme\s*:\s*(?:#.*)?$/m);
      if (!block || block.index === undefined) continue;
      const rest = text.slice(block.index);
      const hit = rest.match(/^\s+preference\s*:\s*["']?(light|dark|system)["']?\s*(?:#.*)?$/m);
      if (hit) {
        value = hit[1] as ThemePreference;
        break;
      }
    } catch {
      // 文件不存在/不可读：继续尝试下一个候选，最终回退 system
    }
  }
  themePreferenceCache = { value, at: now };
  return value;
}

/** 主题引导脚本：在 <head> 内尽早设置 data-theme 与 color-scheme，避免闪烁 */
function themeBootScript(preference: ThemePreference): string {
  return `<script>(function(){var pref=${JSON.stringify(preference)};var mq=window.matchMedia&&matchMedia('(prefers-color-scheme: dark)');function apply(){var dark=pref==='dark'||(pref==='system'&&mq&&mq.matches);document.documentElement.setAttribute('data-theme',dark?'dark':'light');document.documentElement.style.colorScheme=dark?'dark':'light';}apply();if(pref==='system'&&mq){try{mq.addEventListener('change',apply)}catch(e){mq.addListener(apply)}}})();</script>`;
}

/**
 * 登录/配置页共享样式：完全采用 dsh 设计令牌（design-platform.css）
 * - 浅色为默认（dsh 默认主题 = 简约白色）：bg #fff、主文字 rgb(15,17,21)、
 *   品牌蓝 rgb(65,118,230)（deepseek-500）、边框 rgba(0,0,0,.1) 等
 * - html[data-theme=dark] 覆盖为 dsh 暗色令牌（neutral-bluish-950 等）
 * - 输入框修复：-webkit-autofill 会把输入栏刷成白色/黄色（粘贴触发布局），
 *   用 inset 大阴影 + text-fill-color 回压为当前主题输入底色
 * - 动画只动 transform/opacity/box-shadow，并尊重 prefers-reduced-motion
 */
const PAGE_STYLE = `
:root{
  --bg:rgb(255,255,255);
  --card:rgba(255,255,255,.94);
  --field:rgb(255,255,255);
  --txt:rgb(15,17,21);
  --sub:rgb(97,102,107);
  --muted:rgb(129,133,140);
  --caption:rgb(173,178,184);
  --border:rgba(0,0,0,.1);
  --border-soft:rgba(0,0,0,.06);
  --border-strong:rgba(0,0,0,.16);
  --brand:rgb(65,118,230);
  --brand-hi:rgb(86,134,254);
  --danger:rgb(242,90,90);
  --danger-soft:rgba(242,90,90,.08);
  --danger-border:rgba(242,90,90,.3);
  --ok:rgb(34,197,94);
  --warn:rgb(247,173,49);
  --warn-soft:rgba(247,173,49,.1);
  --warn-border:rgba(247,173,49,.35);
  --ring:rgba(65,118,230,.16);
  --glow-a:rgba(77,147,248,.18);
  --glow-b:rgba(103,65,217,.09);
  --glow-c:rgba(96,165,250,.11);
  --grid-line:rgba(15,17,21,.03);
  --shadow-card:0 24px 48px -24px rgba(15,23,42,.18),0 2px 8px rgba(15,23,42,.05);
  --shadow-field:0 1px 2px rgba(15,23,42,.05);
  --shadow-btn:0 4px 14px -4px rgba(65,118,230,.5);
}
html[data-theme=dark]{
  --bg:rgb(21,21,23);
  --card:rgba(35,35,36,.92);
  --field:rgb(44,44,46);
  --txt:rgb(249,250,251);
  --sub:rgb(207,211,214);
  --muted:rgb(173,178,184);
  --caption:rgb(129,133,140);
  --border:rgba(255,255,255,.12);
  --border-soft:rgba(255,255,255,.06);
  --border-strong:rgba(255,255,255,.2);
  --brand:rgb(86,134,254);
  --brand-hi:rgb(103,158,254);
  --danger:rgb(242,90,90);
  --danger-soft:rgba(242,90,90,.14);
  --danger-border:rgba(242,90,90,.35);
  --ok:rgb(34,197,94);
  --warn:rgb(247,173,49);
  --warn-soft:rgba(247,173,49,.12);
  --warn-border:rgba(247,173,49,.4);
  --ring:rgba(86,134,254,.28);
  --glow-a:rgba(86,134,254,.15);
  --glow-b:rgba(103,65,217,.13);
  --glow-c:rgba(96,165,250,.09);
  --grid-line:rgba(255,255,255,.025);
  --shadow-card:0 24px 60px -20px rgba(0,0,0,.6);
  --shadow-field:0 1px 2px rgba(0,0,0,.3);
  --shadow-btn:0 4px 18px -4px rgba(86,134,254,.5);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{background:var(--bg);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Hiragino Sans GB','Microsoft YaHei','Helvetica Neue',Helvetica,Arial,sans-serif;display:flex;align-items:center;justify-content:center;overflow:hidden;-webkit-font-smoothing:antialiased}
.orbs{position:fixed;inset:0;overflow:hidden;pointer-events:none;z-index:0}
.orbs i{position:absolute;border-radius:50%;filter:blur(80px);will-change:transform;animation:drift 22s ease-in-out infinite}
.orbs .a{width:46vw;height:46vw;max-width:520px;max-height:520px;left:-12vw;top:-14vh;background:radial-gradient(circle,var(--glow-a),transparent 68%)}
.orbs .b{width:40vw;height:40vw;max-width:440px;max-height:440px;right:-10vw;bottom:-12vh;background:radial-gradient(circle,var(--glow-b),transparent 68%);animation-delay:-7s}
.orbs .c{width:30vw;height:30vw;max-width:320px;max-height:320px;right:16vw;top:-16vh;background:radial-gradient(circle,var(--glow-c),transparent 68%);animation-delay:-13s}
@keyframes drift{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(4vw,3vh) scale(1.08)}66%{transform:translate(-3vw,2vh) scale(.95)}}
.grid{position:fixed;inset:0;pointer-events:none;z-index:0;background-image:linear-gradient(var(--grid-line) 1px,transparent 1px),linear-gradient(90deg,var(--grid-line) 1px,transparent 1px);background-size:44px 44px;-webkit-mask-image:radial-gradient(ellipse 90% 70% at 50% 40%,#000 25%,transparent 78%);mask-image:radial-gradient(ellipse 90% 70% at 50% 40%,#000 25%,transparent 78%)}
.card{position:relative;z-index:10;width:100%;max-width:400px;margin:0 16px;background:var(--card);border:1px solid var(--border-soft);border-radius:16px;padding:32px 32px 28px;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);box-shadow:var(--shadow-card);animation:enter .55s cubic-bezier(.22,1,.36,1) both}
@keyframes enter{from{opacity:0;transform:translateY(20px) scale(.98)}to{opacity:1;transform:translateY(0) scale(1)}}
.logo{width:48px;height:48px;margin:0 auto 16px;border-radius:14px;background:linear-gradient(135deg,var(--brand-hi),var(--brand));display:flex;align-items:center;justify-content:center;box-shadow:0 8px 20px -6px var(--shadow-btn);position:relative}
.logo::after{content:"";position:absolute;inset:-4px;border-radius:18px;border:1px solid var(--ring);opacity:0;animation:ping 4s ease-out infinite}
@keyframes ping{0%{opacity:.7;transform:scale(.92)}55%{opacity:0;transform:scale(1.18)}100%{opacity:0}}
h1{font-size:20px;font-weight:600;letter-spacing:-.01em;text-align:center}
.sub{margin-top:8px;font-size:13px;color:var(--muted);text-align:center;line-height:1.5}
label{display:block;margin-top:14px}
label span{display:block;margin-bottom:6px;font-size:12px;font-weight:500;color:var(--sub)}
input,button{font-family:inherit}
input{width:100%;padding:10px 14px;font-size:14px;line-height:20px;color:var(--txt);background:var(--field);border:1px solid var(--border);border-radius:10px;box-shadow:var(--shadow-field);transition:border-color .16s,box-shadow .16s;caret-color:var(--brand)}
input::placeholder{color:var(--caption)}
input::selection{background:var(--ring)}
input:hover{border-color:var(--border-strong)}
input:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px var(--ring),var(--shadow-field)}
input:-webkit-autofill,input:-webkit-autofill:hover,input:-webkit-autofill:focus{-webkit-text-fill-color:var(--txt);-webkit-box-shadow:0 0 0 1000px var(--field) inset;box-shadow:0 0 0 1000px var(--field) inset;caret-color:var(--txt);transition:background-color 999999s ease-in-out 0s}
button{margin-top:22px;width:100%;padding:10px 16px;font-size:14px;font-weight:500;color:#fff;background:linear-gradient(135deg,var(--brand-hi),var(--brand));border:none;border-radius:10px;cursor:pointer;box-shadow:var(--shadow-btn);transition:transform .16s,box-shadow .16s,filter .16s}
button:hover:not(:disabled){transform:translateY(-1px);filter:brightness(1.06);box-shadow:0 6px 22px -4px var(--shadow-btn)}
button:active:not(:disabled){transform:translateY(0) scale(.99);filter:brightness(.96)}
button:disabled{opacity:.7;cursor:default}
.error-bar{display:none;margin-top:14px;padding:8px 12px;font-size:12px;color:var(--danger);background:var(--danger-soft);border:1px solid var(--danger-border);border-radius:8px;animation:shake .4s}
.db-hint{margin-top:14px;padding:8px 12px;font-size:12px;color:var(--warn);background:var(--warn-soft);border:1px solid var(--warn-border);border-radius:8px}
@keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-10px)}40%{transform:translateX(10px)}60%{transform:translateX(-6px)}80%{transform:translateX(6px)}}
.rules{margin-top:12px;display:flex;flex-wrap:wrap;gap:4px 12px;font-size:11px;color:var(--caption)}
.rules span{display:inline-flex;align-items:center;gap:4px}
.rules span.on{color:var(--ok)}
.strength{height:4px;margin-top:10px;border-radius:999px;background:var(--field);border:1px solid var(--border-soft);overflow:hidden}
.strength i{display:block;height:100%;width:0;border-radius:999px;background:var(--danger);transition:width .32s cubic-bezier(.22,1,.36,1),background .32s}
.lang-switch{position:absolute;top:14px;right:16px;display:flex;gap:12px;font-size:12px}
.lang-switch a{color:var(--caption);text-decoration:none;transition:color .15s}
.lang-switch a:hover{color:var(--sub)}
.lang-switch a.on{color:var(--brand);font-weight:600}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
`;

/** 语言切换链接：中文 / English（当前语言高亮，点击带 ?lang= 走同一个登录路径） */
function langSwitch(lang: Lang, next: string): string {
  const query = next === '' ? '' : `?next=${encodeURIComponent(next)}`;
  const mk = (id: Lang, label: string) =>
    `<a${lang === id ? ' class="on"' : ''} href="/gateway/login${query}${query === '' ? '?' : '&'}lang=${id}">${label}</a>`;
  return `<div class="lang-switch">${mk('zh', '中文')}${mk('en', 'English')}</div>`;
}

/** 页面骨架：共享 head（主题引导 + 样式）+ 背景动画层 + 卡片容器 */
function pageShell(params: { lang: Lang; title: string; body: string; script?: string }): string {
  return `<!doctype html>
<html lang="${params.lang === 'en' ? 'en' : 'zh-CN'}">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${params.title}</title>
${themeBootScript(readDshThemePreference())}
<style>${PAGE_STYLE}</style>
</head>
<body>
<div class="orbs" aria-hidden="true"><i class="a"></i><i class="b"></i><i class="c"></i></div>
<div class="grid" aria-hidden="true"></div>
<div class="card">${params.body}</div>
${params.script ?? ''}
</body>
</html>`;
}

function renderLoginPage(params: { lang: Lang; next: string; error?: string; dbHealthy: boolean; csrf: string }): string {
  const tr = (key: string, tp?: Record<string, string | number>) => t(params.lang, key, tp);
  const errorBlock = params.error
    ? `<div class="error-bar" id="error-bar">${escapeHtml(params.error)}</div>`
    : '';
  const dbHint = params.dbHealthy
    ? ''
    : `<div class="db-hint">${escapeHtml(tr('gw.dbHint'))}</div>`;
  const body = `
  <div class="logo">
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" stroke="white" stroke-width="1.6"/><path d="M8.5 12l2.5 2.5 4.5-5" stroke="white" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
  </div>
  ${langSwitch(params.lang, params.next)}
  <h1>${tr('gw.loginTitle')}</h1>
  <p class="sub">${tr('gw.loginSub1')}<br/>${tr('gw.loginSub2')}</p>
  <form method="POST" action="/gateway/login" id="login-form">
    <input type="hidden" name="csrf" value="${escapeHtml(params.csrf)}" />
    <input type="hidden" name="next" value="${escapeHtml(params.next)}" />
    <label><span>${tr('gw.username')}</span><input type="text" name="username" placeholder="${tr('gw.usernamePlaceholder')}" autocomplete="username" required /></label>
    <label><span>${tr('gw.password')}</span><input type="password" name="password" placeholder="${tr('gw.passwordPlaceholder')}" autocomplete="current-password" required /></label>
    <button type="submit" id="submit-btn">${tr('gw.login')}</button>
  </form>
  ${errorBlock}
  ${dbHint}`;
  return pageShell({
    lang: params.lang,
    title: tr('gw.titleLogin'),
    body,
    script: `<script>
  const err = document.getElementById('error-bar');
  if (err) { setTimeout(() => { err.style.display = 'block'; }, 50); }
  document.getElementById('login-form').addEventListener('submit', () => {
    const btn = document.getElementById('submit-btn');
    btn.textContent = ${JSON.stringify(tr('gw.loggingIn'))};
    btn.disabled = true;
  });
</script>`,
  });
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── 首次配置页（平台未初始化时显示；预设密钥 + 用户名 + 密码） ──
function renderSetupPage(params: { lang: Lang; error?: string; csrf: string }): string {
  const tr = (key: string, tp?: Record<string, string | number>) => t(params.lang, key, tp);
  const errorBlock = params.error
    ? `<div class="error-bar" id="error-bar">${escapeHtml(params.error)}</div>`
    : '';
  const body = `
  <div class="logo"><svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" stroke="white" stroke-width="1.6"/><path d="M8.5 12l2.5 2.5 4.5-5" stroke="white" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
  ${langSwitch(params.lang, '')}
  <h1>${tr('gw.setupTitle')}</h1>
  <p class="sub">${tr('gw.setupSub1')}<br/>${tr('gw.setupSub2')}</p>
  <form method="POST" action="/gateway/setup" id="setup-form">
    <input type="hidden" name="csrf" value="${escapeHtml(params.csrf)}" />
    <label><span>${tr('gw.setupKey')}</span><input type="password" name="setupKey" placeholder="${tr('gw.setupKeyPlaceholder')}" autocomplete="off" required /></label>
    <label><span>${tr('gw.username')}</span><input type="text" name="username" placeholder="${tr('gw.usernameRule')}" autocomplete="username" required /></label>
    <label><span>${tr('gw.password')}</span><input type="password" name="password" id="pw" placeholder="${tr('gw.passwordRule')}" autocomplete="new-password" required /></label>
    <div class="strength"><i id="pw-bar"></i></div>
    <div class="rules" id="pw-rules">
      <span data-r="len">○ ${tr('gw.ruleLen')}</span>
      <span data-r="up">○ ${tr('gw.ruleUp')}</span>
      <span data-r="low">○ ${tr('gw.ruleLow')}</span>
      <span data-r="num">○ ${tr('gw.ruleNum')}</span>
      <span data-r="sym">○ ${tr('gw.ruleSym')}</span>
    </div>
    <label><span>${tr('gw.confirmPassword')}</span><input type="password" name="confirm" placeholder="${tr('gw.confirmPlaceholder')}" autocomplete="new-password" required /></label>
    <button type="submit" id="submit-btn">${tr('gw.initPlatform')}</button>
  </form>
  ${errorBlock}`;
  return pageShell({
    lang: params.lang,
    title: tr('gw.titleSetup'),
    body,
    script: `<script>
  const err = document.getElementById('error-bar');
  if (err) { setTimeout(() => { err.style.display = 'block'; }, 50); }
  const pw = document.getElementById('pw');
  const bar = document.getElementById('pw-bar');
  const COLORS = ['#f25a5a', '#f7ad31', '#f59e0b', '#4d93f8', '#22c55e'];
  pw.addEventListener('input', () => {
    const v = pw.value;
    const rules = {
      len: v.length >= 12, up: /[A-Z]/.test(v), low: /[a-z]/.test(v),
      num: /[0-9]/.test(v), sym: /[^A-Za-z0-9]/.test(v),
    };
    let n = 0;
    document.querySelectorAll('#pw-rules span').forEach((el) => {
      const ok = rules[el.dataset.r];
      if (ok) n++;
      el.className = ok ? 'on' : '';
      el.textContent = (ok ? '✓ ' : '○ ') + el.textContent.replace(/^[✓○] /, '');
    });
    const pct = Math.max(20, (n / 5) * 100);
    bar.style.width = pct + '%';
    bar.style.background = COLORS[Math.max(0, n - 1)];
  });
  document.getElementById('setup-form').addEventListener('submit', (e) => {
    const pwv = pw.value;
    const confirm = document.querySelector('input[name=confirm]').value;
    if (pwv !== confirm) {
      e.preventDefault();
      const err = document.getElementById('error-bar');
      err.textContent = ${JSON.stringify(tr('gw.passwordMismatch'))};
      err.style.display = 'block';
      err.style.animation = 'none';
      void err.offsetWidth;
      err.style.animation = 'shake .4s';
      return;
    }
    const btn = document.getElementById('submit-btn');
    btn.textContent = ${JSON.stringify(tr('gw.initializing'))};
    btn.disabled = true;
  });
</script>`,
  });
}

/**
 * F-A2 隐藏 Unicode 清洗的字节级流（aionui-panel/raw 文本内容用）：
 * 按 UTF-8 字节模式剥离零宽/bidi 等隐形字符序列，跨 chunk 安全。
 * 用 latin1 做 1:1 字节映射，正则匹配字节序列，不破坏任何非目标字节。
 *
 * tail 策略：保留尾部「可能不完整的多字节 UTF-8 序列」——固定保留 3 字节会把
 * 完整零宽序列（如 E2 80 8B）拆散到 body/tail 两侧，永远无法被正则匹配（实测）。
 * 这里从尾部倒查：找到最后一个非续字节（0x80-0xBF 之外），若其声明长度 > 已见
 * 字节数则整体保留，否则全部进 body。
 */
// 目标字符的 UTF-8 字节序列（latin1 字符串形式，逐字节 1:1）
//   E2 80 8B-8F：ZWSP/ZWNJ/ZWJ/LRM/RLM
//   E2 80 AA-AE：LRE/RLE/PDF/LRO/RLO（bidi）
//   E2 81 A0-A9：WJ + 隐形运算符 + 新 bidi 隔离（LRI/RLI/FSI/PDI）
//   EF BB BF：BOM/ZWNBSP
//   C2 AD：软连字符 SHY
//   E1 80 8E：蒙古元音分隔符 MVS
//   CD 8F：组合字连接符 CGJ
//   D8 9C：阿拉伯字母标记 ALM
//   E1 85 9F/A0：谚文填充符
const HIDDEN_BYTES_RE =
  /(?:\xe2\x80[\x8b-\x8f\xaa-\xae]|\xe2\x81[\xa0-\xa9]|\xef\xbb\xbf|\xc2\xad|\xe1\x80\x8e|\xcd\x8f|\xd8\x9c|\xe1\x85[\x9f\xa0])/g;

function stripHiddenUnicodeBytes(buf: Buffer): Buffer {
  return Buffer.from(buf.toString('latin1').replace(HIDDEN_BYTES_RE, ''), 'latin1');
}

function incompleteTailLen(buf: Buffer): number {
  const len = buf.length;
  if (len === 0) return 0;
  const last = buf[len - 1];
  if (last < 0x80) return 0; // ASCII：无跨 chunk 风险
  let n = 0; // 尾部续字节数
  for (let i = len - 1; i >= 0 && i >= len - 4; i--) {
    const b = buf[i];
    if ((b & 0xc0) === 0x80) {
      n++;
      continue;
    }
    let total = 0;
    if ((b & 0xe0) === 0xc0) total = 2;
    else if ((b & 0xf0) === 0xe0) total = 3;
    else if ((b & 0xf8) === 0xf0) total = 4;
    else return 0; // 异常字节：不保留
    const have = n + 1;
    return have < total ? have : 0;
  }
  return n; // 全为续字节（异常）：保留，等下一个首字节再判定
}

function hiddenUnicodeStripStream(): Transform {
  let tail: Buffer = Buffer.alloc(0);
  return new Transform({
    transform(chunk: Buffer, _enc, cb) {
      const buf = tail.length > 0 ? Buffer.concat([tail, chunk]) : chunk;
      const keep = incompleteTailLen(buf);
      const body = buf.subarray(0, buf.length - keep);
      tail = buf.subarray(buf.length - keep);
      cb(null, stripHiddenUnicodeBytes(body));
    },
    flush(cb) {
      cb(null, stripHiddenUnicodeBytes(tail));
    },
  });
}

/** 是否为文本类 content-type（二进制/图片/压缩包不做字节清洗，防损坏） */
function isTextContentType(contentType: string): boolean {
  const t = contentType.split(';')[0].trim().toLowerCase();
  if (t === '') return false;
  if (t.startsWith('text/')) return true;
  return (
    /^application\/(json|xml|javascript|x-www-form-urlencoded|yaml|x-yaml|rtf|graphql|toml|x-toml)(\s*|\+.*)$/.test(t) ||
    /\+json$/.test(t) ||
    /\+xml$/.test(t)
  );
}

/** F-A2：递归清洗 JSON 里所有字符串字段的隐藏 Unicode（read 端点返回文件内容） */
function sanitizeHiddenUnicodeJson(value: unknown, depth = 0): unknown {
  if (depth > 8 || value === null) return value;
  if (typeof value === 'string') return sanitizeHiddenUnicode(value);
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (const item of value) out.push(sanitizeHiddenUnicodeJson(item, depth + 1));
    return out;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) out[k] = sanitizeHiddenUnicodeJson(v, depth + 1);
    return out;
  }
  return value;
}

/**
 * dsh-ssh host SSRF 判定（F-28/F-29，异步版）：
 *   - IP 字面量（含八进制/十六进制/简写段/映射形态）→ isPrivateHost 立即判
 *   - hostname（如 127.0.0.1.nip.io、sslip.io 通配）→ DNS 全量解析后逐地址判定，
 *     任一解析结果命中私网/回环 → 拦截；全部公网 → 返回首个解析 IP 供请求体改写，
 *     把连接目标钉死在已验证地址上，消除「网关判定与插件连接两次解析」的
 *     DNS 重绑定 TOCTOU 窗口。
 *   - 3 秒超时防 DNS 卡死；解析失败/超时一律 fail-closed（返回 null = 拦截）：
 *     无法验证的目标不允许经网关连接，绝不"解析失败即放行"。
 * 返回：'private' = 拦截；IP 字符串 = 校验通过、按它改写 host；null = 解析失败拦截。
 */
function resolveSshHostSafe(host: string): Promise<'private' | string | null> {
  const h = host.trim().toLowerCase();
  if (isPrivateHost(h)) return Promise.resolve('private');
  const lookup = dns.promises
    .lookup(h, { all: true, verbatim: false })
    .then<dns.LookupAddress[] | null>((addrs) => (addrs.length > 0 ? addrs : null))
    .catch(() => null); // 解析失败 = 无法验证 = 拦截（fail-closed）
  const timeout = new Promise<null>((resolve) => setTimeout(() => resolve(null), 3000).unref());
  return Promise.race([lookup, timeout]).then((addrs) => {
    if (addrs === null) return null;
    if (addrs.some((addr) => isPrivateHost(addr.address))) return 'private';
    // verbatim:false 下 Node 已按 RFC6724 排序，首个通常即首选地址
    return addrs[0].address;
  });
}

export function isBackgroundUpdateRequest(gatePath: string): boolean {
  return gatePath === '/api/dsh-passwords/update/status' || gatePath === '/gateway/internal/update';
}

export function createGatewayServer(
  config: PlatformConfig,
  auth: AuthService,
  db: Database,
  updateEngine?: UpdateEngine,
): http.Server {
  const app = express();
  // 两类 WebSocket 路径保持不同权限语义：管理员专用路径不能出现在
  // 子用户授权面；只有 userAllowlist 中的第三方路径可由主用户逐项授权。
  const adminOnlyWebSocketPaths = [...new Set(config.webSocket.adminAllowlist)];
  const userGrantableWebSocketPaths = [...new Set(config.webSocket.userAllowlist)];
  // 不泄露框架信息
  app.disable('x-powered-by');
  // 仅解析 /gateway 表单请求；代理请求的 body 必须原样透传给上游
  // （全局 express.json/urlencoded 会消费掉请求流，导致上游收到空 body）
  app.use('/gateway', express.urlencoded({ extended: false }));

  // CSRF 签名密钥：从 JWT 密钥域分离派生（服务端私有，登录/配置表单的
  // 双重提交令牌用 HMAC 签名——攻击者无法自选 cookie 伪造合法签名）
  const csrfSecret = createHash('sha256').update('dshpw-csrf:' + config.jwtSecret).digest('hex');

  // HTTPS 模式：全站 HSTS（浏览器强制后续走 HTTPS）+ 会话 Cookie 加 Secure
  //（Cookie 标志在登录处理器内按 config.gateway.tls 决定）
  if (config.gateway.tls !== null) {
    app.use((_req, res, next) => {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000');
      next();
    });
  }

  // 受反代/编排器调用的最小健康端点：不返回密钥、用户或上游详情。
  app.get('/gateway/healthz', (_req, res) => {
    res.status(200).json({ ok: true, service: 'dsh-passwords' });
  });
  app.get('/gateway/readyz', async (_req, res) => {
    const healthy = await db.health().catch(() => false);
    res.status(healthy ? 200 : 503).json({ ok: healthy, database: healthy });
  });

  // 登录/配置页安全响应头（仅 /gateway/* 自有页面；代理的 dsh 响应不强制
  // CSP，避免破坏 dsh 前端）：禁嗅探、禁嵌入、无 Referrer、禁缓存、禁索引
  app.use('/gateway', (_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    // 网关标识：客户端插件探测此头判断是否经 dsh-passwords 远程访问
    res.setHeader('X-Dsh-Gateway', '1');
    // 页面完全自包含（内联 CSS/JS、无外部资源）：可以上严格 CSP
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    next();
  });

  const upstream = new URL(config.gateway.upstream);
  const upstreamHost = upstream.hostname;
  const upstreamPort = Number(upstream.port || 80);

  // 上游连接池：复用与 dsh 的 TCP 连接（keep-alive），
  // 避免每个代理请求都新建一次 TCP 握手
  const upstreamAgent = new http.Agent({ keepAlive: true, maxSockets: 64, keepAliveMsecs: 30_000 });

  // workspaceId → 规范路径 映射：从 workspace.list 响应里收集，供 session.create 用 workspaceId 时解析路径
  const workspacePathById = new Map<string, string>();
  // 子用户默认 64 MiB；勾选 allowUpload（大请求体权限）后与 rc.2
  // 上游 carrier cap 对齐到 300 MiB。管理员始终使用 300 MiB。

  // dsh rc.8 将归档状态放在全局 workspace registry；session.list 自身经常不带该字段，
  // 因此在网关实例内保存最近一次可信 workspace.list 快照，避免归档会话掉进 Ungrouped。
  const archivedSessionSnapshot = new Set<string>();
  let archivedSessionSnapshotReady = false;
  let archivedSessionSnapshotRevision = 0;
  let workspaceListRequestRevision = 0;

  // 普通用户各自独立的会话授权快照：不能用全局 sessionId → cwd 映射，
  // 否则一个用户的 workspace.list 会给另一个用户的 session RPC 提供授权依据。
  const userSessionAccess = new Map<number, Map<string, string>>();
  const userSessionAccessRevision = new Map<number, number>();
  const userWorkspaceIds = new Map<number, Set<string>>();
  const userWorkspaceIdsRevision = new Map<number, number>();
  const userSessionAccessFor = (userId: number): Map<string, string> => userSessionAccess.get(userId) ?? new Map();
  const userAccessRevisionFor = (userId: number): number => userSessionAccessRevision.get(userId) ?? 0;
  const replaceUserSessionAccess = (userId: number, access: Map<string, string>, revision: number): void => {
    if (revision < (userSessionAccessRevision.get(userId) ?? 0)) return;
    userSessionAccess.set(userId, access);
    userSessionAccessRevision.set(userId, revision);
  };
  const invalidateUserSessionAccess = (userId: number, revision: number): void => {
    if (revision < (userSessionAccessRevision.get(userId) ?? 0)) return;
    userSessionAccess.delete(userId);
    userSessionAccessRevision.set(userId, revision);
    userWorkspaceIds.delete(userId);
    userWorkspaceIdsRevision.set(userId, revision);
  };
  const replaceUserWorkspaceIds = (userId: number, ids: Set<string>, revision: number): void => {
    if (revision < (userWorkspaceIdsRevision.get(userId) ?? 0)) return;
    userWorkspaceIds.set(userId, ids);
    userWorkspaceIdsRevision.set(userId, revision);
  };

  // sessionId → cwd 映射: 从 session.list/workspace.list/session.create 响应里收集，
  // 供受限子用户的会话作用域 RPC（history/prompt 等）做 cwd 白名单校验——
  // 权限撤销后仍能按 sessionId 直读旧目录会话必须封堵
  const sessionCwdById = new Map<string, string>();
  // 受限子用户的 prompt/fork 必须继承已授权的 agent preset；未知状态不放行。
  // 缓存按用户隔离，避免同一 sessionId 或不同用户的列表响应互相污染授权判断。
  const sessionAgentPresetByUser = new Map<number, Map<string, string>>();
  const sessionAgentPresetMapFor = (userId: number): Map<string, string> => {
    let map = sessionAgentPresetByUser.get(userId);
    if (map === undefined) {
      map = new Map<string, string>();
      sessionAgentPresetByUser.set(userId, map);
    }
    return map;
  };
  const collectSessionAgentPresets = (value: unknown, target: Map<string, string>, depth = 0): void => {
    if (depth > 8 || value === null || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      for (const item of value) collectSessionAgentPresets(item, target, depth + 1);
      return;
    }
    const row = value as Record<string, unknown>;
    const id = typeof row.sessionId === 'string' ? row.sessionId : typeof row.id === 'string' ? row.id : null;
    if (id !== null && typeof row.agentPreset === 'string' && row.agentPreset.length > 0) target.set(id, row.agentPreset);
    for (const child of Object.values(row)) collectSessionAgentPresets(child, target, depth + 1);
  };

  /** 子用户 host SSE 事件按 workspace.list 建立的快照过滤；快照缺失时敏感事件一律丢弃。 */
  const hostEventFilter = (userId: number, perms: UserPermissionsRow): Transform => {
    let pending = '';
    const workspacePathAllowed = (candidate: string): boolean => {
      const currentPerms = db.getPermissions(userId) ?? perms;
      if (!folderAllowed(candidate, currentPerms.allowed_folders)) return false;

      const normalized = normalizePath(candidate);
      return !db.listWorkspaceOwners().some(
        (owner) =>
          owner.userId !== userId &&
          normalizePath(owner.path) === normalized,
      );
    };

    // 连接级工作区快照副本：同一用户并行多个 SSE 连接时，单个连接收到
    // workspace-removed 不得影响其他连接的可见性判断。
    const workspaceIdsForEvent = (): Set<string> | undefined => {
      const snapshot = userWorkspaceIds.get(userId);
      return snapshot === undefined ? undefined : new Set(snapshot);
    };

    const sensitiveTypes = new Set([
      'host/session-added',
      'host/session-removed',
      'host/session-status',
      'host/agent-error',
      'host/workspace-changed',
      'host/workspace-removed',
      'host/workspace-order-changed',
      'host/archived-sessions-changed',
      'host/remote-event',
    ]);
    const filterFrame = (frame: string): string => {
      const normalized = frame.replace(/\r\n/g, '\n');
      const dataLines = normalized.split('\n').filter((line) => line.startsWith('data:'));
      if (dataLines.length === 0) return frame;
      let envelope: Record<string, unknown>;
      try {
        envelope = JSON.parse(dataLines.map((line) => line.slice(5).trimStart()).join('\n')) as Record<string, unknown>;
      } catch {
        return '';
      }
      const payload = envelope.payload;
      if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return '';
      const event = payload as Record<string, unknown>;
      const type = event.type;
      if (typeof type !== 'string' || !sensitiveTypes.has(type)) return '';
      const currentPerms = db.getPermissions(userId) ?? perms;
      const access = userSessionAccess.get(userId);
      const workspaceIds = workspaceIdsForEvent();
      if (access === undefined || workspaceIds === undefined) return '';
      const allowedSession = (id: unknown): id is string =>
        typeof id === 'string' && access.has(id) && !currentPerms.disabled_sessions.includes(id);
      const sessionIdOf = (event: Record<string, unknown>): string | null =>
        typeof event.sessionId === 'string' ? event.sessionId : null;
      if (type === 'host/session-added') {
        if (!allowedSession(event.sessionId)) return '';
        if (typeof event.sessionId === 'string' && typeof event.agentPreset === 'string') {
          sessionAgentPresetMapFor(userId).set(event.sessionId, event.agentPreset);
        }
        delete event.cwd;
        delete event.parentSessionId;
      } else if (
        type === 'host/session-removed' ||
        type === 'host/session-status' ||
        type === 'host/agent-error'
      ) {
        const sessionId = sessionIdOf(event);
        if (sessionId === null || !allowedSession(sessionId)) return '';
      } else if (type === 'host/workspace-changed') {
        const workspace = event.workspace;
        if (workspace === null || typeof workspace !== 'object' || Array.isArray(workspace)) return '';
        const row = workspace as Record<string, unknown>;
        const workspaceId = row.workspaceId;
        const workspacePath = row.path;
        if (
          typeof workspaceId !== 'string' ||
          !workspaceIds.has(workspaceId) ||
          typeof workspacePath !== 'string' ||
          !workspacePathAllowed(workspacePath)
        ) {
          return '';
        }
        if (Array.isArray(row.sessionIds)) row.sessionIds = row.sessionIds.filter(allowedSession);
      } else if (type === 'host/workspace-removed') {
        const id = typeof event.workspaceId === 'string' ? event.workspaceId : event.id;
        if (typeof id !== 'string' || !workspaceIds.has(id)) return '';
      } else if (type === 'host/workspace-order-changed') {
        const ids = event.workspaceIds;
        if (!Array.isArray(ids)) return '';
        event.workspaceIds = ids.filter((id): id is string => typeof id === 'string' && workspaceIds.has(id));
      } else if (type === 'host/archived-sessions-changed') {
        const ids = event.archivedSessionIds;
        if (!Array.isArray(ids)) return '';
        event.archivedSessionIds = ids.filter(allowedSession);
      } else if (type === 'host/remote-event') {
        return '';
      }
      return `data: ${JSON.stringify(envelope)}\n\n`;
    };
    return new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        pending += chunk.toString('utf8');
        const frames = pending.split(/\r?\n\r?\n/);
        pending = frames.pop() ?? '';
        for (const frame of frames) {
          const out = filterFrame(frame);
          if (out !== '') this.push(out);
        }
        callback();
      },
      flush(callback) {
        if (pending !== '') {
          const out = filterFrame(pending);
          if (out !== '') this.push(out);
        }
        callback();
      },
    });
  };

  /** rc.2 WebSocket 下行事件过滤：协议帧是 server-request，客户端不能上行 RPC。 */
  const filterEventWebSocketFrame = (userId: number, perms: UserPermissionsRow, channel: 'host' | 'mux', data: Buffer): Buffer | null => {
    let envelope: Record<string, unknown>;
    try {
      const parsed = JSON.parse(data.toString('utf8')) as unknown;
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
      envelope = parsed as Record<string, unknown>;
    } catch {
      return null;
    }
    if (envelope.type !== 'server-request' || typeof envelope.rpcId !== 'string') return null;
    const payload = envelope.payload;
    if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return null;
    const event = payload as Record<string, unknown>;
    if (envelope.method !== event.type || typeof event.type !== 'string') return null;
    const current = db.getPermissions(userId) ?? perms;
    const access = userSessionAccess.get(userId);
    const workspaceIds = userWorkspaceIds.get(userId);
    const allowedSession = (id: unknown): id is string =>
      typeof id === 'string' && access !== undefined && access.has(id) && !current.disabled_sessions.includes(id);
    if (channel === 'host') {
      if (workspaceIds === undefined || access === undefined) return null;
      const type = event.type;
      if (type === 'host/session-added') {
        if (!allowedSession(event.sessionId)) return null;
        delete event.cwd;
        delete event.parentSessionId;
      } else if (type === 'host/session-removed' || type === 'host/session-status' || type === 'host/agent-error') {
        if (!allowedSession(event.sessionId)) return null;
      } else if (type === 'host/workspace-changed') {
        const workspace = event.workspace;
        if (workspace === null || typeof workspace !== 'object' || Array.isArray(workspace)) return null;
        const row = workspace as Record<string, unknown>;
        if (typeof row.workspaceId !== 'string' || !workspaceIds.has(row.workspaceId) || typeof row.path !== 'string') return null;
        const workspacePath = row.path;
        if (!folderAllowed(workspacePath, current.allowed_folders)) return null;
        if (db.listWorkspaceOwners().some((owner) => owner.userId !== userId && normalizePath(owner.path) === normalizePath(workspacePath))) return null;
        if (Array.isArray(row.sessionIds)) row.sessionIds = row.sessionIds.filter(allowedSession);
      } else if (type === 'host/workspace-removed') {
        const id = typeof event.workspaceId === 'string' ? event.workspaceId : event.id;
        if (typeof id !== 'string' || !workspaceIds.has(id)) return null;
      } else if (type === 'host/workspace-order-changed') {
        if (!Array.isArray(event.workspaceIds)) return null;
        event.workspaceIds = event.workspaceIds.filter((id): id is string => typeof id === 'string' && workspaceIds.has(id));
      } else if (type === 'host/archived-sessions-changed') {
        if (!Array.isArray(event.archivedSessionIds)) return null;
        event.archivedSessionIds = event.archivedSessionIds.filter(allowedSession);
      } else {
        return null;
      }
    } else {
      const allowedTypes = new Set(['session/event', 'session/subscribed', 'approval/requested', 'approval/resolved', 'question/requested', 'question/resolved', 'session/queue', 'session/jobs', 'session/projection']);
      if (!allowedTypes.has(event.type) || !allowedSession(event.sessionId)) return null;
    }
    return Buffer.from(JSON.stringify(envelope), 'utf8');
  };

  /** 子用户 mux SSE 事件按会话授权快照过滤；未知/无归属事件一律丢弃（fail-closed）。 */
  const muxEventFilter = (
    userId: number,
    perms: UserPermissionsRow,
  ): Transform => {
    let pending = '';

    const allowedSession = (sessionId: unknown): boolean => {
      const access = userSessionAccess.get(userId);
      return (
        typeof sessionId === 'string' &&
        access !== undefined &&
        access.has(sessionId) &&
        !perms.disabled_sessions.includes(sessionId)
      );
    };

    const filterFrame = (frame: string): string => {
      const normalized = frame.replace(/\r\n/g, '\n');
      const dataLines = normalized
        .split('\n')
        .filter((line) => line.startsWith('data:'));

      if (dataLines.length === 0) return frame;

      let envelope: Record<string, unknown>;
      try {
        envelope = JSON.parse(
          dataLines.map((line) => line.slice(5).trimStart()).join('\n'),
        ) as Record<string, unknown>;
      } catch {
        return '';
      }

      const payload = envelope.payload;
      if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
        return '';
      }

      const event = payload as Record<string, unknown>;
      const type = event.type;

      if (typeof type !== 'string') return '';

      if (
        type === 'session/event' ||
        type === 'session/subscribed' ||
        type === 'approval/requested' ||
        type === 'approval/resolved' ||
        type === 'question/requested' ||
        type === 'question/resolved' ||
        type === 'session/queue' ||
        type === 'session/jobs' ||
        type === 'session/projection'
      ) {
        return allowedSession(event.sessionId)
          ? `data: ${JSON.stringify(envelope)}\n\n`
          : '';
      }

      // stream/error 没有 sessionId，不能确认租户归属时丢弃。
      if (type === 'stream/error') return '';

      // 未知 mux 类型不能安全判断归属。
      return '';
    };

    return new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        pending += chunk.toString('utf8');
        const frames = pending.split(/\r?\n\r?\n/);
        pending = frames.pop() ?? '';

        for (const frame of frames) {
          const out = filterFrame(frame);
          if (out !== '') this.push(out);
        }

        callback();
      },

      flush(callback) {
        if (pending !== '') {
          const out = filterFrame(pending);
          if (out !== '') this.push(out);
        }

        callback();
      },
    });
  };
  const gatewayRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const configuredRoot = process.env.DSH_PASSWORDS_ENV_FILE?.trim()
    ? path.dirname(path.resolve(process.env.DSH_PASSWORDS_ENV_FILE.trim()))
    : gatewayRoot;

  /**
   * 从 Cookie 校验会话；返回用户或 null（用户已不存在时旧 token 立即失效）。
   * 性能：同一 token 的验签 + 用户存在性查询结果缓存 30 秒——每个代理
   * 请求（含静态资源）都要走鉴权，缓存后只剩一次 Map 查找，避免逐请求
   * 重复 JWT 验签 + SQLite 查询 + HMAC/AES。
   */
  const sessionCache = new Map<
    string,
    { user: { userId: number; username: string }; expireAt: number }
  >();
  const SESSION_CACHE_TTL_MS = 30_000;

  // F-04：登出吊销（内存黑名单）。JWT 无状态，登出只能靠网关侧短期黑名单
  // 使已登出 token 立即失效（TTL 与 JWT 有效期一致，到期自动清理）。
  // 改密/改名已有 credential_version 机制使旧 token 失效，此处只补登出路径。
  // 已知残余（容量权衡）：条目最长保留 12h，持有凭据的用户可反复登录/登出制造
  // 唯一 token 撑大该 Map（成功登录无速率限制）；不能超容量淘汰——未过期条目
  // 必须保持拒绝，否则已登出会话复活。后续可考虑 SQLite TTL 撤销表、随机会话
  // id、或对成功登录/登出加限速（见 PROCESS 步骤 41 残余清单）。
  const revokedTokens = new Map<string, number>();
  const TOKEN_TTL_MS = 12 * 3600 * 1000;

  function revokeToken(token: string): void {
    revokedTokens.set(token, Date.now() + TOKEN_TTL_MS);
    sessionCache.delete(token);
  }

  function isTokenRevoked(token: string): boolean {
    const expiresAt = revokedTokens.get(token);
    if (expiresAt === undefined) return false;
    if (expiresAt > Date.now()) return true;
    revokedTokens.delete(token);
    return false;
  }

  function sessionOf(req: Request): { userId: number; username: string } | null {
    const token = readCookie(req.headers.cookie, COOKIE_NAME);
    if (!token) return null;
    const now = Date.now();
    const hit = sessionCache.get(token);
    if (hit) {
      if (hit.expireAt > now) return hit.user;
      sessionCache.delete(token);
    }
    try {
      const user = auth.verifyToken(token);
      // F-04：登出后的 token 立即拒绝（不重新进入缓存）
      if (isTokenRevoked(token)) return null;
      // 用户被删除/重置/改密后旧会话必须失效（缓存有效期 30 秒内生效）
      const row = db.getUserByUsername(user.username);
      if (row === null) return null;
      if (user.cv !== row.credential_version) return null;
      // 缓存 TTL 与 JWT 到期时间取最小值：否则刚过期就被缓存的 token 会在
      // 命中路径上绕过验签，额外存活最多 30 秒
      const expMs = user.exp !== undefined ? user.exp * 1000 : undefined;
      const cacheTtl =
        expMs !== undefined ? Math.min(SESSION_CACHE_TTL_MS, Math.max(0, expMs - now)) : SESSION_CACHE_TTL_MS;
      if (cacheTtl <= 0) return null; // JWT 已到期：不得进入缓存
      sessionCache.set(token, { user: { userId: user.userId, username: user.username }, expireAt: now + cacheTtl });
      return { userId: user.userId, username: user.username };
    } catch {
      return null;
    }
  }

  /** 子用户权限：缺行时默认关闭全部工作区；已有显式空白名单行仍表示不限目录。 */
  function effectivePermissions(userId: number): UserPermissionsRow {
    return (
      db.getPermissions(userId) ?? {
        user_id: userId,
        // 新子用户默认关闭全部工作区；旧的显式空数组权限行仍保留“不限制”兼容语义。
        allowed_folders: ['__deny__'],
        hourly_token_limit: null,
        daily_minutes_limit: null,
        allow_upload: false,
        allow_workspace_create: false,
        allowed_websocket_paths: [],
        allowed_agent_presets: [],
        // F-12 残余：新子用户默认禁 git 下载（含 dsh-uploads/download 等外带通道），
        // 主用户需要时按需开启；已有权限行的子用户不受影响
        allow_git_download: false,
        banned: false,
        sandbox_mode: null,
        disabled_sessions: [],
        updated_at: '',
      }
    );
  }

  /** 从会话 cookie 解析完整用户（含角色）；无会话/失效返回 null */
  function authedUser(req: Request): { userId: number; username: string; role: 'admin' | 'user' } | null {
    const s = sessionOf(req);
    if (!s) return null;
    const row = db.getUserById(s.userId);
    if (!row) return null;
    return { userId: row.id, username: row.username, role: row.role === 'admin' ? 'admin' : 'user' };
  }

  /** 统一 403 页面（封禁 / 权限拒绝） */
  function forbiddenPage(lang: Lang, message: string): string {
    return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>403</title></head><body style="font-family:system-ui;background:#0f1115;color:#e6e6e6;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h1 style="margin:0 0 8px">403</h1><p style="margin:0;opacity:.7">${escapeHtml(message)}</p></div></body></html>`;
  }

  /** 用量节流：每 15 秒最多写一次活跃时间，返回当前用量（用于配额判定） */
  const usageThrottle = new Map<number, number>();
  function touchUsageThrottled(userId: number) {
    const now = Date.now();
    const day = todayLocal();
    const last = usageThrottle.get(userId) ?? 0;
    if (now - last >= 15000) {
      usageThrottle.set(userId, now);
      return db.touchUsage(userId, day, new Date().toISOString());
    }
    return db.getUsage(userId, day);
  }

  // ── 留言 / 聊天（SSE 广播） ────────────────────────────────
  // 订阅者带 userId，广播时按收件人过滤（与 GET /gateway/api/messages 的
  // 列表语义一致）：定向消息只推给收件人与发件人，公开消息推给所有人。
  const chatClients = new Set<{ res: Response; userId: number }>();
  function broadcastMessage(msg: MessageRow): void {
    const payload = `data: ${JSON.stringify(msg)}\n\n`;
    for (const client of chatClients) {
      const visible =
        msg.recipient_id === null || msg.recipient_id === client.userId || msg.sender_id === client.userId;
      if (!visible) continue;
      try {
        client.res.write(payload);
      } catch {
        chatClients.delete(client);
      }
    }
  }

  // ── 登录页（GET）：平台未初始化时显示首次配置页 ─────────────
  app.get('/gateway/login', async (req, res) => {
    const next = safeNext(typeof req.query.next === 'string' ? req.query.next : undefined);
    const lang = langOf(req);
    const queryLang = typeof req.query.lang === 'string' ? req.query.lang : null;
    const [initialized, dbHealthy] = await Promise.all([
      auth.isInitialized().catch(() => false),
      db.health().catch(() => false),
    ]);
    // 每次渲染下发新 CSRF token（Cookie + 表单隐藏域）
    const csrf = newCsrfToken(csrfSecret);
    setCsrfCookie(res, csrf, config.gateway.tls !== null);
    // 显式 ?lang= 选择持久化到 cookie（语言切换链接点出来的）。
    // 注意 Set-Cookie 头已由 CSRF 占用，这里用数组追加而不是 setHeader 覆盖。
    if (queryLang === 'zh' || queryLang === 'en') {
      const langCookie = `${LANG_COOKIE}=${queryLang}; Path=/gateway; SameSite=Lax; Max-Age=31536000${
        config.gateway.tls !== null ? '; Secure' : ''
      }`;
      const existing = res.getHeader('Set-Cookie');
      const prev: string[] = Array.isArray(existing)
        ? existing.map((value) => String(value))
        : existing
          ? [String(existing)]
          : [];
      res.setHeader('Set-Cookie', [...prev, langCookie]);
    }
    if (!initialized) {
      res.type('html').send(renderSetupPage({ lang, csrf }));
      return;
    }
    res.type('html').send(renderLoginPage({ lang, next, dbHealthy, csrf }));
  });

  // ── 首次配置提交（POST）→ 302 回登录页 ────────────────────────
  // 未初始化阶段 setup 端点对全网匿名可达：按 IP 做滑动窗口限速，防止
  // 匿名狂刷 setup_failure 审计日志（审计表无限增长 → 磁盘耗尽）。
  // 预设密钥为 192 位随机值，暴力破解本身不可行；这里只限速、不防爆破。
  const setupAttempts = new Map<string, number[]>();
  const SETUP_WINDOW_MS = 10 * 60_000;
  const SETUP_MAX_PER_WINDOW = 10;

  app.post('/gateway/setup', async (req, res) => {
    const ipKey = req.ip ?? '';
    const nowTs = Date.now();
    const recent = (setupAttempts.get(ipKey) ?? []).filter((t) => nowTs - t < SETUP_WINDOW_MS);
    if (recent.length >= SETUP_MAX_PER_WINDOW) {
      res.status(429).type('html').send('429 Too Many Requests');
      return;
    }
    recent.push(nowTs);
    setupAttempts.set(ipKey, recent);

    const setupKey = typeof req.body?.setupKey === 'string' ? req.body.setupKey : '';
    const username = typeof req.body?.username === 'string' ? req.body.username : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const meta: RequestMeta = { ip: req.ip, userAgent: req.headers['user-agent'] ?? null };

    // CSRF 校验（double-submit：Cookie 与表单域一致才放行）
    const csrfField = typeof req.body?.csrf === 'string' ? req.body.csrf : '';
    if (!csrfMatches(csrfSecret, readCookie(req.headers.cookie, CSRF_COOKIE), csrfField)) {
      const csrf = newCsrfToken(csrfSecret);
      setCsrfCookie(res, csrf, config.gateway.tls !== null);
      res
        .status(403)
        .type('html')
        .send(renderSetupPage({ lang: langOf(req), error: t(langOf(req), 'gw.csrfFailed'), csrf }));
      return;
    }

    try {
      await auth.setup({ setupKey, username, password }, meta);
      // F-07：初始化成功 → 固话派生密钥 + 轮换 SETUP_KEY + 删 setup-key.txt
      // （失败不阻断初始化，用户仍能进入登录页）
      try {
        hardenSecretsAfterSetup(config);
      } catch (error) {
        console.error('[dsh-passwords] 首次配置密钥加固失败：请立即手动删除 setup-key.txt 并轮换 SETUP_KEY（否则密钥可被派生伪造会话/解密数据）:', error);
      }
      res.redirect(302, '/gateway/login');
    } catch (error) {
      // 真实状态码：409 已初始化 / 401 密钥错误 / 400 参数错误
      const status = error instanceof AuthError ? error.status : 400;
      const lang = langOf(req);
      const message =
        error instanceof AuthError
          ? error.localize(lang)
          : error instanceof Error
            ? error.message
            : t(lang, 'gw.initFailed');
      const csrf = newCsrfToken(csrfSecret);
      setCsrfCookie(res, csrf, config.gateway.tls !== null);
      res.status(status).type('html').send(renderSetupPage({ lang, error: message, csrf }));
    }
  });

  // ── 登录提交（POST） → Set-Cookie + 302 重定向兼容层 ────────
  // 成功登录限速：持有有效凭据的用户可反复登录/登出制造唯一 JWT，撑大
  // revokedTokens 撤销表（12h TTL，不可超容量淘汰）——每用户名每分钟最多
  // 10 次成功登录（正常多设备使用远低于此）。只在成功后计数：无凭据者
  // 无法用它锁定受害者用户名。
  const loginSuccessRate = new Map<string, number[]>();
  const LOGIN_SUCCESS_MAX_PER_MIN = 10;

  app.post('/gateway/login', async (req, res) => {
    const next = safeNext(typeof req.body?.next === 'string' ? req.body.next : undefined);
    const username = typeof req.body?.username === 'string' ? req.body.username : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const meta: RequestMeta = { ip: req.ip, userAgent: req.headers['user-agent'] ?? null };

    // CSRF 校验（double-submit：Cookie 与表单域一致才放行）
    const csrfField = typeof req.body?.csrf === 'string' ? req.body.csrf : '';
    if (!csrfMatches(csrfSecret, readCookie(req.headers.cookie, CSRF_COOKIE), csrfField)) {
      const dbHealthy = await db.health().catch(() => false);
      const csrf = newCsrfToken(csrfSecret);
      setCsrfCookie(res, csrf, config.gateway.tls !== null);
      res
        .status(403)
        .type('html')
        .send(
          renderLoginPage({ lang: langOf(req), next, error: t(langOf(req), 'gw.csrfFailed'), dbHealthy, csrf }),
        );
      return;
    }

    try {
      const { token, username: loggedInAs } = await auth.login({ username, password }, meta);
      const nowTs = Date.now();
      const recent = (loginSuccessRate.get(loggedInAs) ?? []).filter((t) => nowTs - t < 60_000);
      if (recent.length >= LOGIN_SUCCESS_MAX_PER_MIN) {
        loginSuccessRate.set(loggedInAs, recent);
        const dbHealthy = await db.health().catch(() => false);
        const csrf = newCsrfToken(csrfSecret);
        setCsrfCookie(res, csrf, config.gateway.tls !== null);
        res
          .status(429)
          .type('html')
          .send(renderLoginPage({ lang: langOf(req), next, error: '登录过于频繁，请稍后再试', dbHealthy, csrf }));
        return;
      }
      recent.push(nowTs);
      loginSuccessRate.set(loggedInAs, recent);
      res.setHeader(
        'Set-Cookie',
        `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${
          config.gateway.tls !== null ? '; Secure' : ''
        }`,
      );
      // 中文/非 ASCII 路径需重新编码（Node 的 Location 头只接受 latin1，
      // 直接 setHeader 会抛 ERR_INVALID_CHAR → 500）
      res.redirect(302, encodeURI(next));
    } catch (error) {
      // 真实状态码：429 锁定 / 401 凭据错误 / 400 其他
      const status = error instanceof AuthError ? error.status : 400;
      const lang = langOf(req);
      const message =
        error instanceof AuthError
          ? error.localize(lang)
          : error instanceof Error
            ? error.message
            : t(lang, 'gw.loginFailed');
      const dbHealthy = await db.health().catch(() => false);
      const csrf = newCsrfToken(csrfSecret);
      setCsrfCookie(res, csrf, config.gateway.tls !== null);
      res.status(status).type('html').send(renderLoginPage({ lang, next, error: message, dbHealthy, csrf }));
    }
  });

  // ── 登出（F-24：仅 POST，杜绝 <img>/<form> 跨站 GET 强制登出 CSRF） ──
  // SameSite=Lax 的会话 Cookie 不会被跨站 POST 携带，GET 又已移除，
  // 因此跨站无法再伪造登出请求；同源场景本就是可信上下文。
  // GET 显式回 405（而不是掉到 SPA 代理回 200，避免语义含糊）。
  app.get('/gateway/logout', (_req, res) => {
    res.status(405).type('html').send('405 Method Not Allowed');
  });
  app.post('/gateway/logout', (req, res) => {
    // 同站子域页面可借表单强制登出（SameSite=Lax 只挡跨站、不挡同站子域）：
    // 与网关写路由同口径做 Origin 主机校验，提交方与 Host 不一致时拒绝。
    if (!originHostMatches(req)) {
      res.status(403).type('text/plain').send('403 Forbidden');
      return;
    }
    // F-04：服务端吊销——登出的 token 立即失效（黑名单 12h），
    // 即使 Cookie 已被攻击者复制，该 token 也无法再通过认证门卫
    const token = readCookie(req.headers.cookie, COOKIE_NAME);
    if (token) revokeToken(token);
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
    res.redirect(302, '/gateway/login');
  });

  // ── 内部接口：dsh 插件通知网关重载远程设置补丁 ───────────────
  // 仅限本机 dsh 插件调用：要求回环地址 + 恒定时间比对内部密钥
  // （密钥由 SETUP_KEY 派生，泄漏面与安装密钥一致）。响应立即返回，
  // 补丁应用与 dsh 重启异步进行，让设置页的响应先刷给浏览器。
  app.post('/gateway/internal/patch', express.json({ limit: '4kb' }), (req, res) => {
    const remoteIp = req.socket.remoteAddress ?? '';
    if (remoteIp !== '127.0.0.1' && remoteIp !== '::1' && remoteIp !== '::ffff:127.0.0.1') {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    const secret = typeof req.headers['x-internal-secret'] === 'string' ? req.headers['x-internal-secret'] : '';
    const expected = config.internalSecret;
    const a = Buffer.from(secret);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    res.status(202).json({ ok: true });
    setTimeout(() => {
      try {
        const root = findDshRoot(config.patch.dshRoot);
        if (!root) return;
        const result = applyRemotePatch(root);
        if (result === 'applied' && config.patch.restartService) {
          restartDshWeb(config.patch.restartService, 800);
        }
      } catch (error) {
        console.error('[dsh-passwords] 补丁重载失败:', error);
      }
    }, 500);
  });

  // ── 内部接口：dsh 插件通知网关立即失效某用户的会话缓存 ─────
  // 改密/改名/删除用户后，JWT 的 cv 校验要等 30 秒缓存 TTL 才重新查库；
  // 此接口让插件在操作成功后通知网关同步清理该用户的缓存条目，撤销窗口归零。
  app.post('/gateway/internal/session-invalidate', express.json({ limit: '4kb' }), (req, res) => {
    const remoteIp = req.socket.remoteAddress ?? '';
    if (remoteIp !== '127.0.0.1' && remoteIp !== '::1' && remoteIp !== '::ffff:127.0.0.1') {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    const secret = typeof req.headers['x-internal-secret'] === 'string' ? req.headers['x-internal-secret'] : '';
    const expected = config.internalSecret;
    const a = Buffer.from(secret);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    const body = (req.body ?? {}) as Record<string, unknown>;
    const userId = typeof body.userId === 'number' && Number.isSafeInteger(body.userId) ? body.userId : null;
    if (userId !== null) {
      for (const [token, entry] of sessionCache) {
        if (entry.user.userId === userId) sessionCache.delete(token);
      }
    }
    res.status(200).json({ ok: true });
  });

  // ── 内部接口：自动更新引擎（插件经内部通道调用） ───────
  // 仅限本机 dsh 插件调用（回环 + 恒定时间比对内部密钥）。action：
  //   status — 查询引擎状态（当前/最新版本、下载进度、空闲窗剩余、手动命令）
  //   check  — 立即检查 GitHub 最新 release（只发现版本，不下载）
  //   apply  — 按更新状态机下载或安装（主用户按钮触发）
  //   set-auto — 持久化自动更新开关（仅主用户通过插件调用）
  if (updateEngine !== undefined) {
    app.post('/gateway/internal/update', express.json({ limit: '4kb' }), async (req, res) => {
      const remoteIp = req.socket.remoteAddress ?? '';
      if (remoteIp !== '127.0.0.1' && remoteIp !== '::1' && remoteIp !== '::ffff:127.0.0.1') {
        res.status(403).json({ ok: false, error: 'forbidden' });
        return;
      }
      const secret = typeof req.headers['x-internal-secret'] === 'string' ? req.headers['x-internal-secret'] : '';
      const expected = config.internalSecret;
      const a = Buffer.from(secret);
      const b = Buffer.from(expected);
      if (a.length !== b.length || !timingSafeEqual(a, b)) {
        res.status(403).json({ ok: false, error: 'forbidden' });
        return;
      }
      const body = (req.body ?? {}) as Record<string, unknown>;
      const action = typeof body.action === 'string' ? body.action : '';
      if (action === 'status') {
        res.json({ ok: true, status: updateEngine.status() });
        return;
      }
      if (action === 'check') {
        // 手动检查只发现版本；设置页轮询状态展示结果。
        void updateEngine.checkNow({ downloadIfAllowed: false }).catch(() => undefined);
        res.json({ ok: true, started: true });
        return;
      }
      if (action === 'apply') {
        // applyNow 自带 ok/code/message（含冷却与未就绪分支）
        res.json(await updateEngine.applyNow());
        return;
      }
      if (action === 'set-auto') {
        if (typeof body.enabled !== 'boolean') {
          res.status(400).json({ ok: false, code: 'INVALID', error: 'enabled 必须为布尔值' });
          return;
        }
        const effective = updateEngine.setAutoUpdateEnabled(body.enabled);
        res.json({ ok: true, requested: body.enabled, enabled: effective, status: updateEngine.status() });
        return;
      }
      res.status(400).json({ ok: false, code: 'INVALID', error: 'action 无效' });
    });
  }

  // ── 内部辅助：API 路由的输入清洗 ───────────────────────────
  // 严格非负整数：拒绝 1e3/0x10/小数/负数/超大值（之前 Number() 静默接受科学
  // 计数与十六进制，1e21 等超大值在 SQLite 64 位整数绑定里精度失真）。
  // Number.isSafeInteger 封顶 2^53-1，天然低于 int64 上限。
  const nullableInt = (v: unknown): number | null => {
    if (typeof v === 'number') {
      return Number.isSafeInteger(v) && v >= 0 ? v : null;
    }
    if (typeof v === 'string') {
      const t = v.trim();
      if (t === '') return null;
      if (!/^\d+$/.test(t)) return null;
      const n = Number(t);
      return Number.isSafeInteger(n) && n >= 0 ? n : null;
    }
    return null;
  };
  const stringArray = (v: unknown, max = 64): string[] =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').slice(0, max) : [];

  // 统一 API 鉴权：跨站拒绝 + 会话校验 + 可选主用户门控
  const apiAuth = (req: Request, res: Response, requireAdmin = false) => {
    if (req.headers['sec-fetch-site'] === 'cross-site') {
      res.status(403).json({ ok: false, code: 'FORBIDDEN_CSRF', error: 'forbidden' });
      return null;
    }
    const user = authedUser(req);
    if (!user) {
      res.status(401).json({ ok: false, code: 'NOT_AUTHENTICATED', error: '未登录或会话已失效' });
      return null;
    }
    if (user.role !== 'admin' && effectivePermissions(user.userId).banned) {
      res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '账号已被封禁' });
      return null;
    }
    if (requireAdmin && user.role !== 'admin') {
      res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '仅主用户可操作' });
      return null;
    }
    return user;
  };

  const jsonBody = express.json({ limit: '256kb' });

  // token 用量上报节流（客户端 15 秒 flush 一次；这里再加 5 秒最小间隔，防高频自刷）。
  // 声明在权限路由之前：permissions 路由改配额时会清理该缓存。
  const usageReportThrottle = new Map<number, number>();

  // ── 概览（仅主用户）：所有用户 + 权限 + 当日用量 ─────────────
  app.get('/gateway/api/overview', (req, res) => {
    const me = apiAuth(req, res, true);
    if (!me) return;
    const day = todayLocal();
    const registeredUserWebSocketPaths = new Set(userGrantableWebSocketPaths);
    const users = db.listUsers().map((u) => {
      const perms = effectivePermissions(u.id);
      const allowedWebSocketPaths = perms.allowed_websocket_paths.filter((rule) => registeredUserWebSocketPaths.has(rule));
      const usage = db.getUsage(u.id, day);
      return {
        id: u.id,
        username: u.username,
        role: u.role,
        permissions: {
          allowedFolders: perms.allowed_folders,
          hourlyTokenLimit: perms.hourly_token_limit,
          dailyMinutesLimit: perms.daily_minutes_limit,
          allowUpload: perms.allow_upload,
          allowGitDownload: perms.allow_git_download,
          allowWorkspaceCreate: perms.allow_workspace_create,
          allowedWebSocketPaths,
          allowedAgentPresets: perms.allowed_agent_presets,
          banned: perms.banned,
          sandboxMode: perms.sandbox_mode,
          disabledSessions: perms.disabled_sessions,
          allowedSessionIds: db.listUserSessionGrants(u.id),
        },
        usage: usage
          ? {
              day: usage.day,
              activeSeconds: usage.active_seconds,
              hourlyTokens: usage.hourly_tokens,
              firstSeenAt: usage.first_seen_at,
              lastActiveAt: usage.last_active_at,
            }
          : null,
      };
    });
    res.json({
      ok: true,
      me: { id: me.userId, username: me.username, role: me.role },
      availableWebSocketPaths: userGrantableWebSocketPaths,
      adminOnlyWebSocketPaths,
      users,
    });
  });

  // ── 远程文件下载（Issue #4）──────────────────────────────────
  // 经网关远程访问时，点击对话里的“生成文件”标签不再在服务器容器里执行
  // xdg-open（无桌面环境 → spawn xdg-open ENOENT），而是下载到当前浏览器。
  // 安全约束（按执行顺序）：
  //  1. 仅已登录用户（apiAuth）
  //  2. 规范化 + realpath 后再校验，防 ../ 与符号链接逃逸
  //  3. 子用户需开启下载开关，且只能下载 allowedFolders 白名单内的文件（folderAllowed）
  //  4. 屏蔽敏感路径：DSH 根目录、数据库、部署目录（盖 .env/data/dist）、SSH 凭据、OS 系统目录
  //  5. 仅普通文件（拒绝目录/设备/socket），并锁定 fd 防路径替换后再读取
  //  6. 支持 GET（流式）+ HEAD
  app.get('/gateway/api/download', (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    const rawPath = typeof req.query.path === 'string' ? req.query.path : '';
    if (rawPath === '') {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'path 无效' });
      return;
    }

    // 1) 规范化 + 绝对路径（防 ../ 与编码变体）
    const abs = path.resolve(rawPath);
    // 2) realpath 后再校验（防符号链接逃逸；文件不存在也在此失败）
    let real: string;
    try {
      real = realpathSync(abs);
    } catch {
      res.status(404).json({ ok: false, code: 'NOT_FOUND', error: '文件不存在' });
      return;
    }

    // 3) 下载开关与目录白名单：管理员是平台运维者，跳过 tenant folder allowlist，
    // 但不跳过认证、realpath、敏感路径和普通文件检查。
    if (me.role !== 'admin') {
      const perms = effectivePermissions(me.userId);
      if (!perms.allow_git_download) {
        res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '未开启文件下载' });
        return;
      }
      if (!folderAllowed(real, perms.allowed_folders)) {
        res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '目录越权' });
        return;
      }
    }

    // 4) 敏感路径屏蔽：DSH_HOME（会话/设置/凭据）、数据库、部署目录（盖 .env/data/dist）、
    //    本机 SSH 凭据、OS 系统目录（/etc /proc /sys /dev —— 永不会是工作区文件）
    const dbReal = (() => {
      try {
        return realpathSync(config.dbPath);
      } catch {
        return path.resolve(config.dbPath);
      }
    })();
    const home = os.homedir();
    const dshHome = process.env.DSH_HOME !== undefined && process.env.DSH_HOME !== ''
      ? path.resolve(process.env.DSH_HOME)
      : path.join(home, '.dsh');
    // dsh 安装根：显式配置或自动探测（npm root -g/@deepseek-ai/dsh）；
    // 用 findDshRoot 而不是直接读 config.patch.dshRoot，因为它可能是空（自动探测）
    const resolvedDshRoot = findDshRoot(config.patch.dshRoot);
    const sensitiveBases: string[] = [
      gatewayRoot,
      configuredRoot,
      dbReal,
      path.dirname(dbReal),
      // 部署目录（dbPath 的 data/ 再上一级）：盖住 .env / dist / scripts
      path.dirname(path.dirname(dbReal)),
      resolvedDshRoot !== null ? resolvedDshRoot : '',
      dshHome,
      path.join(home, '.ssh'),
      ...(process.platform === 'win32' ? [] : ['/etc', '/proc', '/sys', '/dev', '/boot']),
    ].filter((p) => p !== '');
    const isSensitive = (p: string): boolean =>
      sensitiveBases.some((base) => p === base || p.startsWith(base + path.sep));
    if (isSensitive(real)) {
      res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '敏感文件不可下载' });
      return;
    }

    // 5) 打开并锁定文件描述符：后续 HEAD/GET 都从同一个 fd 读取，避免
    // realpath/stat 之后再次按路径打开时被替换成另一文件。Linux 额外使用
    // O_NOFOLLOW 拒绝最终组件符号链接；Windows 没有等价的通用 flag。
    let fd: number;
    let st;
    try {
      const noFollow = process.platform === 'win32' ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
      fd = openSync(real, fsConstants.O_RDONLY | noFollow);
      st = fstatSync(fd);
    } catch {
      res.status(404).json({ ok: false, code: 'NOT_FOUND', error: '文件不存在' });
      return;
    }
    if (!st.isFile()) {
      closeSync(fd);
      res.status(400).json({ ok: false, code: 'INVALID', error: '不是普通文件' });
      return;
    }

    // 6) 响应：GET 流式下载；HEAD 仅返回头（供客户端探测路径/权限）
    const name = path.basename(real);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(name)}`);
    res.setHeader('Content-Length', String(st.size));
    if (req.method === 'HEAD') {
      closeSync(fd);
      res.end();
      return;
    }
    const stream = createReadStream(real, { fd, autoClose: true });
    stream.on('error', () => {
      if (!res.headersSent) res.status(500).json({ ok: false, code: 'INTERNAL', error: '读取失败' });
      else res.destroy();
    });
    stream.pipe(res);
  });

  // ── 更新某子用户权限（仅主用户） ─────────────────────────────
  app.post('/gateway/api/permissions', jsonBody, (req, res) => {
    const me = apiAuth(req, res, true);
    if (!me) return;
    const body = (req.body ?? {}) as Record<string, unknown>;
    const userId = Number(body.userId);
    if (!Number.isInteger(userId) || userId <= 0) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'userId 无效' });
      return;
    }
    const target = db.getUserById(userId);
    if (!target) {
      res.status(404).json({ ok: false, code: 'NO_SUCH_USER', error: '用户不存在' });
      return;
    }
    if (target.role === 'admin') {
      res.status(400).json({ ok: false, code: 'FORBIDDEN', error: '不能修改主用户权限' });
      return;
    }
    // `__deny__` 是本插件用于表达“不给任何工作区”的唯一内部哨兵值。前端在
    // 关闭最后一个工作区时会提交它；此前它被下面的绝对路径校验误判，导致保存
    // 权限时显示“输入无效”。哨兵只能单独出现，不能与真实目录混用。
    if (!Array.isArray(body.allowedFolders) || body.allowedFolders.some((folder) => typeof folder !== 'string')) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '允许的工作区必须是路径数组' });
      return;
    }
    const allowedFolders = stringArray(body.allowedFolders);
    const denyAll = allowedFolders.length === 1 && allowedFolders[0] === '__deny__';
    // 空字符串、当前目录和根目录会被 folderAllowed 归一为“全盘允许”，与 UI 的
    // “允许的工作区”语义相反；显式拒绝，管理员应使用空数组表示不限制。
    if (!denyAll && allowedFolders.some((folder) => {
      const trimmed = folder.trim().replace(/\\/g, '/');
      return (
        trimmed === '' ||
        trimmed === '.' ||
        trimmed === '/' ||
        (!(trimmed.startsWith('/') || /^[A-Za-z]:\//.test(trimmed))) ||
        /(^|\/)\.\.?($|\/)/.test(trimmed) ||
        normalizePath(trimmed) === '/' ||
        normalizePath(trimmed) === '.' ||
        /^[a-z]:\/$/i.test(normalizePath(trimmed))
      );
    })) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '允许的工作区不能包含空路径、当前目录或根目录' });
      return;
    }
    // 0 归一为 null（=不限）：避免"每日 0 分钟"被误当作"首次使用即封禁"
    const rawToken = nullableInt(body.hourlyTokenLimit);
    const rawMinutes = nullableInt(body.dailyMinutesLimit);
    const hourlyTokenLimit = rawToken === 0 ? null : rawToken;
    const dailyMinutesLimit = rawMinutes === 0 ? null : rawMinutes;
    const currentPermissions = effectivePermissions(userId);
    const readBooleanPermission = (name: string, value: unknown, current: boolean): boolean | null => {
      if (value === undefined) return current;
      if (typeof value !== 'boolean') {
        res.status(400).json({ ok: false, code: 'INVALID', error: `${name} 必须是布尔值` });
        return null;
      }
      return value;
    };
    const allowUpload = readBooleanPermission('allowUpload', body.allowUpload, currentPermissions.allow_upload);
    if (allowUpload === null) return;
    const allowGitDownload = readBooleanPermission('allowGitDownload', body.allowGitDownload, currentPermissions.allow_git_download);
    if (allowGitDownload === null) return;
    const allowWorkspaceCreate = readBooleanPermission('allowWorkspaceCreate', body.allowWorkspaceCreate, currentPermissions.allow_workspace_create);
    if (allowWorkspaceCreate === null) return;
    const banned = readBooleanPermission('banned', body.banned, currentPermissions.banned);
    if (banned === null) return;
    const rawSandbox = typeof body.sandboxMode === 'string' ? body.sandboxMode : '';
    const sandboxMode =
      rawSandbox === 'read-only' || rawSandbox === 'workspace-write' || rawSandbox === 'danger-full-access'
        ? rawSandbox
        : null;
    const submittedAgentPresets = body.allowedAgentPresets;
    if (submittedAgentPresets !== undefined && submittedAgentPresets !== null && !Array.isArray(submittedAgentPresets)) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'Agent preset 权限必须是数组或 null' });
      return;
    }
    if (
      Array.isArray(submittedAgentPresets) &&
      (submittedAgentPresets.length > 256 || submittedAgentPresets.some((id) => typeof id !== 'string' || id.length === 0 || id.length > 200))
    ) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'Agent preset 权限列表无效' });
      return;
    }
    const allowedAgentPresets = submittedAgentPresets === undefined
      ? currentPermissions.allowed_agent_presets
      : submittedAgentPresets === null
        ? null
        : [...new Set(submittedAgentPresets as string[])];
    const submittedWebSocketPaths = body.allowedWebSocketPaths;
    if (submittedWebSocketPaths !== undefined && !Array.isArray(submittedWebSocketPaths)) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'WebSocket 权限必须是路径数组' });
      return;
    }
    if (
      submittedWebSocketPaths !== undefined &&
      (submittedWebSocketPaths.length > 64 || submittedWebSocketPaths.some((value) => typeof value !== 'string'))
    ) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'WebSocket 权限列表无效' });
      return;
    }
    const registeredWebSocketPaths = new Set(userGrantableWebSocketPaths);
    const existingWebSocketPaths = currentPermissions.allowed_websocket_paths
      .filter((rule) => registeredWebSocketPaths.has(rule));
    const allowedWebSocketPaths = submittedWebSocketPaths === undefined
      ? existingWebSocketPaths
      : [...new Set(submittedWebSocketPaths as string[])];
    const disabledSessions = stringArray(body.disabledSessions, 2000)
      .filter((id) => id.length > 0 && id.length <= 200);
    if (body.allowedSessionIds !== undefined && !Array.isArray(body.allowedSessionIds)) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '允许的会话必须是数组' });
      return;
    }
    if (
      Array.isArray(body.allowedSessionIds) &&
      (body.allowedSessionIds.length > 2000 || body.allowedSessionIds.some(
        (id) => typeof id !== 'string' || id.length === 0 || id.length > 200,
      ))
    ) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '允许的会话列表无效' });
      return;
    }
    const allowedSessionIds = body.allowedSessionIds === undefined
      ? db.listUserSessionGrants(userId)
      : [...new Set(body.allowedSessionIds as string[])];
    if (allowedWebSocketPaths.some((rule) => !registeredWebSocketPaths.has(rule))) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'WebSocket 权限必须来自服务器已登记的用户路径' });
      return;
    }
    // 配额语义："改配额 = 重新给额度"——当 token/时长上限发生变化时
    // 重置该子用户已累计的用量（不同子用户每时段用量不同，改上限应重新计）。
    // 只改文件夹/上传/封禁等非配额字段时不重置（避免误清用量）。
    const prevPerms = effectivePermissions(userId);
    const quotaChanged =
      prevPerms.hourly_token_limit !== hourlyTokenLimit || prevPerms.daily_minutes_limit !== dailyMinutesLimit;
    db.setPermissions(userId, {
      allowedFolders,
      hourlyTokenLimit,
      dailyMinutesLimit,
      allowUpload,
      allowGitDownload,
      allowWorkspaceCreate,
      allowedWebSocketPaths,
      allowedAgentPresets,
      banned,
      sandboxMode,
      disabledSessions,
      allowedSessionIds,
    });
    // 权限行与显式 grant 已在数据库层同一事务提交成功后，才失效旧访问快照。
    // 管理员显式保存（含故意置空=回收全部）后标记已初始化，避免后续被重新种子化。
    db.markSessionGrantsSeeded(userId);
    // 工作区白名单、禁用会话、显式 grant 或封禁状态变化后，旧会话授权快照不能继续生效；
    // 递增全局请求序号，让在此之前发出的 workspace.list 响应也不能恢复旧授权。
    invalidateUserSessionAccess(userId, ++workspaceListRequestRevision);
    if (quotaChanged) {
      db.resetUsage(userId);
      // 清掉内存节流缓存：否则 15 秒节流可能跳过新记录的创建，配额暂时不生效
      usageThrottle.delete(userId);
      usageReportThrottle.delete(userId);
    }
    db.audit('permissions_changed', {
      username: target.username,
      detail: JSON.stringify({
        allowedFolders,
        hourlyTokenLimit,
        dailyMinutesLimit,
        allowUpload,
        allowGitDownload,
        allowWorkspaceCreate,
        allowedWebSocketPaths,
        allowedAgentPresets,
        banned,
        sandboxMode,
        disabledSessions,
        allowedSessionIds,
      }),
    });
    res.json({
      ok: true,
      allowedFolders,
      allowedSessionIds: db.listUserSessionGrants(userId),
      disabledSessions,
    });
  });


  // ── token 用量上报（客户端 liveTokenUsage 投影增量，所有登录用户） ──
  // 替代旧的 HTTP 响应正则计量：客户端复用 dsh 的 tokenUsage 投影（与
  // dsh-web-ui 同源），只上报「增量」，服务端按小时窗口累计并用于配额判定。
  app.post('/gateway/api/usage/report', jsonBody, (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    const now = Date.now();
    const last = usageReportThrottle.get(me.userId) ?? 0;
    if (now - last < 5000) {
      res.status(429).json({ ok: false, code: 'RATE_LIMITED', error: '上报过于频繁' });
      return;
    }
    usageReportThrottle.set(me.userId, now);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const tokens = Number(body.tokens);
    if (!Number.isFinite(tokens) || tokens < 0 || tokens > 100_000_000) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'tokens 无效' });
      return;
    }
    const rounded = Math.round(tokens);
    if (rounded <= 0) {
      res.json({ ok: true });
      return;
    }
    db.addTokens(me.userId, todayLocal(), rounded, new Date().toISOString());
    res.json({ ok: true });
  });

  // ── 留言列表（所有登录用户；可见性在 SQL 层按用户过滤） ─────
  // 支持 ?since=<id> 增量拉取（客户端轮询只取新增消息，避免每次全量下载）。
  // reset：游标超前于【当前用户可见】的最新 id（数据库重建/消息清空后自增从头
  // 开始）时，服务端回退全量并显式告知客户端重建基线——只靠客户端“空响应”判断
  // 无法区分“正常无新消息”与“游标已失效”，会永久收不到新消息。
  // 不能用全局最大 id：既泄露全平台消息活动量，也会被其他用户私信干扰判定。
  app.get('/gateway/api/messages', (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    const sinceRaw = typeof req.query.since === 'string' ? Number(req.query.since) : NaN;
    const since = Number.isFinite(sinceRaw) && sinceRaw > 0 ? Math.floor(sinceRaw) : 0;
    let mine = since > 0 ? db.listMessagesAfterForUser(me.userId, since, 300) : db.listMessagesForUser(me.userId, 300);
    let reset = false;
    if (since > 0 && mine.length === 0) {
      const latest = db.latestMessageIdForUser(me.userId);
      if (latest === null || since > latest) {
        reset = true;
        mine = db.listMessagesForUser(me.userId, 300);
      }
    }
    res.json({ ok: true, me: { id: me.userId, username: me.username, role: me.role }, messages: mine, reset });
  });

  // ── 发送留言（所有登录用户） ─────────────────────────────────
  // F-22：留言洪泛限流——每用户 60 秒内最多 12 条（滑动窗口），防止刷爆广播栏。
  const msgRate = new Map<number, number[]>();
  app.post('/gateway/api/messages', jsonBody, (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    const now = Date.now();
    const recent = (msgRate.get(me.userId) ?? []).filter((t) => now - t < 60_000);
    if (recent.length >= 12) {
      msgRate.set(me.userId, recent);
      res.status(429).json({ ok: false, code: 'RATE_LIMITED', error: '留言过于频繁，请稍后再试' });
      return;
    }
    recent.push(now);
    msgRate.set(me.userId, recent);
    const body = (req.body ?? {}) as Record<string, unknown>;
    // 服务端净化（#3）：剥离 HTML/CSS 结构后入库——防存储型注入 + AI agent 间接提示注入
    const content = sanitizeText(typeof body.content === 'string' ? body.content : '');
    if (content === '') {
      res.status(400).json({ ok: false, code: 'INVALID', error: '内容不能为空' });
      return;
    }
    if (content.length > 4000) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '内容过长' });
      return;
    }
    // 投递口径（Discussion #6 实施项 5）：
    //   1. recipientId 显式给出 → 私信该用户（主用户可私信任何人；子用户只能私信主用户）。
    //      非法值绝不静默归一成广播（调用方本意私信却公开发出 = 隐私事故）；
    //      不存在的用户也不能留下永远不可投递的孤儿消息（messages 无 FK）。
    //   2. broadcast === true → 广播；仅主用户可用（子用户广播会被拦下）。
    //   3. 两者都缺 → 子用户默认私信主用户（客服/反馈语义）；主用户必须显式
    //      选择收件人或勾选广播，避免误发全员消息。
    const rawRecipient = body.recipientId;
    const wantBroadcast = body.broadcast === true;
    // 一次取用：两个分支共用，避免两次查询间 admin 被删导致错误码口径漂移
    const adminId = db.findAdminId();
    let recipientId: number | null = null;
    if (rawRecipient !== undefined && rawRecipient !== null) {
      if (wantBroadcast) {
        // 两个意图互斥：同时给出视为歧义请求（主用户本想广播却被静默降级成私信 = 坏契约）
        res.status(400).json({ ok: false, code: 'INVALID', error: 'recipientId 与 broadcast 不能同时提供' });
        return;
      }
      recipientId = nullableInt(rawRecipient);
      if (recipientId === null || recipientId < 1) {
        res.status(400).json({ ok: false, code: 'INVALID', error: 'recipientId 无效' });
        return;
      }
      if (db.getUserById(recipientId) === null) {
        res.status(404).json({ ok: false, code: 'NO_SUCH_USER', error: '收件人不存在' });
        return;
      }
    } else if (wantBroadcast) {
      if (me.role !== 'admin') {
        res.status(403).json({ ok: false, code: 'FORBIDDEN_BROADCAST', error: '仅主用户可以发送广播消息' });
        return;
      }
    } else if (me.role !== 'admin') {
      if (adminId === null) {
        res.status(500).json({ ok: false, code: 'INTERNAL', error: '平台主用户缺失' });
        return;
      }
      recipientId = adminId;
    } else {
      res.status(400).json({ ok: false, code: 'SELECT_RECIPIENT', error: '请选择收件人或勾选广播' });
      return;
    }
    // 子用户只能私信主用户（跨子用户私信在多租户场景下无业务价值，且扩大消息泄露面）
    if (me.role !== 'admin' && recipientId !== null && (adminId === null || recipientId !== adminId)) {
      res.status(403).json({ ok: false, code: 'FORBIDDEN_RECIPIENT', error: '子用户只能给主用户发私信' });
      return;
    }
    // tag 是展示元数据：限制数量、逐项长度并去空白，防 256KB JSON 请求把极长 tag
    // 持久化到每条消息（content 已有 4k 上限）。保留未知短 tag 兼容旧数据/扩展。
    const tags = stringArray(body.tags)
      .map((tag) => tag.trim())
      .filter((tag) => tag.length > 0 && tag.length <= 64)
      .slice(0, 8);
    const msg = db.addMessage(me.userId, recipientId, content, tags);
    broadcastMessage(msg);
    res.json({ ok: true, message: msg });
  });

  // ── SSE 实时推送（所有登录用户） ─────────────────────────────
  app.get('/gateway/api/messages/stream', (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();
    res.write(`data: ${JSON.stringify({ type: 'init', me: { id: me.userId, username: me.username, role: me.role } })}\n\n`);
    const client = { res, userId: me.userId };
    chatClients.add(client);
    // 心跳：25 秒一条 SSE 注释帧。既防止代理/负载均衡器把空闲连接杀掉，
    // 也用于探活——write 失败说明连接已死，立即移除，避免僵尸连接缓慢积累。
    const heartbeat = setInterval(() => {
      try {
        res.write(': ping\n\n');
      } catch {
        clearInterval(heartbeat);
        chatClients.delete(client);
      }
    }, 25_000);
    heartbeat.unref();
    // req/res 双监听 close（断网无 FIN 时 res.close 兜底），清理幂等
    const cleanup = () => {
      clearInterval(heartbeat);
      chatClients.delete(client);
    };
    req.on('close', cleanup);
    res.on('close', cleanup);
  });

  // ── 认证门卫：非 /gateway 请求必须带有效会话 ─────────────────
  // 路径先用 WHATWG URL 规范化（. / .. / %2e%2e 均被归一），再做前缀判断——
  // 否则 /gateway/../api/xxx 会绕过前缀检查直达上游（dsh 侧 new URL 同样
  // 会归一化该路径，等于未认证调用任意 RPC）。解析失败一律按未认证处理，绝不 500。
  //
  // F-03 补强：WHATWG URL 会折叠 %2e 但【不解码 %2f】，导致 /gateway/..%2fapi/…
  // 在门卫眼里仍以 /gateway/ 开头而被放行，上游解码 %2f 后路径变成 /gateway/../api/…
  // （不匹配 dsh 任何路由 → SPA fallback 200，未认证泄露应用外壳）。
  // 修复要点（复检定位）：
  //   1. 必须从【原始 req.url】取路径——第一次 new URL 归一化时
  //      /gateway//../ 的空段会把 .. 吞掉（WHATWG 语义），再用归一化后的
  //      pathname 二次处理就太晚了；
  //   2. 迭代解码（最多 3 轮）：覆盖 %2f、%252f（双重编码）等；
  //   3. 解码后压平重复斜杠再 new URL 归一化，使 ../ 能正确折叠。
  // 绝对形式 request-target（http://host/...）先解析出 host 再取 pathname。
  function gatePathOf(reqUrl: string): string {
    let rawPath: string;
    if (/^https?:\/\//i.test(reqUrl)) {
      try {
        rawPath = new URL(reqUrl).pathname;
      } catch {
        rawPath = reqUrl;
      }
    } else {
      rawPath = reqUrl.split('?')[0];
    }
    return normalizeDecodedPath(rawPath);
  }

  /** 迭代解码（最多 3 轮）+ 压平重复斜杠 + WHATWG 归一化；畸形编码保持原样 */
  function normalizeDecodedPath(rawPath: string): string {
    let decoded = rawPath;
    for (let i = 0; i < 3; i++) {
      let next: string;
      try {
        next = decodeURIComponent(decoded);
      } catch {
        break; // 畸形百分号编码：保留当前值
      }
      if (next === decoded) break; // 无更多可解
      decoded = next;
    }
    return new URL(decoded.replace(/\/+/g, '/'), 'http://localhost').pathname;
  }

  app.use((req, res, next) => {
    try {
      // Host 格式校验：拒绝含路径/控制字符/超长的畸形 Host（防 CRLF/Header 注入
      // 变体）；不做域名白名单——用户可能用任意域名访问（如未配置 domain 的自定义
      // DNS），只拦畸形头。
      const hostRaw = req.headers.host;
      if (hostRaw !== undefined) {
        const h = String(hostRaw);
        if (h.length > 253 || !/^[A-Za-z0-9.\-\[\]:]+$/.test(h)) {
          res.status(400).type('text/plain').send('400 Bad Request');
          return;
        }
      }
      // F-03：从【原始 req.url】迭代解码 + 压平斜杠 + 归一化后做前缀判定
      // （不能先用 new URL(parsed.pathname)——第一次归一化会把 //../ 的空段吞掉）
      const gatePath = gatePathOf(req.url ?? '/');
      // 自动更新引擎的用户活动刷新：任何非内部通道请求都算用户活动（登录/API/页面/SSE），
      // 内部通道（/gateway/internal/*）是引擎/插件自己的调用，不算使用。
      if (updateEngine !== undefined && !gatePath.startsWith('/gateway/internal/') && !isBackgroundUpdateRequest(gatePath)) {
        updateEngine.bumpActivity();
      }
      // /gateway 精确路径与 /gateway/* 都视为网关自有前缀——但只放行已知路由，
      // 未知子路径（如 /gateway/api/dsh-ssh/hosts 误拼接）直接 404，
      // 不透传到上游 dsh（否则未登录也返回 SPA 壳，泄露 window.__DSH_BOOT__ 插件清单）
      if (gatePath === '/gateway' || gatePath.startsWith('/gateway/')) {
        // F-1：编码/压扁变形（/gateway%2Fapi%2Foverview、/gateway//login）——
        // Express 用【原始 URL】匹配路由，%2F 不算分隔符 → 不会命中任何具体路由；
        // 若这里按解码后的白名单放行，请求会落进无鉴权代理 → 转发上游 dsh 返回
        // SPA 壳（泄露 window.__DSH_BOOT__ 插件清单 + 构建 rev，实测 7+ 变体全 200）。
        // 判定：段结构一致性——原始路径按 '/' 分段的段数必须与解码归一化后一致。
        //   %2F 改变段数（/gateway%2Fapi → 原始 2 段 vs 解码 3+ 段）→ 404；
        //   %2f 小写、%252F 双重、// 压扁同理（段数变化）；
        //   段内编码（如 %E7%94%A8 非 ASCII 段，段数不变）→ 放行——为未来含
        //   非 ASCII 段的网关路由留好扩展口（测试方建议：不做过严的字面拒绝）。
        let rawPathOnly = (req.url ?? '/').split('?')[0];
        if (/^https?:\/\//i.test(rawPathOnly)) {
          try {
            rawPathOnly = new URL(rawPathOnly).pathname;
          } catch {
            /* 保持原值 */
          }
        }
        if (rawPathOnly.split('/').length !== gatePath.split('/').length) {
          res.status(404).type('text/plain').send('404 Not Found');
          return;
        }
        // 精确白名单：只放行网关自有路由。
        // /gateway/api/* 不能整段放行——/gateway/api/dsh-ssh/hosts 之类误拼接路径
        // 会透传到上游 dsh 返回 SPA 壳（泄露 window.__DSH_BOOT__ 插件清单）。
        const knownGatewayRoute =
          gatePath === '/gateway' ||
          gatePath === '/gateway/' ||
          /^\/gateway\/(login|setup|logout)(\/|$)/.test(gatePath) ||
          gatePath === '/gateway/api' ||
          gatePath === '/gateway/api/' ||
          gatePath === '/gateway/api/overview' ||
          gatePath === '/gateway/api/permissions' ||
          gatePath === '/gateway/api/usage/report' ||
          gatePath === '/gateway/api/messages' ||
          gatePath.startsWith('/gateway/api/messages/') ||
          gatePath.startsWith('/gateway/internal/');
        if (!knownGatewayRoute) {
          res.status(404).type('text/plain').send('404 Not Found');
          return;
        }
        return next();
      }
      // P1-1：dsh 插件 internal 端点仅限网关→dsh 本机 HTTP 调用，
      // 外部请求一律 404（loopback 校验被代理拓扑绕过，不能依赖插件侧防护）
      if (gatePath.startsWith('/api/dsh-passwords/internal/')) {
        res.status(404).json({ ok: false, error: 'not found' });
        return;
      }
      const user = sessionOf(req);
      if (!user) {
        // 重定向兼容层：记录原始 URL，登录后跳回
        const nextUrl = encodeURIComponent(req.originalUrl);
        res.redirect(302, `/gateway/login?next=${nextUrl}`);
        return;
      }
      const row = db.getUserById(user.userId);
      if (!row) {
        res.redirect(302, `/gateway/login?next=${encodeURIComponent(req.originalUrl)}`);
        return;
      }
      // 所有路径型授权必须使用与上游转发完全相同的规范化路径。若使用 WHATWG
      // 原始 pathname，`/api%2Fsession%2Fhistory` 会在此处躲过检查、却在转发时
      // 解码为真实敏感路由（C-1）。query 仍由 URL 只读解析。
      const parsed = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
      const requestPath = gatePath;
      // 自身插件的写操作必须同源：Sec-Fetch-Site 可被缺省/伪造，且 text/plain
      // 可避免 CORS 预检；浏览器提供 Origin 时严格与请求 Host 一致。跨源攻击的
      // 本质是跨主机（攻击者无法在受害者主机名上托管内容），因此只比主机:端口、
      // 不比协议——否则 README 支持的 nginx/caddy 终结 TLS 反代部署（网关收到
      // 明文 HTTP、req.protocol=http，而浏览器 Origin=https）会全部误判 403。
      // Host 只信直接对端：仅当对端是本机回环（受信本地反代）才采纳
      // X-Forwarded-Host，公网直连请求不能带伪造头绕过。
      if (
        ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) &&
        requestPath.startsWith('/api/dsh-passwords/') &&
        !requestPath.startsWith('/api/dsh-passwords/internal/') &&
        typeof req.headers.origin === 'string'
      ) {
        if (!originHostMatches(req)) {
          res.status(403).type('text/plain').send('403 Forbidden');
          return;
        }
      }
      // 记录所有登录用户（含主用户）的用户 id：供 session.create/fork 响应回调
      // 登记 sessionId→cwd 缓存与 dsh-ssh 主机 SSRF 校验使用；权限行仍只挂子用户
      (req as Req).dshpwUser = user.userId;
      (req as Req).dshpwIsAdmin = row.role === 'admin';
      if (row.role !== 'admin') {
        const perms = effectivePermissions(user.userId);
        const lang = langOf(req);
        if (perms.banned) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.banned')));
          return;
        }
        // F-09/F-12：第三方插件“运维面”端点（dsh-ssh 主机清单/隧道、skin-center、modlens、
        // dsh-uploads 列表/删除等）不在网关权限模型内，对子用户一律 403（仅主用户可访问）
        if (isAdminOnlyPluginEndpoint(req.method, requestPath) || isAdminOnlySidebarEndpoint(requestPath)) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.adminOnly')));
          return;
        }

        if (!perms.allow_git_download && (isGitRequest(requestPath) || isAionuiFileRead(req.method, requestPath))) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.noGit')));
          return;
        }

        const workspaceManagementAllowed =
          perms.allow_workspace_create &&
          (isWorkspaceCreate(requestPath) || isWorkspaceDeleteOrRename(requestPath));
        // 新建工作区的目录选择器会先调用 host.createDirectory；它不属于
        // workspace.* RPC。该调用必须复用同一开关，否则子用户虽不能登记
        // 工作区，仍能在服务器文件系统中创建目录。
        if (
          (isWorkspaceWrite(requestPath) && !workspaceManagementAllowed) ||
          (isWorkspaceDirectoryCreate(requestPath) && !perms.allow_workspace_create)
        ) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.workspaceDenied')));
          return;
        }
        // aionui-panel 文件树：GET/HEAD 的 root 在 query 里，直接校验白名单（拦截目录浏览/下载）
        // ⚠ 只对 aionui-panel 路径做此检查——aionuiRootFrom 对非 aionui-panel 路径返回 null，
        //  若用 null 判 fail-closed 会把普通 GET/HEAD（state/messages/页面资源等）全部 403
        if (
          isWorkspaceRestricted(perms.allowed_folders) &&
          (req.method === 'GET' || req.method === 'HEAD') &&
          isAionuiPanel(requestPath)
        ) {
          const aionuiRoot = aionuiRootFrom(req.method, requestPath, parsed.searchParams, null);
          // 提取不到 root 时也 fail-closed（之前直接放行→白名单外的目录可被下载）
          if (aionuiRoot === null || !folderAllowed(aionuiRoot, perms.allowed_folders)) {
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
        }
        if (!isStaticAsset(requestPath) && !isPollingRequest(requestPath)) {
          // 配额计时从子用户“说第一句话”（发消息锚点）才开始：
          // 未使用过的子用户（无当日记录且非锚点请求）不创建记录、不受配额限制
          const day = todayLocal();
          if (db.getUsage(user.userId, day) !== null || isUsageAnchorRequest(requestPath)) {
            const usage = touchUsageThrottled(user.userId);
            if (usage) {
              if (perms.daily_minutes_limit !== null && usage.active_seconds >= perms.daily_minutes_limit * 60) {
                res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.timeLimit')));
                return;
              }
              if (perms.hourly_token_limit !== null && usage.hourly_tokens >= perms.hourly_token_limit) {
                res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.tokenLimit')));
                return;
              }
            }
          }
        }
        // 附上权限，供后续文件夹限制中间件 / 代理 token 计量使用
        (req as Req).dshpwPerms = perms;
      }
      // ── 第三方插件纵深防御（所有登录用户，含主用户） ──
      // dsh-uploads 上传：高危 Web 可解释扩展名（.php/.jsp/.svg 等）拒绝——
      // 插件本身不限制类型，网关先拦一层（上传目录若被 Web 面暴露即 RCE 面）
      if (
        req.method === 'POST' &&
        gatePath === '/api/dsh-uploads' &&
        isDangerousUploadName(String(req.headers['x-file-name'] ?? ''))
      ) {
        const lang = langOf(req);
        res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
        return;
      }
      return next();
    } catch {
      res.redirect(302, '/gateway/login');
    }
  });

  // ── 反向代理（HTTP）→ 上游 dsh ──────────────────────────────
  // 改写路径：body 已重算，分帧以新 content-length 为准，必须清掉上游的
  // transfer-encoding（RFC 9110 §8.6：CL 与 TE 同帧属于畸形消息，Nginx 直接 502）
  function headersForRewrittenBody(upstreamHeaders: IncomingHttpHeaders): Record<string, string | string[] | undefined> {
    const h: Record<string, string | string[] | undefined> = { ...upstreamHeaders };
    delete h['content-length'];
    delete h['content-encoding'];
    delete h['transfer-encoding'];
    // 网关标识：客户端插件探测此头判断是否经 dsh-passwords 远程访问
    h['x-dsh-gateway'] = '1';
    return h;
  }
  // 流式透传：上游若异常同时带 CL+TE，按 RFC 9110 §8.6 保留 TE、丢弃 CL
  function headersForStreaming(upstreamHeaders: IncomingHttpHeaders): Record<string, string | string[] | undefined> {
    const h: Record<string, string | string[] | undefined> = { ...upstreamHeaders };
    if (h['content-length'] !== undefined && h['transfer-encoding'] !== undefined) delete h['content-length'];
    // 网关标识：客户端插件探测此头判断是否经 dsh-passwords 远程访问
    h['x-dsh-gateway'] = '1';
    return h;
  }

  /** 缓冲上游响应体的上限：超过则放弃改写（注入/过滤），转流式透传，保证内存有界 */
  const MAX_BUFFER_BYTES = 16 * 1024 * 1024;
  /** gunzip 解压后的上限：缓冲体本身有界，但 16MB 高压缩比炸弹可解压出数百 MB——过滤前拒绝 */
  const MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024;
  /** 安全过滤分支专属：解压超限时 fail-closed（502），不得透传未过滤内容 */
  class OversizeResponseError extends Error {}

  /**
   * 有界解压：用 zlib 的 maxOutputLength 在分配内存前限制输出——事后 body.length 检查
   * 只能发现炸弹，内存峰值已经发生（高压缩比 payload 可把 16MB 输入解压到数百 MB）。
   * 超限抛 OversizeResponseError（安全分支 → 502）；其他解压错误（gzip 损坏）原样抛出，
   * 由调用方按既有“解析失败透传”契约处理。
   */
  function gunzipBounded(input: Buffer): Buffer {
    try {
      return zlib.gunzipSync(input, { maxOutputLength: MAX_DECOMPRESSED_BYTES });
    } catch (error) {
      // 超限错误形态：ERR_BUFFER_TOO_LARGE（code）或 "Cannot create a Buffer larger than ..."（message）
      const code = (error as { code?: unknown }).code;
      if (
        error instanceof Error &&
        (code === 'ERR_BUFFER_TOO_LARGE' || /too large|larger than/i.test(error.message))
      ) {
        throw new OversizeResponseError();
      }
      throw error;
    }
  }

  /**
   * 缓冲上游响应：正常路径在 'end' 时调用 onEnd(body) 做改写/过滤；
   * 若超过 MAX_BUFFER_BYTES（异常大的 HTML/JSON），自动放弃缓冲，
   * 无缝切换为流式透传（不再注入/过滤，但连接不中断、内存有界）。
   * 上游中途出错时销毁客户端连接（头未发出，无法再写错误页）。
   */
  function bufferUpstream(
    upstreamRes: http.IncomingMessage,
    res: Response,
    onEnd: (body: Buffer) => void,
    onOversize: 'stream' | 'fail' = 'fail',
  ): void {
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const onData = (chunk: Buffer) => {
      if (settled) return;
      size += chunk.length;
      if (size > MAX_BUFFER_BYTES) {
        settled = true;
        upstreamRes.off('data', onData);
        upstreamRes.off('end', onEndHandler);
        upstreamRes.off('error', onError);
        if (onOversize === 'fail') {
          upstreamRes.destroy();
          if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response too large');
          return;
        }
        // HTML 注入可安全退化为流式透传。必须写入先前缓冲的内容和当前越界 chunk；
        // 旧实现丢弃当前 chunk，导致响应中间断裂。
        // ⚠ 重挂 error 监听：pipe 不会为源挂 error，缺监听时上游中断 emit 'error'
        // 会触发 uncaughtException 击穿网关进程。
        upstreamRes.on('error', () => res.destroy());
        const respHeaders = headersForStreaming(upstreamRes.headers);
        if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
        if (!res.writableEnded) {
          res.write(Buffer.concat([...chunks, chunk]));
          upstreamRes.pipe(res);
        }
        return;
      }
      chunks.push(chunk);
    };
    const onEndHandler = () => {
      if (settled) return;
      settled = true;
      onEnd(Buffer.concat(chunks));
    };
    const onError = () => {
      if (settled) return;
      settled = true;
      res.destroy();
    };
    upstreamRes.on('data', onData);
    upstreamRes.on('end', onEndHandler);
    upstreamRes.on('error', onError);
  }

  /**
   * F-26：向 dsh 注入会话沙盒（loopback + 内部密钥，fire-and-forget）。
   * 受限子用户（sandbox_mode 非空）建会话后，dsh 默认给 workspace-write 沙盒——
   * 这里通知 dsh 插件把该会话的 sandbox/mode 事件追加为其真实授权级别。
   * 插件侧校验 loopback + x-internal-secret（与 SETUP_KEY 同源派生）。
   */
  function applySandboxToSession(sessionId: string, mode: string): void {
    const body = JSON.stringify({ sessionId, mode });
    const r = http.request(
      {
        hostname: upstreamHost,
        port: upstreamPort,
        path: '/api/dsh-passwords/internal/sandbox',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': String(Buffer.byteLength(body)),
          'x-internal-secret': config.internalSecret,
        },
        timeout: 3000,
      },
      () => {},
    );
    r.on('error', (error) => {
      // 沙盒注入失败（dsh 重启窗口期/插件未部署）静默 = 受限子用户新会话拿到默认
      // workspace-write 沙盒（比授权高一档的提权）且无人知晓——必须留日志
      console.error(`[dsh-passwords] 沙盒注入失败 session=${sessionId} mode=${mode}: ${error?.message ?? error}`);
    });
    r.on('timeout', () => r.destroy());
    r.end(body);
  }

  app.use((req, res) => {
    // F-1 纵深防御：能到达这里（代理兑底）的 /gateway* 请求必然是未被具体网关路由
    // 处理的畸形/伪装路径（合法网关路由都在各自处理器里 return 了）——一律 404，
    // 绝不转发上游（防未登录 SPA 壳泄露 window.__DSH_BOOT__ 插件清单）。
    const fallbackGatePath = gatePathOf(req.url ?? '/');
    if (fallbackGatePath === '/gateway' || fallbackGatePath.startsWith('/gateway/')) {
      res.status(404).type('text/plain').send('404 Not Found');
      return;
    }
    const headers: Record<string, string | string[] | undefined> = { ...req.headers };
    // 改写 Host 为上游地址（过 dsh 的 browser-trust fence 第 1 道：Host 检查）
    headers.host = `${upstreamHost}:${upstreamPort}`;
    // 改写 Origin 为上游地址（过第 3 道：Origin 必须与 Host 同 host——
    // 浏览器发来的是网关地址 origin，与改写后的 Host 不一致会被 403）
    if (typeof headers.origin === 'string') {
      headers.origin = `http://${upstreamHost}:${upstreamPort}`;
    }
    delete headers['content-length'];
    // 缓冲/改写路径用 end(body) 重写 content-length，chunked 的 transfer-encoding
    // 若保留会造成 Node 的 ERR_HTTP_CONTENT_LENGTH_MISMATCH
    delete headers['transfer-encoding'];
    // F-15：剥离网关会话 Cookie（dsh_gateway_token JWT）——上游 dsh 是无认证
    // 应用，本不需要令牌；不剥离则上游或其第三方插件被入侵/投毒时可收割全部
    // 活动会话 JWT 并回放。白盒确认 dsh-host-webserver / dsh-anonymous-user-id
    // 均无 cookie 逻辑。
    // 例外：/api/dsh-passwords/* 是本网关自身插件路由，其 guard 靠 Cookie 中
    // 的 JWT 鉴权（同一信任域、自己签发的服务），必须保留；其余上游面全剥。
    const ownPluginRoute = normalizeDecodedPath(
      new URL(req.originalUrl, `http://${req.headers.host ?? 'localhost'}`).pathname,
    ).startsWith('/api/dsh-passwords/');
    if (!ownPluginRoute) delete headers['cookie'];
    // 只允许 gzip/identity：HTML 注入与 workspace/session 过滤只处理 gzip，
    // 上游若返回 br 会损坏页面/导致过滤静默失效（brotli 不走代理缓冲）
    headers['accept-encoding'] = 'gzip';

    const parsedUrl = new URL(req.originalUrl, `http://${req.headers.host ?? 'localhost'}`);
    // 代理后续所有路由分支与认证门卫共享同一口径，禁止编码分隔符制造判定差异。
    const proxyPath = normalizeDecodedPath(parsedUrl.pathname);
    // 请求上挂的用户/权限（子用户才有）
    const reqAs = req as Req;
    // rc.2 client-connection 的统一 carrier 上限：管理员和子用户保持同一平台契约。
    // 先检查声明长度，避免接收必然超限的请求体；无 Content-Length 的请求仍由
    // 下方权限检查分支在实际收包时执行同一上限。
    const declaredRequestLength = Number(req.headers['content-length'] ?? '');
    const requestBodyLimit = requestBodyLimitFor(
      reqAs.dshpwIsAdmin === true ? 'admin' : 'user',
      reqAs.dshpwPerms?.allow_upload === true,
    );
    if (Number.isFinite(declaredRequestLength) && declaredRequestLength > requestBodyLimit) {
      res.status(413).type('html').send(forbiddenPage(langOf(req), t(langOf(req), 'gw.bodyTooLarge')));
      return;
    }
    // 序号在请求发出前分配：并发 workspace.list 返回乱序时，较早请求的旧快照
    // 不能覆盖较晚请求对应的新状态。
    const archiveRequestRevision = req.method === 'POST' && /^\/api\/workspace[.\/]list$/.test(proxyPath)
      ? ++workspaceListRequestRevision
      : 0;
    // fork/create 的响应可能在权限修改后才返回；记录请求开始时的用户授权版本，
    // 这样慢响应不能在管理员撤销权限后把新会话重新写回旧快照。
    const sessionAccessRequestRevision = reqAs.dshpwUser === undefined
      ? 0
      : userAccessRevisionFor(reqAs.dshpwUser);
    const upstreamReq = http.request(
      {
        hostname: upstreamHost,
        port: upstreamPort,
        // 规范化路径转发（与 dsh 的 new URL 解析行为一致，杜绝 ../ 混入上游）
        // F-03：与门卫同口径——pathname 解码后再归一化，编码变体（%2f/%2e）
        // 转发为等价规范路径，避免上游按自身规则解码导致路径语义漂移
        path: proxyPath + parsedUrl.search,
        method: req.method,
        headers,
        agent: upstreamAgent,
      },
      (upstreamRes) => {
        const contentType = String(upstreamRes.headers['content-type'] ?? '');
        const encoding = String(upstreamRes.headers['content-encoding'] ?? '');

        // ── HTML 响应：缓冲 + 注入兼容脚本（crypto.randomUUID polyfill 等） ──
        if (contentType.includes('text/html')) {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              let body = raw;
              if (encoding.includes('gzip')) body = gunzipBounded(body);
              const html = body.toString('utf8');
              const injected = html.replace(/<head[^>]*>/i, (match) => match + INJECT_SCRIPT);
              let out = Buffer.from(injected, 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              // 代理层补齐防嵌框头（dsh 应用自身未设置）：
              // 允许同源内嵌（dsh 内部如有同源 iframe 不受影响），禁止跨站嵌框。
              // 仅在上游未提供 CSP 时补充 frame-ancestors，避免冲掉上游更严的策略。
              respHeaders['x-frame-options'] = 'SAMEORIGIN';
              const upstreamCsp = String(upstreamRes.headers['content-security-policy'] ?? '');
              if (!upstreamCsp.includes('frame-ancestors')) {
                respHeaders['content-security-policy'] = upstreamCsp
                  ? `${upstreamCsp}; frame-ancestors 'self'`
                  : "frame-ancestors 'self'";
              }
              if (encoding.includes('gzip')) {
                out = zlib.gzipSync(out);
                respHeaders['content-encoding'] = 'gzip';
              }
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch {
              // 注入仅改善兼容性，解析失败可安全保留原始 HTML；其余安全过滤分支
              // 则使用 bufferUpstream 默认 fail-closed，不能把未检查内容透传。
              const respHeaders = headersForStreaming(upstreamRes.headers);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(raw);
            }
          }, 'stream');
          return;
        }

        // ── F-A2：aionui-panel/read（POST JSON 读文件内容）——缓冲 + 递归清洗隐藏
        // Unicode（零宽/bidi 等）。文件内容进 AI 模型前必经网关代理，在这里补偿清洗，
        // 不必等供应商（dsh）修复；对全部登录用户生效（主用户同样可能被诱导读恶意文件）。
        if (req.method === 'POST' && proxyPath === '/aionui-panel/read') {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              let body = raw;
              const enc = String(upstreamRes.headers['content-encoding'] ?? '');
              if (enc.includes('gzip')) body = gunzipBounded(body);
              const parsed = JSON.parse(body.toString('utf8'));
              const cleaned = sanitizeHiddenUnicodeJson(parsed);
              const out = Buffer.from(JSON.stringify(cleaned), 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              if (error instanceof OversizeResponseError) {
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response too large');
                return;
              }
              // 非 JSON / gzip 损坏：原样透传（无法解析就不改，避免损坏）
              const respHeaders = headersForStreaming(upstreamRes.headers);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(raw);
            }
          });
          return;
        }

        // ── workspace 管理响应：成功后同步工作区登记 ──
        // 创建 → 登记创建者工作区并加入其目录白名单；重命名/删除同步登记表。
        // 会话级授权由显式 grant（Issue #19）与 session.create/fork 登记负责。
        if (
          reqAs.dshpwWorkspacePath !== undefined &&
          (upstreamRes.statusCode ?? 500) >= 200 &&
          (upstreamRes.statusCode ?? 500) < 300 &&
          reqAs.dshpwUser !== undefined
        ) {
          if (reqAs.dshpwWorkspaceCreate === true) {
            db.addUserWorkspace(reqAs.dshpwUser, reqAs.dshpwWorkspacePath);
            db.addAllowedFolder(reqAs.dshpwUser, reqAs.dshpwWorkspacePath);
          } else if (reqAs.dshpwWorkspaceOldPath !== undefined && reqAs.dshpwWorkspaceNewPath !== undefined) {
            db.renameUserWorkspace(reqAs.dshpwUser, reqAs.dshpwWorkspaceOldPath, reqAs.dshpwWorkspaceNewPath);
          } else if (/(?:remove|delete)(?:[./]|$)/.test(proxyPath)) {
            db.removeUserWorkspace(reqAs.dshpwUser, reqAs.dshpwWorkspacePath);
          }
        }

        // ── workspace.list 响应：收集 id→path 缓存 + 受限子用户过滤白名单外的工作区 ──
        if (req.method === 'POST' && /^\/api\/workspace[.\/]list$/.test(proxyPath)) {
          const requestRevision = archiveRequestRevision;
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              let body = raw;
              const enc = String(upstreamRes.headers['content-encoding'] ?? '');
              if (enc.includes('gzip')) body = gunzipBounded(body);
              const parsed = JSON.parse(body.toString('utf8'));
              // 只有完整、明确的 archivedSessionIds 数组才能更新快照；解析/解压/容量
              // 异常不得用空集合覆盖旧状态。按请求序号防止较早的慢响应回滚新快照。
              const nextArchived = new Set<string>();
              const hasValidArchiveState = replaceArchivedSessionSnapshot(nextArchived, parsed);
              if (hasValidArchiveState && requestRevision >= archivedSessionSnapshotRevision) {
                archivedSessionSnapshot.clear();
                for (const id of nextArchived) archivedSessionSnapshot.add(id);
                archivedSessionSnapshotReady = true;
                archivedSessionSnapshotRevision = requestRevision;
              }
              // 先缓存全量 id→path（供 session.create 用 workspaceId 时解析路径）
              collectIdPathPairs(parsed, workspacePathById);
              // 管理员仍使用全局 cwd 缓存；普通用户只建立自己的可见会话授权快照。
              if (reqAs.dshpwIsAdmin === true) collectSessionCwdFromWorkspaces(parsed, sessionCwdById);
              const workspaceVisible = (candidate: string): boolean => {
                if (!folderAllowed(candidate, reqAs.dshpwPerms?.allowed_folders ?? [])) return false;
                if (reqAs.dshpwUser === undefined || reqAs.dshpwIsAdmin === true) return true;
                const owners = db.listWorkspaceOwners();
                const normalizedCandidate = normalizePath(candidate);
                return !owners.some(
                  (owner) => normalizePath(owner.path) === normalizedCandidate && owner.userId !== reqAs.dshpwUser,
                );
              };
              const outBody = reqAs.dshpwUser !== undefined
                ? filterByPathFieldWithPredicate(parsed, 'path', workspaceVisible)
                : parsed;
              // F-25/#16：子用户只能看到被授权的会话。dsh rc.8 保留归档会话在
              // workspace.sessionIds 槽位，并用 archivedSessionIds 另行标记状态；如果
              // 把归档 ID 从 sessionIds 删除，dsh 会把完整会话错误归入「未分组」。
              if (reqAs.dshpwPerms !== undefined) {
                if (!hasValidArchiveState && !archivedSessionSnapshotReady) {
                  if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
                  return;
                }
                const disabled = new Set(reqAs.dshpwPerms.disabled_sessions);
                const archived = new Set(archivedSessionSnapshot);
                const visibleSessionIds = new Set(collectSessionCwdFromWorkspaces(outBody).keys());
                // Issue #19 旧数据迁移：显式会话授权上线前就已获授权工作区的子用户，
                // 第一次成功拿到 workspace.list 时，把可见工作区内“未禁用”的既有会话一次性
                // 写入显式授权，保持旧行为；之后新出现的会话不会自动加入授权。归档会话也
                // 一并授权——归档是展示状态，不是放弃授权的依据（仍保留在工作区槽位）。
                if (reqAs.dshpwPerms !== undefined && !db.isSessionGrantsSeeded(reqAs.dshpwUser!)) {
                  const seedIds = [...visibleSessionIds].filter((id) => !disabled.has(id));
                  db.replaceUserSessionGrants(reqAs.dshpwUser!, seedIds);
                  db.markSessionGrantsSeeded(reqAs.dshpwUser!);
                }
                const grants = new Set(db.listUserSessionGrants(reqAs.dshpwUser!));
                // 只暴露当前可见工作区中的归档标记，避免借 archivedSessionIds 枚举
                // 其他用户的会话；归档槽位本身仍保留在 sessionIds。
                filterArchivedSessionIds(
                  outBody,
                  (id) => archived.has(id) && visibleSessionIds.has(id) && grants.has(id) && !disabled.has(id),
                );
                // 普通用户只看到显式 grant 的会话；归档会话仍保留在已授权工作区槽位。
                filterOwnedSessionIds(outBody, (id) => grants.has(id) && !disabled.has(id));
                const access = new Map<string, string>();
                collectSessionCwdFromWorkspaces(outBody, access);
                for (const [id, cwd] of access) {
                  if (disabled.has(id)) access.delete(id);
                }
                replaceUserSessionAccess(reqAs.dshpwUser!, access, requestRevision);
                const workspaceIds = new Set<string>();
                const visit = (value: unknown, depth = 0): void => {
                  if (depth > 8 || value === null || typeof value !== 'object') return;
                  if (Array.isArray(value)) {
                    for (const item of value) visit(item, depth + 1);
                    return;
                  }
                  const obj = value as Record<string, unknown>;
                  if (typeof obj.workspaceId === 'string' && typeof obj.path === 'string') {
                    workspaceIds.add(obj.workspaceId);
                  }
                  for (const child of Object.values(obj)) visit(child, depth + 1);
                };
                visit(outBody);
                replaceUserWorkspaceIds(reqAs.dshpwUser!, workspaceIds, requestRevision);
              }
              const out = Buffer.from(JSON.stringify(outBody), 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              if (error instanceof OversizeResponseError) {
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response too large');
                return;
              }
              // 子用户列表需要会话/白名单过滤：解析或过滤异常时无法产出已过滤响应，
              // 绝不能把未过滤的全量列表透传（fail-open 泄露其他租户会话）；
              // 主用户列表不涉及过滤，保持原样透传。
              if (reqAs.dshpwPerms !== undefined) {
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
                return;
              }
              const respHeaders = headersForStreaming(upstreamRes.headers);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(raw);
            }
          });
          return;
        }

        // ── session.create / fork 响应：登记当前用户会话 + 注入真实沙盒（F-26） ──
        // 响应体不变；已通过目录/源会话校验的新会话写入显式授权（未禁用时），
        // 其可见性由显式 grant + 工作区白名单 + 逐会话禁用共同决定。
        if (req.method === 'POST' && /^\/api\/session[.\/](create|fork)$/.test(proxyPath)) {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              const enc = String(upstreamRes.headers['content-encoding'] ?? '');
              const decoded = enc.includes('gzip') ? gunzipBounded(raw) : raw;
              const parsed = JSON.parse(decoded.toString('utf8'));
              const sessionId = extractSessionId(parsed);
              if (sessionId !== null && reqAs.dshpwUser !== undefined) {
                if (reqAs.dshpwAgentPreset !== undefined) sessionAgentPresetMapFor(reqAs.dshpwUser).set(sessionId, reqAs.dshpwAgentPreset);
                else collectSessionAgentPresets(parsed, sessionAgentPresetMapFor(reqAs.dshpwUser));
                const reqCwd = reqAs.dshpwSessionCwd;
                const cwd = typeof reqCwd === 'string' && reqCwd.length > 0
                  ? reqCwd
                  : collectSessionCwd(parsed).get(sessionId);
                if (cwd) {
                  sessionCwdById.set(sessionId, cwd);
                  if (
                    reqAs.dshpwIsAdmin !== true &&
                    reqAs.dshpwPerms !== undefined &&
                    (reqAs.dshpwSessionCwd !== undefined || reqAs.dshpwForkAuthorized === true) &&
                    sessionAccessRequestRevision === userAccessRevisionFor(reqAs.dshpwUser)
                  ) {
                    const access = new Map(userSessionAccessFor(reqAs.dshpwUser));
                    if (!reqAs.dshpwPerms.disabled_sessions.includes(sessionId)) {
                      db.replaceUserSessionGrants(reqAs.dshpwUser, [
                        ...db.listUserSessionGrants(reqAs.dshpwUser),
                        sessionId,
                      ]);
                      access.set(sessionId, cwd);
                    }
                    replaceUserSessionAccess(reqAs.dshpwUser, access, sessionAccessRequestRevision);
                  }
                }
                if (reqAs.dshpwPerms !== undefined && reqAs.dshpwPerms.sandbox_mode !== null) {
                  applySandboxToSession(sessionId, reqAs.dshpwPerms.sandbox_mode);
                }
              }
              const respHeaders = headersForStreaming(upstreamRes.headers);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(raw);
            } catch (error) {
              if (error instanceof OversizeResponseError) {
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response too large');
                return;
              }
              // 非 JSON 响应：原样透传，但 cwd 缓存/沙盒副作用缺失——记录 warn 便于排查。
              console.warn(`[dsh-passwords] session.create/fork 上游响应非 JSON，cwd/沙盒副作用缺失: ${proxyPath}`);
              const respHeaders = headersForStreaming(upstreamRes.headers);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(raw);
            }
          });
          return;
        }


        // ── session.list 响应过滤：显式授权快照 + 工作区白名单 + 逐会话禁用 + 归档排除 ──
        // 子用户只看到授权快照命中（由 workspace.list 建立）、未禁用且未归档的活动会话；
        // 管理员保持完整视图。
        if (
          reqAs.dshpwPerms !== undefined &&
          req.method === 'POST' &&
          /^\/api\/session[.\/]list$/.test(proxyPath)
        ) {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              let body = raw;
              const enc = String(upstreamRes.headers['content-encoding'] ?? '');
              if (enc.includes('gzip')) body = gunzipBounded(body);
              const parsed = JSON.parse(body.toString('utf8'));
              // 管理员需要全局 cwd 映射；普通用户必须使用 workspace.list 建立的
              // 按用户访问快照，不能从未过滤的 session.list 反向获得授权。
              if (reqAs.dshpwIsAdmin === true) collectSessionCwd(parsed, sessionCwdById);

              // 子用户按工作区开关过滤：关闭工作区后，其会话一并从侧栏消失，
              // 不产生「未分组」孤儿项。
              const perms = reqAs.dshpwPerms!;
              const cwdAllowed = isWorkspaceRestricted(perms.allowed_folders)
                ? (cwd: string) => folderAllowed(cwd, perms.allowed_folders)
                : null;
              const disabled = new Set(perms.disabled_sessions);
              // workspace.list 是 rc.8 workspace registry 的权威归档来源。
              // session.list 中同名字段可能来自旧响应，不能无版本覆盖全局快照。
              const access = userSessionAccessFor(reqAs.dshpwUser!);
              if (!archivedSessionSnapshotReady || !userSessionAccess.has(reqAs.dshpwUser!)) {
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
                return;
              }
              collectSessionAgentPresets(parsed, sessionAgentPresetMapFor(reqAs.dshpwUser!));
              const filtered = filterSessionItems(
                parsed,
                (id) => access.has(id) && !disabled.has(id) && !archivedSessionSnapshot.has(id),
                cwdAllowed,
              );
              const out = Buffer.from(JSON.stringify(filtered), 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              // 该分支仅处理子用户列表：任何解析/过滤异常都 fail-closed 502，
              // 绝不把未过滤的全量列表回放给子用户（fail-open 泄露面）
              if (!res.headersSent) {
                const msg =
                  error instanceof OversizeResponseError
                    ? '502 Upstream response too large'
                    : '502 Upstream response unprocessable';
                res.status(502).type('text/plain').send(msg);
              }
              return;
            }
          });
          return;
        }

        // ── Agent preset 成功响应后登记会话当前 preset ──
        // DSH RPC 的业务失败可以使用 HTTP 200，因此必须解析 result.ok，不能只看状态码。
        if (req.method === 'POST' && /^\/api\/agentPreset[.\/]select$/.test(proxyPath) && reqAs.dshpwAgentPreset !== undefined) {
          const sessionId = reqAs.dshpwSelectedSessionId;
          const selectedAgentPreset = reqAs.dshpwAgentPreset;
          bufferUpstream(upstreamRes, res, (raw) => {
            let businessOk = false;
            try {
              const parsed = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
              const result = parsed.result;
              businessOk = result !== null && typeof result === 'object' && (result as Record<string, unknown>).ok === true;
            } catch {
              businessOk = false;
            }
            if (businessOk && sessionId !== undefined && reqAs.dshpwUser !== undefined) {
              sessionAgentPresetMapFor(reqAs.dshpwUser).set(sessionId, selectedAgentPreset);
            }
            const respHeaders = headersForStreaming(upstreamRes.headers);
            if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
            if (!res.writableEnded) res.end(raw);
          });
          return;
        }

        // ── session.history 响应：F-A2 隐藏 Unicode 清洗（所有用户）+ 受限子用户沙盒降级 ──
        // F-A2：AI agent 读取文件后内容进入会话历史，重读历史时隐藏指令（零宽/bidi）会
        // 重新进入模型——历史响应经网关代理，在这里对所有用户清洗（主用户同样可能被
        // 诱导读恶意文件）；上游 dsh 不处理，网关补偿。
        // 沙盒降级：主用户把会话设为 danger-full-access 后共享给子用户，子用户打开会话时
        // 会话 log 里的 permission/preset 就是 full access——不拦截就直接继承提权，
        // 这里把超过子用户授权级别的 preset/mode 统一降级（仅受限子用户）。
        if (req.method === 'POST' && /^\/api\/session[.\/]history$/.test(proxyPath)) {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              let body = raw;
              const enc = String(upstreamRes.headers['content-encoding'] ?? '');
              if (enc.includes('gzip')) body = gunzipBounded(body);
              const parsed = JSON.parse(body.toString('utf8'));
              if (reqAs.dshpwPerms !== undefined && reqAs.dshpwPerms.sandbox_mode !== null) {
                void clampSessionHistorySandbox(
                  parsed,
                  reqAs.dshpwPerms!.sandbox_mode as 'read-only' | 'workspace-write' | 'danger-full-access',
                );
              }
              // F-A2：递归清洗历史中所有字符串字段（消息内容/工具结果）的隐藏 Unicode
              const cleaned = sanitizeHiddenUnicodeJson(parsed);
              const out = Buffer.from(JSON.stringify(cleaned), 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              if (error instanceof OversizeResponseError) {
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response too large');
                return;
              }
              const respHeaders = headersForStreaming(upstreamRes.headers);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(raw);
            }
          });
          return;
        }

        // ── 受限用户 Agent preset 列表过滤 ──
        if (req.method === 'POST' && reqAs.dshpwPerms !== undefined && reqAs.dshpwPerms.allowed_agent_presets !== null && /^\/api\/agentPreset[.\/]list$/.test(proxyPath)) {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              const parsed = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
              const allowed = new Set(reqAs.dshpwPerms!.allowed_agent_presets);
              const filterItems = (value: unknown): unknown => {
                if (!Array.isArray(value)) return value;
                return value.filter((item) => {
                  if (item === null || typeof item !== 'object') return false;
                  const row = item as Record<string, unknown>;
                  const id = typeof row.id === 'string' ? row.id : typeof row.agentPreset === 'string' ? row.agentPreset : null;
                  return id !== null && allowed.has(id);
                });
              };
              const result = parsed.result;
              if (result !== null && typeof result === 'object') {
                const resultObj = result as Record<string, unknown>;
                const value = resultObj.value;
                if (value !== null && typeof value === 'object') {
                  const valueObj = value as Record<string, unknown>;
                  if ('items' in valueObj) valueObj.items = filterItems(valueObj.items);
                  if ('presets' in valueObj) valueObj.presets = filterItems(valueObj.presets);
                } else if (Array.isArray(value)) {
                  resultObj.value = filterItems(value);
                }
              }
              const out = Buffer.from(JSON.stringify(parsed), 'utf8');
              const headers = headersForRewrittenBody(upstreamRes.headers);
              headers['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, headers);
              if (!res.writableEnded) res.end(out);
            } catch {
              if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
            }
          });
          return;
        }

        // ── 非 HTML：原样流式转发 ───────────────────────────────────
        const respHeaders = headersForStreaming(upstreamRes.headers);
        // dsh 对插件/静态资源返回 no-cache（或不给缓存头），浏览器每次
        // 进页面都要重新下载全部 ~30 个插件文件，导致卡在 "Loading plugins…"。
        // rev 参数/文件名都是内容哈希（换内容即换新 URL），可安全长缓存：
        const isHashedStatic =
          proxyPath.startsWith('/assets/') ||
          (proxyPath.startsWith('/plugins/') && parsedUrl.searchParams.has('rev'));
        if (isHashedStatic) {
          respHeaders['cache-control'] = 'public, max-age=31536000, immutable';
        }
        if (res.headersSent) {
          // 响应已被 fail-closed 分支发送（上游仍返回了响应）：不再重复写头
          res.destroy();
          return;
        }
        res.writeHead(upstreamRes.statusCode ?? 502, respHeaders);
        // F-A2：aionui-panel/raw（GET 流式读文件）文本类型 → 字节级流式清洗隐藏 Unicode
        // （图片/二进制不洗，防损坏）。read（POST JSON）已在上面缓冲分支清洗。
        if (req.method === 'GET' && proxyPath === '/aionui-panel/raw' && isTextContentType(contentType)) {
          upstreamRes.pipe(hiddenUnicodeStripStream()).pipe(res);
          upstreamRes.on('error', () => res.destroy());
          return;
        }
        if (proxyPath === '/api/events.host' && reqAs.dshpwUser !== undefined && reqAs.dshpwPerms !== undefined) {
          upstreamRes.pipe(hostEventFilter(reqAs.dshpwUser, reqAs.dshpwPerms)).pipe(res);
          upstreamRes.on('error', () => res.destroy());
          return;
        }
        if (proxyPath === '/api/events.mux' && reqAs.dshpwUser !== undefined && reqAs.dshpwPerms !== undefined) {
          upstreamRes.pipe(muxEventFilter(reqAs.dshpwUser, reqAs.dshpwPerms)).pipe(res);
          upstreamRes.on('error', () => res.destroy());
          return;
        }
        upstreamRes.pipe(res);
        // 上游响应流中途断开：客户端侧直接中断（头已发，不能再写错误页）
        upstreamRes.on('error', () => {
          res.destroy();
        });
      },
    );
    upstreamReq.on('error', (error) => {
      if (res.headersSent) {
        // 响应已开始转发：只能中断连接，避免 ERR_HTTP_HEADERS_SENT 崩溃
        res.destroy();
        return;
      }
      res
        .status(502)
        .type('html')
        .send(`<h3>${escapeHtml(t(langOf(req), 'gw.upstreamDown'))}</h3><p>${escapeHtml(error.message)}</p>`);
    });
    // 客户端中途断开：中止上游请求，避免悬挂连接
    res.on('close', () => {
      if (!res.writableEnded) upstreamReq.destroy();
    });
    // 受限子用户的请求体缓冲检查（尽力而为）：
    //   1) 文件夹白名单：session.create/fork 的 cwd/workspaceId 必须在授权目录内
    //   2) 沙盒权限：settings.mutate 试图把 defaultPreset 切到高于授权级别 → 403
    const workspaceManagementRequest = isWorkspaceCreate(proxyPath) || isWorkspaceDeleteOrRename(proxyPath);
    const needsFolderCheck =
      reqAs.dshpwPerms !== undefined &&
      (req.method === 'POST' || req.method === 'PUT' || (req.method === 'DELETE' && isAionuiPanel(proxyPath))) &&
      (WORKSPACE_ENDPOINT_RE.test(proxyPath) || (isWorkspaceRestricted(reqAs.dshpwPerms.allowed_folders) && isAionuiPanel(proxyPath)) || workspaceManagementRequest);
    const needsSandboxCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwPerms.sandbox_mode !== null &&
      (req.method === 'POST' || req.method === 'PUT') &&
      /^\/api\/settings[.\/]/.test(proxyPath);
    // 沙盒切换的实际主路径是 /permission slash 命令：经 commands/execute RPC
    // （body { agentId, line }，line 形如 "/permission workspace-write"），
    // 而不是 settings.mutate。这里对受限子用户同样做越权预设检查。
    const needsCommandCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwPerms.sandbox_mode !== null &&
      (req.method === 'POST' || req.method === 'PUT') &&
      /^\/api\/commands[.\/]execute$/.test(proxyPath);
    // AI 提权审批：沙盒升级经 /api/respond（body { sessionId, approvalId, outcome }）。
    // 受限子用户（sandbox_mode 非空）即使点了“允许”，也强制改成 rejected，把 AI 的
    // 越权提权直接取消。ask_user_question 用的是 answer 字段，不会被这里误伤。
    const needsApprovalCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwPerms.sandbox_mode !== null &&
      (req.method === 'POST' || req.method === 'PUT') &&
      /^\/api\/respond$/.test(proxyPath);
    // 会话作用域 RPC（history/prompt/respond/archive/delete/rename/fork 等）
    // 必须命中显式授权快照、位于已开启工作区，且未被管理员逐会话关闭。
    const needsOwnershipCheck =
      reqAs.dshpwPerms !== undefined &&
      (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE') &&
      (SESSION_SCOPED_RE.test(proxyPath) || /^\/api\/agentPreset[.\/]select$/.test(proxyPath));
    // ── 第三方插件纵深防御：dsh-ssh 创建/修改/测试主机时，host 为私网/回环地址
    // 一律拒绝（SSRF 封堵——插件源码不在我们控制内，网关拦一层；
    // 所有登录用户含主用户都拦，管理员同样可能被诱导连接内网）
    // F-27：PATCH（修改主机）/PUT 同样要拦——之前只拦 POST，PATCH 可直接把
    // 已有主机的 host 改成 127.0.0.1 等私网地址（实测可修改成功）
    const needsAgentPresetCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwPerms.allowed_agent_presets !== null &&
      (req.method === 'POST' || req.method === 'PUT') &&
      (/^\/api\/session[.\/](create|fork|prompt)$/.test(proxyPath) ||
        /^\/api\/agentPreset[.\/]select$/.test(proxyPath));
    const agentPresetMutation = /^\/api\/agentPreset[.\/](copy|openDocument|remove|read)$/.test(proxyPath);
    if (reqAs.dshpwPerms !== undefined && reqAs.dshpwPerms.allowed_agent_presets !== null && agentPresetMutation) {
      res.status(403).type('html').send(forbiddenPage(langOf(req), t(langOf(req), 'gw.folderDenied')));
      return;
    }
    const needsSshHostCheck =
      reqAs.dshpwUser !== undefined &&
      (req.method === 'POST' || req.method === 'PATCH' || req.method === 'PUT') &&
      /^\/api\/dsh-ssh[.\/](hosts|test)([.\/]|$)/.test(proxyPath);

    if (needsFolderCheck || needsSandboxCheck || needsCommandCheck || needsApprovalCheck || needsOwnershipCheck || needsAgentPresetCheck || needsSshHostCheck) {
      const chunks: Buffer[] = [];
      let size = 0;
      let settled = false;
      // 权限检查必须先完整读取 JSON，平台统一设置有界硬上限；不再按子用户
      // 或上传/Prompt 类型施加业务大小限制。超过平台硬上限时 fail-closed，
      // 防止超大请求绕过 ownership/preset/sandbox 检查或耗尽网关内存。
      const bodyLimit = requestBodyLimit;
      const declaredLength = Number(req.headers['content-length'] ?? '');
      if (Number.isFinite(declaredLength) && declaredLength > bodyLimit) {
        settled = true;
        upstreamReq.destroy();
        res.status(413).type('html').send(forbiddenPage(langOf(req), t(langOf(req), 'gw.bodyTooLarge')));
        return;
      }
      req.on('data', (chunk: Buffer) => {
        if (settled) return;
        size += chunk.length;
        if (size > bodyLimit) {
          // F-17：超限一律 fail-closed（413）——之前 aionui 写超大 body 会
          // 透传跳过白名单校验（fail-open），形成防御缺口
          settled = true;
          const lang = langOf(req);
          // 先中止上游请求，否则上游响应到达时会对已发送的响应再 writeHead
          upstreamReq.destroy();
          res.status(413).type('html').send(forbiddenPage(lang, t(lang, 'gw.bodyTooLarge')));
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', async () => {
        if (settled) return;
        settled = true;
        const lang = langOf(req);
        let bodyObj: unknown = null;
        try {
          bodyObj = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        } catch {
          bodyObj = null;
        }
        // 需要检查的端点 body 必须是可解析的 JSON。解析失败（gzip/非 JSON 编码
        // 构造）一律 fail-closed：直接拒绝，防止绕过文件夹白名单、沙盒越权、
        // 命令越权与 AI 提权审批（之前会静默透传到上游）。
        if (bodyObj === null) {
          upstreamReq.destroy();
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
          return;
        }
        // 转发体默认原样；SSRF 校验或审批改写时会整体重建（重建必须同步更新 content-length）
        let forwardBody = Buffer.concat(chunks);

        if (needsAgentPresetCheck) {
          const allowedPresets = new Set(reqAs.dshpwPerms!.allowed_agent_presets ?? []);
          const requestedPreset = findStringField(bodyObj, 'agentPreset');
          const sessionIds = collectSessionIds(bodyObj);
          const requiresExplicitPreset = /^\/api\/agentPreset[./]select$/.test(proxyPath);
          const sessionAgentPresets = sessionAgentPresetMapFor(reqAs.dshpwUser!);
          const inheritedPreset = /^\/api\/session[.\/]fork$/.test(proxyPath)
            ? [...sessionIds].map((id) => sessionAgentPresets.get(id)).find((id): id is string => id !== undefined)
            : undefined;
          const promptPresets = /^\/api\/session[.\/]prompt$/.test(proxyPath)
            ? [...sessionIds].map((id) => sessionAgentPresets.get(id))
            : [];
          const selectedPreset = requestedPreset ?? inheritedPreset;
          const isSessionCreate = /^\/api\/session[.\/]create$/.test(proxyPath);
          const allowed = isSessionCreate
            ? requestedPreset === null || allowedPresets.has(requestedPreset)
            : requiresExplicitPreset
            ? requestedPreset !== null && allowedPresets.has(requestedPreset)
            : /^\/api\/session[.\/]fork$/.test(proxyPath)
              ? selectedPreset !== undefined && allowedPresets.has(selectedPreset)
              : promptPresets.length > 0 && promptPresets.every((preset) => preset !== undefined && allowedPresets.has(preset));
          if (!allowed) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          if ((/^\/api\/session[.\/](create|fork)$/.test(proxyPath) || /^\/api\/agentPreset[.\/]select$/.test(proxyPath)) && selectedPreset !== undefined) {
            reqAs.dshpwAgentPreset = selectedPreset;
          }
          if (/^\/api\/agentPreset[.\/]select$/.test(proxyPath)) {
            reqAs.dshpwSelectedSessionId = [...sessionIds][0];
          }
        }

        // dsh-ssh SSRF 封堵：创建/修改主机时 body.host 命中私网/回环 → 403。
        // 只校验 host 字段存在的情况（test 请求用 alias 引用已创建主机，无 host 字段——
        // 私网主机在创建时已被拦截，test 无从引用私网目标）。
        // F-28：host 为 hostname（如 nip.io 通配）时 DNS 解析逐地址判定；校验通过后
        // 把请求体 host 改写为已验证的 IP 字面量，钉死 DNS 重绑定 TOCTOU。
        if (needsSshHostCheck && bodyObj !== null && typeof bodyObj === 'object') {
          const host = (bodyObj as Record<string, unknown>).host;
          if (typeof host === 'string') {
            const verdict = await resolveSshHostSafe(host);
            if (verdict === 'private' || verdict === null) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
              return;
            }
            (bodyObj as Record<string, unknown>).host = verdict;
            forwardBody = Buffer.from(JSON.stringify(bodyObj), 'utf8');
            // 重写 body 必须同步更新 content-length，否则上游按旧长度读流会挂起/错位
            upstreamReq.setHeader('content-length', String(forwardBody.length));
          }
        }

        if (needsFolderCheck) {
          let targetPath: string | null = null;
          if (isAionuiPanel(proxyPath)) {
            // aionui-panel 文件树：root 是工作区路径，path 是 root 下的相对文件路径
            targetPath = aionuiRootFrom(req.method, proxyPath, parsedUrl.searchParams, bodyObj);
            // F-17b：提取不到 root（DELETE 无 query/body、异常编码等）→ fail-closed，
            // 不能静默跳过白名单校验后透传
            if (targetPath === null) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
              return;
            }
          } else {
            targetPath = extractPathFromBody(bodyObj);
            if (targetPath === null) {
              const wid = extractWorkspaceId(bodyObj);
              if (wid !== null) targetPath = workspacePathById.get(wid) ?? null;
              // 走到这里仍为 null = 既无路径字段、也无 workspaceId 缓存命中（含空 body /
              // 缓存 miss）→ 一律 fail-closed：不能跳过白名单校验后透传，否则可创建到
              // 白名单外的工作区
              if (targetPath === null) {
                upstreamReq.destroy();
                res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
                return;
              }
            }
          }
          // session.create 即使用户的目录白名单为空（不限目录），仍不可借共享父目录
          // 或 workspaceId 缓存向其他用户拥有的工作区创建会话。
          if (targetPath !== null && WORKSPACE_ENDPOINT_RE.test(proxyPath) && !reqAs.dshpwIsAdmin) {
            const normalizedTarget = normalizePath(targetPath);
            const owners = db.listWorkspaceOwners();
            if (owners.some((owner) => normalizePath(owner.path) === normalizedTarget && owner.userId !== reqAs.dshpwUser)) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.workspaceDenied')));
              return;
            }
          }
          // 新建工作区由专门权限控制：成功后会自动加入创建者白名单，因此不能被
          // 新用户的初始 __deny__ 白名单反向锁死。已有工作区的删除/重命名仍须在白名单内。
          if (targetPath !== null && !isWorkspaceCreate(proxyPath) && !folderAllowed(targetPath, reqAs.dshpwPerms!.allowed_folders)) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          if (targetPath !== null && (isWorkspaceCreate(proxyPath) || isWorkspaceDeleteOrRename(proxyPath))) {
            const renamePaths = isWorkspaceDeleteOrRename(proxyPath) ? extractWorkspaceRenamePaths(bodyObj) : null;
            if (isWorkspaceDeleteOrRename(proxyPath) && renamePaths === null && /(?:rename|update)(?:[./]|$)/.test(proxyPath)) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
              return;
            }
            const oldPath = normalizePath(renamePaths?.oldPath ?? targetPath);
            const newPath = renamePaths === null ? null : normalizePath(renamePaths.newPath);
            const pathsToAuthorize = newPath === null ? [oldPath] : [oldPath, newPath];
            const owners = db.listWorkspaceOwners();
            if (!reqAs.dshpwIsAdmin && owners.some((owner) => pathsToAuthorize.includes(normalizePath(owner.path)) && owner.userId !== reqAs.dshpwUser)) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.workspaceDenied')));
              return;
            }
            if (newPath !== null && !folderAllowed(newPath, reqAs.dshpwPerms!.allowed_folders)) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
              return;
            }
            reqAs.dshpwWorkspacePath = oldPath;
            reqAs.dshpwWorkspaceCreate = isWorkspaceCreate(proxyPath);
            if (newPath !== null) {
              reqAs.dshpwWorkspaceOldPath = oldPath;
              reqAs.dshpwWorkspaceNewPath = newPath;
            }
          }
          // 记录本次判定出的目标目录，供 session.create/fork 响应回调登记 sessionId→cwd 缓存
          if (targetPath !== null) reqAs.dshpwSessionCwd = targetPath;
        }

        if (needsSandboxCheck && bodyObj !== null) {
          const preset = presetFromSettingsMutate(bodyObj);
          const assignedRank =
            SANDBOX_RANK[reqAs.dshpwPerms!.sandbox_mode as keyof typeof SANDBOX_RANK] ?? 0;
          const targetRank = preset === null ? assignedRank : sandboxPresetRank(preset);
          if (targetRank > assignedRank) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.sandboxDenied')));
            return;
          }
        }

        if (needsCommandCheck && bodyObj !== null) {
          const line = findStringField(bodyObj, 'line');
          const preset = line === null ? null : permissionPresetFromCommand(line);
          if (preset !== null) {
            const assignedRank =
              SANDBOX_RANK[reqAs.dshpwPerms!.sandbox_mode as keyof typeof SANDBOX_RANK] ?? 0;
            const targetRank = sandboxPresetRank(preset);
            if (targetRank > assignedRank) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.sandboxDenied')));
              return;
            }
          }
        }

        // 审批响应改写：受限子用户的 AI 提权审批一律强制 rejected（返回取消）
        if (needsApprovalCheck && bodyObj !== null && typeof bodyObj === 'object') {
          if (forceRejectApproval(bodyObj)) {
            forwardBody = Buffer.from(JSON.stringify(bodyObj), 'utf8');
            upstreamReq.setHeader('content-length', String(forwardBody.length));
          }
        }

        // 会话访问校验：子用户须命中显式授权快照且位于已开启工作区；逐会话关闭优先。
        if (needsOwnershipCheck && bodyObj !== null) {
          const bodySessionIds = collectSessionIds(bodyObj);
          const querySessionId = parsedUrl.searchParams.get('sessionId');
          if (querySessionId !== null) bodySessionIds.add(querySessionId);
          const perms = reqAs.dshpwPerms!;
          const access = reqAs.dshpwUser === undefined ? new Map<string, string>() : userSessionAccessFor(reqAs.dshpwUser);
          const allowed = (sessionId: string): boolean => {
            const cwd = reqAs.dshpwIsAdmin === true
              ? sessionCwdById.get(sessionId)
              : access.get(sessionId);
            return !perms.disabled_sessions.includes(sessionId) && cwd !== undefined && folderAllowed(cwd, perms.allowed_folders);
          };
          if (bodySessionIds.size === 0 || [...bodySessionIds].some((sessionId) => !allowed(sessionId))) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          // 只有已经通过源会话授权的 fork 才能把新 sessionId 登记到当前用户快照。
          // fork 的 cwd 必须继承已校验的源会话目录，不能信任上游响应里的 cwd，
          // 否则异常/被投毒的响应可能把新会话写入白名单外目录。
          if (/^\/api\/session[.\/]fork$/.test(proxyPath)) {
            const sourceId = [...bodySessionIds][0];
            const sourceCwd = access.get(sourceId);
            if (sourceCwd === undefined) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
              return;
            }
            reqAs.dshpwForkAuthorized = true;
            reqAs.dshpwSessionCwd = sourceCwd;
          }
        }

        upstreamReq.end(forwardBody);
      });
      req.on('error', () => {
        if (!settled) {
          settled = true;
          upstreamReq.destroy();
        }
      });
    } else {
      req.pipe(upstreamReq);
    }
  });

  const hasTls = config.gateway.tls !== null;
  const server = hasTls
    ? https.createServer(
        {
          // 默认证书（启动时读一次）：不带 SNI 的客户端（如 https://127.0.0.1
          // 直连、插件→网关内部回环调用）不会触发 SNICallback，必须要有默认
          // cert/key 才能完成握手
          cert: readFileSync(config.gateway.tls!.cert),
          key: readFileSync(config.gateway.tls!.key),
          // 证书每次 TLS 握手时从文件动态读取：自动续期写入新文件后
          // 下一个连接即用新证书，无需重启进程
          SNICallback: (_servername, callback) => {
            try {
              callback(
                null,
                createSecureContext({
                  cert: readFileSync(config.gateway.tls!.cert),
                  key: readFileSync(config.gateway.tls!.key),
                  minVersion: 'TLSv1.2',
                }),
              );
            } catch (error) {
              callback(error as Error);
            }
          },
          // 仅允许 TLS 1.2+，拒绝老旧协议与弱套件协商
          minVersion: 'TLSv1.2',
        },
        app,
      )
    : http.createServer(app);

  // slowloris 加固（第四轮 P-note）：显式请求超时 + 并发连接上限
  //   - headersTimeout 20s：半开头部（慢速发头）更快被切断（Node 默认 60s）
  //   - requestTimeout 60s：完整请求体超时（Node 默认 300s；仅影响收包，不影响 SSE/长连接）
  //   - maxConnections 512：防千级慢连接耗尽文件句柄（100 并发压力测试实测无压力）
  server.headersTimeout = 20_000;
  server.requestTimeout = 60_000;
  server.maxConnections = 512;

  // ── 内存结构周期性清理（防长期运行缓慢积累） ───────────────────
  // sessionCache / revokedTokens / usageThrottle / usageReportThrottle /
  // setupAttempts / msgRate 都以 token / IP / userId 为键，平时按需淘汰，
  // 这里兑底每 10 分钟全量扫一遍过期条目：内存面与活跃用户数成正比，
  // 而不是与进程运行时长成正比。定时器 unref，不阻碍进程退出。
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of sessionCache) if (v.expireAt <= now) sessionCache.delete(k);
    for (const [k, v] of revokedTokens) if (v <= now) revokedTokens.delete(k);
    for (const [k, v] of usageThrottle) if (now - v > 3600_000) usageThrottle.delete(k);
    for (const [k, v] of usageReportThrottle) if (now - v > 3600_000) usageReportThrottle.delete(k);
    for (const [k, v] of setupAttempts) {
      const keep = v.filter((t) => now - t < SETUP_WINDOW_MS);
      if (keep.length > 0) setupAttempts.set(k, keep);
      else setupAttempts.delete(k);
    }
    for (const [k, v] of msgRate) {
      const keep = v.filter((t) => now - t < 60_000);
      if (keep.length > 0) msgRate.set(k, keep);
      else msgRate.delete(k);
    }
    for (const [k, v] of loginSuccessRate) {
      const keep = v.filter((t) => now - t < 60_000);
      if (keep.length > 0) loginSuccessRate.set(k, keep);
      else loginSuccessRate.delete(k);
    }
    // 极端 token/IP 洪泛下，TTL 尚未到期的键也可能无界增长；保留最新一半，
    // 牺牲极端情况下的短期缓存命中而不牺牲进程可用性。
    // ⚠ revokedTokens 不参与裁剪：它是登出吊销语义（未过期条目=拒绝该 JWT），
    // “淘汰即放行”会让已登出的会话重新可用；其条目仅能由 sweep 按到期时间清理。
    const cap = <T>(map: Map<T, unknown>, limit = 10_000) => {
      if (map.size <= limit) return;
      let drop = Math.ceil(map.size / 2);
      for (const key of map.keys()) {
        map.delete(key);
        if (--drop === 0) break;
      }
    };
    cap(sessionCache);
    cap(usageThrottle);
    cap(usageReportThrottle);
    cap(setupAttempts);
    cap(msgRate);
    // 会话路径缓存按容量裁剪（重启后由 session.list/workspace.list 重建；防长期运行无界增长）
    cap(sessionCwdById);
    cap(workspacePathById, 20_000);
    // 数据库周期清理：登录失败/节流表与注册表幽灵会话（写失败只告警不致命）
    try {
      db.pruneStaleSecurityRows();
    } catch (error) {
      console.warn('[dsh-passwords] 周期清理失败:', String(error));
    }
  }, 10 * 60_000);
  sweep.unref();
  server.on('close', () => clearInterval(sweep));

  // ── WebSocket 升级代理（dsh 前端依赖 WS 通信） ──────────────
  server.on('upgrade', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    // F-03 同口径：网关前缀判定与转发路径都用「原始路径迭代解码 + 压平
    // 斜杠 + WHATWG 归一化」，与 HTTP 代理保持一致，杜绝 %2f/%2e 变体
    // 在 WS 升级请求里漂移（HTTP 侧已修，这里补齐同口径）。
    const rawPath = (req.url ?? '/').split('?')[0];
    const gatePath = normalizeDecodedPath(rawPath);
    if (gatePath === '/gateway' || gatePath.startsWith('/gateway/')) {
      socket.destroy();
      return;
    }
    const queryIndex = (req.url ?? '').indexOf('?');
    const fwdPath = gatePath + (queryIndex >= 0 ? (req.url ?? '').slice(queryIndex) : '');
    // WebSocket 同样是浏览器携带 Cookie 的状态变更通道，先拒绝跨源升级。
    if (!originHostMatches(req)) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }
    // 认证检查（复用 Cookie；与 HTTP 侧一致：校验 cv + banned + 登出吊销）
    const token = readCookie(req.headers.cookie, COOKIE_NAME);
    let authed = false;
    let authUserId: number | null = null;
    let userRole: 'admin' | 'user' | null = null;
    let userWebSocketGrants: string[] = [];
    if (token && !isTokenRevoked(token)) {
      try {
        const user = auth.verifyToken(token);
        const row = db.getUserByUsername(user.username);
        if (row !== null && user.cv === row.credential_version) {
          const perms = effectivePermissions(row.id);
          if (!perms.banned) {
            authed = true;
            authUserId = row.id;
            userRole = row.role === 'admin' ? 'admin' : 'user';
            const registeredWebSocketPaths = new Set(userGrantableWebSocketPaths);
            userWebSocketGrants = perms.allowed_websocket_paths.filter((rule) => registeredWebSocketPaths.has(rule));
          }
        }
      } catch {
        authed = false;
      }
    }
    if (!authed) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    // P1-1：internal 端点不接受外部 WS 升级（仅限网关→dsh 本机 HTTP 调用）
    if (gatePath.startsWith('/api/dsh-passwords/internal/')) {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
      return;
    }
    // 终端/侧栏等运维能力在 HTTP 与 WebSocket 层使用同一管理员边界；
    // 仅有路径授权并不意味着其 frame 协议可按工作区安全隔离。
    if (userRole === 'user' && isAdminOnlySidebarEndpoint(gatePath)) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }
    // rc.2 的 events.host/events.mux 是 downlink-only WebSocket；子用户走网关
    // 协议过滤适配器，remote.mux 在 rc.2 不存在，仍默认拒绝。
    if (userRole === 'user' && (gatePath === '/api/events.host' || gatePath === '/api/events.mux')) {
      const channel = gatePath === '/api/events.host' ? 'host' : 'mux';
      const wsServer = new WebSocket.WebSocketServer({ noServer: true });
      wsServer.handleUpgrade(req, socket, head, (client: any) => {
        const upstreamWs = new (require('ws'))(`${upstream.protocol === 'https:' ? 'wss' : 'ws'}://${upstreamHost}:${upstreamPort}${fwdPath}`, {
          headers: { host: `${upstreamHost}:${upstreamPort}`, origin: `http://${upstreamHost}:${upstreamPort}` },
        });
        client.on('message', () => client.close(1008, 'downlink only'));
        client.on('close', () => { try { upstreamWs.close(); } catch {} });
        upstreamWs.on('open', () => {});
        upstreamWs.on('message', (data: Buffer) => {
          const filtered = authUserId === null
            ? null
            : filterEventWebSocketFrame(authUserId, effectivePermissions(authUserId), channel, Buffer.from(data));
          if (filtered !== null && client.readyState === WebSocket.OPEN) client.send(filtered);
        });
        upstreamWs.on('error', () => { if (client.readyState === WebSocket.OPEN) client.close(1011, 'upstream error'); });
        upstreamWs.on('close', () => { if (client.readyState === WebSocket.OPEN) client.close(); });
      });
      return;
    }
    // 内置事件通道保持原有行为。第三方 WebSocket 必须先配置，
    // 子用户还必须获得主用户在设置页中的明确授权。默认拒绝未知路径。
    const builtinWsPath =
      gatePath === '/api/events.mux' ||
      gatePath === '/api/events.host' ||
      gatePath === '/plugins/events' ||
      gatePath === '/aionui-panel/events' ||
      gatePath.startsWith('/aionui-panel/events/');
    const wsAccess = webSocketAccessForPath(
      gatePath,
      userRole === 'admin'
        ? [...adminOnlyWebSocketPaths, ...userGrantableWebSocketPaths]
        : userGrantableWebSocketPaths,
      userWebSocketGrants,
      userRole ?? 'user',
      builtinWsPath,
    );
    if (wsAccess === 'deny') {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
      return;
    }

    // 转发升级请求（Host/Origin 改写，同 HTTP 路径；路径已规范化）
    const upstreamSocket = net.connect(upstreamPort, upstreamHost, () => {
      const lines: string[] = [
        `${req.method ?? 'GET'} ${fwdPath} HTTP/1.1`,
      ];
      for (const [key, value] of Object.entries(req.headers)) {
        const lower = key.toLowerCase();
        // F-15：与 HTTP 代理同口径——不把网关会话 Cookie 转发给上游
        if (lower === 'cookie') continue;
        if (lower === 'host') {
          lines.push(`Host: ${upstreamHost}:${upstreamPort}`);
        } else if (lower === 'origin' && typeof value === 'string') {
          lines.push(`Origin: http://${upstreamHost}:${upstreamPort}`);
        } else if (value !== undefined) {
          lines.push(`${key}: ${Array.isArray(value) ? value.join(', ') : value}`);
        }
      }
      lines.push('', '');
      upstreamSocket.write(lines.join('\r\n'));
      if (head && head.length > 0) upstreamSocket.write(head);
      socket.pipe(upstreamSocket);
      upstreamSocket.pipe(socket);
    });
    upstreamSocket.on('error', () => socket.destroy());
    socket.on('error', () => upstreamSocket.destroy());
    socket.on('close', () => upstreamSocket.destroy());
    upstreamSocket.on('close', () => socket.destroy());
  });

  return server;
}

/**
 * HTTP→HTTPS 301 跳转服务器（仅 TLS 模式且配置了 redirectPort 时创建）。
 * 解决“网关裸奔在 80 明文”问题：80 不再提供任何页面内容，只做跳转。
 * 自动 HTTPS 模式下同时承载 ACME HTTP-01 挑战应答（/.well-known/acme-challenge/*）。
 */
export function createRedirectServer(
  config: PlatformConfig,
  challengeStore?: Map<string, string>,
): http.Server | null {
  if (config.gateway.tls === null || config.gateway.redirectPort === null) return null;
  const server = http.createServer((req, res) => {
    // ACME HTTP-01 挑战应答：优先于跳转处理（Let's Encrypt 校验走这里）
    if (challengeStore) {
      const pathname = (() => {
        try {
          return new URL(req.url ?? '/', 'http://localhost').pathname;
        } catch {
          return '/';
        }
      })();
      const prefix = '/.well-known/acme-challenge/';
      if (pathname.startsWith(prefix)) {
        const token = pathname.slice(prefix.length).split('/')[0];
        const keyAuthz =
          token !== '' && /^[A-Za-z0-9_-]{1,128}$/.test(token)
            ? challengeStore.get(token)
            : undefined;
        if (keyAuthz !== undefined) {
          res.writeHead(200, {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Length': String(Buffer.byteLength(keyAuthz)),
            'Cache-Control': 'no-store',
            Connection: 'close',
          });
          res.end(keyAuthz);
          return;
        }
        res.writeHead(404, { 'Content-Length': '0', Connection: 'close' });
        res.end();
        return;
      }
    }
    // Host 头部可能带跳转端口或 :80 后缀，跳转目标去掉它们；空 Host 回退主端口
    const strip = new RegExp(`:(${config.gateway.redirectPort}|80)$`);
    const rawHost = (req.headers.host ?? '').replace(strip, '');
    // 防 Host 反射（HTTP/1.0 可伪造 Host: evil.com → Location: https://evil.com/）：
    // 自动 HTTPS 固定用证书域名；否则用配置的公网主机；再否则严格校验请求 Host 格式
    const candidate = config.gateway.domain || config.gateway.publicHost || rawHost;
    const host =
      /^[A-Za-z0-9.\-[\]:]+$/.test(candidate) && candidate !== ''
        ? candidate
        : `127.0.0.1:${config.gateway.port}`;
    const target = `https://${host}${req.url ?? '/'}`;
    res.writeHead(301, {
      Location: target,
      'Content-Length': '0',
      Connection: 'close',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
    });
    res.end();
  });
  // slowloris 加固：80 跳转端口同样设显式超时 + 连接上限（ACME 挑战不受影响）
  server.headersTimeout = 20_000;
  server.requestTimeout = 60_000;
  server.maxConnections = 256;
  return server;
}
