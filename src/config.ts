// .env 加载：优先读 DSH_PASSWORDS_ENV_FILE（dsh 插件进程用，与网关共享同一份 .env），
// 否则相对模块位置解析项目根目录 .env。
// 这样无论从哪个目录运行（systemd WorkingDirectory、npm start、
// 任意目录下的 CLI）都读到同一份配置与同一把密钥。
import { config as loadEnv } from 'dotenv';
import { fileURLToPath } from 'node:url';
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { parseWebSocketAllowlist } from './permissions.js';

const moduleDir = path.dirname(fileURLToPath(import.meta.url));
// dsh 进程里没有本项目的 .env（通过 DSH_PASSWORDS_ENV_FILE 显式指定网关 .env 路径）。
// npm 更新会切换模块目录；部署配置和数据必须跟随这个显式配置文件，而不能跟随新包目录。
const explicitEnvFile = process.env.DSH_PASSWORDS_ENV_FILE?.trim();
const configRoot = explicitEnvFile ? path.dirname(path.resolve(explicitEnvFile)) : path.resolve(moduleDir, '..');
if (explicitEnvFile) {
  loadEnv({ path: explicitEnvFile, quiet: true });
}
loadEnv({ path: path.join(moduleDir, '..', '.env'), quiet: true });



function readEnv(name: string, fallback: string): string {
  return (process.env[name] ?? '').trim() || fallback;
}

/** 环境文件明确指定时，配置相对路径必须以环境文件目录为锚点。 */
export function resolveConfigPath(value: string, configRoot: string, fallbackName: string): string {
  const raw = value.trim() || fallbackName;
  return path.isAbsolute(raw) ? raw : path.resolve(configRoot, raw);
}

export interface PlatformConfig {
  setupKey: string;
  /** SQLite 数据库文件路径（Node 内置 node:sqlite，无需外部数据库） */
  dbPath: string;
  /** 数据静态加密密钥（可选，留空则从 SETUP_KEY 派生） */
  dbEncKey: string;
  /** 登录网关（dsh 访问门卫）：对外端口 + 上游 dsh 地址 */
  gateway: {
    host: string;
    port: number;
    upstream: string;
    /** HTTPS 证书/密钥文件路径（都配置时网关启用 TLS） */
    tls: { cert: string; key: string } | null;
    /** HTTP→HTTPS 301 跳转端口（TLS 开启时可选；空/0 = 关闭） */
    redirectPort: number | null;
    /** 公网访问主机（跳转固定用它，防 Host 头反射；留空则用校验后的请求 Host） */
    publicHost: string;
    /** 证书域名（自动 HTTPS 用；由 MCP_GATEWAY_DOMAIN 或公网 IP 推导 <IP>.sslip.io） */
    domain: string;
    /** 自动申请/续期 Let's Encrypt 证书（零配置 HTTPS） */
    autoTls: boolean;
    /** ACME 联系邮箱（可选，证书到期提醒用） */
    acmeEmail: string;
    /** 使用 Let's Encrypt 测试环境签发（浏览器不信任，仅调试用） */
    acmeStaging: boolean;

  };
  jwtSecret: string;
  /** 网关内部管理接口密钥（dsh 插件通知网关用；留空则从 SETUP_KEY 派生） */
  internalSecret: string;
  /** 远程设置补丁（settings host 模式 + 白名单）管理配置；补丁强制启用，无开关 */
  patch: {
    /** dsh 安装根目录（@deepseek-ai/dsh 所在位置）；留空自动探测 npm root -g */
    dshRoot: string;
    /** 补丁应用后要重启的 dsh systemd 服务名；留空则不自动重启 */
    restartService: string;
  };
  /** WebSocket 路径授权：内置事件默认开放，第三方路径必须显式配置。 */
  webSocket: {
    adminAllowlist: string[];
    userAllowlist: string[];
  };
}

export function loadConfig(): PlatformConfig {
  // F-07：启动时收紧 .env 权限（POSIX 0600），防止同机其他用户/备份泄露密钥
  tightenEnvPerm(envFilePath());
  // Windows：手动创建/复制来的 .env 不经过安装器，这里启动时同样用 icacls 收紧
  // （失败仅告警不阻断启动，见 tightenWindowsAcl）
  tightenWindowsAcl(envFilePath());
  const setupKey = readEnv('SETUP_KEY', '');
  // 无 SETUP_KEY 时拒绝加载（fail-closed）：
  // 之前回退到 sha256('dev') 可被公开计算，攻击者能伪造任意 JWT 认证绕过。
  // cli/plugin 入口本就强制 SETUP_KEY 非空，这里兜底防其他调用路径漏拦。
  if (setupKey === '') {
    throw new Error('SETUP_KEY 未配置：请先运行安装脚本或手动配置 .env（见 .env.example）');
  }
  // JWT 密钥：从 SETUP_KEY 稳定派生（重启不失效）；生产建议显式配置 MCP_JWT_SECRET
  const jwtSecret =
    readEnv('MCP_JWT_SECRET', '') ||
    createHash('sha256').update('dsh-jwt:' + setupKey).digest('hex');
  // 内部接口密钥：与 JWT 域分离派生，插件→网关的通知通道用
  const internalSecret =
    readEnv('MCP_INTERNAL_SECRET', '') ||
    createHash('sha256').update('dshpw-internal:' + setupKey).digest('hex');

  const dbPath = readEnv(
    'MCP_DB_PATH',
    // 若服务通过 DSH_PASSWORDS_ENV_FILE 指向部署目录，更新后的 npm 包会位于
    // 另一模块目录。默认数据库必须锚定该部署配置目录，避免切包后打开空库。
    path.join(configRoot, 'data', 'platform.db'),
  );
  // 显式相对路径也按配置目录解析。网关和 dsh 进程内插件的 cwd/模块目录
  // 可能不同，统一锚点避免各自打开一份数据库。
  const dbPathResolved = resolveConfigPath(dbPath, configRoot, path.join('data', 'platform.db'));

  // MCP_DSH_RESTART_SERVICE 语义：未设置→默认 'dsh-web'；显式空值→不自动重启。
  // （不能用 readEnv：它会把空值当未设置回退到默认，导致 Windows 上
  // 尝试 systemctl 报错。）
  const restartService =
    process.env.MCP_DSH_RESTART_SERVICE !== undefined
      ? process.env.MCP_DSH_RESTART_SERVICE.trim()
      : 'dsh-web';

  // ── 自动 HTTPS（零配置 Let's Encrypt 证书） ────────────────────
  // 优先级：MCP_GATEWAY_DOMAIN（真实域名）> MCP_GATEWAY_PUBLIC_HOST
  // （公网 IP → <IP>.sslip.io）> 启动时探测公网 IP（cli.ts 异步补）。
  // 已配置 TLS_CERT/KEY 时不生效（用户自管证书）。
  const userTlsCert = readEnv('MCP_GATEWAY_TLS_CERT', '');
  const userTlsKey = readEnv('MCP_GATEWAY_TLS_KEY', '');
  const userCerts = userTlsCert !== '' && userTlsKey !== '';
  const publicHost = readEnv('MCP_GATEWAY_PUBLIC_HOST', '');
  const autoTlsRaw = readEnv('MCP_GATEWAY_AUTO_TLS', '').trim().toLowerCase();
  let domain = readEnv('MCP_GATEWAY_DOMAIN', '').trim();
  if (domain === '' && isPublicIp(publicHost)) domain = `${publicHost}.sslip.io`;
  const autoOn =
    autoTlsRaw === '1' || autoTlsRaw === 'true' || autoTlsRaw === 'yes' || autoTlsRaw === 'auto';
  const autoOff = autoTlsRaw === '0' || autoTlsRaw === 'false' || autoTlsRaw === 'no';
  // 留空 = 自动判断：未自备证书且未显式关闭即启用（域名由 cli 启动时补全，
  // 零配置路径会探测公网 IP 推导 <IP>.sslip.io）
  const autoTls = !userCerts && !autoOff && (autoOn || autoTlsRaw === '');
  const acmeDir = path.join(path.dirname(dbPathResolved), 'acme');

  const gatewayPortRaw = readEnv('MCP_GATEWAY_PORT', '8080').trim();
  const gatewayPortNum = Number(gatewayPortRaw);
  // 端口非法（非数字/越界）回退默认 8080，避免 listen(NaN) 的泛化报错
  const gatewayPort =
    gatewayPortRaw !== '' && Number.isInteger(gatewayPortNum) && gatewayPortNum > 0 && gatewayPortNum <= 65535
      ? gatewayPortNum
      : 8080;

  return {
    setupKey,
    dbPath: dbPathResolved,
    dbEncKey: readEnv('MCP_DB_ENC_KEY', ''),
    gateway: {
      host: readEnv('MCP_GATEWAY_HOST', '0.0.0.0'),
      port: gatewayPort,
      upstream: readEnv('MCP_GATEWAY_UPSTREAM', 'http://127.0.0.1:3080'),
      tls: userCerts
        ? { cert: userTlsCert, key: userTlsKey }
        : autoTls
          ? { cert: path.join(acmeDir, 'fullchain.pem'), key: path.join(acmeDir, 'cert.key.pem') }
          : null,
      // HTTP→HTTPS 跳转端口：TLS 开启时在 80 提供 301，避免明文服务；
      // 自动 HTTPS 默认开 80（同时承载 ACME 挑战应答）
      redirectPort: (() => {
        const raw = readEnv('MCP_GATEWAY_REDIRECT_PORT', '').trim();
        // 0 = 显式关闭跳转端口（此前 0 不满足 >0 被当作"未配置"落到默认 80，文档承诺失效）
        if (raw === '0') return null;
        const n = Number(raw);
        const explicit = raw !== '' && Number.isInteger(n) && n > 0 && n <= 65535 ? n : null;
        if (explicit !== null) return explicit;
        return autoTls ? 80 : null;
      })(),
      publicHost,
      domain,
      autoTls,
      acmeEmail: readEnv('MCP_GATEWAY_ACME_EMAIL', ''),
      acmeStaging: ['1', 'true', 'yes'].includes(readEnv('MCP_GATEWAY_ACME_STAGING', '').trim().toLowerCase()),
    },
    jwtSecret,
    internalSecret,
    patch: {
      dshRoot: readEnv('MCP_DSH_ROOT', ''),
      restartService,
    },
    webSocket: {
      adminAllowlist: parseWebSocketAllowlist(process.env.MCP_GATEWAY_WS_ADMIN_ALLOWLIST, 'MCP_GATEWAY_WS_ADMIN_ALLOWLIST'),
      userAllowlist: parseWebSocketAllowlist(process.env.MCP_GATEWAY_WS_USER_ALLOWLIST, 'MCP_GATEWAY_WS_USER_ALLOWLIST'),
    },
  };
}

/** 当前生效的 .env 文件路径（与 loadConfig 的读取路径保持一致） */
function envFilePath(): string {
  return process.env.DSH_PASSWORDS_ENV_FILE?.trim() || path.join(moduleDir, '..', '.env');
}

/**
 * F-07 补强：.env 是全部密钥的载体，POSIX 下启动时收紧为仅属主可读写（0600），
 * 防止备份/目录共享/同机其他用户读取。Windows 无 POSIX 权限，自动跳过。
 */
function tightenEnvPerm(file: string): void {
  try {
    chmodSync(file, 0o600);
  } catch {
    // 非 POSIX / 只读挂载：忽略（不影响启动）
  }
}

/**
 * Windows 无 POSIX 权限：用 icacls 收紧密钥文件 ACL（仅当前用户 + SYSTEM）。
 * hardenSecretsAfterSetup 用临时文件+rename 替换 .env 后，新文件继承的是临时
 * 文件的 ACL（可能随目录宽松）——必须重新收紧，否则 SETUP_KEY/JWT/内部/DB 密钥
 * 在共享目录下会被同机其他用户读到。icacls 的失败（账号无法解析/策略禁止）
 * 不阻塞启动主流程，但必须留告警——否则“已收紧”是静默假象。
 */
function tightenWindowsAcl(file: string): void {
  if (process.platform !== 'win32') return;
  try {
    // 域环境用 DOMAIN\user 完整主体；本地账号 USERDOMAIN=机器名同样可用
    const account =
      process.env.USERDOMAIN && process.env.USERNAME
        ? `${process.env.USERDOMAIN}\\${process.env.USERNAME}`
        : process.env.USERNAME;
    const args = [file, '/inheritance:r'];
    if (account) args.push('/grant:r', `${account}:F`);
    args.push('/grant:r', 'SYSTEM:F');
    const result = spawnSync('icacls', args, { stdio: 'ignore' });
    if (result.status !== 0 || result.error !== undefined) {
      console.warn(
        `[dsh-passwords] 无法收紧密钥文件 ACL（${file}）：` +
          (result.error !== undefined ? String(result.error) : `icacls 退出码 ${String(result.status)}`),
      );
    }
  } catch {
    // 收紧失败不影响启动主流程
  }
}

/**
 * F-07：首次配置成功后自动加固密钥残留面。
 *   1. 把当前派生密钥固化为显式 .env 变量（MCP_JWT_SECRET / MCP_INTERNAL_SECRET /
 *      MCP_DB_ENC_KEY）——此后即使 SETUP_KEY 泄露，也不再连带伪造会话/解密数据库；
 *   2. SETUP_KEY 轮换为新随机值（旧值立即失效；仍保留非空以满足插件 configured 检查）；
 *   3. 删除安装脚本写入的 setup-key.txt（只用于第一次初始化，用完即删）。
 * 幂等：已显式设置过的密钥不覆盖；.env 不存在/不可写时静默跳过（不影响初始化主流程）。
 */
export function hardenSecretsAfterSetup(config: PlatformConfig): void {
  const envFile = envFilePath();
  if (!existsSync(envFile)) return;
  let raw: string;
  try {
    raw = readFileSync(envFile, 'utf8');
  } catch {
    return;
  }

  // 需要固化的密钥：当前运行进程里真正生效的值（与 loadConfig 派生一致）
  const freeze: Record<string, string> = {
    MCP_JWT_SECRET: config.jwtSecret,
    MCP_INTERNAL_SECRET: config.internalSecret,
    MCP_DB_ENC_KEY: config.dbEncKey || config.setupKey,
  };
  const newSetupKey = randomBytes(24).toString('hex');

  // 逐行重写：保留注释与无关键，替换/追加目标键
  const lines = raw.split(/\r?\n/);
  const present = new Set<string>();
  const out: string[] = [];
  for (const line of lines) {
    const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (m && !line.trimStart().startsWith('#')) {
      const key = m[1];
      present.add(key);
      if (key === 'SETUP_KEY') {
        out.push(`SETUP_KEY=${newSetupKey}`); // 轮换
        continue;
      }
      if (freeze[key] !== undefined) {
        // 按 dotenv 规则剥离引号 / `#` 注释后再判空：
        //   MCP_DB_ENC_KEY=""   → 空  → 固化当前生效值
        //   MCP_DB_ENC_KEY=     → 空  → 固化当前生效值
        //   MCP_DB_ENC_KEY= # x → 空  → 固化当前生效值（防止 dotenv 把注释当空值）
        // 之前 m[2] !== '' 的裸等会把引号空 / 注释空当"有值"，不固化，
        // 轮换 SETUP_KEY 后历史加密数据永久不可解密。
        const stripped = m[2].replace(/^['"]|['"]$/g, '').replace(/\s+#.*$/, '').trim();
        // 不论旧值是否为空，都冻结为本进程当前实际生效的值：否则显式但陈旧的
        // 值会在 SETUP_KEY 轮换后留下不可预测的 JWT/内部接口/数据库加密状态。
        if (stripped !== freeze[key]) {
          out.push(`${key}=${freeze[key]}`);
          continue;
        }
      }
    }
    out.push(line);
  }
  for (const key of Object.keys(freeze)) {
    if (!present.has(key)) out.push(`${key}=${freeze[key]}`); // 缺失则追加
  }

  try {
    // 同目录临时文件 + 原子 rename：进程崩溃时保留旧完整 .env，绝不留下半写入密钥文件。
    const tempFile = `${envFile}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
    try {
      writeFileSync(tempFile, out.join('\n') + (out.length > 0 ? '\n' : ''), { encoding: 'utf8', mode: 0o600 });
      renameSync(tempFile, envFile);
      // rename 后新文件继承临时文件的 ACL：Windows 下重新用 icacls 收紧，
      // POSIX 下 mode 已随临时文件写入生效
      tightenWindowsAcl(envFile);
    } catch (error) {
      try { if (existsSync(tempFile)) unlinkSync(tempFile); } catch { /* best effort */ }
      throw error;
    }
  } catch {
    // 写入失败不阻断初始化（用户仍可登录）；下次安装/重启时 .env 仍在
    return;
  }

  // 删除安装脚本写入的一次性密钥文件
  try {
    const keyFile = path.join(path.dirname(envFile), 'setup-key.txt');
    if (existsSync(keyFile)) unlinkSync(keyFile);
  } catch {
    // 删除失败不影响主流程；README 已有手动删除指引
  }
}

/** 公网 IPv4 判定（排除私网/环回/链路本地/CGNAT/文档段） */
export function isPublicIp(value: string): boolean {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return false;
  const parts = value.split('.').map((p) => Number(p));
  if (parts.some((n) => n > 255)) return false;
  // 归一化后判断私有段（前导零如 010.0.0.1 会被 Number 归一成 10.0.0.1）
  const normalized = parts.join('.');
  return !/^(0\.|10\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|198\.(1[89])\.|198\.51\.100\.|203\.0\.113\.)/.test(normalized);
}
