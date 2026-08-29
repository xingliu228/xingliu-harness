// 回归测试（issue #1）：网关响应不得同时携带 Content-Length 与 Transfer-Encoding
//
// 根因回顾：dsh 上游以 chunked（Transfer-Encoding: chunked）返回 HTML/JSON 时，
// 网关改写路径（HTML 注入、workspace.list / session.list / session.history 过滤）
// 重算了 body 并设置了新的 content-length，但没有删掉上游的 transfer-encoding，
// Node http 服务端会把两个头原样发出 → 畸形消息 → Nginx（NPM）直接 502。
//
// 修复后契约（RFC 9110 §8.6）：
//   - 改写路径：只有 content-length，绝不带 transfer-encoding
//   - 流式透传 / JSON 解析失败回退：保留上游 transfer-encoding（chunked），
//     绝不带 content-length；任何路径都不得同时出现两者
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import jwt from 'jsonwebtoken';

import { createGatewayServer } from '../src/gateway.js';
import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import type { PlatformConfig } from '../src/config.js';

const HTML_BODY = '<html><head><title>home</title></head><body>hello</body></html>';
const WORKSPACES_JSON = JSON.stringify({
  ok: true,
  data: [{ id: 'ws-1', path: '/workspaces/a' }],
});
const ARCHIVED_WORKSPACES_JSON = JSON.stringify({
  rpcId: 'workspace-list-archive-regression',
  result: {
    ok: true,
    value: {
      items: [
        {
          workspaceId: 'ws-visible',
          path: '/workspaces/a',
          sessionIds: ['s-active', 's-archived', 's-disabled'],
        },
        {
          workspaceId: 'ws-hidden',
          path: '/workspaces/b',
          sessionIds: ['s-other-user'],
        },
      ],
      archivedSessionIds: ['s-archived', 's-other-user', 's-disabled'],
    },
  },
});

let tempDir: string;
let db: Database;
let auth: AuthService;
let upstream: http.Server;
let gateway: http.Server;
let gatewayPort = 0;
let cookie = '';
/** 会话 JWT 明文（Cookie Chaos 回归测试用：构造 Unicode 前缀的伪同名 cookie） */
let tokenValue = '';
/** 上游最后一次收到的请求头（F-15 回归测试用：验证网关 cookie 不被透传） */
let lastUpstreamHeaders: http.IncomingHttpHeaders = {};

/** mock 上游：刻意不设 content-length（write 分段写），Node 会以 chunked 分帧——
 *  这正是生产环境 dsh 的行为，也是触发原 bug 的前提 */
function startMockUpstream(): Promise<http.Server> {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      lastUpstreamHeaders = req.headers;
      const badJson = req.headers['x-test-mode'] === 'bad-json';
      if ((req.url ?? '').startsWith('/html')) {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.write(HTML_BODY.slice(0, 20)); // 无 CL 的多次 write → chunked
        res.end(HTML_BODY.slice(20));
      } else if ((req.url ?? '').startsWith('/api/workspace.list')) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.write(
          badJson
            ? 'not-json{'
            : req.headers['x-test-mode'] === 'archived-sessions'
              ? ARCHIVED_WORKSPACES_JSON
              : WORKSPACES_JSON,
        );
        res.end();
      } else {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.write(JSON.stringify({ ok: true, method: req.method, url: req.url }));
        res.end();
      }
    });
    server.on('upgrade', (req, socket) => {
      lastUpstreamHeaders = req.headers;
      socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
      socket.destroy();
    });
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function rawNames(rawHeaders: string[]): string[] {
  const names: string[] = [];
  for (let i = 0; i < rawHeaders.length; i += 2) names.push(rawHeaders[i].toLowerCase());
  return names;
}

function gatewayReq(
  method: string,
  url: string,
  headers: Record<string, string> = {},
  body?: string,
): Promise<{ status: number; rawHeaders: string[]; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port: gatewayPort, method, path: url, headers: { cookie, ...headers } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            rawHeaders: res.rawHeaders,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

/** 契约断言：响应绝不能同时出现 CL 与 TE */
function assertNoClTe(rawHeaders: string[]): void {
  const names = rawHeaders
    .filter((_, i) => i % 2 === 0)
    .map((n) => String(n).toLowerCase());
  assert.ok(
    !(names.includes('content-length') && names.includes('transfer-encoding')),
    `响应同时携带 Content-Length 与 Transfer-Encoding（Nginx 会 502）：${JSON.stringify(rawHeaders)}`,
  );
}

before(async () => {
  tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-test-'));
  db = new Database(path.join(tempDir, 'test.db'), createFieldCrypto('testkey', 'testkey'));
  db.init(); // 建表（构造函数不建表）
  const user = db.createUser('admin', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');

  upstream = await startMockUpstream();
  const upstreamPort = (upstream.address() as { port: number }).port;

  const config: PlatformConfig = {
    setupKey: 'test-setup-key',
    dbPath: path.join(tempDir, 'test.db'),
    dbEncKey: 'testkey',
    gateway: {
      host: '127.0.0.1',
      port: 0,
      upstream: `http://127.0.0.1:${upstreamPort}`,
      tls: null,
      redirectPort: null,
      publicHost: '',
      domain: 'localhost',
      autoTls: false,
      acmeEmail: '',
      acmeStaging: false,
    },
    jwtSecret: 'test-secret',
    internalSecret: 'test-internal',
    patch: { dshRoot: '', restartService: '' },
    webSocket: { adminAllowlist: ['/sidebar/ws/terminal'], userAllowlist: ['/plugin/ws/*'] },
  };

  auth = new AuthService(config, db);
  gateway = createGatewayServer(config, auth, db);
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', () => resolve()));
  gatewayPort = (gateway.address() as { port: number }).port;

  // 直接签一个合法会话（等价于登录成功后的 cookie），cv=0 与新建用户一致
  const token = jwt.sign({ sub: String(user.id), username: user.username, cv: 0 }, config.jwtSecret, {
    expiresIn: '12h',
  });
  tokenValue = token;
  cookie = `dsh_gateway_token=${token}`;
});

after(() => {
  gateway?.close();
  upstream?.close();
  // Windows 上 node:sqlite 文件句柄保持打开（Database 无 close 接口），
  // 临时目录清理为尽力而为，失败时由系统临时目录回收
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    /* 忽略：文件锁未释放 */
  }
});

function websocketHandshake(url: string, headers: Record<string, string>): Promise<{ statusLine: string; headers: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port: gatewayPort,
      path: url,
      headers: {
        connection: 'Upgrade',
        upgrade: 'websocket',
        'sec-websocket-version': '13',
        'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
        ...headers,
      },
    });
    req.once('upgrade', (res, socket) => {
      const statusLine = `HTTP/${res.httpVersion} ${String(res.statusCode)} ${res.statusMessage ?? ''}`.trim();
      socket.destroy();
      resolve({ statusLine, headers: JSON.stringify(res.headers) });
    });
    req.once('response', (res) => {
      res.resume();
      res.once('end', () => resolve({ statusLine: `HTTP/${res.httpVersion} ${String(res.statusCode)}`, headers: JSON.stringify(res.headers) }));
    });
    req.once('error', reject);
    req.end();
  });
}

test('better-sidebar HTTP 宿主路由：子用户请求在网关层拒绝', async () => {
  const subUser = db.createUser('sidebar-denied', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
  db.setPermissions(subUser.id, {
    allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: true, allowGitDownload: true, allowWorkspaceCreate: false,
    banned: false, sandboxMode: null, disabledSessions: [],
  });
  const subToken = jwt.sign({ sub: String(subUser.id), username: subUser.username, cv: 0 }, 'test-secret', { expiresIn: '12h' });
  const originalCookie = cookie;
  cookie = `dsh_gateway_token=${subToken}`;
  try {
    for (const path of ['/sidebar/api/fs.tree', '/sidebar/upload', '/sidebar/file/x', '/sidebar/html/x']) {
      const response = await gatewayReq('POST', path, { origin: 'http://127.0.0.1' }, '{}');
      assert.equal(response.status, 403, `${path} must be denied before upstream`);
    }
  } finally {
    cookie = originalCookie;
  }
});

test('better-sidebar WebSocket：管理员可升级，未知路径被拒绝', async () => {
  const allowed = await websocketHandshake('/sidebar/ws/terminal?tab=test', {
    cookie,
    origin: 'http://127.0.0.1',
    host: '127.0.0.1',
  });
  assert.match(allowed.statusLine, /101 Switching Protocols/);
  const denied = await websocketHandshake('/sidebar/ws/unknown', {
    cookie,
    origin: 'http://127.0.0.1',
    host: '127.0.0.1',
  });
  assert.match(denied.statusLine, /404/);
});

test('跨源 better-sidebar WebSocket 在升级前被拒绝', async () => {
  const denied = await websocketHandshake('/sidebar/ws/terminal', {
    cookie,
    origin: 'https://attacker.example',
    host: '127.0.0.1',
  });
  assert.match(denied.statusLine, /403/);
});

test('Issue #13：子用户必须先获得主用户授予的 WebSocket 路径权限', async () => {
  const subUser = db.createUser('plugin-user', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
  db.setPermissions(subUser.id, {
    allowedFolders: [],
    hourlyTokenLimit: null,
    dailyMinutesLimit: null,
    allowUpload: true,
    allowGitDownload: true,
    allowWorkspaceCreate: false,
    banned: false,
    sandboxMode: null,
    disabledSessions: [],
  });
  const subToken = jwt.sign({ sub: String(subUser.id), username: subUser.username, cv: 0 }, 'test-secret', { expiresIn: '12h' });
  const subCookie = `dsh_gateway_token=${subToken}`;
  const originalCookie = cookie;
  try {
    const beforeGrant = await websocketHandshake('/plugin/ws/run', {
      cookie: subCookie,
      origin: 'http://127.0.0.1',
      host: '127.0.0.1',
    });
    assert.match(beforeGrant.statusLine, /404/);

    cookie = originalCookie;
    const save = await gatewayReq(
      'POST',
      '/gateway/api/permissions',
      { 'content-type': 'application/json' },
      JSON.stringify({
        userId: subUser.id,
        allowedFolders: [],
        allowedWebSocketPaths: ['/plugin/ws/*'],
      }),
    );
    assert.equal(save.status, 200);

    const overview = await gatewayReq('GET', '/gateway/api/overview');
    assert.equal(overview.status, 200);
    const overviewBody = JSON.parse(overview.body) as {
      availableWebSocketPaths: string[];
      adminOnlyWebSocketPaths: string[];
      users: Array<{ id: number; permissions: { allowedWebSocketPaths: string[] } }>;
    };
    assert.deepEqual(overviewBody.availableWebSocketPaths, ['/plugin/ws/*']);
    assert.deepEqual(overviewBody.adminOnlyWebSocketPaths, ['/sidebar/ws/terminal']);
    assert.deepEqual(
      overviewBody.users.find((user) => user.id === subUser.id)?.permissions.allowedWebSocketPaths,
      ['/plugin/ws/*'],
    );

    const afterGrant = await websocketHandshake('/plugin/ws/run', {
      cookie: subCookie,
      origin: 'http://127.0.0.1',
      host: '127.0.0.1',
    });
    assert.match(afterGrant.statusLine, /101 Switching Protocols/);

    const sidebarAfterGrant = await websocketHandshake('/sidebar/ws/terminal', {
      cookie: subCookie,
      origin: 'http://127.0.0.1',
      host: '127.0.0.1',
    });
    assert.match(sidebarAfterGrant.statusLine, /403/);
  } finally {
    cookie = originalCookie;
  }
});

test('HTML 改写路径（注入脚本）：只有 content-length，无 transfer-encoding', async () => {
  const r = await gatewayReq('GET', '/html');
  assert.equal(r.status, 200);
  assertNoClTe(r.rawHeaders);
  const names = rawNames(r.rawHeaders);
  assert.ok(names.includes('content-length'), '改写路径必须带 content-length');
  assert.ok(!names.includes('transfer-encoding'), '改写路径不得带 transfer-encoding');
  assert.ok(r.body.includes('randomUUID'), 'HTML 注入脚本缺失');
  assert.ok(r.body.includes('<title>home</title>'), 'HTML 内容缺失');
});

test('workspace.list JSON 改写路径：只有 content-length，无 transfer-encoding', async () => {
  const r = await gatewayReq('POST', '/api/workspace.list', { 'content-type': 'application/json' });
  assert.equal(r.status, 200);
  assertNoClTe(r.rawHeaders);
  const names = rawNames(r.rawHeaders);
  assert.ok(names.includes('content-length'), '改写路径必须带 content-length');
  assert.ok(!names.includes('transfer-encoding'), '改写路径不得带 transfer-encoding');
  const parsed = JSON.parse(r.body);
  assert.deepEqual(parsed.data[0], { id: 'ws-1', path: '/workspaces/a' });
});

test('workspace.list：子用户归档会话保留工作区槽且不会掉入未分组', async () => {
  const subUser = db.createUser('archive-user', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
  db.setPermissions(subUser.id, {
    allowedFolders: ['/workspaces/a'],
    hourlyTokenLimit: null,
    dailyMinutesLimit: null,
    allowUpload: true,
    allowGitDownload: true,
    allowWorkspaceCreate: false,
    banned: false,
    sandboxMode: null,
    disabledSessions: ['s-disabled'],
  });
  const subToken = jwt.sign(
    { sub: String(subUser.id), username: subUser.username, cv: 0 },
    'test-secret',
    { expiresIn: '12h' },
  );
  const originalCookie = cookie;
  cookie = `dsh_gateway_token=${subToken}`;
  try {
    const response = await gatewayReq(
      'POST',
      '/api/workspace.list',
      { 'content-type': 'application/json', 'x-test-mode': 'archived-sessions' },
      '{}',
    );
    assert.equal(response.status, 200);
    const value = (JSON.parse(response.body) as {
      result: {
        value: {
          items: Array<{ path: string; sessionIds: string[] }>;
          archivedSessionIds: string[];
        };
      };
    }).result.value;
    assert.deepEqual(value.items.map((item) => item.path), ['/workspaces/a']);
    assert.deepEqual(
      value.items[0].sessionIds,
      ['s-active', 's-archived'],
      '归档会话保留在工作区计数槽中，由 archivedSessionIds 负责隐藏',
    );
    assert.deepEqual(
      value.archivedSessionIds,
      ['s-archived'],
      '只下发当前子用户可见且未禁用的归档 ID',
    );
  } finally {
    cookie = originalCookie;
  }
});

test('workspace.archiveSession：子用户可归档可见会话，但不能归档禁用或越权会话', async () => {
  const subUser = db.createUser('archive-action-user', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
  db.setPermissions(subUser.id, {
    allowedFolders: ['/workspaces/a'],
    hourlyTokenLimit: null,
    dailyMinutesLimit: null,
    allowUpload: true,
    allowGitDownload: true,
    allowWorkspaceCreate: false,
    banned: false,
    sandboxMode: null,
    disabledSessions: ['s-disabled'],
  });
  const subToken = jwt.sign(
    { sub: String(subUser.id), username: subUser.username, cv: 0 },
    'test-secret',
    { expiresIn: '12h' },
  );
  const originalCookie = cookie;
  cookie = `dsh_gateway_token=${subToken}`;
  try {
    // 先走 workspace.list，模拟真实前端并建立 sessionId -> cwd 归属缓存。
    const list = await gatewayReq(
      'POST',
      '/api/workspace.list',
      { 'content-type': 'application/json', 'x-test-mode': 'archived-sessions' },
      '{}',
    );
    assert.equal(list.status, 200);

    const allowed = await gatewayReq(
      'POST',
      '/api/workspace.archiveSession',
      { 'content-type': 'application/json' },
      JSON.stringify({ sessionId: 's-active' }),
    );
    assert.equal(allowed.status, 200, '可见且未禁用的会话应允许归档');

    const disabled = await gatewayReq(
      'POST',
      '/api/workspace.archiveSession',
      { 'content-type': 'application/json' },
      JSON.stringify({ sessionId: 's-disabled' }),
    );
    assert.equal(disabled.status, 403, '被管理员禁用的会话不得归档');

    const hidden = await gatewayReq(
      'POST',
      '/api/workspace.archiveSession',
      { 'content-type': 'application/json' },
      JSON.stringify({ sessionId: 's-other-user' }),
    );
    assert.equal(hidden.status, 403, '白名单外的会话不得归档');
  } finally {
    cookie = originalCookie;
  }
});

test('流式透传路径（session.list，管理员）：保留 chunked，不带 content-length', async () => {
  const r = await gatewayReq('GET', '/api/session.list');
  assert.equal(r.status, 200);
  assertNoClTe(r.rawHeaders);
  const names = rawNames(r.rawHeaders);
  assert.ok(names.includes('transfer-encoding'), '透传路径应保留上游的 chunked 分帧');
  assert.ok(!names.includes('content-length'), '透传路径不得出现 content-length');
  const parsed = JSON.parse(r.body);
  assert.equal(parsed.ok, true);
});

test('JSON 解析失败回退路径：不得同时出现 CL+TE，body 原样透传', async () => {
  const r = await gatewayReq('POST', '/api/workspace.list', {
    'content-type': 'application/json',
    'x-test-mode': 'bad-json',
  });
  assert.equal(r.status, 200);
  assertNoClTe(r.rawHeaders);
  const names = rawNames(r.rawHeaders);
  assert.ok(names.includes('transfer-encoding'), '回退路径应保留上游的 chunked 分帧');
  assert.ok(!names.includes('content-length'), '回退路径不得出现 content-length');
  assert.equal(r.body, 'not-json{');
});

test('F-15：网关会话 Cookie 不得转发给上游（信任边界最小化）', async () => {
  const r = await gatewayReq('GET', '/api/workspace.list');
  assert.equal(r.status, 200);
  // 上游收到的请求头里不得出现 cookie（含 dsh_gateway_token JWT）——
  // 否则上游/插件被入侵时可收割全部活动会话并回放
  assert.equal(
    lastUpstreamHeaders['cookie'],
    undefined,
    `上游收到网关 Cookie：${JSON.stringify(lastUpstreamHeaders['cookie'])}`,
  );
});

test('工作区创建权限关闭时拒绝 rc.2 目录选择器写入', async () => {
  const subUser = db.createUser('workspace-denied', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
  db.setPermissions(subUser.id, {
    allowedFolders: ['__deny__'],
    hourlyTokenLimit: null,
    dailyMinutesLimit: null,
    allowUpload: true,
    allowGitDownload: false,
    allowWorkspaceCreate: false,
    banned: false,
    sandboxMode: null,
    disabledSessions: [],
  });
  const subToken = jwt.sign({ sub: String(subUser.id), username: subUser.username, cv: 0 }, 'test-secret', {
    expiresIn: '12h',
  });
  const originalCookie = cookie;
  cookie = `dsh_gateway_token=${subToken}`;
  try {
    const r = await gatewayReq('POST', '/api/host.createDirectory', { 'content-type': 'application/json' }, JSON.stringify({ path: '/tmp', name: 'should-not-exist' }));
    assert.equal(r.status, 403, '子用户无创建权限时不得进入目录选择器写入');
  } finally {
    cookie = originalCookie;
  }
});

test('权限保存拒绝非布尔 allowUpload 且缺失字段保留现值', async () => {
  const subUser = db.createUser('upload-contract', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
  db.setPermissions(subUser.id, {
    allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: false,
    banned: false, sandboxMode: null, disabledSessions: [],
  });
  const base = { userId: subUser.id, allowedFolders: ['__deny__'], hourlyTokenLimit: null, dailyMinutesLimit: null, allowGitDownload: false, allowWorkspaceCreate: false, banned: false, sandboxMode: null, disabledSessions: [] };
  const invalid = JSON.stringify({ ...base, allowUpload: 'false' });
  const invalidResponse = await gatewayReq('POST', '/gateway/api/permissions', { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(invalid)) }, invalid);
  assert.equal(invalidResponse.status, 400);
  assert.equal(db.getPermissions(subUser.id)?.allow_upload, false);
  const omitted = JSON.stringify(base);
  const omittedResponse = await gatewayReq('POST', '/gateway/api/permissions', { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(omitted)) }, omitted);
  assert.equal(omittedResponse.status, 200, omittedResponse.body);
  assert.equal(db.getPermissions(subUser.id)?.allow_upload, false);
});

test('权限保存接受唯一的拒绝全部工作区哨兵', async () => {
  const subUser = db.createUser('save-deny-sentinel', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
  const payload = JSON.stringify({
    userId: subUser.id,
    allowedFolders: ['__deny__'],
    hourlyTokenLimit: null,
    dailyMinutesLimit: null,
    allowUpload: true,
    allowGitDownload: false,
    allowWorkspaceCreate: false,
    banned: false,
    sandboxMode: null,
    disabledSessions: [],
  });
  const r = await gatewayReq('POST', '/gateway/api/permissions', { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)) }, payload);
  assert.equal(r.status, 200, r.body);
  assert.deepEqual(db.getPermissions(subUser.id)?.allowed_folders, ['__deny__']);
});

test('F-15 例外：自身插件路由 /api/dsh-passwords/* 必须保留 Cookie（插件 guard 鉴权依赖）', async () => {
  const r = await gatewayReq('GET', '/api/dsh-passwords/state');
  assert.equal(r.status, 200);
  assert.equal(
    lastUpstreamHeaders['cookie'],
    cookie,
    '插件路由的上游请求必须携带网关 Cookie，否则设置页用户管理全部 401',
  );
});

test('Cookie Chaos 加固（P3）：Unicode 空白前缀的会话 cookie 不再被归一化匹配 → 未认证', async () => {
  const locationOf = (rh: string[]): string => {
    const i = rh.findIndex((v, idx) => idx % 2 === 0 && v.toLowerCase() === 'location');
    return i >= 0 ? rh[i + 1] ?? '' : '';
  };
  // 只有 U+00A0 前缀的伪同名 cookie（旧 trim() 会按 Unicode 空白语义归一化成
  // dsh_gateway_token 读入并放行认证）；严格解析应视为不同 cookie → 302 登录页
  const r = await gatewayReq('GET', '/html', {
    cookie: `\u00a0dsh_gateway_token=${tokenValue}`, // U+00A0 在 latin1 下为单字节 0xA0
  });
  assert.equal(r.status, 302, 'Unicode 前缀 cookie 不应通过认证，应重定向到登录页');
  assert.match(locationOf(r.rawHeaders), /\/gateway\/login/);

  // 对照：正常 cookie 认证通过（U+00A0 精确匹配不被干扰）
  const ok = await gatewayReq('GET', '/html', { cookie: `dsh_gateway_token=${tokenValue}` });
  assert.equal(ok.status, 200, '正常会话 cookie 应认证通过');
});
