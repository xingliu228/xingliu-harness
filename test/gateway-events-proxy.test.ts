import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import jwt from 'jsonwebtoken';

import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import { createGatewayServer } from '../src/gateway.js';
import type { PlatformConfig } from '../src/config.js';

let tempDir: string;
let db: Database;
let upstream: http.Server;
let gateway: http.Server;
let port = 0;
let adminCookie = '';
let userCookie = '';
let freshCookie = '';

const workspaces = {
  result: {
    value: {
      items: [
        {
          workspaceId: 'visible-workspace',
          path: '/work/visible',
          title: 'Visible',
          sessionIds: ['visible-session', 'disabled-session'],
          createdAt: '2026-08-28T00:00:00.000Z',
          updatedAt: '2026-08-28T00:00:00.000Z',
        },
        {
          workspaceId: 'hidden-workspace',
          path: '/work/hidden',
          title: 'Hidden',
          sessionIds: ['hidden-session'],
          createdAt: '2026-08-28T00:00:00.000Z',
          updatedAt: '2026-08-28T00:00:00.000Z',
        },
      ],
      archivedSessionIds: [],
    },
  },
};

function request(pathname: string, cookie: string, body = '{}'): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: pathname,
      method: pathname.includes('workspace.list') ? 'POST' : 'GET',
      headers: {
        cookie,
        'content-type': 'application/json',
        'content-length': String(Buffer.byteLength(body)),
      },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

before(async () => {
  tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-events-'));
  db = new Database(path.join(tempDir, 'test.db'), createFieldCrypto('test-key', 'test-key'));
  db.init();
  const admin = db.createUser('admin', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');
  const user = db.createUser('events-user', '$2a$10$dummyhashdummyhashdummyhashdu');
  const other = db.createUser('other-user', '$2a$10$dummyhashdummyhashdummyhashdu');
  const fresh = db.createUser('fresh-user', '$2a$10$dummyhashdummyhashdummyhashdu');
  db.addUserWorkspace(user.id, '/work/visible');
  db.addUserWorkspace(other.id, '/work/hidden');
  db.setPermissions(user.id, {
    allowedFolders: ['/work/visible'], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: true, allowGitDownload: false, allowWorkspaceCreate: false,
    disabledSessions: ['disabled-session'], banned: false, sandboxMode: null,
  });
  db.setPermissions(fresh.id, {
    allowedFolders: ['/work/visible'], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: true, allowGitDownload: false, allowWorkspaceCreate: false,
    disabledSessions: [], banned: false, sandboxMode: null,
  });

  upstream = http.createServer((req, res) => {
    if (req.url?.startsWith('/api/workspace.list')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(workspaces));
      return;
    }
    if (req.url?.startsWith('/api/events.host')) {
      const frames = [
        { rpcId: 'hidden-changed', payload: { type: 'host/workspace-changed', workspace: { workspaceId: 'hidden-workspace', path: '/work/hidden', title: 'Hidden', sessionIds: ['hidden-session'], createdAt: '2026-08-28T00:00:00.000Z', updatedAt: '2026-08-28T00:00:00.000Z' } } },
        { rpcId: 'visible-changed', payload: { type: 'host/workspace-changed', workspace: { workspaceId: 'visible-workspace', path: '/work/visible', title: 'Visible', sessionIds: ['visible-session', 'disabled-session'], createdAt: '2026-08-28T00:00:00.000Z', updatedAt: '2026-08-28T00:00:00.000Z' } } },
        { rpcId: 'renamed-outside', payload: { type: 'host/workspace-changed', workspace: { workspaceId: 'visible-workspace', path: '/work/also-allowed', title: 'Visible', sessionIds: ['visible-session'], createdAt: '2026-08-28T00:00:00.000Z', updatedAt: '2026-08-28T00:00:00.000Z' } } },
        { rpcId: 'collision-path', payload: { type: 'host/workspace-changed', workspace: { workspaceId: 'visible-workspace', path: '/work/hidden', title: 'Visible', sessionIds: ['visible-session'], createdAt: '2026-08-28T00:00:00.000Z', updatedAt: '2026-08-28T00:00:00.000Z' } } },
        { rpcId: 'blocked-session', payload: { type: 'host/session-added', sessionId: 'hidden-session', cwd: '/work/hidden' } },
        { rpcId: 'allowed-session', payload: { type: 'host/session-added', sessionId: 'visible-session', cwd: '/work/visible', parentSessionId: 'hidden-session' } },
        { rpcId: 'removed-hidden', payload: { type: 'host/session-removed', sessionId: 'hidden-session' } },
        { rpcId: 'removed-visible', payload: { type: 'host/session-removed', sessionId: 'visible-session' } },
        { rpcId: 'status-hidden', payload: { type: 'host/session-status', sessionId: 'hidden-session', running: true } },
        { rpcId: 'status-visible', payload: { type: 'host/session-status', sessionId: 'visible-session', running: true } },
        { rpcId: 'error-hidden', payload: { type: 'host/agent-error', sessionId: 'hidden-session', message: 'boom' } },
        { rpcId: 'error-visible', payload: { type: 'host/agent-error', sessionId: 'visible-session', message: 'boom' } },
        { rpcId: 'remote-event', payload: { type: 'host/remote-event', event: 'workspace/somewhere', args: [{ path: '/work/hidden' }] } },
        { rpcId: 'workspace-removed-visible', payload: { type: 'host/workspace-removed', workspaceId: 'visible-workspace' } },
        { rpcId: 'order-mixed', payload: { type: 'host/workspace-order-changed', workspaceIds: ['visible-workspace', 'hidden-workspace'] } },
        { rpcId: 'archived-mixed', payload: { type: 'host/archived-sessions-changed', archivedSessionIds: ['visible-session', 'hidden-session'] } },
        { rpcId: 'unknown-type', payload: { type: 'host/unknown', path: '/work/hidden' } },
        { rpcId: 'malformed-payload', payload: '/work/hidden' },
      ];
      const payload = frames.map((frame) => `data: ${JSON.stringify(frame)}\n\n`).join('');
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(payload.slice(0, 37));
      res.end(payload.slice(37));
      return;
    }
    if (req.url?.startsWith('/api/events.mux')) {
      const frames = [
        { rpcId: 'mux-visible', payload: { type: 'session/event', sessionId: 'visible-session', event: { id: 'e1' } } },
        { rpcId: 'mux-hidden', payload: { type: 'session/event', sessionId: 'hidden-session', event: { id: 'e2' } } },
        { rpcId: 'mux-subscribed-hidden', payload: { type: 'session/subscribed', sessionId: 'hidden-session', lastSeq: 1 } },
        { rpcId: 'mux-subscribed-visible', payload: { type: 'session/subscribed', sessionId: 'visible-session', lastSeq: 2 } },
        { rpcId: 'mux-approval-hidden', payload: { type: 'approval/requested', sessionId: 'hidden-session', approvalId: 'a1', toolName: 't' } },
        { rpcId: 'mux-queue-visible', payload: { type: 'session/queue', sessionId: 'visible-session', items: [] } },
        { rpcId: 'mux-error', payload: { type: 'stream/error', error: { message: 'boom' } } },
      ];
      const payload = frames.map((frame) => `data: ${JSON.stringify(frame)}\n\n`).join('');
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(payload.slice(0, 25));
      res.end(payload.slice(25));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamPort = (upstream.address() as { port: number }).port;
  const config: PlatformConfig = {
    setupKey: 'test-setup-key', dbPath: path.join(tempDir, 'test.db'), dbEncKey: 'test-key',
    gateway: {
      host: '127.0.0.1', port: 0, upstream: `http://127.0.0.1:${upstreamPort}`,
      tls: null, redirectPort: null, publicHost: '', domain: 'localhost', autoTls: false,
      acmeEmail: '', acmeStaging: false,
    },
    jwtSecret: 'test-secret', internalSecret: 'test-internal',
    patch: { dshRoot: '', restartService: '' },
    webSocket: { adminAllowlist: [], userAllowlist: [] },
  };
  adminCookie = `dsh_gateway_token=${jwt.sign({ sub: String(admin.id), username: admin.username, cv: 0 }, config.jwtSecret, { expiresIn: '12h' })}`;
  userCookie = `dsh_gateway_token=${jwt.sign({ sub: String(user.id), username: user.username, cv: 0 }, config.jwtSecret, { expiresIn: '12h' })}`;
  freshCookie = `dsh_gateway_token=${jwt.sign({ sub: String(fresh.id), username: fresh.username, cv: 0 }, config.jwtSecret, { expiresIn: '12h' })}`;
  gateway = createGatewayServer(config, new AuthService(config, db), db);
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', resolve));
  port = (gateway.address() as { port: number }).port;
});

after(() => {
  gateway?.close();
  upstream?.close();
  db?.close();
  try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* Windows cleanup is best effort */ }
});

test('Issue #20: 子用户 host SSE 仅接收已授权工作区和会话，且不泄露 cwd', async () => {
  const snapshot = await request('/api/workspace.list', userCookie);
  assert.equal(snapshot.status, 200);

  const response = await request('/api/events.host', userCookie);
  assert.equal(response.status, 200);
  assert.doesNotMatch(response.body, /hidden-workspace|hidden-session|\/work\/hidden|\/work\/also-allowed/);
  assert.match(response.body, /visible-workspace|visible-session/);
  assert.doesNotMatch(response.body, /disabled-session/);
  assert.doesNotMatch(response.body, /cwd|parentSessionId/);
});

test('Issue #20: 管理员 host SSE 保持原始事件流', async () => {
  const response = await request('/api/events.host', adminCookie);
  assert.equal(response.status, 200);
  assert.match(response.body, /hidden-workspace|hidden-session/);
  assert.match(response.body, /cwd/);
});

test('Issue #20: workspace-changed 携带白名单外路径时丢弃', async () => {
  await request('/api/workspace.list', userCookie);
  const response = await request('/api/events.host', userCookie);
  assert.doesNotMatch(response.body, /renamed-outside|also-allowed/);
});

test('Issue #20: workspace-changed 路径与其他用户所有权冲突时丢弃', async () => {
  await request('/api/workspace.list', userCookie);
  const response = await request('/api/events.host', userCookie);
  assert.doesNotMatch(response.body, /collision-path/);
  assert.doesNotMatch(response.body, /"workspaceId":"visible-workspace","path":"\/work\/hidden"/);
});

test('Issue #20: 隐藏会话的 session-removed/session-status/agent-error 均丢弃', async () => {
  await request('/api/workspace.list', userCookie);
  const response = await request('/api/events.host', userCookie);
  for (const needle of ['removed-hidden', 'status-hidden', 'error-hidden']) {
    assert.doesNotMatch(response.body, new RegExp(needle));
  }
  for (const needle of ['removed-visible', 'status-visible', 'error-visible']) {
    assert.match(response.body, new RegExp(needle));
  }
});

test('Issue #20: unknown or malformed host frames are fail-closed', async () => {
  await request('/api/workspace.list', userCookie);
  const response = await request('/api/events.host', userCookie);
  assert.doesNotMatch(response.body, /unknown-type|malformed-payload|host\/unknown|work\/hidden/);
});

test('Issue #20: host/remote-event 对子用户一律丢弃', async () => {
  await request('/api/workspace.list', userCookie);
  const response = await request('/api/events.host', userCookie);
  assert.doesNotMatch(response.body, /remote-event|workspace\/somewhere/);
});

test('Issue #20: mux 只透传已授权会话事件，stream/error 与隐藏会话丢弃', async () => {
  await request('/api/workspace.list', userCookie);
  const response = await request('/api/events.mux', userCookie);
  assert.equal(response.status, 200);
  assert.doesNotMatch(response.body, /mux-hidden|mux-subscribed-hidden|mux-approval-hidden|mux-error/);
  assert.match(response.body, /mux-visible|mux-subscribed-visible|mux-queue-visible/);
});

test('Issue #20: 未建立快照前敏感事件一律 fail-closed 丢弃', async () => {
  const response = await request('/api/events.host', freshCookie);
  assert.equal(response.status, 200);
  assert.equal(response.body, '');
  const mux = await request('/api/events.mux', freshCookie);
  assert.equal(mux.body, '');
});

test('Issue #20: 并行 SSE 连接互不影响对方工作区快照', async () => {
  await request('/api/workspace.list', userCookie);
  const [first, second] = await Promise.all([
    request('/api/events.host', userCookie),
    request('/api/events.host', userCookie),
  ]);
  assert.match(first.body, /visible-workspace/);
  assert.match(second.body, /visible-workspace/);
  assert.doesNotMatch(second.body, /hidden-workspace/);
});