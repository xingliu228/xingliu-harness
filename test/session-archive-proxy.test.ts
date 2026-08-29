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
let workspaceDir: string;
let otherWorkspaceDir: string;
let legacyWorkspaceDir: string;
let db: Database;
let upstream: http.Server;
let gateway: http.Server;
let gatewayPort = 0;
let adminCookie = '';
let userCookie = '';
let archiveIds: string[] | undefined;
let malformedWorkspace = false;
let extraSessionIds: string[] = [];
let showLegacyWorkspace = false;
let workspaceResponsePlan: Array<{ archived: string[]; delayMs: number }> = [];

const sessionListBody = () => {
  const value = [
    { sessionId: 's-active', cwd: workspaceDir, title: 'active' },
    { sessionId: 's-archived', cwd: workspaceDir, title: 'archived' },
    { sessionId: 's-other', cwd: otherWorkspaceDir, title: 'other user' },
  ];
  if (showLegacyWorkspace) {
    value.push({ sessionId: 's-legacy', cwd: legacyWorkspaceDir, title: 'legacy' });
  }
  return { result: { value } };
};

function workspaceListBody() {
  const workspace: Record<string, unknown> = {
    id: 'w-1', path: workspaceDir, sessionIds: ['s-active', 's-archived', ...extraSessionIds],
  };
  const otherWorkspace: Record<string, unknown> = {
    id: 'w-2', path: otherWorkspaceDir, sessionIds: ['s-other'],
  };
  const items = [workspace, otherWorkspace];
  if (showLegacyWorkspace) {
    items.push({
      id: 'w-legacy',
      path: legacyWorkspaceDir,
      sessionIds: ['s-legacy', ...extraSessionIds],
    });
  }
  if (archiveIds !== undefined) {
    workspace.archivedSessionIds = archiveIds;
    otherWorkspace.archivedSessionIds = archiveIds;
  }
  return {
    result: {
      value: {
        items,
        archivedSessionIds: archiveIds,
      },
    },
  };
}

function request(method: string, pathname: string, cookie: string, body = '{}'): Promise<{ status: number; json: unknown; text: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: gatewayPort, method, path: pathname,
      headers: { cookie, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json: unknown = null;
        try { json = JSON.parse(text); } catch { /* status-only error response */ }
        resolve({ status: res.statusCode ?? 0, json, text });
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

function tokenFor(user: { id: number; username: string }, secret: string): string {
  return `dsh_gateway_token=${jwt.sign({ sub: String(user.id), username: user.username, cv: 0 }, secret, { expiresIn: '12h' })}`;
}

before(async () => {
  tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-archive-proxy-'));
  workspaceDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-archive-workspace-'));
  otherWorkspaceDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-archive-other-workspace-'));
  legacyWorkspaceDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-archive-legacy-workspace-'));
  const dbPath = path.join(tempDir, 'test.db');
  db = new Database(dbPath, createFieldCrypto('testkey', 'testkey'));
  db.init();
  const admin = db.createUser('admin', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');
  const user = db.createUser('archiveuser', '$2a$10$dummyhashdummyhashdummyhashdu');
  const otherOwner = db.createUser('other-owner', '$2a$10$dummyhashdummyhashdummyhashdu');
  db.addUserWorkspace(user.id, workspaceDir);
  db.addUserWorkspace(otherOwner.id, otherWorkspaceDir);
  db.setPermissions(user.id, {
    allowedFolders: [workspaceDir, otherWorkspaceDir], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: true, allowGitDownload: true, allowWorkspaceCreate: false,
    banned: false, sandboxMode: null,
  });
  db.replaceUserSessionGrants(user.id, ['s-active', 's-archived']);

  upstream = http.createServer((req, res) => {
    let body: unknown;
    if (req.url?.startsWith('/api/workspace.list') && malformedWorkspace) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{malformed');
      return;
    }
    if (req.url?.startsWith('/api/session.fork')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ result: { value: { sessionId: 's-forked', cwd: otherWorkspaceDir } } }));
      return;
    }
    if (req.url?.startsWith('/api/workspace.list')) {
      const plan = workspaceResponsePlan.shift();
      if (plan !== undefined) {
        archiveIds = plan.archived;
        body = workspaceListBody();
        const out = Buffer.from(JSON.stringify(body), 'utf8');
        setTimeout(() => {
          res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(out.length) });
          res.end(out);
        }, plan.delayMs);
        return;
      }
      body = workspaceListBody();
    } else if (req.url?.startsWith('/api/session.list')) body = sessionListBody();
    else body = { ok: true };
    const out = Buffer.from(JSON.stringify(body), 'utf8');
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(out.length) });
    res.end(out);
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamPort = (upstream.address() as { port: number }).port;
  const config: PlatformConfig = {
    setupKey: 'test-setup-key', dbPath, dbEncKey: 'testkey',
    gateway: {
      host: '127.0.0.1', port: 0, upstream: `http://127.0.0.1:${upstreamPort}`,
      tls: null, redirectPort: null, publicHost: '', domain: 'localhost', autoTls: false,
      acmeEmail: '', acmeStaging: false,
    },
    jwtSecret: 'test-secret', internalSecret: 'test-internal',
    patch: { dshRoot: '', restartService: '' },
    webSocket: { adminAllowlist: [], userAllowlist: [] },
  };
  adminCookie = tokenFor(admin, config.jwtSecret);
  userCookie = tokenFor(user, config.jwtSecret);
  gateway = createGatewayServer(config, new AuthService(config, db), db);
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', resolve));
  gatewayPort = (gateway.address() as { port: number }).port;
});

after(() => {
  gateway?.close();
  upstream?.close();
  for (const dir of [tempDir, workspaceDir, otherWorkspaceDir, legacyWorkspaceDir]) {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort on Windows */ }
  }
});

test('Issue #16: session.list before archive snapshot fails closed', async () => {
  const response = await request('POST', '/api/session.list', userCookie);
  assert.equal(response.status, 502);
  assert.match(response.text, /unprocessable/);
});

test('Issue #19: legacy subusers are seeded with their visible sessions on first workspace.list', async () => {
  const legacy = db.createUser('legacy-seed', '$2a$10$dummyhashdummyhashdummyhashdu');
  db.setPermissions(legacy.id, {
    allowedFolders: [legacyWorkspaceDir], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: true, allowGitDownload: true, allowWorkspaceCreate: false,
    banned: false, sandboxMode: null,
  });
  assert.equal(db.isSessionGrantsSeeded(legacy.id), false, '旧用户初始未初始化');
  const legacyCookie = `dsh_gateway_token=${jwt.sign({ sub: String(legacy.id), username: legacy.username, cv: 0 }, 'test-secret', { expiresIn: '12h' })}`;
  archiveIds = [];
  showLegacyWorkspace = true;
  try {
    const workspace = await request('POST', '/api/workspace.list', legacyCookie);
    assert.equal(workspace.status, 200);
    const workspaceJson = workspace.json as { result: { value: { items: Array<{ sessionIds: string[] }> } } };
    assert.deepEqual(
      workspaceJson.result.value.items[0].sessionIds,
      ['s-legacy'],
      '旧用户既有会话应被种子化保留',
    );
    assert.equal(db.isSessionGrantsSeeded(legacy.id), true);
    assert.deepEqual(db.listUserSessionGrants(legacy.id), ['s-legacy']);

    const list = await request('POST', '/api/session.list', legacyCookie);
    assert.equal(list.status, 200);
    const ids = (list.json as { result: { value: Array<{ sessionId: string }> } }).result.value.map((item) => item.sessionId);
    assert.deepEqual(ids, ['s-legacy']);

    const history = await request('POST', '/api/session.history', legacyCookie, JSON.stringify({ sessionId: 's-legacy' }));
    assert.equal(history.status, 200, '种子化后的既有会话应可正常读取');
  } finally {
    showLegacyWorkspace = false;
  }
});

test('Issue #19: sessions created after seeding do not auto-appear for subusers', async () => {
  archiveIds = [];
  const legacy = db.createUser('post-seed', '$2a$10$dummyhashdummyhashdummyhashdu');
  db.setPermissions(legacy.id, {
    allowedFolders: [legacyWorkspaceDir], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: true, allowGitDownload: true, allowWorkspaceCreate: false,
    banned: false, sandboxMode: null,
  });
  const legacyCookie = `dsh_gateway_token=${jwt.sign({ sub: String(legacy.id), username: legacy.username, cv: 0 }, 'test-secret', { expiresIn: '12h' })}`;
  db.replaceUserSessionGrants(legacy.id, ['s-legacy']);
  db.markSessionGrantsSeeded(legacy.id);
  showLegacyWorkspace = true;
  try {
    assert.equal((await request('POST', '/api/workspace.list', legacyCookie)).status, 200);
    extraSessionIds = ['s-brand-new'];
    const workspace = await request('POST', '/api/workspace.list', legacyCookie);
    assert.equal(workspace.status, 200);
    const workspaceJson = workspace.json as { result: { value: { items: Array<{ sessionIds: string[] }> } } };
    assert.deepEqual(workspaceJson.result.value.items[0].sessionIds, ['s-legacy'], '新会话不得自动加入授权');
    const list = await request('POST', '/api/session.list', legacyCookie);
    const ids = (list.json as { result: { value: Array<{ sessionId: string }> } }).result.value.map((item) => item.sessionId);
    assert.deepEqual(ids, ['s-legacy']);
    const history = await request('POST', '/api/session.history', legacyCookie, JSON.stringify({ sessionId: 's-brand-new' }));
    assert.equal(history.status, 403, '种子化之后的新会话必须显式授权');
  } finally {
    extraSessionIds = [];
    showLegacyWorkspace = false;
  }
});

test('Issue #19: same-workspace sessions require an explicit grant before listing or history access', async () => {
  archiveIds = [];
  const workspace = await request('POST', '/api/workspace.list', userCookie);
  assert.equal(workspace.status, 200);
  const workspaceJson = workspace.json as { result: { value: { items: Array<{ sessionIds: string[] }> } } };
  assert.deepEqual(workspaceJson.result.value.items[0].sessionIds, ['s-active', 's-archived']);

  const list = await request('POST', '/api/session.list', userCookie);
  assert.equal(list.status, 200);
  const ids = (list.json as { result: { value: Array<{ sessionId: string }> } }).result.value.map((item) => item.sessionId);
  assert.deepEqual(ids, ['s-active', 's-archived']);

  const ungranted = await request('POST', '/api/session.history', userCookie, JSON.stringify({ sessionId: 's-other' }));
  assert.equal(ungranted.status, 403, '同一目录白名单不等于会话授权');
});

test('Issue #16: workspace archive state is reused by session.list and hidden from subusers', async () => {
  archiveIds = ['s-archived', 's-other'];
  const workspace = await request('POST', '/api/workspace.list', userCookie);
  assert.equal(workspace.status, 200);
  const workspaceJson = workspace.json as { result: { value: { items: Array<{ sessionIds: string[] }>; archivedSessionIds: string[] } } };
  assert.deepEqual(
    workspaceJson.result.value.items[0].sessionIds,
    ['s-active', 's-archived'],
    '归档会话仍需保留在 workspace.sessionIds 槽位',
  );
  assert.equal(workspaceJson.result.value.items.length, 1, '白名单外工作区不可见');
  assert.deepEqual(
    workspaceJson.result.value.archivedSessionIds,
    ['s-archived'],
    '只暴露当前可见工作区中的归档标记',
  );
  const visibleWorkspace = workspaceJson.result.value.items[0] as { archivedSessionIds?: string[] };
  assert.deepEqual(visibleWorkspace.archivedSessionIds, ['s-archived']);

  const sessions = await request('POST', '/api/session.list', userCookie);
  assert.equal(sessions.status, 200);
  const sessionItems = (sessions.json as { result: { value: Array<{ sessionId: string }> } }).result.value;
  assert.deepEqual(sessionItems.map((item) => item.sessionId), ['s-active']);

  const history = await request('POST', '/api/session.history', userCookie, JSON.stringify({ sessionId: 's-other' }));
  assert.equal(history.status, 403, '同一白名单范围内的其他用户会话仍不可访问');
  const remove = await request('DELETE', '/api/session.delete', userCookie, JSON.stringify({ sessionId: 's-other' }));
  assert.equal(remove.status, 403, 'DELETE 同样必须校验会话归属');
});

test('Issue #16: explicit empty archive state replaces old snapshot', async () => {
  archiveIds = [];
  const workspace = await request('POST', '/api/workspace.list', userCookie);
  assert.equal(workspace.status, 200);
  const sessions = await request('POST', '/api/session.list', userCookie);
  assert.equal(sessions.status, 200);
  const sessionItems = (sessions.json as { result: { value: Array<{ sessionId: string }> } }).result.value;
  assert.deepEqual(sessionItems.map((item) => item.sessionId), ['s-active', 's-archived']);
});

test('Issue #16: malformed workspace response preserves the previous archive snapshot', async () => {
  archiveIds = ['s-archived'];
  malformedWorkspace = false;
  assert.equal((await request('POST', '/api/workspace.list', userCookie)).status, 200);
  malformedWorkspace = true;
  const badWorkspace = await request('POST', '/api/workspace.list', userCookie);
  assert.equal(badWorkspace.status, 502);
  const sessions = await request('POST', '/api/session.list', userCookie);
  assert.equal(sessions.status, 200);
  const sessionItems = (sessions.json as { result: { value: Array<{ sessionId: string }> } }).result.value;
  assert.deepEqual(sessionItems.map((item) => item.sessionId), ['s-active']);
  malformedWorkspace = false;
});

test('Issue #16: older concurrent workspace response cannot restore stale archive state', async () => {
  workspaceResponsePlan = [
    { archived: ['s-active'], delayMs: 40 },
    { archived: ['s-archived'], delayMs: 0 },
  ];
  const oldResponse = request('POST', '/api/workspace.list', userCookie);
  const newResponse = request('POST', '/api/workspace.list', userCookie);
  const newest = await newResponse;
  assert.equal(newest.status, 200);
  const old = await oldResponse;
  assert.equal(old.status, 200);
  const sessions = await request('POST', '/api/session.list', userCookie);
  assert.equal(sessions.status, 200);
  const sessionItems = (sessions.json as { result: { value: Array<{ sessionId: string }> } }).result.value;
  assert.deepEqual(sessionItems.map((item) => item.sessionId), ['s-active']);
});

test('Issue #16: authorized fork registers the new session for the same user', async () => {
  archiveIds = [];
  assert.equal((await request('POST', '/api/workspace.list', userCookie)).status, 200);

  const fork = await request('POST', '/api/session.fork', userCookie, JSON.stringify({ sessionId: 's-active' }));
  assert.equal(fork.status, 200);

  const history = await request('POST', '/api/session.history', userCookie, JSON.stringify({ sessionId: 's-forked' }));
  assert.equal(history.status, 200, '授权源会话 fork 出来的新会话应立即可访问');
  const second = await request('POST', '/api/session.history', userCookie, JSON.stringify({ sessionId: 's-other' }));
  assert.equal(second.status, 403, 'fork 响应中的 cwd 不得把新会话授权到其他用户工作区');
});

test('Issue #16: workspace.archiveSession uses session ownership checks', async () => {
  archiveIds = ['s-archived'];
  assert.equal((await request('POST', '/api/workspace.list', userCookie)).status, 200);

  const allowed = await request('POST', '/api/workspace.archiveSession', userCookie, JSON.stringify({ sessionId: 's-active' }));
  assert.equal(allowed.status, 200, '授权工作区中的会话可以归档');

  const denied = await request('POST', '/api/workspace.archiveSession', userCookie, JSON.stringify({ sessionId: 's-not-known' }));
  assert.equal(denied.status, 403, '未知/未授权会话不得归档');

  const other = await request('POST', '/api/workspace.archiveSession', userCookie, JSON.stringify({ sessionId: 's-other' }));
  assert.equal(other.status, 403, '其他用户工作区中的会话不得归档');
});

test('Issue #16: admin retains raw workspace and session archive views', async () => {
  archiveIds = ['s-archived'];
  const workspace = await request('POST', '/api/workspace.list', adminCookie);
  assert.equal(workspace.status, 200);
  const workspaceJson = workspace.json as { result: { value: { items: Array<{ sessionIds: string[] }>; archivedSessionIds: string[] } } };
  assert.deepEqual(workspaceJson.result.value.items[0].sessionIds, ['s-active', 's-archived']);
  assert.deepEqual(workspaceJson.result.value.archivedSessionIds, ['s-archived']);

  const sessions = await request('POST', '/api/session.list', adminCookie);
  assert.equal(sessions.status, 200);
  const sessionItems = (sessions.json as { result: { value: Array<{ sessionId: string }> } }).result.value;
  assert.deepEqual(sessionItems.map((item) => item.sessionId), ['s-active', 's-archived', 's-other']);
});
