import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';

test('Issue #19：显式会话 grant 原子持久化、隔离且拒绝非法 ID', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-session-grants-'));
  const dbPath = path.join(tempDir, 'grants.db');
  const crypto = createFieldCrypto('test-key', 'test-key');
  const db = new Database(dbPath, crypto);
  try {
    db.init();
    const first = db.createUser('first-user', '$2a$10$dummyhashdummyhashdummyhashdu');
    const second = db.createUser('second-user', '$2a$10$dummyhashdummyhashdummyhashdu');

    db.replaceUserSessionGrants(first.id, ['s-one', 's-one', '', 'x'.repeat(201), 's-two']);
    assert.deepEqual(db.listUserSessionGrants(first.id), ['s-one', 's-two']);
    assert.equal(db.hasUserSessionGrant(first.id, 's-one'), true);
    assert.equal(db.hasUserSessionGrant(second.id, 's-one'), false, '授权不得跨用户泄露');

    db.replaceUserSessionGrants(first.id, ['s-three']);
    assert.deepEqual(db.listUserSessionGrants(first.id), ['s-three'], '替换必须移除旧授权');
    db.close();

    const reopened = new Database(dbPath, crypto);
    try {
      reopened.init();
      assert.deepEqual(reopened.listUserSessionGrants(first.id), ['s-three'], '重启后授权必须持久化');
    } finally {
      reopened.close();
    }
  } finally {
    try { db.close(); } catch { /* already closed for reopen assertion */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('极旧 user_permissions 表缺少上传与 git 列时会补齐并默认关闭', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-db-legacy-upload-'));
  const dbPath = path.join(tempDir, 'legacy-upload.db');
  const raw = new DatabaseSync(dbPath);
  raw.exec(`
    CREATE TABLE user_permissions (
      user_id INTEGER PRIMARY KEY,
      allowed_folders TEXT,
      hourly_token_limit INTEGER,
      daily_minutes_limit INTEGER,
      banned INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    INSERT INTO user_permissions (user_id, allowed_folders) VALUES (7, '["/srv/project"]');
  `);
  raw.close();

  const db = new Database(dbPath, createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const migrated = db.getPermissions(7);
    assert.equal(migrated?.allow_upload, false);
    assert.equal(migrated?.allow_git_download, false);
  } finally {
    db.close();
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('旧 user_permissions 表会迁移 WebSocket 授权列，并保留现有权限', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-db-'));
  const dbPath = path.join(tempDir, 'legacy.db');
  const raw = new DatabaseSync(dbPath);
  raw.exec(`
    CREATE TABLE user_permissions (
      user_id INTEGER PRIMARY KEY,
      allowed_folders TEXT,
      hourly_token_limit INTEGER,
      daily_minutes_limit INTEGER,
      allow_upload INTEGER NOT NULL DEFAULT 1,
      allow_git_download INTEGER NOT NULL DEFAULT 0,
      banned INTEGER NOT NULL DEFAULT 0,
      sandbox_mode TEXT,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    INSERT INTO user_permissions
      (user_id, allowed_folders, hourly_token_limit, daily_minutes_limit, allow_upload, allow_git_download, banned, sandbox_mode)
    VALUES (7, '["/srv/project"]', 10, 20, 1, 1, 0, 'workspace-write');
  `);
  raw.close();

  const db = new Database(dbPath, createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const migrated = db.getPermissions(7);
    assert.deepEqual(migrated, {
      user_id: 7,
      allowed_folders: ['/srv/project'],
      hourly_token_limit: 10,
      daily_minutes_limit: 20,
      allow_upload: true,
      allow_git_download: true,
      allow_workspace_create: false,
      allowed_websocket_paths: [],
      allowed_agent_presets: null,
      banned: false,
      sandbox_mode: 'workspace-write',
      disabled_sessions: [],
      updated_at: migrated?.updated_at,
    });

    db.setPermissions(7, {
      allowedFolders: ['/srv/project'],
      hourlyTokenLimit: 10,
      dailyMinutesLimit: 20,
      allowUpload: true,
      allowGitDownload: true,
      allowWorkspaceCreate: false,
      allowedWebSocketPaths: ['/plugin/ws/*'],
      allowedAgentPresets: ['system/default'],
      banned: false,
      sandboxMode: 'workspace-write',
      disabledSessions: [],
    });
    db.setPermissions(7, {
      allowedFolders: ['/srv/project'],
      hourlyTokenLimit: 10,
      dailyMinutesLimit: 20,
      allowUpload: true,
      allowGitDownload: true,
      allowWorkspaceCreate: false,
      banned: false,
      sandboxMode: 'workspace-write',
      disabledSessions: [],
    });
    assert.deepEqual(db.getPermissions(7)?.allowed_websocket_paths, ['/plugin/ws/*']);
    assert.deepEqual(db.getPermissions(7)?.allowed_agent_presets, ['system/default']);
    db.setPermissions(7, {
      allowedFolders: ['/srv/project'],
      hourlyTokenLimit: 10,
      dailyMinutesLimit: 20,
      allowUpload: true,
      allowGitDownload: true,
      allowWorkspaceCreate: false,
      allowedAgentPresets: null,
      banned: false,
      sandboxMode: 'workspace-write',
      disabledSessions: [],
    });
    assert.equal(db.getPermissions(7)?.allowed_agent_presets, null, 'NULL 必须保留不限制的兼容语义');
  } finally {
    db.close();
    rmSync(tempDir, { recursive: true, force: true });
  }
});
