import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { PlatformConfig } from '../src/config.ts';
import { isBackgroundUpdateRequest } from '../src/gateway.ts';
import {
  compareVersions,
  detectRuntime,
  parseNpmPackageInfo,
  parseReleaseInfo,
  type UpdateEngineOps,
  type UpdateStore,
  UpdateEngine,
  UPDATE_DEFAULT_MAX_BPS,
  UPDATE_IDLE_MS,
} from '../src/update.ts';

function config(dbPath: string, restartService = 'dsh-web'): PlatformConfig {
  return {
    setupKey: 'test-setup-key', dbPath, dbEncKey: '', jwtSecret: 'test-jwt-secret', internalSecret: 'test-internal-secret',
    gateway: { host: '127.0.0.1', port: 9443, upstream: 'http://127.0.0.1:3080', tls: null, redirectPort: null, publicHost: '', domain: 'localhost', autoTls: false, acmeEmail: '', acmeStaging: false },
    patch: { dshRoot: '', restartService }, webSocket: { adminAllowlist: [], userAllowlist: [] },
  };
}

function store(): UpdateStore & { values: Map<string, string> } {
  const values = new Map<string, string>();
  return { values, getSetting: (key) => values.get(key) ?? null, setSetting: (key, value) => values.set(key, value), audit: () => {} };
}

async function flushUpdates(count = 12): Promise<void> {
  for (let i = 0; i < count; i += 1) await new Promise((resolve) => setImmediate(resolve));
}

function release(version = '2.6.3'): unknown { return { tag_name: `v${version}` }; }
function metadata(version = '2.6.3', payload = Buffer.from('verified package')): unknown {
  return { name: 'dsh-passwords', version, dist: { tarball: `https://registry.npmjs.org/dsh-passwords/-/dsh-passwords-${version}.tgz`, integrity: `sha512-${createHash('sha512').update(payload).digest('base64')}` } };
}

function setupDocker(root: string, autoEnabled: boolean, nowRef: { value: number }, results: { pull?: boolean; up?: boolean; ps?: boolean } = {}) {
  const composeDir = path.join(root, 'compose');
  mkdirSync(composeDir, { recursive: true });
  writeFileSync(path.join(composeDir, 'compose.yml'), 'services:\n  dsh-passwords:\n    image: skywalker237234/dsh-passwords:2.6.2\n');
  const calls: Array<{ command: string; args: string[]; cwd?: string }> = [];
  let installAudits = 0;
  const db = store();
  db.setSetting('auto_update_enabled', autoEnabled ? '1' : '0');
  const ops: UpdateEngineOps = {
    now: () => nowRef.value,
    fetchRelease: async () => release(),
    fetchNpmMetadata: async () => {
      throw new Error('Docker must not query npm metadata');
    },
    download: async () => {
      throw new Error('Docker must not download npm artifacts');
    },
    runInstall: async () => {
      throw new Error('Docker must not run npm install');
    },
    runCommand: async (command, args, cwd) => {
      calls.push({ command, args, cwd });
      if (command !== 'docker') return { ok: false, message: 'unexpected command' };
      if (args[0] !== 'compose') return { ok: false, message: 'unexpected docker command' };
      if (args.includes('pull')) return { ok: results.pull !== false, message: results.pull === false ? 'pull failed' : '' };
      if (args.includes('up')) return { ok: results.up !== false, message: results.up === false ? 'up failed' : '' };
      if (args.includes('ps')) return { ok: results.ps !== false, message: results.ps === false ? 'ps failed' : 'dsh-passwords' };
      if (args.some((arg) => arg.includes('package.json'))) return { ok: true, message: '2.6.3' };
      if (args.some((arg) => arg.includes('readyz'))) return { ok: true, message: '' };
      return { ok: false, message: 'unexpected compose command' };
    },
    restartWebService: async () => ({ ok: false, message: 'Docker must not restart systemd' }),
    log: () => {},
  };
  const engine = new UpdateEngine(config(path.join(root, 'platform.db')), db, ops, {
    installRoot: root,
    env: {
      DSH_PASSWORDS_RUNTIME: 'docker',
      MCP_DSH_DOCKER_COMPOSE_DIR: composeDir,
      DSH_HOME: path.join(root, 'dsh-home'),
      MCP_DSH_DOCKER_SELF_UPDATE: '1',
      MCP_DSH_DOCKER_COMPOSE_FILE: 'compose.yml',
      MCP_DSH_DOCKER_IMAGE: 'skywalker237234/dsh-passwords',
    },
    dockerSelfUpdateAvailable: true,
  });
  const originalAudit = db.audit;
  db.audit = (...args) => { installAudits += 1; originalAudit(...args); };
  return { engine, db, ops, calls, installAudits: () => installAudits, composeDir };
}

function setup(root: string, autoEnabled: boolean, nowRef: { value: number }, restartOk = true, restartService = 'dsh-web') {
  writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'dsh-passwords', version: '2.6.2' }));
  writeFileSync(path.join(root, 'obsolete-runtime.js'), 'old program file\n');
  const envFile = path.join(root, '.env');
  writeFileSync(envFile, 'SETUP_KEY=test-setup-key\n');
  mkdirSync(path.join(root, 'data'), { recursive: true });
  writeFileSync(path.join(root, 'data', 'platform.db'), 'user database\n');
  const dshHome = path.join(root, 'dsh-home');
  const globalRoot = path.join(root, 'global', 'node_modules');
  const calls: Array<{ command: string; args: string[] }> = [];
  let restarts = 0;
  let restartAllowed = restartOk;
  const payload = Buffer.from('verified package');
  const ops: UpdateEngineOps = {
    now: () => nowRef.value,
    fetchRelease: async () => release(),
    fetchNpmMetadata: async () => metadata(),
    download: async (_url, dest, maxBps, resumed, progress) => {
      assert.equal(resumed, 0);
      progress?.(payload.length, payload.length);
      writeFileSync(dest, payload);
      assert.ok(maxBps <= UPDATE_DEFAULT_MAX_BPS || maxBps > 1_000_000_000_000);
      return createHash('sha512').update(payload).digest('hex');
    },
    runInstall: async (args) => {
      const prefixIndex = args.indexOf('--prefix');
      if (prefixIndex >= 0) {
        const stagingRoot = args[prefixIndex + 1];
        const packageRoot = path.join(stagingRoot, 'node_modules', 'dsh-passwords');
        mkdirSync(path.join(packageRoot, 'dist'), { recursive: true });
        mkdirSync(path.join(packageRoot, 'scripts'), { recursive: true });
        writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({ name: 'dsh-passwords', version: '2.6.3' }));
        writeFileSync(path.join(packageRoot, 'dist', 'cli.js'), 'export {};\n');
        writeFileSync(path.join(packageRoot, 'scripts', 'register-plugin.mjs'), 'export {};\n');
        writeFileSync(path.join(stagingRoot, 'node_modules', 'runtime-dependency.js'), 'export {};\n');
      }
      return { ok: true, message: '' };
    },
    runCommand: async (command, args, _cwd, env) => {
      calls.push({ command, args });
      if (args[0] === 'root' && args[1] === '-g') return { ok: true, message: globalRoot };
      if (command === process.execPath && args[0]?.endsWith('register-plugin.mjs')) {
        const packageRoot = path.resolve(path.dirname(args[0]), '..');
        const profile = path.join(env?.DSH_HOME ?? dshHome, 'profiles', 'web');
        mkdirSync(path.join(profile, 'node_modules'), { recursive: true });
        const linkPath = path.join(profile, 'node_modules', 'dsh-passwords');
        rmSync(linkPath, { recursive: true, force: true });
        symlinkSync(packageRoot, linkPath, process.platform === 'win32' ? 'junction' : 'dir');
        writeFileSync(path.join(profile, 'package.json'), JSON.stringify({ dependencies: { 'dsh-passwords': `link:${packageRoot}` } }));
      }
      return { ok: true, message: '' };
    },
    restartWebService: async () => { restarts += 1; return restartAllowed ? { ok: true, message: '' } : { ok: false, message: 'systemd unavailable' }; }, log: () => {},
  };
  const db = store();
  db.setSetting('auto_update_enabled', autoEnabled ? '1' : '0');
  const engine = new UpdateEngine(config(path.join(root, 'platform.db'), restartService), db, ops, { installRoot: root, env: { DSH_PASSWORDS_RUNTIME: 'git', DSH_HOME: dshHome, DSH_PASSWORDS_ENV_FILE: envFile } });
  return { engine, db, ops, calls, restarts: () => restarts, setRestartAllowed: (allowed: boolean) => { restartAllowed = allowed; } };
}

test('test package flow targets 2.6.5 from a 2.6.4 baseline', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
  assert.equal(pkg.version, '2.6.5');
  assert.equal(compareVersions(pkg.version, '2.6.4'), 1);
});

test('source archives without .git still use the npm update runtime', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-runtime-'));
  try {
    mkdirSync(path.join(root, 'src'));
    mkdirSync(path.join(root, 'scripts'));
    assert.equal(detectRuntime(root, { DSH_PASSWORDS_RUNTIME: '' }), 'git');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('update metadata parser only accepts the expected npm package, version, registry and integrity', () => {
  assert.equal(compareVersions('2.6.10', '2.6.2'), 1);
  assert.equal(parseReleaseInfo({ tag_name: 'v2.6.3' })?.version, '2.6.3');
  assert.equal(parseNpmPackageInfo(metadata(), '2.6.3')?.version, '2.6.3');
  assert.equal(parseNpmPackageInfo({ name: 'dsh-passwords', version: '2.6.3', dist: { tarball: 'https://example.test/x.tgz', integrity: 'sha512-x' } }, '2.6.3'), null);
  assert.equal(parseNpmPackageInfo(metadata(), '2.6.2'), null);
});

test('automatic update downloads a verified npm package and installs only after idle', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, db, calls, restarts } = setup(root, true, now);
    await engine.checkNow({ downloadIfAllowed: true });
    assert.equal(engine.status().phase, 'ready');
    assert.equal(engine.status().downloadMode, 'automatic');
    assert.equal(restarts(), 0);
    now.value += UPDATE_IDLE_MS;
    engine.tick();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(restarts(), 1);
    assert.equal(db.getSetting('update_downloaded_ready'), '');
    assert.equal(calls.some((call) => call.command === 'git'), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('manual mode checks without download, then requires download and installation confirmation', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, db, restarts } = setup(root, false, now);
    await engine.checkNow();
    assert.equal(engine.status().updateAvailable, true);
    assert.equal(engine.status().phase, 'idle');
    const first = await engine.applyNow();
    assert.equal(first.code, 'DOWNLOAD_STARTED');
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(engine.status().phase, 'ready');
    assert.equal(engine.status().installConfirmationRequired, true);
    assert.equal(db.getSetting('update_download_mode'), 'manual');
    assert.equal(db.getSetting('update_install_confirmation_required'), '1');
    assert.ok(db.getSetting('update_last_notification_at'));
    assert.equal(restarts(), 0);
    const second = await engine.applyNow();
    assert.equal(second.ok, true);
    assert.equal(second.code, 'INSTALL_STARTED');
    assert.equal(second.phase, 'installing');
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(restarts(), 1);
    assert.match(readFileSync(path.join(root, '.env'), 'utf8'), /MCP_DB_PATH=.*platform\.db/);
    assert.equal(readFileSync(path.join(root, 'data', 'platform.db'), 'utf8'), 'user database\n');
    assert.equal(existsSync(path.join(root, 'obsolete-runtime.js')), false);
    assert.equal(existsSync(path.join(root, 'update')), false);
    const profile = JSON.parse(readFileSync(path.join(root, 'dsh-home', 'profiles', 'web', 'package.json'), 'utf8')) as { dependencies: Record<string, string> };
    assert.equal(profile.dependencies['dsh-passwords'], `link:${root}`);
  } finally { rmSync(root, { recursive: true, force: true }); }
});


test('update status polling is background traffic, while user actions remain activity', () => {
  assert.equal(isBackgroundUpdateRequest('/api/dsh-passwords/update/status'), true);
  assert.equal(isBackgroundUpdateRequest('/gateway/internal/update'), true);
  assert.equal(isBackgroundUpdateRequest('/api/dsh-passwords/update/check'), false);
  assert.equal(isBackgroundUpdateRequest('/api/dsh-passwords/update/apply'), false);
  assert.equal(isBackgroundUpdateRequest('/gateway/api/overview'), false);
});

test('turning automatic updates off requires confirmation for an already downloaded package', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine } = setup(root, true, now);
    await engine.checkNow({ downloadIfAllowed: true });
    assert.equal(engine.status().installConfirmationRequired, false);
    engine.setAutoUpdateEnabled(false);
    assert.equal(engine.status().installConfirmationRequired, true);
    assert.equal(engine.status().downloadMode, 'manual');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('restart failure is reported and does not claim a successful update', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine } = setup(root, false, now, false);
    await engine.checkNow();
    const downloaded = await engine.applyNow();
    assert.equal(downloaded.code, 'DOWNLOAD_STARTED');
    await flushUpdates();
    const started = await engine.applyNow();
    assert.equal(started.code, 'INSTALL_STARTED');
    await flushUpdates();
    assert.equal(engine.status().phase, 'error');
    assert.match(engine.status().lastError ?? '', /重启失败/);
    assert.equal(engine.status().restartPendingVersion, '2.6.3');
    assert.match(engine.status().lastError ?? '', /重启失败/);
    assert.equal(engine.status().phase, 'error');
    assert.equal(engine.status().restartPendingVersion, '2.6.3');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('restart failure can be retried immediately and clears the pending restart after recovery', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, setRestartAllowed } = setup(root, false, now, false);
    await engine.checkNow();
    const downloaded = await engine.applyNow();
    assert.equal(downloaded.code, 'DOWNLOAD_STARTED');
    await flushUpdates();
    const started = await engine.applyNow();
    assert.equal(started.code, 'INSTALL_STARTED');
    await flushUpdates();
    const failed = await engine.applyNow();
    assert.equal(failed.code, 'RESTART_FAILED');
    setRestartAllowed(true);
    const retried = await engine.applyNow();
    assert.equal(retried.ok, true);
    assert.equal(engine.status().restartPendingVersion, null);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('restart pending state survives engine reconstruction and can be resumed', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const first = setup(root, false, now, false);
    await first.engine.checkNow();
    const downloaded = await first.engine.applyNow();
    assert.equal(downloaded.code, 'DOWNLOAD_STARTED');
    await flushUpdates();
    const started = await first.engine.applyNow();
    assert.equal(started.code, 'INSTALL_STARTED');
    await flushUpdates();
    assert.equal(first.db.getSetting('update_restart_pending_version'), '2.6.3');
    const second = setup(root, false, now, true);
    // setup's fresh store is replaced with the persisted settings to model a gateway restart.
    second.db.setSetting('update_restart_pending_version', '2.6.3');
    const restored = new UpdateEngine(config(path.join(root, 'platform.db')), second.db, second.ops, { installRoot: root, env: { DSH_PASSWORDS_RUNTIME: 'git', DSH_HOME: path.join(root, 'dsh-home'), DSH_PASSWORDS_ENV_FILE: path.join(root, '.env') } });
    assert.equal(restored.status().restartPendingVersion, '2.6.3');
    const retried = await restored.applyNow();
    assert.equal(retried.ok, true);
    assert.equal(restored.status().restartPendingVersion, null);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('manual restart mode reports manual action without persisting a failed restart', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, db } = setup(root, false, now, true, '');
    await engine.checkNow();
    await engine.applyNow();
    await flushUpdates();
    const result = await engine.applyNow();
    assert.equal(result.ok, true);
    assert.equal(result.code, 'INSTALL_STARTED');
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(engine.status().phase, 'error');
    assert.equal(engine.status().restartPendingVersion, '2.6.3');
    assert.equal(db.getSetting('update_restart_pending_version'), '2.6.3');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('docker manual update uses compose without npm or systemd', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, calls, installAudits, composeDir } = setupDocker(root, false, now);
    await engine.checkNow();
    assert.equal(engine.status().env, 'docker');
    assert.equal(engine.status().updateAvailable, true);
    const started = await engine.applyNow();
    assert.equal(started.ok, true);
    assert.equal(started.code, 'INSTALL_STARTED');
    assert.equal(started.phase, 'installing');
    await flushUpdates();
    assert.equal(calls.length, 5);
    assert.deepEqual(calls.slice(0, 3).map((call) => call.args.at(-1)), ['dsh-passwords', 'dsh-passwords', 'dsh-passwords']);
    assert.match(calls[0].args.join(' '), /compose -f compose\.yml -f \.dsh-passwords-update\.override\.yml pull dsh-passwords/);
    assert.ok(calls.some((call) => call.args.some((arg) => arg.includes('package.json'))));
    assert.ok(calls.some((call) => call.args.some((arg) => arg.includes('readyz'))));
    assert.ok(calls.every((call) => call.cwd === composeDir));
    assert.equal(installAudits(), 1);
    assert.equal(engine.status().phase, 'idle');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('docker automatic update waits for idle and never downloads npm', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, calls, installAudits } = setupDocker(root, true, now);
    await engine.checkNow({ downloadIfAllowed: true });
    assert.equal(calls.length, 0);
    assert.equal(engine.status().updateAvailable, true);
    now.value += UPDATE_IDLE_MS;
    engine.tick();
    assert.equal(engine.status().phase, 'installing');
    await flushUpdates();
    assert.equal(calls.length, 5);
    assert.equal(installAudits(), 1);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('docker update failures stop the compose chain and enter error', async () => {
  for (const failure of ['pull', 'up', 'ps'] as const) {
    const root = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-'));
    try {
      const now = { value: 1_000_000 };
      const { engine, calls, installAudits } = setupDocker(root, false, now, { [failure]: false });
      await engine.checkNow();
      const result = await engine.applyNow();
      assert.equal(result.code, 'INSTALL_STARTED');
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(engine.status().phase, 'error');
      assert.match(engine.status().lastError ?? '', new RegExp(`Docker .*${failure === 'pull' ? '拉取' : failure === 'up' ? '重启' : '健康检查'}`));
      assert.equal(installAudits(), 0);
      const commands = calls.map((call) => call.args.find((arg) => ['pull', 'up', 'ps'].includes(arg))).filter((arg): arg is string => arg !== undefined);
      if (failure === 'pull') assert.deepEqual(commands, ['pull']);
      if (failure === 'up') assert.deepEqual(commands, ['pull', 'up']);
      if (failure === 'ps') assert.deepEqual(commands, ['pull', 'up', 'ps']);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('docker update without compose directory is manual-only', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-'));
  try {
    const db = store();
    db.setSetting('auto_update_enabled', '0');
    const ops: UpdateEngineOps = {
      now: () => 1_000_000,
      fetchRelease: async () => release(),
      fetchNpmMetadata: async () => { throw new Error('must not query npm'); },
      download: async () => { throw new Error('must not download npm'); },
      runInstall: async () => { throw new Error('must not install npm'); },
      runCommand: async () => { throw new Error('must not run docker'); },
      restartWebService: async () => ({ ok: false, message: 'must not restart' }),
      log: () => {},
    };
    const engine = new UpdateEngine(config(path.join(root, 'platform.db')), db, ops, { installRoot: root, env: { DSH_PASSWORDS_RUNTIME: 'docker' } });
    await engine.checkNow();
    const result = await engine.applyNow();
    assert.equal(result.code, 'MANUAL_ONLY');
    assert.match(result.message, /MCP_DSH_DOCKER_COMPOSE_DIR/);
    assert.equal(engine.status().autoInstallSupported, false);
    assert.match(engine.status().manualCommand, /docker compose pull/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('docker update rejects duplicate apply while compose is running', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-'));
  try {
    const now = { value: 1_000_000 };
    const composeDir = path.join(root, 'compose');
    mkdirSync(composeDir, { recursive: true });
    let releaseUp: (() => void) | null = null;
    const calls: string[] = [];
    const db = store();
    db.setSetting('auto_update_enabled', '0');
    const ops: UpdateEngineOps = {
      now: () => now.value,
      fetchRelease: async () => release(),
      fetchNpmMetadata: async () => { throw new Error('must not query npm'); },
      download: async () => { throw new Error('must not download npm'); },
      runInstall: async () => { throw new Error('must not install npm'); },
      runCommand: async (_command, args) => {
        const action = args.find((arg) => ['pull', 'up', 'ps'].includes(arg)) ?? '';
        calls.push(action);
        if (action === 'up') await new Promise<void>((resolve) => { releaseUp = resolve; });
        if (args.some((arg) => arg.includes('package.json'))) return { ok: true, message: '2.6.3' };
        if (args.some((arg) => arg.includes('readyz'))) return { ok: true, message: '' };
        return { ok: true, message: action === 'ps' ? 'dsh-passwords' : '' };
      },
      restartWebService: async () => ({ ok: false, message: 'must not restart' }),
      log: () => {},
    };
    writeFileSync(path.join(composeDir, 'compose.yml'), 'services:\n  dsh-passwords:\n    image: skywalker237234/dsh-passwords:2.6.2\n');
    const engine = new UpdateEngine(config(path.join(root, 'platform.db')), db, ops, { installRoot: root, env: { DSH_PASSWORDS_RUNTIME: 'docker', MCP_DSH_DOCKER_COMPOSE_DIR: composeDir, MCP_DSH_DOCKER_SELF_UPDATE: '1', MCP_DSH_DOCKER_COMPOSE_FILE: 'compose.yml', MCP_DSH_DOCKER_IMAGE: 'skywalker237234/dsh-passwords' }, dockerSelfUpdateAvailable: true });
    await engine.checkNow();
    const first = await engine.applyNow();
    assert.equal(first.code, 'INSTALL_STARTED');
    const second = await engine.applyNow();
    assert.equal(second.code, 'INSTALL_IN_PROGRESS');
    assert.deepEqual(calls, ['pull', 'up']);
    (releaseUp as (() => void) | null)!();
    await flushUpdates();
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('docker restart pending state recovers with a single health check', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-'));
  try {
    const now = { value: 1_000_000 };
    const first = setupDocker(root, false, now);
    first.db.setSetting('update_restart_pending_version', '2.6.3');
    const restored = new UpdateEngine(config(path.join(root, 'platform.db')), first.db, first.ops, { installRoot: root, env: { DSH_PASSWORDS_RUNTIME: 'docker', MCP_DSH_DOCKER_COMPOSE_DIR: first.composeDir, MCP_DSH_DOCKER_SELF_UPDATE: '1', MCP_DSH_DOCKER_COMPOSE_FILE: 'compose.yml', MCP_DSH_DOCKER_IMAGE: 'skywalker237234/dsh-passwords' }, dockerSelfUpdateAvailable: true });
    await flushUpdates();
    assert.equal(restored.status().phase, 'idle');
    assert.equal(restored.status().currentVersion, '2.6.3');
    assert.equal(first.db.getSetting('update_restart_pending_version'), '');
    assert.equal(first.db.getSetting('update_docker_applied_version'), '2.6.3');
    assert.ok(first.calls.some((call) => call.args.includes('ps')));
    assert.ok(first.calls.some((call) => call.args.some((arg) => arg.includes('package.json'))));
    assert.ok(first.calls.some((call) => call.args.some((arg) => arg.includes('readyz'))));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('docker restart recovery clears the pending marker when health check fails', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-'));
  try {
    const now = { value: 1_000_000 };
    const first = setupDocker(root, false, now, { ps: false });
    first.db.setSetting('update_restart_pending_version', '2.6.3');
    const restored = new UpdateEngine(config(path.join(root, 'platform.db')), first.db, first.ops, { installRoot: root, env: { DSH_PASSWORDS_RUNTIME: 'docker', MCP_DSH_DOCKER_COMPOSE_DIR: first.composeDir, MCP_DSH_DOCKER_SELF_UPDATE: '1', MCP_DSH_DOCKER_COMPOSE_FILE: 'compose.yml', MCP_DSH_DOCKER_IMAGE: 'skywalker237234/dsh-passwords' }, dockerSelfUpdateAvailable: true });
    await flushUpdates();
    assert.equal(restored.status().phase, 'error');
    assert.equal(restored.status().restartPendingVersion, null);
    assert.equal(first.db.getSetting('update_restart_pending_version'), '');
    assert.match(restored.status().lastError ?? '', /恢复(健康检查|失败)/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('integrity mismatch discards the artifact and never installs', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, ops, restarts } = setup(root, true, now);
    ops.fetchNpmMetadata = async () => metadata('2.6.3', Buffer.from('different integrity'));
    await engine.checkNow({ downloadIfAllowed: true });
    assert.equal(engine.status().phase, 'error');
    assert.match(engine.status().lastError ?? '', /sha512/);
    assert.equal(restarts(), 0);
    assert.equal(existsSync(path.join(root, 'update', 'dsh-passwords-2.6.3.tgz')), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
