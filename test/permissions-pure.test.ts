// 权限模块安全关键纯函数的回归测试（之前零覆盖）：
// 沙盒降级 / 审批强制拒绝 / 会话归属过滤 / 权限路径过滤 / preset 解析。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  permissionPresetFromCommand,
  presetFromSettingsMutate,
  forceRejectApproval,
  clampSessionHistorySandbox,
  filterByPathField,
  filterOwnedSessionIds,
  sandboxPresetRank,
} from '../src/permissions.js';

// ── permissionPresetFromCommand（/permission 命令解析） ─────────

test('permissionPresetFromCommand：解析 preset 参数', () => {
  assert.equal(permissionPresetFromCommand('/permission workspace-write'), 'workspace-write');
  assert.equal(permissionPresetFromCommand('/permission read-only'), 'read-only');
  assert.equal(permissionPresetFromCommand('/permission danger-full-access'), 'danger-full-access');
});

test('permissionPresetFromCommand：非本命令/无参数返回 null', () => {
  assert.equal(permissionPresetFromCommand('/permission'), null);
  assert.equal(permissionPresetFromCommand('/help'), null);
  assert.equal(permissionPresetFromCommand('/permission '), null);
  assert.equal(permissionPresetFromCommand('permission workspace-write'), null);
});

// ── presetFromSettingsMutate（settings.mutate 找 defaultPreset） ─

test('presetFromSettingsMutate：path 数组含 defaultPreset 时返回 value', () => {
  const body = {
    ops: [{ path: ['permission', 'defaultPreset'], value: 'read-only' }],
  };
  assert.equal(presetFromSettingsMutate(body), 'read-only');
  assert.equal(presetFromSettingsMutate({ ops: [{ path: ['other'], value: 'x' }] }), null);
  assert.equal(presetFromSettingsMutate(null), null);
});

test('presetFromSettingsMutate：args 伪包裹里的值也会命中（fail-closed 方向）', () => {
  const body = { args: { path: ['permission', 'defaultPreset'], value: 'danger-full-access' } };
  // 与 extractPathFromBody/extractWorkspaceId 不同，这里不跳过 args——
  // 注意：这是故意的 fail-closed（沙盒检测里命中 args 高权限会 403 拦截，
  // dsh 忽略 args 走默认 preset 时也只是多拦不误放），与路径白名单相反方向，安全。
  assert.equal(presetFromSettingsMutate(body), 'danger-full-access');
});

// ── forceRejectApproval（受限子用户 AI 提权审批强制拒绝） ──────

test('forceRejectApproval：outcome 非 rejected 时改为 rejected', () => {
  const obj = { approvalId: 'ap1', outcome: 'approved' };
  assert.equal(forceRejectApproval(obj), true);
  assert.equal(obj.outcome, 'rejected');
});

test('forceRejectApproval：嵌套 result.value 信封也能命中', () => {
  const obj = { result: { value: { approvalId: 'ap2', outcome: 'accepted' } } };
  assert.equal(forceRejectApproval(obj), true);
  assert.equal(obj.result.value.outcome, 'rejected');
});

test('forceRejectApproval：已是 rejected / ask_user_question(answer) 不改', () => {
  const obj = { approvalId: 'ap3', outcome: 'rejected' };
  assert.equal(forceRejectApproval(obj), false);
  assert.equal(obj.outcome, 'rejected');
  const q = { answer: 'yes' }; // ask_user_question 的响应用 answer，不受影响
  assert.equal(forceRejectApproval(q), false);
});

// ── clampSessionHistorySandbox（沙盒降级） ─────────────────────

/** 构造 one-line 对象（不引 dsh 深层类型，结构足够即可） */
const mk = (o: Record<string, unknown>) => o;

test('clampSessionHistorySandbox：preset/mode/currentValue 超过授权级别时降级', () => {
  const target = mk({
    events: [
      { event: { type: 'permission/preset', data: { preset: 'danger-full-access' } } },
      { event: { type: 'sandbox/mode', data: { mode: 'workspace-write' } } },
    ],
    projections: { values: { permissions: { currentValue: 'danger-full-access' } } },
  });
  const changed = clampSessionHistorySandbox(target, 'read-only');
  assert.equal(changed, true);
  assert.equal((target.events[0].event as any).data.preset, 'read-only');
  assert.equal((target.events[1].event as any).data.mode, 'read-only');
  assert.equal((target.projections.values.permissions as any).currentValue, 'read-only');
});

test('clampSessionHistorySandbox：同级别/更低级别不改', () => {
  const target = mk({
    events: [{ event: { type: 'sandbox/mode', data: { mode: 'read-only' } } }],
    projections: { values: { permissions: { currentValue: 'read-only' } } },
  });
  assert.equal(clampSessionHistorySandbox(target, 'workspace-write'), false);
  assert.equal((target.events[0].event as any).data.mode, 'read-only');
});

test('clampSessionHistorySandbox：allowedMode=null 时不动（主用户不限）', () => {
  const target = mk({ events: [{ event: { type: 'sandbox/mode', data: { mode: 'danger-full-access' } } }] });
  assert.equal(clampSessionHistorySandbox(target, null), false);
});

// ── filterByPathField（白名单路径过滤） ────────────────────────

test('filterByPathField：白名单外的带 path 对象被丢弃，其余保留', () => {
  const input = {
    items: [
      { path: '/root/11', id: 'a' },
      { path: '/root/21', id: 'b' },
      { title: '无 path 字段' },
    ],
  };
  const out = filterByPathField(input, ['/root/21'], 'path') as typeof input;
  assert.equal(out.items.length, 2);
  assert.equal((out.items[0] as any).id, 'b');
  assert.equal((out.items[1] as any).title, '无 path 字段');
});

test('filterByPathField：空白名单 = 全部允许；__deny__ 哨兵 = 全部拒绝', () => {
  const input = { items: [{ path: '/x' }] };
  assert.equal((filterByPathField(input, [], 'path') as any).items.length, 1);
  assert.equal((filterByPathField(input, ['__deny__'], 'path') as any).items.length, 0);
});

// ── filterOwnedSessionIds（会话归属过滤） ───────────────────────

test('filterOwnedSessionIds：只保留 keep() 通过的 sessionId', () => {
  const input = { items: [{ path: '/w', sessionIds: ['s1', 's2', 's3'] }] };
  filterOwnedSessionIds(input, (id) => id === 's2');
  assert.deepEqual((input.items[0] as any).sessionIds, ['s2']);
});

test('filterOwnedSessionIds：sessionIds 含非字符串时清除非法值（fail-closed）', () => {
  const input = { items: [{ sessionIds: ['s1', 2] }] };
  filterOwnedSessionIds(input, () => true);
  assert.deepEqual((input.items[0] as any).sessionIds, ['s1']);
});

// ── sandboxPresetRank（级别映射） ──────────────────────────────

test('sandboxPresetRank：未知值按最宽松 2 处理（防越权切换）', () => {
  assert.equal(sandboxPresetRank('read-only'), 0);
  assert.equal(sandboxPresetRank('workspace-write'), 1);
  assert.equal(sandboxPresetRank('danger-full-access'), 2);
  assert.equal(sandboxPresetRank('bogus'), 2);
});
