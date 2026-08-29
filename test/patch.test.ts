// 补丁机制回归测试：兼容 rc.6（WEB_SETTINGS_NAMESPACES 白名单）与 rc.7（机制移除）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { applyRemotePatch, patchStatus } from '../src/patch.js';

/** 构建一个模拟 dsh 根目录（含两个必选补丁目标文件 + 可选 workspace 文件），返回 root 与清理函数 */
function makeDshRoot(
  apiproxyContent: string,
  settingsContent: string,
  workspaceContent?: string,
): { root: string; cleanup: () => void } {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-patch-'));
  const settingsDir = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib');
  const apiproxyDir = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-host-apiproxy', 'lib');
  mkdirSync(settingsDir, { recursive: true });
  mkdirSync(apiproxyDir, { recursive: true });
  writeFileSync(path.join(settingsDir, 'client.js'), settingsContent);
  writeFileSync(path.join(apiproxyDir, 'index.js'), apiproxyContent);
  if (workspaceContent !== undefined) {
    const wsDir = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-workspace', 'lib');
    mkdirSync(wsDir, { recursive: true });
    writeFileSync(path.join(wsDir, 'client.js'), workspaceContent);
  }
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

const RC6_APIPROXY = 'const WEB_SETTINGS_NAMESPACES = [\n\t"dsh-web-ui",\n\t"dsh-ssh"\n];\n';
const RC7_APIPROXY = 'export function describe(){return settings.describe({redactSecrets:true});}\n';
const RC7_SETTINGS_UNPATCHED =
  'const mode = connection.isLoopback ? "host" : "memory";\nexport default mode;\n';
const RC7_SETTINGS_PATCHED = 'const mode = "host";\nexport default mode;\n';

/** 与真实 dsh-client-ui-workspace client.js 相同的 click-outside 粘滞搜索块（制表符缩进） */
const WORKSPACE_STICKY = [
  '\t\t\t(0, react.useEffect)(() => {',
  '\t\t\t\tif (!wide || !searchExpanded) return;',
  '\t\t\t\tconst onClick = (event) => {',
  '\t\t\t\t\tif (!(event.target instanceof Node) || searchRoot.current?.contains(event.target) === true) return;',
  '\t\t\t\t\tsearchInput.current?.blur();',
  '\t\t\t\t\tif (normalizedQuery !== "") return;',
  '\t\t\t\t\tsetSearchExpanded(false);',
  '\t\t\t\t};',
  '\t\t\t\tdocument.addEventListener("click", onClick);',
  '\t\t\t\treturn () => {',
  '\t\t\t\t\tdocument.removeEventListener("click", onClick);',
  '\t\t\t\t};',
  '\t\t\t}, [',
  '\t\t\t\tnormalizedQuery,',
  '\t\t\t\twide,',
  '\t\t\t\tsearchExpanded',
  '\t\t\t]);',
  '\t\t\t(0, react_jsx_runtime.jsx)("input", {',
  '\t\t\t\t\tref: searchInput,',
  '\t\t\t\t\tclassName: WorkspaceBrowser_module_css_default.searchInput,',
  '\t\t\t\t\ttype: "text",',
  '\t\t\t\t\tplaceholder: t("search.placeholder"),',
  '\t\t\t\t}),',
  '',
].join('\n');

test('补丁：rc.6 结构（含 WEB_SETTINGS_NAMESPACES 白名单）→ 插入 dsh-passwords 并打 host 模式', () => {
  const { root, cleanup } = makeDshRoot(RC6_APIPROXY, RC7_SETTINGS_UNPATCHED);
  try {
    const statusBefore = patchStatus(root);
    assert.equal(statusBefore.settingsHostMode, false, '初始未打 host 模式');
    assert.equal(statusBefore.whitelist, false, '初始白名单未含 dsh-passwords');

    const result = applyRemotePatch(root);
    assert.equal(result, 'applied', 'rc.6 结构应实际应用补丁');

    const statusAfter = patchStatus(root);
    assert.equal(statusAfter.settingsHostMode, true, 'host 模式已启用');
    assert.equal(statusAfter.whitelist, true, '白名单已含 dsh-passwords');

    const w = readFileSync(path.join(root, 'node_modules', '@deepseek-ai', 'dsh-host-apiproxy', 'lib', 'index.js'), 'utf8');
    assert.ok(w.includes('"dsh-passwords"'), 'apiproxy 应含 dsh-passwords 命名空间');
  } finally {
    cleanup();
  }
});

test('补丁：rc.7 结构（无 WEB_SETTINGS_NAMESPACES）→ 不报 missing，白名单视为已满足', () => {
  // settings 已打 + 白名单机制移除 → 无任何可打 → unchanged；核心是绝不返回 missing
  const { root, cleanup } = makeDshRoot(RC7_APIPROXY, RC7_SETTINGS_PATCHED);
  try {
    const result = applyRemotePatch(root);
    // 关键断言：rc.7 移除白名单机制，不再当失败（missing）
    assert.notEqual(result, 'missing', 'rc.7 不应报 missing（机制已移除，非失败）');
    assert.equal(result, 'unchanged', 'rc.7 settings 已打 + 白名单跳过 → unchanged');

    const status = patchStatus(root);
    assert.equal(status.settingsHostMode, true, 'host 模式已启用');
    assert.equal(status.whitelist, true, 'rc.7 无白名单机制 → 视为已满足');
  } finally {
    cleanup();
  }
});

test('补丁：rc.7 settings 未打 host 模式时会被打进（settings 子补丁仍适用）', () => {
  const { root, cleanup } = makeDshRoot(RC7_APIPROXY, RC7_SETTINGS_UNPATCHED);
  try {
    const result = applyRemotePatch(root);
    // rc.7 下：白名单跳过（不适用），但 settings 未打 → 本次实际改了 settings → applied
    assert.equal(result, 'applied', 'rc.7 下 settings 未打时应应用并返回 applied');
    const s = readFileSync(path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib', 'client.js'), 'utf8');
    assert.ok(s.includes('"host"') && !s.includes('connection.isLoopback'), 'client.js 已强制 host 模式');
  } finally {
    cleanup();
  }
});

test('补丁：工作区搜索粘滞态 → 无结果时点击别处自动收起清空（消除“无匹配会话”滞留）', () => {
  const { root, cleanup } = makeDshRoot(RC7_APIPROXY, RC7_SETTINGS_PATCHED, WORKSPACE_STICKY);
  try {
    const before = patchStatus(root);
    assert.equal(before.workspaceSearch, false, '初始未打 workspace 子补丁');

    const result = applyRemotePatch(root);
    assert.equal(result, 'applied', 'settings/白名单已满足，workspace 子补丁应实际应用');

    const ws = readFileSync(
      path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-workspace', 'lib', 'client.js'),
      'utf8',
    );
    assert.ok(!ws.includes('if (normalizedQuery !== "") return;'), '旧粘滞行为（query 非空直接 return）已移除');
    assert.ok(ws.includes('remoteSearch.status !== "loading"'), '已注入无结果自动收起逻辑');
    assert.ok(ws.includes('remoteSearch,'), 'click-outside effect 依赖数组已补 remoteSearch（防闭包过期）');
    // v2 搜索框自动填充加固：search 类型 + 折叠态只读 + 密码管理器忽略标记。
    assert.ok(ws.includes('autoComplete: "search"'), '搜索框已改为 search autocomplete');
    assert.ok(ws.includes('dshpw-session-search'), '搜索框已注入中性 name，摘掉用户名框资格');
    assert.ok(ws.includes('data-dshpw-autofill-harden'), '搜索框已注入 v2 自动填充加固标记');

    const after = patchStatus(root);
    assert.equal(after.workspaceSearch, true, '状态检测为已打');

    // 幂等：再跑一次必须 unchanged
    const again = applyRemotePatch(root);
    assert.equal(again, 'unchanged', '幂等：二次应用不再改动');
  } finally {
    cleanup();
  }
});

test('补丁：workspace 目标文件缺失时不失败（可选子补丁，1/2 不受影响）', () => {
  // 不传 workspaceContent → 文件不存在；settings 未打 → applied 仅由 settings 驱动
  const { root, cleanup } = makeDshRoot(RC7_APIPROXY, RC7_SETTINGS_UNPATCHED);
  try {
    const result = applyRemotePatch(root);
    assert.notEqual(result, 'missing', 'workspace 文件缺失不应报 missing');
    assert.equal(result, 'applied', 'settings 子补丁仍正常应用');

    const st = patchStatus(root);
    assert.equal(st.workspaceSearch, false, '缺失按未打处理');
    assert.equal(st.settingsHostMode, true, 'settings host 模式已打');
  } finally {
    cleanup();
  }
});
