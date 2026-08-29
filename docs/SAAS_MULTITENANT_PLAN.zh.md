# dsh-passwords 多用户套餐收费 SaaS 方案

> 目标：把 DeepSeek Harness 做成「多个用户各自使用、按套餐收费」的 SaaS 功能。
> 基座：`dsh-passwords` v2.6.5（`reference/dsh-passwords`），宿主 dsh。
> 版本基线：dsh `0.1.1-rc.2`（插件编译目标）。当前 upstream master 为 `0.1.2-alpha.1`（pre-release，有破坏性变更风险）。

---

## 一、基座现状（dsh-passwords 已具备，可直接复用）

| 能力 | 实现 | 位置 |
|---|---|---|
| 多用户登录 | `users` 表（username/password_hash/role）+ 登录防暴力（`login_attempts`/`ip_throttle`） | `src/db.ts` `src/auth.ts` |
| 每用户权限 | `user_permissions` 行；缺行=默认全量 | `db.ts` |
| 每用户用量记账 | `user_usage` 按天（`active_seconds`、`hourly_tokens`） | `db.ts` |
| 会话按用户隔离 | `user_session_grants` 授权表 + WebSocket 事件帧 fail-closed 过滤 | `db.ts` `gateway.ts:970-1093` |
| 进程级沙箱 | `sandbox_mode`（read-only/workspace-write/danger-full-access）→ dsh `ctx.sandbox`；网关命令级 403 审计 | `gateway.ts:3301-3323` `plugin.ts:864-897` |
| 读隔离 | `allowed_folders` 工作区白名单 + DSH_HOME 敏感路径屏蔽 | `gateway.ts:1696` |
| 审计 | `audit_logs`（事件/用户/IP/UA/详情） | `db.ts` |
| HTTPS | ACME 自动签发 + 续期热加载 | `src/acme.ts` |
| 站内消息 | `messages`（admin→user 广播/私信） | `db.ts` |
| 设置/更新 | 设置页卡片、补丁重载、自更新（含回滚） | `src/update.ts` |

### 一套「套餐」可直接映射的权限字段（`user_permissions`）

| 字段 | 语义 | 套餐卖点 |
|---|---|---|
| `allowed_agent_presets` | `NULL`=不限；`[]`=全禁；数组=白名单 | 高档解锁更多 agent preset |
| `hourly_token_limit` / `daily_minutes_limit` | 每时段用量上限；`NULL`=不限 | 低档限流，高档无限 |
| `allowed_folders` | 工作区目录白名单 | 档位决定能访问的目录 |
| `allow_workspace_create` / `allow_upload` / `allow_git_download` | 建工作区 / 传图 / git 克隆 | 能力边界 |
| `sandbox_mode` | `read-only`/`workspace-write`/`danger-full-access` | 安全强度（危险档勿开给用户） |
| `banned` | 封禁 | 停用 |
| `disabled_sessions` | 逐会话关闭 | 粒度控制 |

---

## 二、缺口（基座没有，需二开）

1. **套餐抽象（plans）**：缺少「一组权限字段 = 一个档位」的模板化与按档位分配。
2. **计费/订阅**：无支付、升降级、用量结算、催费。
3. **（可选）per-user 环境级隔离**：当前是「同世界进程沙箱」，不是「每用户独立容器」。
4. **方案落地前置**：`dsh-passwords` 对 dsh `0.1.2-alpha.1` 有 2 个真实变数（见风险）。

---

## 三、方案 A：plans 套餐层（成本小，先做，能收费）

**核心思路：套餐 = `user_permissions` 模板 + `user_usage` 阈值。**

### 1. 新增 `plans` 表 + `users.plan_id`

```sql
CREATE TABLE plans (
  id                 INTEGER PRIMARY KEY,
  name               TEXT NOT NULL,          -- 免费版 / Pro / 尊享
  price_cents        INTEGER NOT NULL,       -- 按月，单位分
  currency           TEXT NOT NULL DEFAULT 'CNY',
  permissions_json   TEXT NOT NULL,          -- 一份 user_permissions 模板
  hourly_token_limit INTEGER,                -- NULL=不限（覆盖 user_permissions）
  daily_minutes_limit INTEGER,
  sandbox_mode       TEXT,                   -- read-only / workspace-write / danger-full-access
  max_concurrent_sessions INTEGER DEFAULT 1, -- 档位并发会话数
  max_days           INTEGER,                -- 试用期天数
  active             INTEGER NOT NULL DEFAULT 1,
  created_at         TEXT NOT NULL DEFAULT (datetime('now'))
);
-- users 增加 plan_id 与 plan_expires_at
-- ALTER TABLE users ADD COLUMN plan_id INTEGER;
-- ALTER TABLE users ADD COLUMN plan_expires_at TEXT;  -- 到期自动降级
```

### 2. 套餐 → 用户生效（落成 `user_permissions`）

- 用户创建/登录/购买时，把 `plans.permissions_json` 模板**落成该用户的 `user_permissions` 行**（现有 `setPermissions` 复用）。
- 手动调整：管理员改某用户权限时直接覆盖该行（缺行=全量权限，高价值用户不受模板约束）。
- `sandbox_mode` 一并按套餐写入。

### 3. 用量熔断

- 网关校验：`user_usage.hourly_tokens > plans.hourly_token_limit` → 返回 429 / 暂停该 user（`banned` 临时）。
- 每日对照 `daily_minutes_limit`，超额提醒升级或降级。
- 结算：按 `user_usage` 记账，套餐到期校准。

### 4. 计费（MVP → 完整）

- **MVP（先跑通）**：后台手动分配套餐 + 邀请码 / 充值余额，`users.plan_id` 直接设置。可对外收费（人工收款）。
- **进阶**：接支付（Stripe / 支付宝 / 微信），回调置 `plan_id` + `plan_expires_at`；提供「升级/降级」接口；到期自动降级到免费档。

### 5. 后台/设置页

- 复用 dsh-passwords 设置页卡片（仅主用户）：新增「套餐管理」——建套餐、给子用户分配/调档、看用量与到期。

### 工作量（方案 A）

- 表 + 后端（创建/绑定/熔断/到期降级）
- 一个套餐管理设置页
- 计费回调（进阶）

**评级：小~中。** 在 `plans` 表抽象清楚后，机械度高；是最快能收费的路径。

---

## 四、方案 B：e2b per-user 环境级隔离（phase 2，安全增强）

> 若只需要「用户任务互不越权」——方案 A + 现有 `sandbox_mode`/`allowed_folders`/命令级 403 **已够用**。
> 若需要「每个用户独立容器/VM，任务完全物理隔绝」——上 e2b。

### 关键矛盾

- dsh 自带 e2b（`packages/e2b`：`e2b`/`subprocess-e2b`/`fs-e2b`）是**进程级单沙箱**（`Shared ownership of one E2B sandbox`），替换 `ctx.subprocess`/`ctx.fs`——**不是** per-user，也**不消费** `ctx.sandbox`/`sandbox/mode` 分层。
- dsh-passwords 的 `sandbox_mode` 是**会话级同世界权限**。
- → 要把两者接起来，实质是「把 e2b 改造成 per-user 执行器 + 用 dsh scope 做 per-session 绑定」。

### 最小改造四步

1. **e2b owner：单沙箱 → per-user 注册表**（`packages/e2b/e2b/src/index.ts`）
   - `Map<userId, Sandbox>`，每用户懒创建，按用户生命周期/注销/到期销毁。
   - 复用 `apiKey`（`E2B_API_KEY`）、`remoteWorkingDir`（可 per-user 改写）、`lifetime`。

2. **shell/fs provider：全局单例 → scope 感知分发**
   - 用 dsh `dsh-scope`（`createScope` + `scopeTarget`，支持「近者遮蔽远者」父链）把 `subprocess-e2b`/`fs-e2b` 按 **agent/session** 路由到该用户的沙箱；每用户独立 provider 实例。

3. **sandbox_mode → e2b 策略**
   - 复用 `dsh-passwords` 现有链路（`plugin.ts:864-897` 的 `/api/dsh-passwords/internal/sandbox` + 会话 append `sandbox/mode`）。
   - `read-only` → 沙箱内禁写文件工具；`workspace-write` → 沙箱内可写不暴露宿主；`danger-full-access` → 沙箱放通网络/工具。
   - 每用户沙箱创建时按 `sandbox_mode`（套餐）订策略；网关命令级 403 审计保留复用。

4. **生命周期与成本**
   - 每用户沙箱 `lifetime` 到期销毁、注销/降级销毁、并发沙箱上限（按套餐配额封顶）。
   - 接 `user_usage` 控制在线沙箱数与用量（e2b 是付费远程资源，必须限流）。

### 工作量与风险（方案 B）

- 改动面：`e2b` + `subprocess-e2b` + `fs-e2b` 三包 + `dsh-passwords` 授权链路 + 新增「用户→沙箱」生命周期管理。
- **评级：中~大。** 明显重于方案 A。
- **风险**：e2b 属官方 `POC`/`experimental`，接口可能随上游变；远程沙箱每次命令有异步初始化延迟（README 明示）；改前需锁版本并留意上游。

---

## 五、落地路线

| 阶段 | 内容 | 成本 |
|---|---|---|
| 0 | 锁 dsh 到 `0.1.1-rc.2`（`git tag dsh-v0.1.1-rc.2`） | 0 |
| 1 | 部署 dsh-passwords：多用户 + 权限 + `sandbox_mode` + `allowed_folders` + 配额 | 0（现成） |
| 2 | **方案 A：`plans` 套餐层** —— 表 + 后台分配 + 用量熔断 + 人工计费 | 小~中 |
| 3 | 自动计费（支付回调、升级/降级、到期降级） | 中 |
| 4 | **方案 B：e2b per-user 隔离**（合规/强隔离需求时） | 中~大 |

---

## 六、风险与坑

1. **版本漂移（最高风险）**：dsh 官方 pre-release 破坏兼容；`dsh-passwords` 的构建产物补丁靠**正则匹配 dsh `lib/*.js`**（`patch.ts` 的 `SETTINGS_FROM`/`BIND_ALL_FROM`/`SEARCH_*_RE` 等）。升级 dsh 后**必须 `node dist/cli.js patch status` 检查所有子补丁**——补丁会静默跳过（返回 `unchanged`/`missing`）且不报错，功能悄悄失效。收费系统最怕这个。
2. **`@deepseek-ai/dsh-host-apiproxy` 包已在 `0.1.2-alpha.1` 移除**：对应「插件命名空间进 settings 白名单」子补丁无法命中 → 第三方 settings 命名空间（含 dsh-passwords 自己的用户管理设置页）可能进不了白名单。功能降级（非崩溃）。
3. **mux WebSocket 帧协议未验证**：`gateway.ts:969` 的 `filterEventWebSocketFrame` 硬编码 rc.2 帧/事件名；通道名 `/api/remote.mux` 未变，但帧格式需实测（登录→子用户会话→工具调用走一遍）。
4. **同世界沙箱**：默认沙箱与宿主共享内核/文件系统；`danger-full-access` 用户能读全盘（含其他用户 DSH_HOME）——**不要给收费用户开 danger**。
5. **e2b 是 POC**：作为 per-user 隔离方案有上游不稳定风险；且为付费远程资源。
6. **合规**：多用户 + 对外收费，需自建用户数据备份/注销（GDPR 类）、凭证加密（`dsh-passwords` 用 AES-256-GCM，`MCP_DB_ENC_KEY`）、审计留存。

---

## 七、结论

- **先做方案 A（plans 套餐层）**：基座 `dsh-passwords` 已覆盖多用户/权限/配额/会话隔离/沙箱/审计，缺的只是「套餐模板 + 计费」。成本小，能最快对外收费。
- **方案 B（e2b per-user）作为 phase 2**：仅在需要「每用户独立容器」的强隔离/合规时上，成本中~大且 e2b 是 POC。
- **上线前**：锁 dsh `0.1.1-rc.2`；部署后实测 mux 帧；`patch status` 全程监控。
