# xingliu-harness

xingliu 一人公司 IM harness — 基于 dsh-passwords 二开，集成 xingliu-plus-uniapp Ruoyi 认证与对话存储。

## 架构

```
xingliu-harness (网关)
  ├── auth: 委托 xingliu-plus-uniapp (/auth/login, Sa-Token)
  ├── 会话存储: 调 xingliu-plus-uniapp (/dsh/session/*)
  ├── 反向代理: dsh web 实例
  └── 多租户: 基于 xingliu-plus-uniapp 用户体系
```

## 快速开始

```bash
pnpm install
pnpm build
pnpm start
```

## 环境变量

|变量|说明|默认值|
|---|---|---|
|`PORT`|网关端口|3080|
|`DSH_PORT`|dsh web 端口|3090|
|`PLUS_API`|xingliu-plus-uniapp API 地址|http://localhost:8080|
|`DEEPSEEK_API_KEY`|DeepSeek API 密钥|—|

## 许可证

GPL-3.0-only