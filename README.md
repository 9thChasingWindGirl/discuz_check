# Discuz 类论坛每日签到

基于 Discuz! 类论坛的每日签到脚本,通过 **GitHub Actions 定时运行**,实现签到、自动补签、签到信息获取与邮件通知。支持**账号密码登录优先、Cookie 兜底**,并自动探寻可用的镜像分流域名。

## 功能

- ✅ 每日定时签到(自动选择最快可用域名)
- ✅ 自动检测断签并补签
- ✅ 签到信息(连续天数 / 总签到 / 等级 / 奖励)
- ✅ 邮件通知(签到成功后发送报告)
- ✅ 账号密码登录(优先),失效时自动用 Cookie 兜底
- ✅ 分流域名自动探寻(抓取论坛首页提取域名线索,与种子域名合并)

## 目录结构

```
.
├── sijishe_sign.py          # 核心脚本(签到/补签/登录/域名探寻/邮件)
├── sijishe_api.py           # JSON 输出 API(供 GitHub Actions 调用,无交互)
├── requirements.txt         # 依赖(仅 requests)
├── .gitignore               # 排除运行时配置与日志
└── .github/workflows/
    └── sign.yml             # 定时签到工作流
```

## 设计说明:配置直接来自 Secrets / Variables

脚本原生支持 **环境变量配置模式**:workflow 在 job 级将 Secrets / Variables 直接注入为 `SJS_*` 环境变量,脚本检测到后:

- 配置**完全由环境变量构建**(账号、Cookie、SMTP、种子域名),**不读写本地配置文件**
- 整个签到链路(登录→域名探寻→签到/补签→邮件)在**单次进程内、内存中**完成,不生成 `sijishe_config.json`
- 日志仅输出到 Actions 控制台,**不写日志文件**

本地运行时(无 `SJS_*` 环境变量)才回退到原有的本地配置文件模式。

## GitHub 仓库配置

所有配置均通过仓库 **Settings → Secrets and variables → Actions** 注入,仓库内不保存任何配置样例。

### Secrets(敏感信息)

| Secret | 说明 |
|---|---|
| `SJS_USERNAME` | 论坛账号(主认证) |
| `SJS_PASSWORD` | 论坛密码 |
| `SJS_COOKIE` | 备用 Cookie(账号密码登录失败时兜底) |
| `SJS_GH_TOKEN` | (可选)GitHub PAT,用于将域名列表写回仓库 Variable。二选一:**fine-grained PAT**(Repository access 含本仓库,Permissions → Actions 勾选 **Read and write**)或 **classic PAT**(勾选 `repo` scope) |
| `SJS_SMTP_HOST` | SMTP 服务器(默认 smtp.qq.com) |
| `SJS_SMTP_PORT` | SMTP 端口(默认 465) |
| `SJS_SMTP_SSL` | 是否 SSL(true/false) |
| `SJS_SMTP_SENDER` | 发件邮箱 |
| `SJS_SMTP_PASSWORD` | SMTP 授权码 |
| `SJS_SMTP_RECEIVERS` | 收件邮箱(多个用逗号分隔) |

### Variables(非敏感配置)

| Variable | 说明 |
|---|---|
| `SJS_DOMAINS` | **必需**。种子域名列表,逗号分隔,供域名自动探寻合并使用(如 `example.com,example.net`)。脚本**不再内置任何硬编码域名** |

> `SJS_DOMAINS` 是签到的基础(域名探寻的种子)。未配置时脚本会报错"未配置 SJS_DOMAINS 或所有域名均不可达"。

### 域名列表的自动更新(写回)

每次运行 `sign` 后,工作流会把**本次探寻到的可用域名列表写回仓库 Variable `SJS_DOMAINS`**(通过 GitHub REST API `PATCH /actions/variables/SJS_DOMAINS`),因此:

- 种子域名只需配置一次,后续每次运行都会用最新探寻结果作为下一轮种子
- 域名被探寻自动维护,**无需手动更新 Variable**(除非初始配置或全部域名失效)
- **公开仓库中 `GITHUB_TOKEN` 无法写 repository variables**,需配置 Secret `SJS_GH_TOKEN` 写回才能生效;未配置则写回仅告警跳过,**不影响签到**
- `SJS_GH_TOKEN` 配置要求:
  - **fine-grained PAT**:Repository access 选择包含本仓库,Permissions → Repository permissions → **Actions: Read and write**(仅 Read 不够)
  - **classic PAT**:勾选 **`repo`** scope
  - 若写回仍报 `403 Resource not accessible by personal access token`,即 PAT 权限不足,请按上述要求重新创建
- 变量不存在时工作流会自动创建;写回失败仅告警,不阻断签到结果

### 认证方式说明

签到报告会明确标注本次使用的认证方式:

- **账号密码 (`用户名`)**:账号密码登录成功(优先)
- **存量 Cookie**:账号密码未配置或登录失败,回退使用 Cookie

## 运行方式

### GitHub Actions(默认)

工作流 `sign.yml` 已配置:

- **定时**:`cron '0 16 * * *'`(UTC 16:00 = 北京时间每日 00:00)
- **手动触发**:仓库 Actions 页面 → 选中 workflow → Run workflow

手动运行时可选 **mode** 输入:

| mode | 行为 |
|---|---|
| `sign`(默认) | 执行完整签到并发送邮件(账号密码登录 → 域名探寻 → 签到/补签 → 邮件) |
| `send_mail` | **仅发送邮件(调试)**:读取当日缓存签到结果,邮件内容注明"来自缓存,非本次实时签到",不执行签到 |

### 签到结果缓存

- 每次 `sign` 执行后,当日签到结果(状态/报告/域名)写入缓存 `sijishe_cache.json`(经 workflow cache 持久化)
- **覆盖规则**:签到成功状态总是覆盖旧缓存;签到失败**不覆盖**当日已有的成功缓存(避免失败结果冲掉当日成功记录)
- 调试邮件(`send_mail` 模式)使用缓存中的最近一次签到结果

每次运行流程:

1. job 级环境变量注入 Secrets / Variables(`SJS_*`)
2. `python sijishe_api.py sign` — 单次调用完成:账号密码登录(失败回退 Cookie)→ 域名自动探寻 → 签到/补签 → 邮件通知
3. 输出 JSON(含探寻到的 `domains`)后,工作流将域名列表写回仓库 Variable `SJS_DOMAINS`,供下次运行作为种子
4. 签到结果写入缓存(供 `send_mail` 调试模式使用)
5. 全程内存内完成,不生成配置/日志文件;日志直接输出到 Actions 控制台,可在运行详情中查看

## 说明与注意事项

- **认证策略**:配置了账号密码时优先登录刷新 Cookie;登录失败或未配置账号时回退使用存量 Cookie。
- **域名自动探寻**:以种子域名为起点抓取论坛首页,提取镜像域名线索后做延迟探测与论坛特征校验,仅保留可访问的镜像域名;种子域名始终保留。
- **状态持久化**:GitHub Actions runner 每次运行是全新环境,`last_sign` / `preferred_domain` 缓存每次重建,因此每天签到成功即发送一封邮件;如需跨天去重可自行改用 Actions cache 持久化状态文件。
- **境外网络**:GitHub runner 位于境外,若论坛对境外 IP 有风控或 Cloudflare 挑战,可能导致登录/签到失败,请在手动触发一次确认可用后再依赖定时任务。
