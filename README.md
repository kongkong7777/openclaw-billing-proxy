# OpenClaw Billing Proxy（kongkong7777 Fork · 中文版）

让第三方 AI 客户端（OpenClaw / LobeChat / NextChat / Hermes 等）复用 Claude Max/Pro 套餐内额度，同时接通 OpenAI / Gemini / Codex / Kimi 等多厂商模型池。

**本 Fork 专为与 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 串接的 Plan B 架构优化**。独立部署（直连 api.anthropic.com）也能跑，但诸多细节是按"串接"假设设计的。

---

## 零、这个 Fork 跟上游有什么不同

三句话总结：
1. **不再直连 Anthropic**，下游改走 CLIProxyAPI 的 `127.0.0.1:18801`，由 CLIProxyAPI 负责 OAuth 账号池、CCH 签名、HTTP header 级 CC 指纹重建
2. **职责边界清晰**：本 proxy 只做 **body 层**的伪装与修复；HTTP header 层（`User-Agent` / `X-Stainless-*` / `Anthropic-Beta` / 会话 ID / CCH 签名）**完全交给 CLIProxyAPI**
3. **吸收了 opencode-claude-auth 的 body-level 修复**（见[版本历史](#版本历史)），例如非 CC 工具名加 `mcp_` 前缀、Haiku 的 `effort` 参数剥离、孤立 `tool_use`/`tool_result` 修复、billing 文本块里用真 SHA256 替代硬编码 `cch=00000` 等

---

## 一、Plan B 架构总览

```
                   ┌───────────────────────────┐
                   │  客户端                   │
                   │  (OpenClaw / LobeChat /   │
                   │   NextChat / Hermes 等)   │
                   └──────────────┬────────────┘
                                  │  HTTPS
                                  ▼
              ┌─────────────────────────────────────┐
              │  Nginx :443 (TLS 终结 + 路由)       │
              └──┬──────────────────────────┬───────┘
                 │ /v1/messages*            │ /v1/chat/completions
                 │ (Claude 原生格式)         │ /v1/responses
                 │                          │ (OpenAI 兼容格式)
                 ▼                          ▼
         ┌───────────────────┐       ┌───────────────────┐
         │  billing-proxy    │       │  CLIProxyAPI      │
         │  :18804           │       │  :18801           │
         │                   │       │                   │
         │  ◆ body-level     │       │  ◆ OAuth 账号池    │
         │    伪装 10 层     │       │    (3 Claude +    │
         │  ◆ 发往           │──────▶│     2 Codex + …)   │
         │    CLIProxyAPI     │       │  ◆ HTTP header     │
         │    :18801         │       │    CC 指纹重建     │
         └───────────────────┘       │  ◆ CCH 签名        │
                                     │  ◆ 多厂商路由      │
                                     └─────────┬─────────┘
                                               │
                                               ▼
                                    ┌──────────────────────┐
                                    │ api.anthropic.com    │
                                    │ api.openai.com       │
                                    │ Google Vertex/AI…    │
                                    └──────────────────────┘
```

**关键点：Anthropic 收到的**：
- **body 内容**（messages / tools / system 的文本和结构）→ 完全由 billing-proxy 决定
- **HTTP 请求头**（UA / Stainless / Beta / 会话 / CCH）→ 完全由 CLIProxyAPI 决定

---

## 二、billing-proxy 实际在做什么

以下是所有**真实生效**的 body-level 变换：

| Layer | 作用 | 对应 Anthropic 检测 |
|-------|------|---|
| **0. Anthropic 内置工具版本化** | `{"type":"web_search"}` → `{"type":"web_search_20260209"}` 等 8 条 shorthand → versioned 映射（web_search / web_fetch / text_editor / code_execution / bash / memory / tool_search_tool_bm25 / tool_search_tool_regex）。**这些内置工具不经 Layer 3 重命名**，否则会跟 `type` 字段机制冲突触发 400 | Anthropic 内置工具接入 |
| **1. Billing 文本块注入** | 在 system 数组插入 `x-anthropic-billing-header: cc_version=<ver>.<fp>; cc_entrypoint=cli; cch=<sha256[:5]>;` 文本 | telemetry/指纹 |
| **2. 关键词替换** | 40 组对称 sanitize（OpenClaw→OCPlatform / LobeChat→Driftwave / NextChat→Swiftline 等） | 品牌关键词扫描 |
| **2.5. Haiku `effort` 剥离** | 侦测 Haiku 模型 → 剥掉 `output_config.effort` 和 `thinking.effort` | Haiku 对 effort 参数返 400 |
| **3. 工具名重写** | 37 条 rename：CC 官方工具映射到 PascalCase（`read`→`Read`、`write`→`Write` 等），非 CC 工具加 `mcp_` 前缀（`pdf`→`mcp_PdfParse`、`music_generate`→`mcp_MusicCreate` 等）。**故意排除** `web_search` / `web_fetch` / `image` —— 这三个是 Anthropic 内置 `type` 标签，重命名会导致 `Input tag 'WebSearch' ... does not match expected tags` 400（详见 commit `ee0a591`） | 工具名集合指纹 |
| **4. System prompt 剥离** | 删除 OpenClaw 配置段（~28K 字符 tooling/workspace/messaging 模板），替换为简短自然语言 | 系统模板签名 |
| **5. CC_TOOL_STUBS 注入** | 在 tools 数组追加 `mcp_Glob` / `mcp_Grep` / `mcp_Agent` / `mcp_NotebookEdit` / `mcp_TodoRead` 5 条假工具，带 case-insensitive 去重 | 工具集对比 CC 基线 |
| **6. 属性名重写** | `session_id`→`thread_id` / `conversation_id`→`thread_ref` 等 8 条 | schema 属性指纹 |
| **8. 尾部 prefill 剥离** | 去掉非 CC 客户端的 trailing assistant prefill | Opus 4.6+ 兼容 |
| **count_tokens 本地拦截** | `/v1/messages/count_tokens*` 在 billing-proxy 入口直接返回启发式估算（text × 0.3 + 5%），**不发上游**，零计费 | 避免 extra usage 扣费 |
| **文件路径保护** | Layer 2 执行前用 NUL 占位符保护所有文件系统路径（Unix/Win 都支持），防止 `/home/user/.openclaw` 被替换成 `/home/user/.ocplatform` | issue #29 ENOENT |
| **thinking block 保护** | mask/unmask `thinking` 和 `redacted_thinking` content block，避免 reverseMap 破坏 byte-exact 签名 | PR #28 / issue #45 |
| **prompt caching 注入** | 未显式设置 `cache_control` 的客户端，自动在 tools/system 末尾加 ephemeral 断点（5 分钟 TTL，0.1× 输入成本）| 省钱，实测命中率 ~87% |
| **孤立 tool block 修复** | 清理无配对的 `tool_use` / `tool_result`，保守处理相邻同 role 消息 | issue #34 |

---

## 三、"僵尸代码"说明

在 Plan B 架构下，以下代码**仍然保留**在 `proxy.js`，但**实际不发挥作用**（被下游 CLIProxyAPI 覆盖）：

| 代码段 | 不起作用的原因 |
|---|---|
| `REQUIRED_BETAS` 数组 | 我们的 beta header 注入是注释掉的（见 `headers['anthropic-beta'] = ...;` 所在处）。CLIProxyAPI 的 `applyClaudeHeaders()` 用自己硬编码的 baseBetas（含 `fast-mode-2026-02-01` 等 9 条）。要改 betas 必须改 CLIProxyAPI。 |
| `getModelBetas(model)` | 调用后结果没写入 header/body，纯摆设。 |
| `getStainlessHeaders()` | 注入的 `x-stainless-*` 会被 CLIProxyAPI 的 `misc.ScrubProxyAndFingerprintHeaders()` 全部 del，然后由 `applyClaudeHeaders` 按 CLIProxyAPI 的 device profile 重新设置（默认 PackageVersion=0.74.0）。 |
| `user-agent: claude-cli/<VER>` 注入 | 同上，被 CLIProxyAPI 的 device profile 覆盖。 |

保留原因：零代码负担、方便对比 upstream 变化、万一某天不走 CLIProxyAPI 还能独立兜底。

**想改 HTTP header 层的伪装？去改 CLIProxyAPI。本仓库只管 body。**

---

## 四、部署

### 4.1 前置要求

- Linux 服务器（脚本以 Ubuntu/Debian 为例）
- Node.js 18+
- **[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)** 已部署并运行于 `127.0.0.1:18801`，至少配置一个 Claude OAuth 账号
- Nginx 或类似 TLS 终结层（可选，但推荐）

### 4.2 CLIProxyAPI 配置关键项

在 CLIProxyAPI 的 `~/.cli-proxy-api/config.yaml` 里，**至少**需要：

```yaml
port: 18801
tls:
  enable: false          # 由 nginx 做 TLS 终结
debug: true              # 打开 debug 日志（claude-watchdog 依赖这一点）

experimental-cch-signing: true    # 必须开启（OAuth 默认也会开）

api-keys:
  - "sk-YourCustomKey"   # 客户端 → 本代理用的 key

# OAuth Claude 账号池（至少 1 个）
# 用 CLIProxyAPI 自带 CLI 登录后会在 ~/.cli-proxy-api/ 生成 claude-*.json
# 账号池文件自动发现，不用显式列出

# OpenAI / Gemini / Codex 账号池按需配置
```

详见 [CLIProxyAPI 官方文档](https://github.com/router-for-me/CLIProxyAPI#configuration)。

### 4.3 billing-proxy 部署

```bash
git clone https://github.com/kongkong7777/openclaw-billing-proxy.git
cd openclaw-billing-proxy

# 创建 config.json（下游地址指向 CLIProxyAPI）
cat > config.json <<'EOF'
{
  "port": 18804,
  "upstreamHost": "127.0.0.1",
  "upstreamPort": 18801,
  "upstreamProtocol": "http",
  "authMode": "x-api-key",
  "apiKey": "sk-YourCustomKey",
  "stripToolDescriptions": true,
  "injectCCStubs": true,
  "stripTrailingAssistantPrefill": true
}
EOF

# 测试启动
node proxy.js

# 应看到日志
# [INFO] Proxy listening on :18804
# [INFO] Forwarding to http://127.0.0.1:18801
```

### 4.4 Systemd 服务

`/etc/systemd/system/billing-proxy.service`:

```ini
[Unit]
Description=OpenClaw Billing Proxy (Plan B chain)
After=network.target cliproxyapi.service
Requires=cliproxyapi.service

[Service]
Type=simple
User=apiadmin
WorkingDirectory=/home/apiadmin/openclaw-billing-proxy
ExecStart=/usr/bin/node proxy.js
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now billing-proxy
sudo systemctl status billing-proxy
```

### 4.5 Nginx 路由配置

```nginx
# Claude 原生格式 → billing-proxy（走 body-level 伪装）
location /v1/messages {
    proxy_pass http://127.0.0.1:18804;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_buffering off;
    proxy_http_version 1.1;
    proxy_read_timeout 600s;
    proxy_send_timeout 600s;
}

# OpenAI 兼容格式（GPT / Gemini / 跟 Claude 无关的路径）→ 直连 CLIProxyAPI
# 不走 billing-proxy，因为我们的 body 变换是 Claude 专用
location /v1/chat/completions { proxy_pass http://127.0.0.1:18801; }
location /v1/responses        { proxy_pass http://127.0.0.1:18801; }

# 管理面板
location /management.html { proxy_pass http://127.0.0.1:18801; }
location /v0/             { proxy_pass http://127.0.0.1:18801; }

# 兜底：其他走 CLIProxyAPI
location / { proxy_pass http://127.0.0.1:18801; }
```

### 4.6 客户端配置

统一用一个 API key，两种接口格式都支持：

```bash
# OpenAI 兼容（多数客户端的默认）
export ANTHROPIC_BASE_URL=https://your.domain/
export ANTHROPIC_AUTH_TOKEN=sk-YourCustomKey

# Anthropic 原生（Claude Code 等）
curl https://your.domain/v1/messages \
  -H "x-api-key: sk-YourCustomKey" \
  -H "anthropic-version: 2023-06-01" \
  -d '{"model":"claude-opus-4-6","max_tokens":500,"messages":[...]}'
```

---

## 五、工具名映射表

### ⚠️ 三类工具的不同处理

proxy.js 对工具做**三类不同**处理，搞混会导致 Anthropic 返回 400：

| 类别 | 举例 | 处理方式 | 对应 Layer |
|---|---|---|---|
| **Anthropic 内置工具** | `web_search` / `web_fetch` / `text_editor` / `code_execution` / `bash` / `memory` / `tool_search_tool_bm25` / `tool_search_tool_regex` | **绝不重命名**！只做 `type` 字段的 shorthand → versioned 映射（如 `web_search` → `web_search_20260209`） | Layer 0 |
| **CC 原生工具（客户端用的）** | `read` / `write` / `edit` / `grep` / `glob` / `ls` / `exec` / `process` / ... | 重命名到 PascalCase（`Read` / `Write` / `Bash` 等，无前缀） | Layer 3 |
| **非 CC 的 MCP 工具** | `pdf` / `image_generate` / `music_generate` / `memory_search` / `lcm_*` / `yield_task` / ... | 重命名 + `mcp_` 前缀（如 `pdf` → `mcp_PdfParse`） | Layer 3 |

**关键规则**：Anthropic 内置工具（第一类）用 `type` 字段在 API 里做版本识别，如果我们还把 `"web_search"` 重命名成 `"WebSearch"`，Anthropic 会返回：

```
tools.N: Input tag 'WebSearch' found using 'type' does not match
any of the expected tags: 'web_search_20250305', 'web_search_20260209', ...
```

同理 `image` 类型内容块的 `type: "image"` 也会被误替，在 tool_result 里渲染的图会报 400（issue #14）。这些工具**从 `DEFAULT_TOOL_RENAMES` 里显式排除**，见 proxy.js 里的 NOTE 注释。

### 表一：Anthropic 内置工具（Layer 0 版本化，不改名）

| 客户端可发送的 shorthand | Layer 0 映射为（发给 Anthropic） |
|---|---|
| `web_search` | `web_search_20260209` |
| `web_fetch` | `web_fetch_20260309` |
| `text_editor` | `text_editor_20250728` |
| `code_execution` | `code_execution_20260120` |
| `bash` | `bash_20250124` |
| `memory` | `memory_20250818` |
| `tool_search_tool_bm25` | `tool_search_tool_bm25_20251119` |
| `tool_search_tool_regex` | `tool_search_tool_regex_20251119` |

版本号跟随 Anthropic 官方更新；以 API 返回的 expected tags 为准。

### 表二：CC 原生工具（无 `mcp_` 前缀）

| 原始 | 映射为 |
|---|---|
| exec | Bash |
| process | BashSession |
| browser | BrowserControl |
| canvas | CanvasView |
| cron | Scheduler |
| message | SendMessage |
| tts | Speech |
| gateway | SystemCtl |
| agents_list | AgentList |
| create_task | TaskCreate |
| list_tasks | TaskList |
| get_history | TaskHistory |
| send_to_task | TaskSend |
| subagents | AgentControl |
| session_status | StatusCheck |
| read / write / edit / grep / glob / ls | Read / Write / Edit / Grep / Glob / LS |

### 表三：非 CC 的 MCP 工具（带 `mcp_` 前缀，PR #48 引入）

| 原始 | 映射为 |
|---|---|
| pdf | mcp_PdfParse |
| image_generate | mcp_ImageCreate |
| music_generate | mcp_MusicCreate |
| video_generate | mcp_VideoCreate |
| memory_search | mcp_KnowledgeSearch |
| memory_get | mcp_KnowledgeGet |
| lcm_expand_query | mcp_ContextQuery |
| lcm_grep | mcp_ContextGrep |
| lcm_describe | mcp_ContextDescribe |
| lcm_expand | mcp_ContextExpand |
| yield_task | mcp_TaskYield |
| task_store | mcp_TaskStore |
| task_yield_interrupt | mcp_TaskYieldInterrupt |

另外注入 5 条假 CC 工具：`mcp_Glob` / `mcp_Grep` / `mcp_Agent` / `mcp_NotebookEdit` / `mcp_TodoRead`。`mcp_` 前缀告诉 Anthropic 这是"用户 MCP 工具"，不参与 CC 官方工具名匹配。

---

## 六、关键词替换（Layer 2，双向）

| 原始 | 替换为 |
|---|---|
| OpenClaw / openclaw | OCPlatform / ocplatform |
| LobeChat / lobechat | Driftwave / driftwave |
| LobeHub / lobehub | Driftgate / driftgate |
| NextChat / nextchat | Swiftline / swiftline |
| `ChatGPT-Next-Web` | `Swiftline-Web` |
| `x-anthropic-billing-header` | `x-meter-token` |
| `x-anthropic-billing` | `x-meter-id` |
| `cch=00000` | `mtx=00000` |
| `cc_version` / `cc_entrypoint` | `mtx_version` / `mtx_entrypoint` |
| `billing proxy` / `billing-proxy` | `metering bridge` / `metering-bridge` |
| `extra usage` | `spare allowance` |
| `assistant platform` | `tessera runtime` |
| `sessions_spawn` / `sessions_list` / ... | `create_task` / `list_tasks` / ... |
| `HEARTBEAT_OK` | `HB_ACK` |

共 40 条对称映射，响应返回时自动反向还原，客户端无感知。

---

## 七、属性重命名（Layer 6）

| 原始属性 | 替换为 |
|---|---|
| session_id | thread_id |
| conversation_id | thread_ref |
| summaryIds / summary_id | chunk_ids / chunk_id |
| system_event | event_text |
| agent_id | worker_id |
| wake_at / wake_event | trigger_at / trigger_event |

---

## 八、故障排查

**1. 检查整条链路是否通**

```bash
# 1. CLIProxyAPI 活着？
curl http://127.0.0.1:18801/v1/models -H "Authorization: Bearer sk-YourCustomKey" | head

# 2. billing-proxy 活着？
curl http://127.0.0.1:18804/v1/messages \
  -H "x-api-key: sk-YourCustomKey" \
  -H "anthropic-version: 2023-06-01" \
  -d '{"model":"claude-opus-4-6","max_tokens":20,"messages":[{"role":"user","content":"ping"}]}'

# 3. nginx 终结层活着？
curl -k https://your.domain/health
```

**2. 常见症状**

| 症状 | 可能原因 |
|---|---|
| `unknown provider for model claude-opus-4-7` | CLIProxyAPI 版本太旧，需要升级以加入新模型 |
| `Tool names must be unique` (400) | 客户端自带工具跟 CC_TOOL_STUBS 重名，升级到带 case-insensitive 去重的版本 |
| 429 Extra Usage 增加 | 检查 `experimental-cch-signing` 是否开启；检查 Haiku 模型是否被发 effort 参数 |
| `out of extra usage` 账号被拉黑 | 单独账号被限流，用 [claude-watchdog](../claude-watchdog)（配套 sidecar）自动降级 |
| 客户端 15 秒 timeout | 非 SSE 响应 heartbeatfix 确认生效（本 Fork 已内置） |

---

## 九、版本历史

| 版本/提交 | 日期 | 变更 |
|---|---|---|
| PR #48 port | 2026-04-21 | 移植 opencode-claude-auth 的 5 项 body-level 修复：`mcp_` 前缀（non-CC tools + stubs）、真 SHA256 CCH（替代 `cch=00000`）、Haiku `effort` 剥离、`repairToolPairs` 孤立 tool block 修复、Stainless SDK 版本升到 0.90.0（header 层，Plan B 下被 CLIProxyAPI 覆盖） |
| Plan B 改造 | 2026-04-09 | `upstreamHost` 改为 `127.0.0.1:18801/http/x-api-key`；禁用 Anthropic-Beta header 注入以让 CLIProxyAPI 负责；禁用 cache_control 注入（后续又加回，因 CLIProxyAPI 不做 body 层注入）|
| v2.2.4 | 2026-04-10 | 系统 prompt 边界用文件系统路径而不是 AGENTS.md（closes #26）|
| PR #28 集成 | 2026-04-08 | thinking/redacted_thinking block 保护（mask/unmask）|
| 本 Fork 独有 | 2026-04-09 起 | `count_tokens` 本地拦截、文件路径保护、prompt caching 注入、heartbeatfix（PR #40）|

---

## 十、License & 致谢

MIT License. 基于 [zacdcook/openclaw-billing-proxy](https://github.com/zacdcook/openclaw-billing-proxy)，body-level 修复思路借鉴 [griffinmartin/opencode-claude-auth](https://github.com/griffinmartin/opencode-claude-auth) v1.4.10 (PR #48)。

**配套 sidecar**（不在本仓库，单独部署）：

- `billing-logger` — 流量抓取 + SQLite 持久化 + Web 仪表盘（`/traffic-dashboard`），支持客户端 IP 筛选、按 upstream 筛选、全文搜索
- `claude-watchdog` — 监听 CLIProxyAPI debug 日志，遇到账号被 rate-limit 自动降 priority，30 分钟后恢复

这俩沿用 Plan B 架构的上下文，跟本 proxy 一起形成完整的 `nginx → logger → billing-proxy → CLIProxyAPI → Anthropic` 链路。
