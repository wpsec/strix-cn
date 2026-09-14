<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771932705094-c88426f2-74cc-4214-8f91-e3a4c8882279.png)

# Strix CN

Strix 开源 AI 渗透测试工具的中文维护分支。当前分支已合并上游 `v1.6.2`，默认中文体验，优先解决国内模型接入、Burp / Caido 工作流、受限网络兼容，以及本地源码扫描落地问题。

- 上游项目：[https://github.com/usestrix/strix](https://github.com/usestrix/strix)
- 当前分支：[https://github.com/wpsec/strix-cn](https://github.com/wpsec/strix-cn)

## 分支目标

- 完整吸收上游当前发布版的功能、修复和新架构
- 保留 `strix-cn` 既有的中文文档、中文提示和中文报告输出
- 保留 Burp / Caido 流量驱动的常规渗透测试工作流与本地模型、兼容网关适配
- 保留本地开发者熟悉的 CLI 入口、常用参数和恢复路径

## 当前版本重点

- 吸收上游 MCP server 支持（`~/.strix/mcp-servers.json` 配置，agent 按需调用）
- 新增 `--workspace-file` 把本地辅助文件注入沙箱 workspace
- 报告新增情境化 CVSS、反证 / 置信度闭环与 `update_vulnerability_report` 修订通道
- `LLM_API_BASE` 指向 Anthropic 协议端点时，裸模型名自动按 `/v1/messages` 路由
- 交互界面为上游 Go / Bubble Tea TUI；本地 Viewer 内置，无需额外前端安装
- 支持 `LLM_EXTRA_HEADERS`、`LLM_DISABLE_STREAMING`、`STRIX_REASONING_EFFORT=max`
- Web Search 支持 Exa 与 Perplexity，可通过配置选择 Provider；Exa 支持搜索结果摘要和页面全文抓取
- 支持通过 Vercel AI Gateway 接入多个模型 Provider
- 默认沙箱镜像基线 `ghcr.io/usestrix/strix-sandbox:1.3.0`；本地目录统一走挂载模式

## 使用注意

- 只能在你拥有或获得明确书面授权的目标上运行
- Burp/Caido 流量驱动模式下，不要一次性把整站大量接口流量导给 Strix；按功能点分批测试
- 对增删改类接口保持谨慎，不建议把高风险破坏性操作直接交给 AI
- AI 会把任务分发给多个专家代理，复杂扫描通常需要较长时间

## 核心能力

- 多代理渗透测试：侦察、利用、验证和报告并行协作
- Web、代码库、API 契约、域名、IP、Burp/Caido 流量驱动测试支持
- 真实 PoC 验证：报告包含可复现步骤和证据
- Burp / Caido 联动：适合“采集一个功能点，再开始测试”的工作流
- 中文交付体验：CLI、TUI、README、关键 docs、报告默认中文
- 本地兼容优先：支持 OpenAI-compatible 网关、本地模型和代理环境

## 快速开始

### 前置要求

- Docker 已启动
- Python 3.12+
- Go 1.24+
  - 仅源码仓库下的交互模式需要，例如 `strix`、`strix --burp-port 8081`
  - 官方 wheel / 发布包已内置 Go TUI sidecar，不需要额外安装 Go
- 一个可用的 LLM 接入方式
  - 推荐：OpenAI-compatible 网关、本地模型、LiteLLM 路由
  - 兼容：OpenAI、Anthropic、Vertex AI、Bedrock、Azure、ChatGPT 订阅登录

### 从源码安装

```bash
# 获取当前分支源码
git clone https://github.com/wpsec/strix-cn.git
cd strix-cn

# 创建虚拟环境并安装
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .

# 如果要直接在源码仓库里使用交互式 TUI / Burp/Caido 流量入口
# macOS 可先安装 Go
brew install go

# 确认版本
.venv/bin/strix --version
go version
```

### 更新已有源码环境

在其他机器（例如 Kali）使用当前分支前，先拉取最新提交并刷新源码安装：

```bash
cd /home/tmp/strix-cn
git pull --ff-only
.venv/bin/python -m pip install -e .
.venv/bin/strix --version
```

如果工作树存在未提交改动，请先确认并保留这些改动，再执行 `git pull`。

说明：

- 源码仓库下的交互模式会直接运行 Go / Bubble Tea TUI；如果本机没有 `go`，启动 `strix` 或 `strix --burp-port 8081` 时会报 `Bubble Tea TUI binary not found`
- 只跑无交互模式 `-n/--non-interactive` 时，不依赖本机 Go TUI
- 使用官方 wheel / 发布包安装时，Go sidecar 已随包提供，不需要额外安装 Go

### 准备本地沙箱镜像

```bash
# 准备 overlay 构建依赖的基础镜像
docker pull ghcr.io/usestrix/strix-sandbox:1.3.0

# 国内网络可选：配置构建镜像源
export STRIX_KALI_APT_MIRROR="http://mirrors.tuna.tsinghua.edu.cn/kali"
export STRIX_GO_PROXY="https://goproxy.cn,direct"
export STRIX_GO_SUMDB="sum.golang.google.cn"
export STRIX_NPM_REGISTRY="https://registry.npmmirror.com"
export STRIX_PIP_INDEX_URL="https://pypi.tuna.tsinghua.edu.cn/simple"

# 推荐：在上游 1.3.0 基础上叠加当前分支改动
./scripts/docker-overlay.sh local

# 如果你明确修改了大量基础环境，再执行完整构建
# ./scripts/docker.sh local

# 指定 Strix 使用本地镜像
export STRIX_IMAGE="strix-sandbox:local"
```

### 配置模型

```bash
# 示例：兼容网关 / 自建入口 / 国内可访问模型网关
export STRIX_LLM="openai/your-compatible-model"
export LLM_API_KEY="your-api-key"
export LLM_API_BASE="https://your-gateway.example/v1"

# 也可以将配置写入项目目录的 .env；已 export 的变量优先级更高
# STRIX_LLM=openai/your-compatible-model
# LLM_API_KEY=your-api-key
# LLM_API_BASE=https://your-gateway.example/v1

# 可选：额外路由头
export LLM_EXTRA_HEADERS='{"X-Tenant":"acme"}'

# 可选：受限网络或兼容网关流式不稳定时关闭 streaming
export LLM_DISABLE_STREAMING="false"

# 可选：推理强度
export STRIX_REASONING_EFFORT="high"

# 可选：启用实时 Web 搜索（二选一或同时配置）
# export PERPLEXITY_API_KEY="your-perplexity-api-key"
# export EXA_API_KEY="your-exa-api-key"
# export STRIX_WEB_SEARCH_PROVIDER="auto"  # auto、exa 或 perplexity
# export STRIX_EXA_SEARCH_TYPE="auto"       # auto、fast、instant、deep-lite、deep、deep-reasoning
# export STRIX_EXA_NUM_RESULTS="5"           # 1-100

# 可选：受限网络环境
export HTTP_PROXY="http://127.0.0.1:7897"
export HTTPS_PROXY="http://127.0.0.1:7897"
export ALL_PROXY="socks5://127.0.0.1:7897"
```

配置优先级为：已 `export` 的环境变量 > 项目目录 `.env` > `~/.strix/cli-config.json` > 默认值。
`.env` 不应提交到 Git；请使用 `.env.example` 保存变量名和占位符。

### 第一条命令

```bash
# 本地代码扫描
.venv/bin/strix --target ./app-directory

# Web 应用扫描
.venv/bin/strix --target https://example.com

# Burp/Caido 流量驱动常规渗透测试
.venv/bin/strix --burp-port 8081
```

### 单请求入口

单个数据包如果目的是让 Strix 深入测试并尝试形成有效漏洞，直接使用普通模式的 `--request`：

```bash
.venv/bin/strix \
  --request ./burp-request.txt \
  --issue "检查该请求涉及的参数是否存在越权、注入或可获得更高权限的利用链" \
  -n
```

这条命令会启动完整的 AI 渗透测试链路、Docker sandbox、Caido 代理、子 Agent 和原生漏洞报告。请求文件只是起始证据，Agent 会在授权范围内重放基线、分析相关接口和业务流程、变异参数并验证实际影响，不会停在一次固定探针的响应比较上。未指定 `--target` 时，Strix 从请求的 Scheme、Host 和 Port 自动建立目标；指定 `--target` 或 `--target-list` 时，请求的 Host/Port 必须命中授权目标。

模式边界如下：

| 入口 | 适用目的 | 执行引擎 |
| --- | --- | --- |
| `--verify --request` | 确定性复测、修复回归、证明已知假设 | 受限验证执行器 |
| `--request` | 以单个数据包为入口的完整 AI 渗透测试 | 完整 AI Agent 图 |
| `--burp-port` | 从 Burp/Caido 流量采集并测试功能点 | 完整目标级扫描链路 |
| `--target` | 常规目标级渗透测试 | 常规 Agent 图 |

因此，`--verify` 的结果是“复测证据”，不代表它已经完成一次完整的单包测试；想让 AI 自主扩展测试面，应使用普通模式的 `--request`。

模式选择优先级为：CLI 参数 > `STRIX_MODE` > 持久化配置 > `normal`。当前支持 `normal` 和 `verify` 两种模式；扫描开始后模式不可切换，使用 `--resume` 时必须沿用原运行记录中的模式。

报告生成遵循原生 Strix 行为：Markdown、HTML、JSON、CSV 及 SARIF 保留真实验证证据，不用说明性占位文本冒充 Request、Response、PoC 或凭据字段。`reproduction_requests` 中的原始请求和实际响应会回填到报告主证据；静态/依赖发现会明确标记 HTTP 字段不适用，动态发现缺少数据时会标记证据缺口并保留在报告中。SARIF 默认只保留 PoC 描述和脚本存在标记。

运行产物位于 `strix_runs/<run-name>/`，包括 `penetration_test_report.md`、`penetration_test_report.html`、`vulnerabilities/*`、`run.json` 和 `findings.sarif`。

普通模式会按完整 Agent 图测试目标；单请求只提供上下文，不会改变报告格式、作用域校验或 Agent 工具能力。

### 单个漏洞验证模式

验证计划由当前配置的 Strix LLM 根据“漏洞描述 + 脱敏请求结构”生成。模型只提出漏洞标签、目标字段、验证能力、探针和判定器，随后由本地校验器检查字段白名单、动作、载荷、请求数量和副作用边界；模型调用失败或意图不完整时直接阻断，不按漏洞名称匹配固定模板，也不猜测请求中不存在的字段。运行前请先完成模型配置，至少设置 STRIX_LLM、LLM_API_KEY，以及兼容网关所需的 LLM_API_BASE。

确认漏洞时报告会提供“可复现 PoC”和已执行探针请求；未复现、阻断或证据不足时会提供“未复现证明”，包括控制请求、探针请求、响应状态码、长度、响应指纹和未满足的判定条件。报告中的原始请求和实际重放请求仍按原样保留，便于在 Burp Repeater 中复核。

需要第二授权身份时，使用 --secondary-request 提供第二个 Burp 请求包；需要受控出站验证时，使用 --canary-url 提供由操作员控制的公网 Canary 地址。模型不能自行指定第二身份请求或出站目标。

当前版本没有 OOB 回调确认能力，Canary 回显只记录为证据不足，不会单凭回显确认服务端请求伪造。

`--verify` 用于复核一个具体漏洞，不启动普通扫描或整站攻击面发现。提供 Burp 的 Raw HTTP / Copy as cURL 请求，以及一句自然语言问题描述，Strix 会先生成验证计划，确认后才启动与普通扫描一致的 Docker sandbox，并通过容器内配置的 Caido 代理发送受限探针请求；计划阶段不会启动容器或发送请求。需要 AI 自主探索测试面时，使用上面的普通模式 `--request`，不要把 `--verify` 当作单包完整扫描入口。

```bash
# 交互模式：按提示粘贴请求和漏洞描述
.venv/bin/strix --verify

# 非交互模式：请求文件和描述均由参数提供
.venv/bin/strix --verify \
  --request ./burp-request.txt \
  --issue "疑似 IDOR，修改订单 ID 后可能读取其他用户订单" \
  -n --yes

# 修复后复测：沿用历史验证计划和探针
.venv/bin/strix --verify \
  --baseline <历史运行名> \
  --request ./burp-request-after-fix.txt \
  -n --yes

# 跨身份对象边界：额外提供第二个授权身份的同端点请求
.venv/bin/strix --verify \
  --request ./primary-request.txt \
  --secondary-request ./secondary-request.txt \
  --issue "疑似对象访问边界问题" \
  -n --yes

# 需要受控出站验证时：只使用操作员控制的 Canary 地址
.venv/bin/strix --verify \
  --request ./burp-request.txt \
  --canary-url https://canary.example/strix-test \
  --issue "疑似服务端出站请求边界问题" \
  -n --yes
```

交互模式中，请求内容以单独一行 `__STRIX_END__` 结束。执行前会展示识别出的漏洞类型、目标字段、验证动作、预计请求数和副作用提示；JSON 请求会递归暴露叶子字段，例如 `body.dataPackage.configList[0].conditionSql`，不需要手工填写参数路径。IDOR/BOLA 等需要第二身份的场景会继续要求提供第二个请求包。Raw 请求缺少 Scheme 时，如果同源 `Origin` 或 `Referer` 已明确给出协议，验证模式会自动采用；否则交互模式只询问一次使用 `http` 还是 `https`，非交互模式会直接阻断。

验证结果和可复制的 Burp Repeater 请求保存在 `strix_runs/<run-name>/`，包括 `verification-plan.json`、`verification-result.json`、`verification-evidence.jsonl` 和 `penetration_test_report.md`。执行环境记录为 `docker-sandbox`，验证完成后会清理临时容器；容器启动或执行失败时不会回退到宿主机直连，而是生成证据不足的报告。验证模式与 `--target`、`--burp-port` 和 `--resume` 互斥；只能对已获得授权的目标执行。

## 常见用法

### 基础扫描

```bash
# 本地代码库
strix --target ./app-directory

# GitHub 仓库
strix --target https://github.com/org/repo

# Web 应用
strix --target https://your-app.com
```

### API Testing（OpenAPI / Swagger / Postman）

```bash
# OpenAPI / Swagger 文件
strix --target ./openapi.yaml --target https://api.your-app.com

# Postman collection 导出文件
strix --target ./collection.postman_collection.json --target https://api.your-app.com

# 通过 Postman collection id 实时拉取
export POSTMAN_API_KEY="PMAK-..."
strix --target "postman://<collection-uuid>?env=<environment-uuid>"
```

### Burp/Caido 流量驱动常规渗透测试

`--burp-port` 使用 `normal` 模式，从 Burp/Caido 进入的请求、响应、会话和功能流程建立测试上下文，再交给完整 Agent 链路进行常规渗透测试。它不是 `--verify` 的单漏洞复测。

```bash
# 仅使用 Burp/Caido 流量建立测试上下文
strix --burp-port 8081

# 同时显式限制目标主机
strix --target https://example.com --burp-port 8081
```

推荐工作流：

1. 在 Burp 中把上游代理指向 `127.0.0.1:8081`
2. 浏览器继续走 Burp，先手工完成一个完整功能点
3. 回到 Strix 后在对话框发送 `开始测试`，冻结当前功能点并暂停继续采集
4. 当前功能点测完后发送 `下一功能点`，重新开启下一轮采集
5. 全部功能点完成后发送 `结束测试`，生成总报告

这种“单功能采集 -> 开始测试 -> 切换下一功能”的方式，比一次性灌入整站流量更稳定；每个功能点都会进入常规 Agent 渗透测试流程，也更符合当前 `strix-cn` 的 Burp/Caido 工作流。

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1786415507094-4dcef33f-036e-4d73-b6ab-a7a351c6e9b9.png)

burp 将想要测试的功能点击完成后，代理到 strix， 输入开始测试

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1786416228642-a75838b5-d36c-462a-9f41-ee6aff0352e4.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1786415516431-f151710b-5f19-4f10-bd9f-d6c4fa6c6a88.png)

测试开始，rootagent 会梳理当前接口信息，启一个攻击面分析专家子 agent

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1786416018194-5500ce56-5614-4c7a-944d-788a76626506.png)

子 agent 分析

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1786416257456-95305157-cadc-4f66-87ce-7d5403c8ca91.png)

分析完后返回给 rootagent，rootagent 根据分析结果，下发对应的子 agent 专家进行测试

本地报告

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1786428778765-802e1bf1-8680-4155-b533-276beb6fcbfb.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1786428823302-3d14f367-7f6d-4aee-8aef-31ad88bd4aad.png)

### 进阶组合

```bash
# 多目标测试（源码 + 已部署应用）
strix -t https://github.com/org/app -t https://staging.example.com

# 从文件读取目标
strix --target-list ./targets.txt

# 兼容参数：只挂载工作目录
strix --mount ./huge-monorepo --instruction "Review the changed auth flow"

# 聚焦测试
strix --target api.example.com --instruction "重点测试 IDOR、认证绕过和业务逻辑缺陷"

# 从文件读取详细说明
strix --target api.example.com --instruction-file ./instruction.md

# 快速模式 + diff-scope
strix -n --target ./ --scan-mode quick --scope-mode diff --diff-base origin/main

# 限制扫描级有效 Token，优先完成严重/高危漏洞路径
strix -n --target ./ --token-limit 100M

# 恢复之前中断的运行
strix --resume <run_name>
```

### Token 限制与恢复

`--token-limit` 是整次扫描的有效 Token 上限，按模型调用的 `input_tokens + output_tokens` 统计；支持整数及 `K/M/G/T/B` 后缀，例如 `100M` 表示 100,000,000 Token。未配置时不限制 Token，但仍会记录实际用量。配置后扫描会优先执行 P0/P1 的授权、攻击面、严重/高危漏洞发现、验证和报告，再进入中低危扩展测试。

Token 用尽时运行状态会标记为 `token_limit_exhausted`，报告会明确列出已完成测试、未完成阶段、跳过任务和严重度覆盖范围，不能将未覆盖区域视为“未发现问题”。`--max-budget-usd` 仍然只负责费用限制；两者同时配置时，任一限制先达到都会停止继续扩展测试。

如果因 Token 上限耗尽而提前结束，运行状态会保留为可恢复运行。使用 `--resume` 可以从原运行记录继续未完成的任务，不会从头开始扫描。恢复时默认沿用原始 Token 上限；由于该上限已经耗尽，必须显式提供更大的累计总上限：

```bash
# 原扫描使用 --token-limit 100M，恢复时将累计总上限提高到 200M
strix --resume <run_name> --token-limit 200M
```

这里的 `200M` 是整次扫描的累计总上限，不是额外增加 200M；如果原运行已经消耗约 98M，恢复后大约还可使用 102M。恢复时不要再次指定 `--target`、`--target-list` 或 `--mount`，目标和未完成任务计划会从原运行记录恢复。若耗尽的是模型供应商的 API 余额或配额，而不是 Strix 的 `--token-limit`，则需要先补充供应商额度或更换可用模型。

## 本地 Viewer

每次扫描结果都会实时落盘。你可以直接在浏览器中查看运行状态、漏洞详情、代理图和历史运行：

```bash
# 打开最近一次运行
strix view

# 或者打开指定运行
strix view <run_name>
```

Viewer 默认只绑定到本机回环地址，读取本地 `strix_runs/` 目录中的结果文件，不需要额外前端安装。

## ChatGPT 订阅登录

如果你不想直接使用按量 API Key，也可以使用当前版本内置的 ChatGPT 订阅登录能力：

```bash
strix auth login chatgpt

export STRIX_LLM="chatgpt/gpt-5.4"
strix --target ./app-directory

strix auth status
strix auth logout
```

## 在编码代理中使用 Strix

Strix 已支持通过 skills 接入常见编码代理：

```bash
npx skills add usestrix/strix
```

这会安装 4 个技能，分别覆盖无头扫描与结果读取、云端托管渗透测试 API 驱动、修复后复扫验证，以及 CI 场景下的 PR 安全扫描。编码代理既可以直接驱动本地开源 CLI，也可以在没有本地 Docker 或 LLM Key 时走托管云端能力。

相关参考：

- `[AGENTS.md](AGENTS.md)`：本地快速说明
- [docs.strix.ai/llms.txt](https://docs.strix.ai/llms.txt)：CLI 文档
- [docs.app.strix.ai](https://docs.app.strix.ai)：云端 API 文档
- `strix-pentest`：无头扫描与结果读取
- `strix-cloud-api`：通过云端平台 REST API 驱动扫描
- `strix-fix-findings`：修复并复扫验证
- `strix-ci-setup`：在 CI 中接入 PR 扫描

## 无头模式与 CI

无交互场景下可使用 `-n/--non-interactive`：

```bash
strix -n --target https://your-app.com
```

GitHub Actions 示例：

```yaml
name: strix-penetration-test

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v6
        with:
          python-version: "3.12"

      - name: Install strix-cn
        run: |
          python -m pip install -U pip
          python -m pip install "git+https://github.com/wpsec/strix-cn.git"

      - name: Run Strix
        env:
          STRIX_LLM: ${{ secrets.STRIX_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: strix -n -t ./ --scan-mode quick
```

## 相关文档

- CLI 参考：`docs/usage/cli.mdx`
- 配置说明：`docs/advanced/configuration.mdx`
- 贡献说明：`CONTRIBUTING.md`
- 同步计划：`docs/plan/071-v1.5.0主线全量吸收与兼容迁移方案.md`

## 致谢

Strix 构建在多个优秀的开源项目之上，包括 LiteLLM、Caido、Nuclei、Playwright 和 Bubble Tea。感谢这些项目的维护者。

## 安全声明

Strix 会主动对目标发起安全测试。请仅在你拥有或已获得明确书面授权的系统上运行，并严格遵守约定范围与适用法律。对于未经授权的使用或由此产生的后果，使用者自行承担责任。
