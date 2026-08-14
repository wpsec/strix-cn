<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771932705094-c88426f2-74cc-4214-8f91-e3a4c8882279.png)

# Strix CN

Strix 开源 AI 渗透测试工具的中文维护分支。当前分支已追平上游 `v1.5.3`，默认中文体验，优先解决国内模型接入、Burp / Caido 工作流、受限网络兼容，以及本地源码扫描落地问题。

- 上游项目：[https://github.com/usestrix/strix](https://github.com/usestrix/strix)
- 当前分支：[https://github.com/wpsec/strix-cn](https://github.com/wpsec/strix-cn)

## 分支目标

- 完整吸收上游当前发布版的功能、修复和新架构
- 保留 `strix-cn` 既有的中文文档、中文提示和中文报告输出
- 保留 Burp / Caido 被动扫描工作流与本地模型、兼容网关适配
- 保留本地开发者熟悉的 CLI 入口、常用参数和恢复路径

## 当前版本重点

- 交互界面已迁移到上游 Go / Bubble Tea TUI
- 支持 API spec / Postman collection 目标类型
- 支持 `LLM_EXTRA_HEADERS`、`LLM_DISABLE_STREAMING`、`STRIX_REASONING_EFFORT=max`
- 默认沙箱镜像基线升级到 `ghcr.io/usestrix/strix-sandbox:1.3.0`
- 本地目录统一走挂载模式，不再保留旧的逐文件复制主路径
- 本地 Viewer 已内置，无需额外前端安装

## 使用注意

- 只能在你拥有或获得明确书面授权的目标上运行
- Burp 被动扫描模式下，不要一次性把整站大量接口流量导给 Strix
- 对增删改类接口保持谨慎，不建议把高风险破坏性操作直接交给 AI
- AI 会把任务分发给多个专家代理，复杂扫描通常需要较长时间

## 核心能力

- 多代理渗透测试：侦察、利用、验证和报告并行协作
- Web、代码库、API 契约、域名、IP、Burp 被动流量多目标支持
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

# 如果要直接在源码仓库里使用交互式 TUI / Burp 被动代理入口
# macOS 可先安装 Go
brew install go

# 确认版本
.venv/bin/strix --version
go version
```

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

# 可选：额外路由头
export LLM_EXTRA_HEADERS='{"X-Tenant":"acme"}'

# 可选：受限网络或兼容网关流式不稳定时关闭 streaming
export LLM_DISABLE_STREAMING="false"

# 可选：推理强度
export STRIX_REASONING_EFFORT="high"

# 可选：受限网络环境
export HTTP_PROXY="http://127.0.0.1:7897"
export HTTPS_PROXY="http://127.0.0.1:7897"
export ALL_PROXY="socks5://127.0.0.1:7897"
```

### 第一条命令

```bash
# 本地代码扫描
.venv/bin/strix --target ./app-directory

# Web 应用扫描
.venv/bin/strix --target https://example.com

# Burp 被动扫描
.venv/bin/strix --burp-port 8081
```

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

### Burp 被动扫描

```bash
# 仅使用 Burp 流量建立作用域
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

这种“单功能采集 -> 开始测试 -> 切换下一功能”的方式，比一次性灌入整站流量更稳定，也更符合当前 `strix-cn` 的 Burp 工作流。

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

# 恢复之前中断的运行
strix --resume <run_name>
```

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
