<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771932705094-c88426f2-74cc-4214-8f91-e3a4c8882279.png)

Strix开源 AI 渗透测试工具。面向中文用户持续维护，优先解决国内模型、Burp 工作流与兼容性适配。

> [!TIP]  
> **新功能**：Strix 已可无缝接入 GitHub Actions 和 CI/CD 流水线。你可以在每个 Pull Request 上自动执行漏洞扫描，在不安全代码进入生产环境前直接拦截。可前往 [app.strix.ai](https://app.strix.ai) 体验免配置接入。

> [!IMPORTANT]  
> `strix-cn` 是面向中文用户的持续维护分支。这个分支会优先围绕以下方向长期演进：
>
> - 国内可访问、可落地的模型接入，包括 OpenAI-compatible 网关、LiteLLM 路由与本地模型
> - Burp Suite 与常用 Burp 插件工作流兼容，方便接入现有手工验证流程
> - macOS、Linux、Windows 以及受限网络环境下的安装、运行与代理兼容性
> - 中文文档、中文说明和中文报告输出体验

---

## Strix 简介

Strix 是一组自治 AI 渗透测试代理，工作方式尽量贴近真实黑客。它会动态运行你的代码、发现漏洞，并通过真实的 PoC 进行验证。`strix-cn` 在保留上游核心能力的同时，优先补齐国内模型接入、Burp 工作流协同、环境兼容和中文化体验，方便在本地研发、内网、自建网关和受限网络环境中落地。

**核心能力：**

- **完整渗透测试工具链**：内置侦察、利用、验证能力
- **多代理协同**：多名 AI 渗透测试代理可协作并行工作
- **真实利用验证**：输出可执行 PoC，而不只是传统扫描器式的告警
- **面向开发者的 CLI**：提供可执行的修复建议与可落地的发现结果
- **自动修复与报告**：可生成补丁与适合合规场景的渗透测试报告
- **模型兼容优先**：优先验证 OpenAI-compatible、LiteLLM 路由和本地模型接入
- **语言与环境适配**：默认中文报告，并持续修复跨平台与代理环境兼容问题

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1784536956050-e0b0a273-a147-4e27-991a-66fd1fb3754f.png)

burp 被动扫描模式

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1784712512567-eabda74b-64ec-4cc8-89d2-003481b604f0.png)

主 agent 下发任务

各类子 agent 扮演专家，执行安全测试，结果返回给主 agent

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1784728665153-44214901-8922-430f-8104-65c064e3753e.png)

报告自带 poc ，方便复现

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1784730867493-84b575d8-5fd7-4a76-8374-15f168864d85.png)

## 使用场景

- **应用安全测试**：发现并验证应用中的高危安全漏洞
- **快速渗透测试**：在数小时内完成渗透测试，而不是等待数周，并输出合规报告
- **漏洞赏金自动化**：自动化研究、生成 PoC，加快漏洞提交
- **CI/CD 集成**：在发布前阻断漏洞进入生产环境
- **内网与受限环境落地**：配合本地模型、兼容网关和网络代理完成扫描

## 注意！！！

一定在测试系统使用

不要一次性代理过多的接口给工具，burp 可以少量多次的进行功能接口的分发，不要把所有接口都跑一边然后等结果！

增删改的接口一定慎重（不建议给 AI 测）

AI 需要分发任务给对应的专家，测试过程会很慢，过多的接口可能导致不可预测的结果。

## 快速开始

**前置要求：**

- Docker 已启动
- 一个可用的 LLM 接入方式。优先推荐 OpenAI-compatible 网关、LiteLLM 路由或本地模型；仍兼容 OpenAI、Anthropic、Google 等上游提供商。

### 安装并执行第一次扫描

```bash
# 获取当前 strix-cn 分支源码
git clone https://github.com/wpsec/strix-cn.git
cd strix-cn

# 创建虚拟环境并安装当前分支
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .

# 提前拉取默认沙箱镜像
docker pull ghcr.io/usestrix/strix-sandbox:1.0.0

# 基于当前仓库构建本地 sandbox 镜像
./scripts/docker.sh local

# 在当前 shell 中指定 Strix 使用本地镜像
export STRIX_IMAGE=strix-sandbox:local

# 配置 AI 提供商
# 示例：兼容国内/自建 OpenAI-compatible 网关
export STRIX_LLM="openai/your-compatible-model"
export LLM_API_KEY="your-api-key"
export LLM_API_BASE="https://your-gateway.example/v1"

# 扫描app-directory
.venv/bin/strix --target ./app-directory
```

> [!NOTE]  
> 上面的方式安装的是当前 `strix-cn` 分支源码，不是官方安装脚本拉取的发布版。首次运行会自动拉取沙箱 Docker 镜像。扫描结果会保存在 `strix_runs/<run-name>`。  
> 当前分支默认输出中文报告；如果你需要英文或双语结果，可在 `--instruction` 中显式说明。

> [!IMPORTANT]  
> 上面的 `docker pull ghcr.io/usestrix/strix-sandbox:1.0.0` 只是提前准备基础镜像；真正运行当前 `strix-cn` 分支时，推荐按快速开始里的方式继续执行 `./scripts/docker.sh local`，再通过 `export STRIX_IMAGE=strix-sandbox:local` 明确使用本地构建镜像。  
> 这样可以确保当前分支在 `containers/`、证书、代理端口、Caido 启动参数、浏览器环境等 sandbox 侧改动也一并生效，而不是误用默认发布镜像。

如果你之后开了一个新的 shell，或者想重新确认当前用的是本地镜像，可以再执行一次：

```bash
export STRIX_IMAGE=strix-sandbox:local

# 后续运行会继续复用这个设置，直到你关闭当前 shell 或重新覆盖该变量
.venv/bin/strix --target ./app-directory
```

如果你只想临时指定一次，也可以这样运行：

```bash
STRIX_IMAGE=strix-sandbox:local .venv/bin/strix --target ./app-directory
```

如果你只是改了 `containers/docker-entrypoint.sh`、少量启动脚本，或者当前网络环境无法顺利访问 `docker.io/kalilinux`，也可以优先使用轻量覆盖构建：

```bash
# 基于本机已有的发布镜像覆一层，只替换当前分支修改过的容器文件
./scripts/docker-overlay.sh local

export STRIX_IMAGE=strix-sandbox:local
.venv/bin/strix --target ./app-directory
```

轻量覆盖构建默认基于本机已有的 `ghcr.io/usestrix/strix-sandbox:1.0.0`。如果这个基础镜像已经在本地，通常不需要再访问 `docker.io`。

如果你所在环境访问 `ghcr.io` 较慢或受限，建议先手动执行上面的 `docker pull`，确认镜像 `ghcr.io/usestrix/strix-sandbox:1.0.0` 已可用后再启动扫描。

### 先看帮助

```bash
# 源码仓库内直接运行
.venv/bin/strix -h

# 已安装到系统后直接运行
strix -h
```

> [!NOTE]  
> 某些网络环境下执行 `-h` 时，可能先看到 LiteLLM 关于远端 model cost map 的 warning。它通常会自动回退到本地 backup，不影响查看帮助或正常运行。

---

## 功能特性

### Agentic 渗透测试工具集

Strix 代理内置了完整的攻防工具链，覆盖专业渗透测试人员和白帽黑客常用能力：

- **HTTP 拦截代理**：当前基于 Caido，并持续补齐与 Burp Suite 工作流的兼容适配
- **浏览器利用能力**：自动化浏览器，可测试 XSS、CSRF、点击劫持和认证绕过流程
- **Shell 与命令执行**：交互式终端，用于漏洞利用与后渗透阶段
- **自定义利用运行时**：内置 Python 沙箱，用于编写和验证 PoC
- **侦察与 OSINT**：自动化攻击面梳理、子域枚举、指纹识别
- **静态与动态代码分析**：同时具备 SAST 与 DAST 能力
- **漏洞知识库**：结构化发现结果，带 CVSS 评分与 OWASP 分类

### 综合漏洞扫描能力

Strix 可以识别、验证并利用覆盖 OWASP Top 10 及更多类别的安全问题：

- **访问控制缺陷**：IDOR、提权、认证绕过
- **注入类攻击**：SQL 注入、NoSQL 注入、命令注入、SSTI
- **服务端漏洞**：SSRF、XXE、不安全反序列化、RCE
- **客户端攻击**：XSS（存储型 / 反射型 / DOM）、原型污染、CSRF
- **业务逻辑缺陷**：竞态条件、支付绕过、流程绕过
- **认证与会话问题**：JWT 攻击、会话固定、撞库向量
- **基础设施与云安全**：配置错误、暴露服务、云侧安全问题
- **API 安全**：认证缺陷、批量赋值、限速绕过

### 多代理图（Graph of Agents）

Strix 提供多代理协同编排能力，用于更完整的自动化渗透测试：

- **分布式渗透测试**：将侦察、利用、后渗透交给不同 AI 代理执行
- **可扩展的安全测试**：面向多目标并行执行，加快覆盖速度
- **动态协同**：代理间可共享发现、串联漏洞，接近真实红队协作方式

---

## 使用示例

### 基础用法

```bash
# 扫描本地代码库
strix --target ./app-directory

# 审查 GitHub 仓库
strix --target https://github.com/org/repo

# 黑盒 Web 应用测试
strix --target https://your-app.com
```

### 进阶测试场景

```bash
# Burp 被动扫描：浏览器 -> Burp -> Strix -> 目标站点
strix --burp-port 8081

# Burp 被动扫描 + 显式限制目标主机
strix --target https://example.com --burp-port 8081

# 灰盒认证测试
strix --target https://your-app.com --instruction "Perform authenticated testing using credentials: user:pass"

# 多目标测试（源码 + 已部署应用）
strix -t https://github.com/org/app -t https://your-app.com

# 从文件读取目标，每行一个，忽略空行和注释
strix --target-list ./targets.txt

# 白盒源码感知扫描（本地仓库）
strix --target ./app-directory --scan-mode standard

# 带自定义要求的聚焦测试
strix --target api.your-app.com --instruction "Focus on business logic flaws and IDOR vulnerabilities"

# 通过文件提供详细说明（例如测试规则、范围、排除项）
strix --target api.your-app.com --instruction-file ./instruction.md

# 针对指定基线分支强制启用 PR diff-scope
strix -n --target ./ --scan-mode quick --scope-mode diff --diff-base origin/main
```

### 常用参数组合

```bash
# 查看完整帮助与全部参数
.venv/bin/strix -h

# Burp 被动扫描，固定监听给 Burp 的上游代理端口
strix --burp-port 8081

# 大型本地仓库改用只读挂载，而不是逐文件复制
strix --mount ./huge-monorepo

# 从文件批量读取目标
strix --target-list ./targets.txt

# 快速模式 + 成本上限，适合先跑一轮摸底
strix -n --target ./app-directory --scan-mode quick --max-budget-usd 1

# CI / PR 场景中只审查变更文件
strix -n --target ./ --scan-mode quick --scope-mode diff --diff-base origin/main

# 恢复之前中断的扫描
strix --resume <run_name>
```

### 无头模式

使用 `-n/--non-interactive` 参数即可在无交互场景下以程序化方式运行 Strix。非常适合服务器与自动化任务。CLI 会实时输出漏洞发现与最终报告。若发现漏洞，进程会以非零退出码结束。

```bash
strix -n --target https://your-app.com
```

### CI/CD（GitHub Actions）

你可以通过轻量化 GitHub Actions 工作流，将 Strix 集成进 PR 安全测试流程：

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

> [!TIP]  
> 在 CI 的 Pull Request 场景下，Strix 会自动把快速审查范围限制在变更文件内。  
> 如果 diff-scope 无法解析，请确认 `checkout` 使用了完整历史（`fetch-depth: 0`），或者显式传入 `--diff-base`。

### 配置

```bash
# 示例 1：OpenAI-compatible 网关
export STRIX_LLM="openai/your-compatible-model"
export LLM_API_KEY="your-api-key"
export LLM_API_BASE="https://your-gateway.example/v1"

# 示例 2：本地模型（Ollama / LM Studio / vLLM）
# export STRIX_LLM="ollama/qwen3-vl"
# export LLM_API_BASE="http://localhost:11434"

# 可选
export PERPLEXITY_API_KEY="your-api-key"  # 用于搜索能力
export STRIX_REASONING_EFFORT="high"  # 控制思考强度（默认 high，quick 扫描默认 medium）
```

> [!NOTE]  
> Strix 会自动把配置保存到 `~/.strix/cli-config.json`，无需每次重新输入。

> [!TIP]  
> 如果你的网络环境访问外部模型或安装源受限，可以在运行前设置 `HTTP_PROXY`、`HTTPS_PROXY` 和 `ALL_PROXY`，并通过 `LLM_API_BASE` 指向可访问的兼容网关。

**本分支优先推荐的模型接入路径：**

- **OpenAI-compatible 网关**：`openai/<your-model>` + `LLM_API_BASE=https://.../v1`
- **本地模型**：`ollama/qwen3-vl`、`ollama/deepseek-v3.1`
- **兼容提供商**：如 [Novita](https://docs.strix.ai/llm-providers/novita) 等 OpenAI-compatible 服务
- **上游官方提供商**：继续支持 OpenAI、Anthropic、Vertex AI、Bedrock、Azure 等

可前往 [LLM Providers 文档](https://docs.strix.ai/llm-providers/overview) 查看完整支持列表，以及本地模型、兼容网关与提供商接入方式。

## 公益项目

欢迎支持

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1784541650281-4adb72be-cb03-4ee9-89ca-454354165e2e.png)
