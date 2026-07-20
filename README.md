<p align="center">
  <a href="https://strix.ai/">
    <img src="https://github.com/usestrix/.github/raw/main/imgs/cover.png" alt="Strix Banner" width="100%">
  </a>
</p>

<div align="center">

# Strix

### 开源 AI 渗透测试工具。面向中文用户持续维护，优先解决国内模型、Burp 工作流与兼容性适配。

<br/>


<a href="https://docs.strix.ai"><img src="https://img.shields.io/badge/Docs-docs.strix.ai-2b9246?style=for-the-badge&logo=gitbook&logoColor=white" alt="Docs"></a>
<a href="https://strix.ai"><img src="https://img.shields.io/badge/Website-strix.ai-f0f0f0?style=for-the-badge&logoColor=000000" alt="Website"></a>
[![](https://dcbadge.limes.pink/api/server/strix-ai)](https://discord.gg/strix-ai)

<a href="https://deepwiki.com/usestrix/strix"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
<a href="https://github.com/usestrix/strix"><img src="https://img.shields.io/github/stars/usestrix/strix?style=flat-square" alt="GitHub Stars"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-3b82f6?style=flat-square" alt="License"></a>
<a href="https://pypi.org/project/strix-agent/"><img src="https://img.shields.io/pypi/v/strix-agent?style=flat-square" alt="PyPI Version"></a>


<a href="https://discord.gg/strix-ai"><img src="https://github.com/usestrix/.github/raw/main/imgs/Discord.png" height="40" alt="Join Discord"></a>
<a href="https://x.com/strix_ai"><img src="https://github.com/usestrix/.github/raw/main/imgs/X.png" height="40" alt="Follow on X"></a>


<a href="https://trendshift.io/repositories/15362?utm_source=trendshift-badge&amp;utm_medium=badge&amp;utm_campaign=badge-trendshift-15362" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/trendshift/repositories/15362/weekly" alt="usestrix%2Fstrix | Trendshift" width="250" height="55"/></a>
<a href="https://trendshift.io/repositories/15362" target="_blank"><img src="https://trendshift.io/api/badge/repositories/15362" alt="usestrix/strix | Trendshift" width="250" height="55"/></a>

</div>


> [!TIP]
> **新功能**：Strix 已可无缝接入 GitHub Actions 和 CI/CD 流水线。你可以在每个 Pull Request 上自动执行漏洞扫描，在不安全代码进入生产环境前直接拦截。可前往 [app.strix.ai](https://app.strix.ai) 体验免配置接入。

> [!IMPORTANT]
> `strix-cn` 是面向中文用户的持续维护分支。这个分支会优先围绕以下方向长期演进：
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


<br>


<div align="center">
  <a href="https://strix.ai">
    <img src=".github/screenshot.png" alt="Strix Demo" width="1000" style="border-radius: 16px;">
  </a>
</div>


## 使用场景

- **应用安全测试**：发现并验证应用中的高危安全漏洞
- **快速渗透测试**：在数小时内完成渗透测试，而不是等待数周，并输出合规报告
- **漏洞赏金自动化**：自动化研究、生成 PoC，加快漏洞提交
- **CI/CD 集成**：在发布前阻断漏洞进入生产环境
- **内网与受限环境落地**：配合本地模型、兼容网关和网络代理完成扫描

## 🚀 快速开始

**前置要求：**
- Docker 已启动
- 一个可用的 LLM 接入方式。优先推荐 OpenAI-compatible 网关、LiteLLM 路由或本地模型；仍兼容 OpenAI、Anthropic、Google 等上游提供商。

### 安装并执行第一次扫描

```bash
# 安装 Strix
curl -sSL https://strix.ai/install | bash

# 配置 AI 提供商
# 示例：兼容国内/自建 OpenAI-compatible 网关
export STRIX_LLM="openai/your-compatible-model"
export LLM_API_KEY="your-api-key"
export LLM_API_BASE="https://your-gateway.example/v1"

# 执行第一次安全测试
strix --target ./app-directory
```

> [!NOTE]
> 首次运行会自动拉取沙箱 Docker 镜像。扫描结果会保存在 `strix_runs/<run-name>`。
> 当前分支默认输出中文报告；如果你需要英文或双语结果，可在 `--instruction` 中显式说明。

---

## ☁️ Strix 平台

你也可以体验完整的 Strix 全栈渗透测试平台：**[app.strix.ai](https://app.strix.ai)**。注册后连接代码仓库和域名，即可在几分钟内发起一次渗透测试。

- **已验证的漏洞发现**：每个漏洞都附带可执行 PoC 与复现步骤
- **一键自动修复**：AI 生成安全补丁，并以可合并 PR 的形式交付
- **持续渗透测试**：常驻式漏洞扫描，跟随部署节奏持续运行
- **DevSecOps 集成**：支持 GitHub、GitLab、Bitbucket、Slack、Jira、Linear 与 CI/CD
- **持续学习能力**：AI 会结合历史发现与代码库上下文，逐步降低误报

[**开始你的第一次渗透测试 →**](https://app.strix.ai)

---

## ✨ 功能特性

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

      - name: Install Strix
        run: curl -sSL https://strix.ai/install | bash

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

## 企业级渗透测试

如果你需要与 Strix 平台相同的体验，同时具备 [企业级](https://strix.ai/demo) 控制能力，可以进一步了解：SSO（SAML/OIDC）、适配 SOC 2 / ISO 27001 / PCI DSS 的定制渗透测试报告、专属支持与 SLA、自定义部署方式（VPC / 自托管）、BYOK 模型支持，以及针对你的环境优化的 AI 渗透测试代理。[了解更多](https://strix.ai/demo)。

## 文档

完整文档请访问 **[docs.strix.ai](https://docs.strix.ai)**，其中包含使用指南、CI/CD 集成、skills 机制与高级配置说明。
