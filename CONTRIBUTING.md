# 参与贡献 Strix

感谢你对 Strix 的关注。本文档用于帮助你快速进入开发与贡献流程。

## 分支定位

`strix-cn` 是面向中文用户的持续维护分支。提交改动时，请优先考虑以下方向：

- 国内可访问、可落地的模型接入与兼容网关
- Burp Suite / Burp 插件工作流兼容
- macOS、Linux、Windows 与受限网络环境兼容性
- 中文文档、中文说明与中文报告体验

## 🚀 开发环境准备

### 前置要求

- Python 3.12+
- Docker 已启动
- [uv](https://docs.astral.sh/uv/)（用于依赖管理）
- Git

### 本地开发

1. **克隆仓库**
   ```bash
   git clone https://github.com/usestrix/strix.git
   cd strix
   ```

2. **安装开发依赖**
   ```bash
   make setup-dev

   # 或手动执行：
   uv sync
   uv run pre-commit install
   ```

3. **配置 LLM 提供商**
   ```bash
   export STRIX_LLM="openai/your-compatible-model"
   export LLM_API_KEY="your-api-key"
   export LLM_API_BASE="https://your-gateway.example/v1"
   ```

4. **以开发模式运行 Strix**
   ```bash
   uv run strix --target https://example.com
   ```

## 📚 贡献 Skills

Skills 是用于增强代理能力的专业知识包。详细规范请查看 [strix/skills/README.md](strix/skills/README.md)。

### 快速指引

1. **选择合适的分类目录**（如 `/vulnerabilities`、`/frameworks`、`/technologies`）
2. **创建 `.md` 文件** 并写入 skill 内容
3. **提供可操作示例**，例如 payload、命令或测试用例
4. **补充验证方法**，说明如何确认发现结果并避免误报
5. **通过 PR 提交**，并写清楚背景与目标

## 🔧 贡献代码

### Pull Request 流程

1. **先创建 Issue**：描述问题或功能需求
2. **Fork 并创建分支**：从你要贡献的维护线开始工作；若同步上游能力，请在描述中说明来源与适配范围
3. **完成修改**：遵循项目现有代码风格
4. **编写或更新测试**：确保新功能和修复有覆盖
5. **运行质量检查**：`make check-all` 应通过
6. **提交 PR**：关联 Issue，并提供足够上下文

### PR 规范

- **描述清晰**：说明改了什么、为什么要改
- **改动聚焦**：一个 PR 尽量只解决一个问题或功能
- **带上示例**：尽量展示修改前后的行为差异
- **同步更新文档**：若功能变化影响使用方式，请一起更新文档
- **通过全部检查**：测试、lint、类型检查都应通过

### 代码风格

- 遵循 PEP 8，单行长度上限 100
- 所有函数都应提供类型标注
- 公共方法应编写 docstring
- 保持函数职责单一、规模适中
- 变量命名应清晰可读

## 🐛 提交问题

提交 Bug 时，请尽量附带以下信息：

- Python 版本与操作系统
- Strix 版本
- 使用的 LLM
- 完整错误堆栈
- 复现步骤
- 预期行为与实际行为

## 💡 功能建议

欢迎提出功能想法。建议在提交前：

- 先搜索是否已有类似 Issue
- 清楚描述使用场景
- 说明这个能力能为用户带来什么价值
- 简要考虑实现方向
- 保持开放讨论

## 🤝 社区

- **Discord**：[加入社区](https://discord.gg/strix-ai)
- **Issues**：[GitHub Issues](https://github.com/usestrix/strix/issues)

## ✨ 致谢

我们重视每一份贡献。贡献者将会：

- 出现在发行说明中
- 在 Discord 社区中获得感谢
- 被加入贡献者列表（即将推出）

---

**有问题？** 欢迎前往 [Discord](https://discord.gg/strix-ai) 交流，或直接创建 Issue。
