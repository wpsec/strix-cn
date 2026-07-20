# 030 CLI、TUI 与运行提示汉化

## 目标

把用户运行 Strix 时第一眼看到的文案改为中文，解决帮助输出、占位词、状态提示和常见错误提示仍为英文的问题。

## 范围

- CLI `--help`
- 环境校验、镜像拉取、启动告警、结束提示
- TUI renderers
- 用户可见的 todo / notes / reporting / finish 工具返回消息

## 输入

- 010 术语规范
- 当前 CLI 帮助输出
- 当前 TUI renderers 和用户反馈

## 变更点

- 把帮助说明、示例说明、环境缺失提示改为中文
- 把 Todo、Notes、Loading、Creating、Updated、Completed、Removed 等高频标签改为中文
- 把用户可见错误提示改为中文，但保持机器字段和数据结构不变
- 保持命令名、flags、环境变量名、JSON 键不变

## 验收条件

- `strix --help` 主体说明为中文
- TUI 高频标签与占位文案为中文
- 用户主路径上不再频繁出现可控的英文提示词

## 剩余问题

- 第三方库原始异常仍可能是英文，作为白名单保留
