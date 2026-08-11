# 2026-08-11 System Prompt 定向迭代记录

## 范围

- 文件：`strix/agents/prompts/system_prompt.jinja`
- 目标：收紧 Burp 被动代理批次状态机、总报告闭环、目标登录凭据保密边界

## 本轮落地改动

- 被动代理模式明确限定为“仅基于代理历史工作”，禁止主动扩域与 shell 直连探测
- 新增功能批次协作约束：先映射冻结 endpoint，再分配测试专家；未闭环不得等待或结束
- 新增目标登录凭据上下文：只允许通过 `STRIX_TARGET_USERNAME` / `STRIX_TARGET_PASSWORD` 使用，不得打印、记录、持久化或通过 agent message 传播
- 普通登录与凭据攻击分离：默认只允许正常登录；只有显式授权 `allow_credential_attacks` 才允许弱口令、喷洒或重试验证

## Prompt-Optimizer 调用记录

### Round 1

- 时间：2026-08-11
- 工具：`mcp__prompt_optimizer.iterate_prompt`
- 模板：`iterate`
- 版本：`round-1`
- 模型：未返回
- 得分：未返回
- 结果：超时失败
- 备注：等待 `prompt-optimizer/iterate-prompt` 超过 300 秒，工具返回 `timed out awaiting tools/call after 300s`

### Round 2

- 时间：2026-08-11
- 工具：`mcp__prompt_optimizer.optimize_system_prompt`
- 模板：`analytical-optimize`
- 版本：`round-2`
- 模型：未返回
- 得分：未返回
- 结果：超时失败
- 备注：等待 `prompt-optimizer/optimize-system-prompt` 超过 300 秒，工具返回 `timed out awaiting tools/call after 300s`

## 输入焦点

- 防止 Burp 被动代理模式下误主动探测、误扩域
- 防止 root 在功能批次未覆盖完成时过早 `wait` / `finish`
- 防止目标登录凭据泄露到日志、报告、运行记录、notes、inter-agent message 或工具参数

## 本地采纳结论

虽然本轮 `Prompt-Optimizer` 服务未返回可用结果，但围绕上述目标已在系统提示词中落地以下强化：

1. 采集阶段只允许看代理历史，不允许触达推断出的 host / URL
2. `开始测试` 后冻结当前批次；测试期间新增流量不属于当前批次
3. root 必须覆盖冻结 endpoint 清单，或写明 `not applicable` 理由
4. findings 文本不等于报告，必须经 `create_vulnerability_report`
5. 收尾必须经过正式报告与 `finish_scan`
6. 凭据只允许在浏览器或 HTTP 客户端消费点读取，禁止环境转储

## 下次补跑要求

- 待 `Prompt-Optimizer` 服务恢复后，继续对同一片段执行至少一轮正式优化
- 用真实返回值补齐“模型”“得分”字段
- 若优化建议改变了约束语义，必须同步更新：
  - `strix/agents/prompts/system_prompt.jinja`
  - `tests/test_inputs.py`
  - `tests/test_runner_root_prompt.py`
  - `docs/plan/091-主线同步门禁与能力契约.md`
