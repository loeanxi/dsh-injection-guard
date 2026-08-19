# dsh-injection-guard

[English](#dsh-injection-guard) | [中文](#dsh-injection-guard-中文)

Source-aware prompt injection protection for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness).

Coding agents read files, web pages, tool results, skills, and other external content. That content can contain instructions aimed at the agent. `dsh-injection-guard` tracks untrusted context and blocks sensitive tool calls when indirect prompt injection is suspected.

```text
untrusted content → injection signals → sensitive tool call → risk decision → ALLOW / ASK / BLOCK
```

## 30-second demo

The repository includes a deliberately malicious fixture at [`examples/malicious-repo/README.md`](examples/malicious-repo/README.md). It asks an agent to ignore the user's task, read `~/.ssh/id_rsa`, and send the contents to an external URL.

The guard treats the README as untrusted. A subsequent credential read is scored as critical and denied before the tool body runs:

```text
⚠ DSH Injection Guard

Possible indirect prompt injection detected.

Untrusted context:
  source: README.md

Injection signals:
  - ignore previous instructions
  - ~/.ssh
  - send ...

Sensitive action:
  tool: filesystem.read
  target: {"path":"~/.ssh/id_rsa"}

Risk:
  CRITICAL (90/100)

Decision:
  BLOCKED
```

The demo uses local fixtures only. It does not read real credentials or contact a network endpoint.

## Install and load

The plugin currently targets the developer-preview DSH plugin API. Install the package from this repository while developing:

```bash
npm install github:loeanxi/dsh-injection-guard
```

Load it in a DSH composition:

```yaml
- id: injection-guard
  name: '@dsh-plugins/injection-guard'
  config:
    log: true
    askThreshold: 60
```

The DSH preview API is still changing. Pin compatible DSH package versions in production deployments.

## What it detects

The v0.1 detector uses deterministic rules and does not call an LLM security judge.

- Instruction hijacking: `ignore previous instructions`, `override system`, fake system/developer messages
- Identity and authority spoofing: `you are now`, administrator claims, security verification
- Credential access: `.env`, `.ssh`, `.aws`, private keys, passwords, tokens, credentials
- Exfiltration: `curl`, `wget`, upload, webhook, HTTP submission
- Obfuscated or hidden execution: `base64`, `eval`, decode, execute/run commands

Sensitive sinks include credential access, network operations, shell execution, download-to-execute patterns, and destructive filesystem operations.

## How it works

At `agent/pre-step`, the plugin classifies message sources and records the current turn's risk state. File, web, tool, and document content is treated as untrusted by default.

At `tools/post-execute`, it also inspects the completed tool output and carries detected injection signals into the next step of the same turn. This covers DSH compositions where tool results are not repeated in the next `agent/pre-step.messages` snapshot. If source metadata is absent but an injection signal is present, the context is conservatively treated as untrusted.

At `tools/pre-execute`, it classifies the proposed tool call, combines the sink with the turn risk state, and returns a DSH-native `allow`, `ask`, or `deny` decision. Blocked calls include the source, signals, target, score, and decision in the audit message. Credential-like arguments are redacted from audit output.

The score is intentionally simple and explainable in v0.1:

| Signal | Points |
| --- | ---: |
| Untrusted context | +20 |
| Injection signal | +30 |
| Credential access | +40 |
| Network operation | +40 |
| Download → execute | +50 |
| Shell / privilege operation | +40 |
| Destructive filesystem operation | +30 |

`0–29` is `LOW/ALLOW`, `30–59` is `MEDIUM/ALLOW + log`, `60–79` is `HIGH/ASK`, and `80+` is `CRITICAL/BLOCK`.

## Test it locally

```bash
npm install
npm test
npm run test:integration
npm run typecheck
npm run build
```

The integration tests verify both the real DSH Loader composition and the real DSH ToolRuntime path from malicious README content to a blocked credential sink. All sinks are local simulated tools.

## Scope and limitations

This is a turn-level, source-aware policy signal. It is not:

- precise character-level causal or taint tracking;
- a general permission system;
- a sandbox;
- a dangerous-command blacklist;
- an LLM-based semantic judge;
- a guarantee that an agent will never be influenced by malicious content.

Source provenance should be retained by the surrounding DSH composition. Sensitive actions should still have independent permissions, argument validation, sandboxing, and user approval where appropriate.

## Research basis

The design is informed by the recent assessment [Security Assessment of DeepSeek Harness with A.I.G: Evaluating Resistance to Indirect Prompt Injection](https://arxiv.org/abs/2608.16393), which evaluated the real DSH runtime across multiple content channels, carrier formats, and attack transformations. The assessment highlights fake completion, obfuscation, skills, hidden Unicode, and file representation as important test dimensions.

The local research notes are available in [`research/dsh-prompt-injection.md`](research/dsh-prompt-injection.md).

## Status

This repository contains the v0.1 MVP: rule-based detection, source-aware turn state, sensitive sink analysis, risk scoring, audit logging, a malicious README fixture, and DSH integration tests.

License: MIT

<a id="dsh-injection-guard-中文"></a>

# dsh-injection-guard 中文说明

面向 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 的、基于来源感知的 Prompt Injection 防护插件。

Coding Agent 会读取文件、网页、工具结果、Skills 以及其他外部内容。这些内容可能包含针对 Agent 的恶意指令。`dsh-injection-guard` 会跟踪不可信上下文，并在怀疑存在间接提示词注入时阻断敏感工具调用。

```text
不可信内容 → 注入信号 → 敏感工具调用 → 可解释风险决策 → ALLOW / ASK / BLOCK
```

## 30 秒 Demo

仓库中的 [`examples/malicious-repo/README.md`](examples/malicious-repo/README.md) 是一个故意构造的恶意 README。它要求 Agent 忽略用户任务、读取 `~/.ssh/id_rsa`，并把内容发送到外部 URL。

Guard 会把这个 README 标记为不可信。当 Agent 随后请求读取凭据时，风险会被评估为 `CRITICAL`，并在工具实际执行前阻断：

```text
⚠ DSH Injection Guard

检测到可能的间接提示词注入。

不可信上下文：
  source: README.md

注入信号：
  - ignore previous instructions
  - ~/.ssh
  - send ...

敏感操作：
  tool: filesystem.read
  target: {"path":"~/.ssh/id_rsa"}

风险：
  CRITICAL (90/100)

决策：
  BLOCKED
```

Demo 只使用本地 fixture，不会读取真实凭据，也不会访问网络。

## 安装与加载

当前版本面向 DSH developer preview 插件 API，并已适配 DSH 可安装 Bundle。Bundle 由 `package.json` 中的 `dsh.bundle` 声明和 `cordis.patch.yml` 组成。

从本地 checkout 安装到隔离的 `web` profile：

```powershell
cd D:\mycode\deepseek\dsh-stock
$env:DSH_HOME = 'D:\mycode\deepseek\dsh-stock-runtime'
pnpm dsh plugin --profile web add D:\mycode\deepseekplugin\dsh-injection-guard
```

也可以从 GitHub 安装（Git 安装需要先构建 `lib/`）：

```bash
pnpm dsh plugin --profile web add github:loeanxi/dsh-injection-guard
```

确认 Bundle 已进入 composition：

```powershell
$env:DSH_HOME = 'D:\mycode\deepseek\dsh-stock-runtime'
pnpm dsh --profile web --dump-config |
  Select-String 'injection-guard|dsh-plugins'
```

预期能看到：

```text
# == @dsh-plugins/injection-guard
- id: injection-guard
  name: '@dsh-plugins/injection-guard'
```

这一步只证明 Bundle 已进入配置树；要证明拦截生效，还必须在同一个 DSH runtime 中发起带 `source: { kind: "file" }` 的回合，并让 Agent 产生敏感 Tool Call。完整的确定性验证可运行：

```bash
npm test
```

DSH preview API 仍在快速变化，生产环境应固定兼容的 DSH 依赖版本。

## 检测范围

v0.1 使用确定性规则，不调用 LLM Security Judge：

- 指令劫持：`ignore previous instructions`、`override system`、伪造 system/developer message
- 身份与权限伪装：`you are now`、管理员身份、安全验证等
- 凭据访问：`.env`、`.ssh`、`.aws`、私钥、密码、Token、credentials
- 外传行为：`curl`、`wget`、upload、webhook、HTTP 提交
- 混淆或隐蔽执行：`base64`、`eval`、decode、execute/run command

敏感 Sink 包括凭据访问、网络操作、Shell 执行、下载后执行，以及破坏性文件操作。

## 工作原理

在 `agent/pre-step` 阶段，插件对消息来源进行分类，并保存当前 Turn 的风险状态。默认将 file、web、tool、document 内容视为不可信。

在 `tools/post-execute` 阶段，插件还会检查刚完成的 Tool 输出，并把检测到的注入信号带入同一 Turn 的下一步。这样即使 DSH 下一次 `agent/pre-step.messages` 没有回填 Tool Result，也不会丢失恶意 README 的风险状态。如果缺少 source 元数据但已经检测到注入信号，插件会保守地将上下文判为不可信。

在 `tools/pre-execute` 阶段，插件分析即将执行的 Tool Call，将敏感 Sink 与当前 Turn 风险状态结合，并返回 DSH 原生的 `allow`、`ask` 或 `deny` 决策。被阻断的调用会在审计信息中说明来源、信号、目标、分数和最终决策；凭据类参数会在审计日志中脱敏。

v0.1 的评分规则保持简单且可解释：

| 信号 | 分值 |
| --- | ---: |
| 存在不可信上下文 | +20 |
| 存在注入信号 | +30 |
| 凭据访问 | +40 |
| 网络操作 | +40 |
| 下载后执行 | +50 |
| Shell / 权限操作 | +40 |
| 破坏性文件操作 | +30 |

`0–29` 为 `LOW/ALLOW`，`30–59` 为 `MEDIUM/ALLOW + log`，`60–79` 为 `HIGH/ASK`，`80+` 为 `CRITICAL/BLOCK`。

## 本地测试

```bash
npm install
npm test
npm run test:integration
npm run typecheck
npm run build
```

集成测试会验证真实 DSH Loader composition，以及从恶意 README 内容到凭据 Sink 被阻断的 DSH ToolRuntime 路径。所有 Sink 都是本地模拟工具。

## 范围与限制

这是一个 Turn-level、source-aware 的策略信号，不是：

- 精确到字符级别的因果追踪或 Taint Tracking；
- 通用权限系统；
- Sandbox；
- 普通危险命令黑名单；
- 基于 LLM 的语义裁判；
- 对恶意内容影响 Agent 的绝对保证。

外围 DSH composition 仍应保留来源信息。敏感操作仍应配合独立的权限控制、参数校验、Sandbox 和用户审批。

## 研究依据

本项目参考了近期评测 [Security Assessment of DeepSeek Harness with A.I.G: Evaluating Resistance to Indirect Prompt Injection](https://arxiv.org/abs/2608.16393)。该评测在真实 DSH Runtime 上测试了多种内容渠道、载体格式和攻击变体，特别指出 fake completion、obfuscation、skills、hidden Unicode 以及文件载体表示是重要测试维度。

本地调研记录见 [`research/dsh-prompt-injection.md`](research/dsh-prompt-injection.md)。

## 当前状态

本仓库包含 v0.1 MVP：基于规则的检测、来源感知的 Turn 状态、敏感 Sink 分析、风险评分、审计日志、恶意 README fixture，以及 DSH 集成测试。

许可证：MIT
