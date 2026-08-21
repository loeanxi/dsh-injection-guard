# dsh-injection-guard

[English](#dsh-injection-guard) | [中文](#dsh-injection-guard-中文)

Source-aware prompt injection protection for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness).

**v0.1.0 status:** installable DSH bundle, turn-level source tracking, deterministic injection signals, sensitive-tool interception, explainable risk scoring, localized audit logs, and reproducible DSH integration fixtures.

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
    failClosed: true
    semantic: true
    locale: zh-CN
```

The DSH preview API is still changing. Pin compatible DSH package versions in production deployments.

### Configuration

All options are optional. The safe defaults are shown below:

| Option | Default | Purpose |
| --- | --- | --- |
| `log` | `true` | Emit an explainable audit message for each decision |
| `askThreshold` | `60` | Minimum score for `ASK` when a block threshold is not reached |
| `failClosed` | `true` | Review-gate sensitive calls when no turn state is available |
| `semantic` | `true` | Add conservative local intent signals; never weakens deterministic rules |
| `locale` | `en` | Use `en` or `zh-CN` for audit text while retaining machine markers |

For Chinese audit output:

```yaml
config:
  log: true
  locale: zh-CN
```

## What it detects

The v0.1 detector uses deterministic rules and does not call an LLM security judge.

- Instruction hijacking: `ignore previous instructions`, `override system`, fake system/developer messages
- Identity and authority spoofing: `you are now`, administrator claims, security verification
- Credential access: `.env`, `.ssh`, `.aws`, private keys, passwords, tokens, credentials
- Exfiltration: `curl`, `wget`, upload, webhook, HTTP submission
- Obfuscated or hidden execution: `base64`, `eval`, decode, execute/run commands, zero-width and bidirectional Unicode controls

Sensitive sinks include credential access, network operations (including PowerShell web requests and `scp`/`nc`), shell execution, download-to-execute patterns (including PowerShell `iwr | iex` and interpreter pipes), and destructive filesystem operations.

## How it works

At `agent/pre-step`, the plugin classifies message sources and records the current turn's risk state. File, web, tool, and document content is treated as untrusted by default.

At `tools/post-execute`, it also inspects the completed tool output and carries detected injection signals into the next step of the same turn. This covers DSH compositions where tool results are not repeated in the next `agent/pre-step.messages` snapshot. If source metadata is absent but an injection signal is present, the context is conservatively treated as untrusted.

The parser accepts DSH text blocks, arrays, nested `content`/`data`/`parts` values, and string source kinds used by lightweight adapters. Repeated snapshots and repeated tool results are deduplicated so a long turn does not inflate its audit trail.

Signals retain the source label and normalized match offsets for audit and downstream policy use. A signal in an explicitly trusted user/system message is not reclassified as untrusted; provenance must be unknown or explicitly untrusted before it can affect a sensitive sink.

The optional `semantic` layer is enabled by default. It is a conservative local intent scorer: it can add up to 20 points and reasons, but it cannot reduce a deterministic score or turn `BLOCK` into `ALLOW`. A host can disable it with `semantic: false` while retaining the deterministic baseline.

At `tools/pre-execute`, it classifies the proposed tool call, combines the sink with the turn risk state, and returns a DSH-native `allow`, `ask`, or `deny` decision. Blocked calls include the source, signals, target, score, and decision in the audit message. Credential-like arguments are redacted from audit output.

If a sensitive Tool Call arrives before the plugin has observed an `agent/pre-step`, the default `failClosed: true` setting returns `ask` instead of silently allowing the call. Set it to `false` only when another policy layer owns this fail-safe decision.

Credential-like filesystem reads are always review-gated: with untrusted or injected context they are blocked, and even a trusted-context read returns `ask` for explicit approval. This prevents an absolute Windows path such as `C:\\Users\\name\\.ssh\\id_rsa` from being silently passed through.

Audit messages support `locale: en` and `locale: zh-CN`. Chinese mode keeps the machine-readable `BLOCKED`, `ASKED`, and `ALLOWED` markers, for example `已阻断（BLOCKED）`.

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
npm run test:robustness
npm run typecheck
npm run build
```

The repository corpus evaluator also reports precision, recall, false-positive rate, false-negative rate, and interception rate:

```bash
npm test -- tests/corpus-evaluation.test.ts
```

The checked-in corpus is a small regression baseline, not a production benchmark; expand it with representative benign and adversarial DSH carriers before making release claims.

The integration tests verify both the real DSH Loader composition and the real DSH ToolRuntime path from malicious README content to a blocked credential sink. All sinks are local simulated tools.

To reproduce the same flow manually, place the fixture in the active DSH workspace and ask the agent to read it. The expected security signal is an audit entry containing `BLOCKED` (Chinese mode also contains `已阻断`); the dangerous tool body must not run. Do not use a real private key or a real external endpoint.

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

**v0.1.0 状态：** 已具备可安装的 DSH Bundle、Turn-level 来源跟踪、确定性注入信号检测、敏感 Tool Call 拦截、可解释风险评分、多语言审计日志，以及可复现的 DSH 集成测试夹具。

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

### 配置项

所有配置项均可省略，以下是安全默认值：

| 配置项 | 默认值 | 作用 |
| --- | --- | --- |
| `log` | `true` | 为每次决策输出可解释审计信息 |
| `askThreshold` | `60` | 未达到阻断阈值时触发 `ASK` 的最低分数 |
| `failClosed` | `true` | 没有 Turn 状态时，对敏感调用进行人工复核 |
| `semantic` | `true` | 增加保守的本地意图信号，不会削弱确定性规则 |
| `locale` | `en` | 使用 `en` 或 `zh-CN` 输出审计文本，同时保留机器标记 |

如果希望页面上看到中文审计结果：

```yaml
config:
  log: true
  locale: zh-CN
```

## 检测范围

v0.1 使用确定性规则，不调用 LLM Security Judge：

- 指令劫持：`ignore previous instructions`、`override system`、伪造 system/developer message
- 身份与权限伪装：`you are now`、管理员身份、安全验证等
- 凭据访问：`.env`、`.ssh`、`.aws`、私钥、密码、Token、credentials
- 外传行为：`curl`、`wget`、upload、webhook、HTTP 提交
- 混淆或隐蔽执行：`base64`、`eval`、decode、execute/run command，以及零宽和双向 Unicode 控制字符

敏感 Sink 包括凭据访问、网络操作（含 PowerShell Web 请求以及 `scp`/`nc`）、Shell 执行、下载后执行（含 PowerShell `iwr | iex` 和解释器管道），以及破坏性文件操作。

## 工作原理

在 `agent/pre-step` 阶段，插件对消息来源进行分类，并保存当前 Turn 的风险状态。默认将 file、web、tool、document 内容视为不可信。

在 `tools/post-execute` 阶段，插件还会检查刚完成的 Tool 输出，并把检测到的注入信号带入同一 Turn 的下一步。这样即使 DSH 下一次 `agent/pre-step.messages` 没有回填 Tool Result，也不会丢失恶意 README 的风险状态。如果缺少 source 元数据但已经检测到注入信号，插件会保守地将上下文判为不可信。

解析器支持 DSH 文本块、数组、嵌套的 `content`/`data`/`parts` 内容，以及轻量适配器使用的字符串 source kind。重复的消息快照和 Tool Result 会去重，避免长 Turn 造成审计记录膨胀。

每个信号会保留来源标签和规范化文本中的匹配范围，供审计和后续策略使用。明确标记为 trusted 的 user/system 消息即使包含测试关键词，也不会被重新判定为不可信；只有来源未知或明确不可信时，信号才会影响敏感 Sink。

可选的 `semantic` 层默认开启。它是保守的本地意图评分器，最多增加 20 分和解释原因，但不能降低确定性评分，也不能把 `BLOCK` 改成 `ALLOW`。设置 `semantic: false` 可以关闭它，同时保留确定性规则底线。

在 `tools/pre-execute` 阶段，插件分析即将执行的 Tool Call，将敏感 Sink 与当前 Turn 风险状态结合，并返回 DSH 原生的 `allow`、`ask` 或 `deny` 决策。被阻断的调用会在审计信息中说明来源、信号、目标、分数和最终决策；凭据类参数会在审计日志中脱敏。

如果敏感 Tool Call 到达时插件还没有观察到 `agent/pre-step`，默认的 `failClosed: true` 会返回 `ask`，而不是静默放行。只有在其他策略层负责这个故障安全决策时，才应设置为 `false`。

凭据类文件读取始终需要人工复核：如果关联了不可信或注入上下文则直接阻断；即使上下文可信，也会返回 `ask` 请求显式批准。这样可以避免类似 `C:\\Users\\name\\.ssh\\id_rsa` 的 Windows 绝对路径被静默放行。

审计消息支持 `locale: en` 和 `locale: zh-CN`。中文模式仍保留机器可识别的 `BLOCKED`、`ASKED`、`ALLOWED` 标记，例如 `已阻断（BLOCKED）`。

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
npm run test:robustness
npm run typecheck
npm run build
```

仓库还提供对照集评估，输出 precision、recall、误报率、漏报率和拦截率：

```bash
npm test -- tests/corpus-evaluation.test.ts
```

当前对照集只是小型回归基线，不是生产 benchmark；发布前应补充有代表性的正常样本和 adversarial DSH 载体。

集成测试会验证真实 DSH Loader composition，以及从恶意 README 内容到凭据 Sink 被阻断的 DSH ToolRuntime 路径。所有 Sink 都是本地模拟工具。

页面手测时，请把 fixture 放进当前 DSH 工作区，再要求 Agent 读取它。预期审计信息同时包含 `已阻断` 和机器可识别的 `BLOCKED`，危险 Tool 的实际执行体不会运行。不要使用真实私钥，也不要访问真实外部地址。

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
