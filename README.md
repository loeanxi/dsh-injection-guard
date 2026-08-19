# dsh-injection-guard

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

At `tools/pre-execute`, it classifies the proposed tool call, combines the sink with the turn risk state, and returns a DSH-native `allow`, `ask`, or `deny` decision. Blocked calls include the source, signals, target, score, and decision in the audit message.

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
