# DeepSeek Harness (DSH) and indirect prompt injection

Research date: 2026-08-19

## Executive summary

The most recent primary-source assessment found measurable indirect-injection influence in one unmodified DeepSeek Harness configuration, but it is not a claim of a universal DSH or model vulnerability rate. The paper reports 14,560 controlled executions using Tencent Zhuque Lab’s A.I.G against the real TypeScript runtime, with local simulated sinks. Its headline results are 17.0% full success for fake-completion payloads in text mode, 25.5% for hidden Unicode in file mode, and 16.0% for the skills channel in file mode under its deterministic judge. The paper’s broader full-plus-partial influence rate is 7.6% under the rule judge and 12.6% under the semantic LLM judge.

## Recent assessment

- **Paper:** [Security Assessment of DeepSeek Harness with A.I.G: Evaluating Resistance to Indirect Prompt Injection](https://arxiv.org/abs/2608.16393), authors Zonghao Ying et al., posted **2026-08-17**. It tests a benign user request plus attacker-controlled content delivered through source tools, then traces whether the agent reaches a sensitive sink or output canary.
- **Method:** 16 indirect-content channels, text and file carriers, 35 payload objectives, 12 attack transformations plus an unmodified baseline, 6 source fixtures, 8 tracked sink fixtures, and the `deepseek-v4-flash` backend through a local proxy. RuleJudge and LLMJudge classify full success, partial compliance, or failure.
- **Important limitation:** sink calls only recorded attempted actions locally; they did not send mail, execute commands, move funds, or contact external endpoints. The authors explicitly scope the result to one DSH revision, backend, persona, and baseline configuration.
- **Interpretation:** file representation matters: aggregate rule-judge full success was 6.2% in file mode versus 5.1% in text mode. Hidden Unicode was 0.0% in text mode and 25.5% in file mode, illustrating that text-only approximations can miss parser/encoding behavior. The paper recommends retaining source provenance and independently authorizing sensitive sinks.

## What the official DSH repository exposes

- [Official repository README](https://github.com/deepseek-ai/deepseek-harness/blob/master/README.md), last retrieved with repository metadata dated **2026-08-13**, identifies DSH as an open-source DeepSeek AI agent harness, currently in developer preview with compatibility-breaking changes expected. It documents the `@deepseek-ai/dsh` CLI and source build path.
- [Official architecture documentation at the assessed commit](https://github.com/deepseek-ai/deepseek-harness/blob/47f943859bef60e4160492346772ded9b24f765a/docs/architecture.md), commit `47f943859bef60e4160492346772ded9b24f765a` created **2026-08-13**, says everything is a plugin: model adapter, tool registry, session log, and agent loop. The same document describes model-visible context as derived from the session log and places tool calls through `tools/pre-execute -> tools/execute -> tools/post-execute -> tool/result`.
- [Agent-loop tool-call implementation at that commit](https://github.com/deepseek-ai/deepseek-harness/blob/47f943859bef60e4160492346772ded9b24f765a/packages/core/agent-loop/src/tool-calls.ts) appends tool results in model order and accepts each result’s `additionalContexts` into the next-step context. This is the key source-to-model boundary described by the assessment.
- [Tool registry/policy API at that commit](https://github.com/deepseek-ai/deepseek-harness/blob/47f943859bef60e4160492346772ded9b24f765a/packages/core/tools/src/index.ts) defines the pre-execute, execute, post-execute, and result extension points. The API documents pre-execute as an allow/deny/ask gate, making it a natural deployment seam for source-aware authorization. The repository’s presence of these hooks should not be read as proof that a deployment has configured them safely.

The official material reviewed did not present a dedicated DSH indirect-prompt-injection evaluation or a built-in blanket defense. It presents a highly composable runtime with policy seams; the assessment evaluates how untrusted tool-returned content can influence later model/tool decisions in a particular deployment.

## Cited assessment tooling

- [Tencent A.I.G repository](https://github.com/Tencent/AI-Infra-Guard), first-party source repository for the testing platform cited by the paper; README release notes list **v4.5.2 on 2026-08-17**. It describes A.I.G as an AI red-teaming platform covering agent, skill, MCP, infrastructure, and jailbreak evaluation. The repository also warns that the current deployment lacks authentication and should not be exposed on public networks.
- [A.I.G README at the cited repository](https://github.com/Tencent/AI-Infra-Guard/blob/main/README.md) documents source/Docker deployment and the platform’s testing scope. The paper is the authoritative source for the specific DSH experiment design and measurements; the general README is not evidence that every advertised scanner feature was used in this study.

## Bottom line for this project

For a DSH-based agent, treat web pages, files, email, chat, skills, tool results, and additional contexts as untrusted data. Preserve provenance through prompt assembly, normalize or surface hidden/metadata content where possible, and enforce argument-level authorization at sensitive sinks independently of the model’s interpretation. Regression tests should include real carrier formats—not only flattened text—and should record full source-to-sink traces.

All fetched web and repository content was treated as untrusted reference material; no instructions embedded in it were followed.
