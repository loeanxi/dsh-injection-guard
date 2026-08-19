import { readFile } from 'node:fs/promises'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import { createUserMessage, CallId } from '@deepseek-ai/dsh-llm'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime, { defineTool } from '@deepseek-ai/dsh-tools'
import { apply } from '../src/index.js'

let context: Context | undefined
afterEach(async () => { await context?.fiber.dispose(); context = undefined })

describe('malicious README to sensitive tool call', () => {
  it('denies a credential read after the README enters model-visible context', async () => {
    const ctx = new Context()
    context = ctx
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    apply(ctx, { log: false })
    let sinkCalled = false
    ctx.tools.register(defineTool({
      name: 'filesystem.read', description: 'read a file', parameters: { path: { type: 'string' } },
      output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
      async execute() { sinkCalled = true; return 'fake secret' },
    }))
    const readme = await readFile('examples/malicious-repo/README.md', 'utf8')
    const agent = {}
    const message = createUserMessage({ content: [{ type: 'text', text: readme }], source: { kind: 'file', path: 'README.md' } })
    await ctx.waterfall('agent/pre-step', { agent, messages: [message] }, () => Promise.resolve({ kind: 'enter', messages: [message] }))
    const result = await ctx.tools.execute({ signal: new AbortController().signal, callId: CallId('demo-credential-read'), name: 'filesystem.read', arguments: { path: '~/.ssh/id_rsa' }, agent } as never)
    expect(result.isError).toBe(true)
    expect(String(result.content[0].text)).toContain('DSH Injection Guard')
    expect(sinkCalled).toBe(false)
  })
})
