import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import Include from '@deepseek-ai/cordis-plugin-include'
import * as Guard from '../src/index.js'

let context: Context | undefined
let root: string | undefined
afterEach(async () => { await context?.fiber.dispose(); context = undefined; if (root) await rm(root, { recursive: true, force: true }); root = undefined })

describe('DSH Loader integration', () => {
  it('loads the plugin export shape through cordis.yml', async () => {
    root = await mkdtemp(join(tmpdir(), 'dsh-injection-loader-'))
    const configPath = join(root, 'cordis.yml')
    await writeFile(configPath, ['- id: injection-guard', "  name: '@dsh-plugins/injection-guard'", ''].join('\n'))
    const ctx = new Context()
    context = ctx
    ctx.baseUrl = pathToFileURL(root).href + '/'
    await ctx.plugin(Loader)
    ctx.loader.builtins.include = Include
    ctx.loader.internal = { version: 'v2', async import(specifier: string) { if (specifier !== '@dsh-plugins/injection-guard') throw new Error(`unexpected import: ${specifier}`); return Guard } } as never
    await ctx.loader.create({ name: 'cordis:include', config: { path: pathToFileURL(configPath).href } })
    await ctx.loader.await()
    const agent = {}
    const decision = await ctx.waterfall('agent/pre-step', { agent, messages: [] }, () => Promise.resolve({ kind: 'enter', messages: [] }))
    expect(decision).toMatchObject({ kind: 'enter' })
  })
})
