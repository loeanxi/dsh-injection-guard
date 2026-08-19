import { describe, expect, it } from 'vitest'
import { evaluateCorpus, evaluationCorpus } from '../src/evaluation/corpus.js'

describe('attack and benign evaluation corpus', () => {
  it('reports the current deterministic baseline metrics', () => {
    const metrics = evaluateCorpus()
    expect(metrics.total).toBe(evaluationCorpus.length)
    expect(metrics.attacks).toBe(4)
    expect(metrics.benign).toBe(4)
    expect(metrics.interceptionRate).toBeGreaterThanOrEqual(0.75)
    expect(metrics.falsePositiveRate).toBeLessThanOrEqual(0.25)
    expect(metrics.falseNegativeRate).toBeLessThanOrEqual(0.25)
    console.info('dsh-injection-guard corpus metrics', metrics)
  })
})
