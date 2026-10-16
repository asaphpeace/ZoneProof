import { describe, expect, it } from 'vitest'
import { funnelPct, funnelReason } from '@/components/brand/brandLabels'

describe('funnel labels', () => {
  it('spells out known reasons in plain words', () => {
    expect(funnelReason('probed_recently')).toBe('Visited recently')
    expect(funnelReason('expired_unclaimed')).toContain('worker down or behind')
    expect(funnelReason('trimmed_by_plan_budget')).toContain('plan')
    expect(funnelReason('layout')).toBe('Same layout and colours')
  })
  it('reads a status split as the current state and never hides an unknown key', () => {
    expect(funnelReason('status_suspicious')).toBe('Now suspicious')
    expect(funnelReason('status_false_positive')).toBe('Now false positive')
    expect(funnelReason('some_new_reason')).toBe('Some new reason')
  })
  it('shows a pass rate as a whole percentage and "no data" as a dash, never as zero', () => {
    expect(funnelPct(0.333)).toBe('33%')
    expect(funnelPct(1)).toBe('100%')
    expect(funnelPct(0)).toBe('0%')
    expect(funnelPct(null)).toBe('–')
    expect(funnelPct(undefined)).toBe('–')
  })
})
