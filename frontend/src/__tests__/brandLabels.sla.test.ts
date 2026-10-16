import { describe, expect, it } from 'vitest'
import { slaText } from '@/components/brand/brandLabels'

describe('slaText', () => {
  it('says nothing when there is no deadline', () => {
    expect(slaText({ state: 'none' })).toBe('')
    expect(slaText(undefined)).toBe('')
  })
  it('names hours left, and under an hour', () => {
    expect(slaText({ state: 'on_track', hours_left: 3.6 })).toBe('On track: 4 h left')
    expect(slaText({ state: 'due_soon', hours_left: 0.4 })).toBe('Due soon: under an hour left')
  })
  it('says how overdue, and whether a closed case met its target', () => {
    expect(slaText({ state: 'breached', hours_left: -5.2 })).toBe('Overdue by 5 h')
    expect(slaText({ state: 'met', hours_left: null })).toBe('Closed within its target')
    expect(slaText({ state: 'breached', hours_left: null })).toBe('Closed after its target')
  })
})
