/**
 * Brand Guard store and label helpers: filters, brand switching, decisions, and the plain-language formatters.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useBrandGuardStore } from '@/stores/brandGuard'
import { humanHours, rungsFor, timeAgo } from '@/components/brand/brandLabels'
import * as client from '@/api/client'

vi.mock('@/api/client', () => ({
  api: {
    brandProfiles: vi.fn(), brandCandidates: vi.fn(), brandGuardSummary: vi.fn(), brandSources: vi.fn(),
    brandSetStatus: vi.fn(), brandScan: vi.fn(), brandScanRun: vi.fn(), brandCampaigns: vi.fn(),
  },
  setToken: vi.fn(), clearToken: vi.fn(), getToken: vi.fn(() => null),
}))

const api = client.api as any
const cand = (id: string, status: string) => ({ id, status, candidate_domain: `${id}.com`, verdict: { key: 'watch' } })

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  api.brandSources.mockResolvedValue([])
  api.brandCampaigns.mockResolvedValue([{ id: 'c1', name: 'acme-login cluster' }])
  api.brandGuardSummary.mockResolvedValue({ open_candidates: 1 })
  api.brandCandidates.mockResolvedValue([cand('a', 'monitoring'), cand('b', 'confirmed'), cand('c', 'takedown'), cand('d', 'false_positive'), cand('e', 'partner')])
})

describe('brand guard store', () => {
  it('loads the first brand by default and scopes candidates and summary to it', async () => {
    api.brandProfiles.mockResolvedValue([{ id: 'p1', latest_run: null }, { id: 'p2', latest_run: null }])
    const s = useBrandGuardStore()
    await s.load()
    expect(s.profile.id).toBe('p1')
    expect(api.brandCandidates).toHaveBeenCalledWith(expect.objectContaining({ profile_id: 'p1' }))
    expect(api.brandGuardSummary).toHaveBeenCalledWith('p1')
  })

  it('switching brands reloads for the new brand and remembers the choice', async () => {
    api.brandProfiles.mockResolvedValue([{ id: 'p1', latest_run: null }, { id: 'p2', latest_run: null }])
    const s = useBrandGuardStore()
    await s.load()
    await s.select('p2')
    expect(s.profile.id).toBe('p2')
    expect(api.brandCandidates).toHaveBeenLastCalledWith(expect.objectContaining({ profile_id: 'p2' }))
    expect(localStorage.getItem('brand_guard_profile')).toBe('p2')
  })

  it('selecting the already-selected brand does nothing', async () => {
    api.brandProfiles.mockResolvedValue([{ id: 'p1', latest_run: null }])
    const s = useBrandGuardStore()
    await s.load()
    api.brandCandidates.mockClear()
    await s.select('p1')
    expect(api.brandCandidates).not.toHaveBeenCalled()
  })

  it('"In case" shows confirmed and takedown; "Not a threat" shows all three reasons; others pass through to the server', async () => {
    api.brandProfiles.mockResolvedValue([{ id: 'p1', latest_run: null }])
    const s = useBrandGuardStore()
    await s.load()
    await s.loadCandidates('in_case')
    expect(s.candidates.map((c: any) => c.id)).toEqual(['b', 'c'])
    await s.loadCandidates('not_a_threat')
    expect(s.candidates.map((c: any) => c.id)).toEqual(['d', 'e'])
    await s.loadCandidates('monitoring')
    expect(s.candidates.map((c: any) => c.id)).toEqual(['a'])
    await s.loadCandidates('open')
    expect(api.brandCandidates).toHaveBeenLastCalledWith(expect.objectContaining({ status: 'open' }))
    await s.loadCandidates('all')
    expect(api.brandCandidates).toHaveBeenLastCalledWith(expect.objectContaining({ status: undefined }))
  })

  it('a decision updates the row in place from the server answer', async () => {
    api.brandProfiles.mockResolvedValue([{ id: 'p1', latest_run: null }])
    const s = useBrandGuardStore()
    await s.load()
    api.brandSetStatus.mockResolvedValue({ id: 'a', status: 'partner', decision: { key: 'not_a_threat', reason: 'partner' } })
    await s.decide('a', 'partner', 'supplier')
    expect(api.brandSetStatus).toHaveBeenCalledWith('a', 'partner', 'supplier')
    expect(s.candidates.find((c: any) => c.id === 'a').decision.reason).toBe('partner')
    expect(s.candidates.find((c: any) => c.id === 'b').status).toBe('confirmed')
  })

  it('resumes watching a scan that is still running when the page opens, and reports scanning', async () => {
    api.brandProfiles.mockResolvedValue([{ id: 'p1', latest_run: { id: 'r1', status: 'running' } }])
    api.brandScanRun.mockResolvedValue({ id: 'r1', status: 'running' })
    const s = useBrandGuardStore()
    await s.load()
    expect(s.scanning).toBe(true)
    s.stopPolling()
  })

  it('a load failure is reported, not thrown, and leaves the store unloaded', async () => {
    api.brandProfiles.mockRejectedValue(new Error('boom'))
    const s = useBrandGuardStore()
    await expect(s.load()).resolves.toBeUndefined()
    expect(s.loaded).toBe(false)
  })
})

describe('campaigns in the store', () => {
  it('loads campaigns for the shown brand with everything else', async () => {
    api.brandProfiles.mockResolvedValue([{ id: 'p1', latest_run: null }])
    const s = useBrandGuardStore()
    await s.load()
    expect(api.brandCampaigns).toHaveBeenCalledWith('p1')
    expect(s.campaigns.map((c: any) => c.id)).toEqual(['c1'])
  })

  it('switching brand clears the previous campaigns and loads the new ones', async () => {
    api.brandProfiles.mockResolvedValue([{ id: 'p1', latest_run: null }, { id: 'p2', latest_run: null }])
    const s = useBrandGuardStore()
    await s.load()
    api.brandCampaigns.mockResolvedValue([])
    await s.select('p2')
    expect(api.brandCampaigns).toHaveBeenLastCalledWith('p2')
    expect(s.campaigns).toEqual([])
  })

  it('a failed campaign load leaves the list as it was instead of throwing', async () => {
    api.brandProfiles.mockResolvedValue([{ id: 'p1', latest_run: null }])
    const s = useBrandGuardStore()
    await s.load()
    api.brandCampaigns.mockRejectedValue(new Error('down'))
    await expect(s.loadCampaigns()).resolves.toBeUndefined()
    expect(s.campaigns).toHaveLength(1)
  })

  it('a decision refreshes campaigns too, because a decision can change who belongs in one', async () => {
    api.brandProfiles.mockResolvedValue([{ id: 'p1', latest_run: null }])
    const s = useBrandGuardStore()
    await s.load()
    api.brandCampaigns.mockClear()
    await s.refreshAfterChange()
    expect(api.brandCampaigns).toHaveBeenCalledTimes(1)
  })
})

describe('label helpers', () => {
  it('formats detection time in the largest sensible unit', () => {
    expect(humanHours(null)).toBe('—')
    expect(humanHours(0.5)).toBe('30 min')
    expect(humanHours(3.7)).toBe('3.7 h')
    expect(humanHours(12)).toBe('12 h')
    expect(humanHours(72)).toBe('3 days')
  })

  it('marks every rung up to the current stage as reached', () => {
    expect(rungsFor('registered').map(r => r.on)).toEqual([true, false, false, false])
    expect(rungsFor('mail_enabled').map(r => r.on)).toEqual([true, true, true, false])
    expect(rungsFor('mail_enabled').find(r => r.current)?.key).toBe('mail_enabled')
    expect(rungsFor('unregistered').every(r => !r.on)).toBe(true)
  })

  it('says when something happened in plain words', () => {
    expect(timeAgo(null)).toBe('never')
    expect(timeAgo(new Date().toISOString())).toBe('just now')
    expect(timeAgo(new Date(Date.now() - 5 * 60000).toISOString())).toBe('5 min ago')
    expect(timeAgo(new Date(Date.now() - 3 * 3600000).toISOString())).toBe('3 h ago')
    expect(timeAgo(new Date(Date.now() - 5 * 86400000).toISOString())).toBe('5 days ago')
  })
})
