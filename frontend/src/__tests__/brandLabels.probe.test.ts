import { describe, expect, it } from 'vitest'
import { probeLines } from '@/components/brand/brandLabels'

describe('probeLines', () => {
  it('says nothing without a probe and admits an unreachable page', () => {
    expect(probeLines(null)).toEqual([])
    expect(probeLines({ reachable: false })).toEqual([{ text: 'We tried to load its page and could not reach it.', tone: 'plain' }])
  })
  it('reports a password form, offsite posting, a copied icon and an odd certificate as warnings', () => {
    const lines = probeLines({ reachable: true, password_form: true, offsite_password_form: true, favicon_matches_brand: true, title: 'Acme - sign in',
      certificate: { issuer: 'X', age_days: 2, self_signed: true, expired: false, valid_for_host: true } })
    const text = lines.map(l => l.text).join(' | ')
    expect(text).toContain('sends it to a different site')
    expect(text).toContain('brand\'s own icon')
    expect(text).toContain('self-signed')
    expect(lines.find(l => l.text.includes('password'))!.tone).toBe('bad')
  })
  it('treats a redirect to the brand as reassuring and always warns about challenge pages', () => {
    const r = probeLines({ reachable: true, redirects: true, redirects_to_brand: true, final_host: 'www.acme.com', challenge_page: true })
    expect(r[0]).toEqual({ text: "It redirects to www.acme.com, the brand's own site.", tone: 'ok' })
    expect(r.some(l => l.text.includes('real visitors may see something different'))).toBe(true)
  })
  it('says plainly when there is no password form, without calling the page clean', () => {
    const t = probeLines({ reachable: true, password_form: false }).map(l => l.text)
    expect(t).toContain('No password form on the page we saw.')
  })
  it('reports a near-copy icon, reused wording and a look-alike layout, and says the layout is not scored', () => {
    const t = probeLines({ reachable: true, password_form: false, similarity: { icon: { similar: true }, wording: { shared: 0.82, n: 120 }, visual: { similar: true } } })
    const text = t.map(l => l.text)
    expect(text).toContain('Its icon is a near copy of the brand\'s (re-sized or re-encoded).')
    expect(text).toContain('82% of the wording on its page also appears on the brand\'s own page.')
    expect(text.find(x => x.includes('same layout'))).toContain('Not scored')
    expect(t.find(l => l.text.includes('82%'))!.tone).toBe('bad')
  })
  it('does not claim a near-copy icon when the icon is byte-identical (that is its own line), and plays down low overlap', () => {
    const exact = probeLines({ reachable: true, favicon_matches_brand: true, similarity: { icon: { similar: true } } }).map(l => l.text)
    expect(exact.filter(x => x.includes('icon')).length).toBe(1)
    const low = probeLines({ reachable: true, similarity: { wording: { shared: 0.05, n: 90 } } })
    expect(low.find(l => l.text.includes('Little of its wording'))!.tone).toBe('plain')
    expect(probeLines({ reachable: true, similarity: { visual: { similar: false } } }).some(l => l.text.includes('same layout'))).toBe(false)
  })
  it('flags a password form that only appeared after scripts ran, and says nothing extra otherwise', () => {
    const late = probeLines({ reachable: true, password_form: true, form_after_scripts: true })
    expect(late.find(l => l.text.includes('only appears after'))!.tone).toBe('warn')
    expect(probeLines({ reachable: true, password_form: true }).some(l => l.text.includes('only appears after'))).toBe(false)
  })
})
