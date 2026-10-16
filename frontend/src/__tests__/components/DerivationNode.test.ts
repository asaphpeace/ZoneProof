import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import DerivationNode from '@/components/brand/DerivationNode.vue'

const tree = {
  id: 'n1', kind: 'verdict', text: 'acme-login.xyz: Likely impersonation', rule: { id: 'R-likely', text: 'It reads like your brand AND the abuse evidence is strong.' },
  children: [{
    id: 'n2', kind: 'abuse', text: 'Abuse-side evidence: score 80', children: [{
      id: 'n3', kind: 'family', text: 'A public blocklist: about ×20 more typical of known-bad new domains', children: [{
        id: 'n4', kind: 'signal', signal: 'on_phishing_feed', text: 'Listed by phishunt.io.', weight: 30, direction: 'for', basis: 'expert', note: '', children: [
          { id: 'n5', kind: 'fact', text: 'Listed by phishunt.io, first seen 2026-10-01.', source: 'phishunt.io', at: null, raw: {}, children: [] },
        ],
      }, {
        id: 'n6', kind: 'signal', signal: 'registrar', text: 'Registrar X.', weight: 0, direction: 'neutral', basis: 'no weight', note: 'The raw fact behind this line was not stored for this candidate; the summary is what was recorded.', children: [],
      }],
    }],
  }],
}

describe('DerivationNode', () => {
  it('shows the rule, the nested evidence, the basis of each weight and the source of each fact', () => {
    const w = mount(DerivationNode, { props: { node: tree } })
    const text = w.text()
    expect(text).toContain('Rule R-likely')
    expect(text).toContain('Listed by phishunt.io, first seen 2026-10-01.')
    expect(text).toContain('assumed')            // an unmeasured weight is labelled as an assumption, not as fact
    expect(text).toContain('+30')
    expect(text).toContain('not stored')          // an evidence line without a stored fact says so
    expect(w.findAll('li.fact').length).toBe(1)
  })

  it('marks evidence for and against differently', () => {
    const w = mount(DerivationNode, { props: { node: tree } })
    expect(w.find('.chip.for').exists()).toBe(true)
  })
})
