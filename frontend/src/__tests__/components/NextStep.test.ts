import { describe, it, expect, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import { createPinia, setActivePinia } from 'pinia'
import NextStep from '@/components/ui/NextStep.vue'
import RoadmapTrack from '@/components/domain/RoadmapTrack.vue'
import TimelineEntry from '@/components/ui/TimelineEntry.vue'

const stub = { template: '<div />' }
function makeRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: ['dmarc', 'tls', 'certs', 'roadmap', 'timeline'].map(name => ({ path: '/' + name, name, component: stub })),
  })
}
const plugins = () => {
  const pinia = createPinia()
  setActivePinia(pinia)
  return [makeRouter(), pinia]
}

const hrefs = (w: any) => w.findAll('a.next-step').map((a: any) => a.attributes('href'))

describe('NextStep', () => {
  beforeEach(() => localStorage.clear())

  it('links to the page and carries the domain', () => {
    const w = mount(NextStep, { props: { to: 'dmarc', label: 'See the senders', domain: 'example.com' }, global: { plugins: plugins() } })
    expect(w.text()).toContain('See the senders')
    expect(w.get('a').attributes('href')).toBe('/dmarc?domain=example.com')
  })

  it('leaves the scope alone when no domain is given', () => {
    const w = mount(NextStep, { props: { to: 'tls', label: 'x' }, global: { plugins: plugins() } })
    expect(w.get('a').attributes('href')).toBe('/tls')
  })
})

const baseTrack = {
  domain: 'example.com', dmarcStage: 1, mtaStage: 1, dmarcComp: 80, dmarcFailSources: 2,
  tlsPassPct: 70, tlsFailReason: 'certificate-expired', advisorMessage: null, advisorCommend: false, advisorLoading: false,
}

describe('Roadmap blockers point at their evidence', () => {
  it('DMARC failures and unaligned senders link to the DMARC page for the domain', () => {
    const w = mount(RoadmapTrack, { props: baseTrack, global: { plugins: plugins() } })
    const h = hrefs(w)
    expect(h.filter((x: string) => x === '/dmarc?domain=example.com').length).toBeGreaterThanOrEqual(2)
  })

  it('a certificate failure links to the certificates page, a low pass rate to the TLS page', () => {
    const w = mount(RoadmapTrack, { props: baseTrack, global: { plugins: plugins() } })
    const h = hrefs(w)
    expect(h).toContain('/certs?domain=example.com')
    expect(h).toContain('/tls?domain=example.com')
  })

  it('a non-certificate TLS failure links to the TLS page', () => {
    const w = mount(RoadmapTrack, {
      props: { ...baseTrack, dmarcStage: 0, tlsFailReason: 'sts-policy-fetch-error', tlsPassPct: 99 },
      global: { plugins: plugins() },
    })
    const h = hrefs(w)
    expect(h).toContain('/tls?domain=example.com')
    expect(h).not.toContain('/certs?domain=example.com')
  })

  it('recommendations link by category', () => {
    const recommendations = [
      { direction: 'hold', severity: 'warn', category: 'cert', title: 't', body: 'b', blocking_reason: null },
    ]
    const w = mount(RoadmapTrack, { props: { ...baseTrack, recommendations: recommendations as any }, global: { plugins: plugins() } })
    expect(hrefs(w)).toContain('/certs?domain=example.com')
  })
})

describe('Timeline entries point at what the change affects', () => {
  const entry = (record_type: string, domain_name: string | null = 'example.com') => ({
    id: '1', record_type, record_host: 'h', previous_value: 'a', current_value: 'b', change_summary: 's',
    change_type: 'modified', is_security_alert: false, detected_at: new Date().toISOString(), domain_name,
  })

  async function expandedLinks(e: any) {
    const w = mount(TimelineEntry, { props: { entry: e }, global: { plugins: plugins() } })
    await w.get('.body').trigger('click')
    return hrefs(w)
  }

  it('a DMARC change links to who is sending and to the roadmap', async () => {
    const h = await expandedLinks(entry('DMARC'))
    expect(h).toEqual(['/dmarc?domain=example.com', '/roadmap?domain=example.com'])
  })

  it('an MTA-STS or MX change links to TLS delivery', async () => {
    expect(await expandedLinks(entry('MTA-STS'))).toContain('/tls?domain=example.com')
    expect(await expandedLinks(entry('MX'))).toContain('/tls?domain=example.com')
  })

  it('falls back to the shared scope when the entry has no domain', async () => {
    localStorage.setItem('zp_scope_domain', 'scoped.example')
    const h = await expandedLinks(entry('SPF', null))
    expect(h).toContain('/dmarc?domain=scoped.example')
  })
})
