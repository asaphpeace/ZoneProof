import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import { createPinia, setActivePinia } from 'pinia'

const sourcesHealth = vi.fn()
vi.mock('@/api/client', () => ({ api: { sourcesHealth: (...a: any[]) => sourcesHealth(...a) } }))

import DataSourcesView from '@/views/DataSourcesView.vue'

const stub = { template: '<div />' }
const router = () => createRouter({
  history: createMemoryHistory(),
  routes: [{ path: '/', name: 'home', component: stub }, ...['dmarc', 'tls', 'certs', 'timeline'].map(name => ({ path: '/' + name, name, component: stub }))],
})

const payload = {
  generated_at: new Date().toISOString(),
  server_started_at: new Date(Date.now() - 3600_000).toISOString(),
  data: [
    {
      key: 'dmarc_reports', label: 'DMARC reports', provides: 'p', status: 'stale', note: 'Some domains are quiet.',
      domains: [{ domain: 'a.example', domain_id: '1', last_at: new Date(Date.now() - 5 * 86400_000).toISOString(), status: 'stale', count: 12 }],
    },
  ],
  integrations: [
    { key: 'report_inbox', label: 'Report inbox (IMAP)', provides: 'p', configured: false, note: 'No inbox password is set.' },
  ],
  jobs: [
    {
      key: 'cert_probe', label: 'Certificate probe', provides: 'p', status: 'failing', note: 'The last run timed out.',
      interval_seconds: 86400, runs: 3, failures: 1, last_started: null,
      last_finished: new Date(Date.now() - 7200_000).toISOString(), last_duration_s: 4.2, next_run: new Date(Date.now() + 3600_000).toISOString(),
    },
  ],
}

async function mountView() {
  setActivePinia(createPinia())
  const w = mount(DataSourcesView, { global: { plugins: [router()] } })
  await flushPromises()
  return w
}

describe('DataSourcesView', () => {
  beforeEach(() => { sourcesHealth.mockClear() })

  it('shows data freshness, services and jobs with plain-language states', async () => {
    sourcesHealth.mockResolvedValue(payload)
    const w = await mountView()
    const t = w.text()
    expect(t).toContain('DMARC reports')
    expect(t).toContain('Out of date')
    expect(t).toContain('Not set up')
    expect(t).toContain('Failing')
    expect(t).toContain('The last run timed out.')
    expect(t).toContain('3 to look at')        // stale data + unconfigured service + failing job
  })

  it('says which server runs the jobs', async () => {
    sourcesHealth.mockResolvedValue({ ...payload, scheduler: { role: 'standby', since: new Date().toISOString() },
      jobs: [{ ...payload.jobs[0], status: 'standby', note: 'Another server is running this job.' }] })
    const w = await mountView()
    expect(w.text()).toContain('Another server is running the background jobs')
    expect(w.text()).toContain('Run by another server')

    sourcesHealth.mockResolvedValue({ ...payload, scheduler: { role: 'leader', since: new Date().toISOString() } })
    const w2 = await mountView()
    expect(w2.text()).toContain('This server is running the background jobs')
  })

  it('lists per-domain freshness on request', async () => {
    sourcesHealth.mockResolvedValue(payload)
    const w = await mountView()
    expect(w.text()).not.toContain('a.example')
    await w.findAll('button.link')[0].trigger('click')
    expect(w.text()).toContain('a.example')
  })

  it('says so when the request fails instead of showing an empty page', async () => {
    sourcesHealth.mockImplementation(() => Promise.reject(new Error('Internal Server Error')))
    const w = await mountView()
    expect(w.text()).toContain('could not be loaded')
  })

  it('explains the admin requirement', async () => {
    sourcesHealth.mockImplementation(() => Promise.reject(new Error('Admin role required')))
    const w = await mountView()
    expect(w.text()).toContain('Only workspace admins')
  })
})
