import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api } from '@/api/client'
import { useUiStore } from '@/stores/ui'

// Shared state for every Brand Guard page: the profile, the dashboard numbers, source health, the scan in flight, and the
// candidate list. Pages ask for what they need; the store keeps one copy and one scan poller.

export const FILTERS = [
  { value: 'open', label: 'Needs attention' },
  { value: 'monitoring', label: 'Watching' },
  { value: 'in_case', label: 'In case' },
  { value: 'not_a_threat', label: 'Not a threat' },
  { value: 'dormant', label: 'Dormant' },
  { value: 'all', label: 'All' },
] as const

// Which stored statuses each filter covers. "open" and "dormant" are server-side views, the rest are plain status sets.
const FILTER_STATUSES: Record<string, string[]> = {
  monitoring: ['monitoring'],
  in_case: ['confirmed', 'takedown'],
  not_a_threat: ['false_positive', 'customer_owned', 'partner', 'benign'],
}

export const useBrandGuardStore = defineStore('brandGuard', () => {
  const ui = useUiStore()

  const loaded = ref(false)
  const loading = ref(false)
  const gated = ref(false)
  const profiles = ref<any[]>([])
  const summary = ref<any>(null)
  const sources = ref<any[]>([])
  const run = ref<any>(null)
  const candidates = ref<any[]>([])
  const candidatesFilter = ref('open')
  const campaigns = ref<any[]>([])
  const adding = ref(false)   // showing the "add another brand" form

  let pollTimer: ReturnType<typeof setInterval> | null = null
  let pollFailures = 0

  // With several brands, one is shown at a time (remembered per browser). Everything below follows the selected brand.
  let remembered = ''
  try { remembered = localStorage.getItem('brand_guard_profile') ?? '' } catch { /* storage blocked: first brand */ }
  const selectedId = ref(remembered)
  const profile = computed(() => profiles.value.find(p => p.id === selectedId.value) ?? profiles.value[0] ?? null)
  const scanning = computed(() => run.value?.status === 'queued' || run.value?.status === 'running')

  async function loadSummary() {
    try { summary.value = await api.brandGuardSummary(profile.value?.id) } catch { /* informational: never block a page on it */ }
  }
  async function loadSources() {
    try { sources.value = await api.brandSources() } catch { /* the strip is informational */ }
  }
  async function loadCampaigns() {
    try { campaigns.value = await api.brandCampaigns(profile.value?.id) } catch { /* the page shows its empty state */ }
  }
  async function loadProfiles() {
    profiles.value = await api.brandProfiles()
  }

  // `server` filters are applied by the API; the multi-status ones are filtered here from "all".
  async function loadCandidates(filter = candidatesFilter.value) {
    candidatesFilter.value = filter
    const sets = FILTER_STATUSES[filter]
    const rows = await api.brandCandidates({ profile_id: profile.value?.id, status: sets ? undefined : filter === 'all' ? undefined : filter, limit: 500 })
    candidates.value = sets ? rows.filter((c: any) => sets.includes(c.status)) : rows
  }

  async function load() {
    loading.value = true
    try {
      await loadProfiles()
      if (profiles.value.length) await Promise.all([loadCandidates(), loadSummary(), loadSources(), loadCampaigns()])
      const latest = profile.value?.latest_run
      if (latest && !pollTimer) {
        run.value = latest
        if (latest.status === 'queued' || latest.status === 'running') startPolling(latest.id)
      }
      loaded.value = true
    } catch (e: any) {
      ui.toast(e.message || 'Could not load Brand Guard', 'error')
    } finally { loading.value = false }
  }

  async function ensureLoaded() {
    if (!loaded.value && !loading.value) await load()
  }

  /** Counts for the sidebar: cheap, and safe to call on any page. */
  async function ensureSummary() {
    if (!summary.value) await loadSummary()
  }

  async function scan() {
    if (!profile.value || scanning.value) return
    try {
      run.value = await api.brandScan(profile.value.id)
      startPolling(run.value.id)
    } catch (e: any) {
      ui.toast(e.message || 'Could not start the scan', 'error')
    }
  }

  function stopPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
  }

  function startPolling(runId: string) {
    stopPolling()
    pollFailures = 0
    pollTimer = setInterval(async () => {
      try {
        run.value = await api.brandScanRun(runId)
        pollFailures = 0
      } catch {
        // Tolerate a blip, but don't poll a dead endpoint forever.
        if (++pollFailures >= 3) { stopPolling(); ui.toast('Lost contact with the scan. Refresh to check its status.', 'error') }
        return
      }
      if (run.value.status === 'queued' || run.value.status === 'running') return
      stopPolling()
      if (run.value.status === 'succeeded') {
        const r = run.value.result
        ui.toast(`Scan complete: ${r.new_candidates} new candidate(s), ${r.alerts} alert(s)`)
        if (r.errors?.length) ui.toast(r.errors[0])
      } else {
        ui.toast(run.value.error || 'Scan failed', 'error')
      }
      await load()
    }, 2000)
  }

  async function refreshAfterChange() {
    await Promise.all([loadCandidates(), loadSummary(), loadProfiles(), loadCampaigns()])
  }

  /** Record a person's decision. `note` is kept with the candidate (the reason for "not a threat" is also in the status). */
  async function decide(id: string, status: string, note?: string) {
    const updated = await api.brandSetStatus(id, status, note)
    candidates.value = candidates.value.map(c => (c.id === id ? { ...c, ...updated } : c))
    return updated
  }

  /** Switch the brand being shown. */
  async function select(id: string) {
    if (id === profile.value?.id) return
    selectedId.value = id
    try { localStorage.setItem('brand_guard_profile', id) } catch { /* not remembered */ }
    stopPolling()
    summary.value = null
    run.value = profile.value?.latest_run ?? null
    if (run.value && (run.value.status === 'queued' || run.value.status === 'running')) startPolling(run.value.id)
    campaigns.value = []
    await Promise.all([loadCandidates(), loadSummary(), loadSources(), loadCampaigns()])
  }

  function applyProfile(updated: any) {
    profiles.value = profiles.value.map(p => (p.id === updated.id ? updated : p))
  }

  function reset() {
    stopPolling()
    loaded.value = false
    profiles.value = []
    summary.value = null
    sources.value = []
    candidates.value = []
    campaigns.value = []
    run.value = null
    adding.value = false
  }

  return {
    adding, loaded, loading, gated, profiles, profile, selectedId, select, summary, sources, run, scanning, candidates, candidatesFilter, campaigns,
    load, loadCampaigns, ensureLoaded, ensureSummary, loadCandidates, loadSummary, loadSources, loadProfiles, scan, stopPolling, decide,
    refreshAfterChange, applyProfile, reset,
  }
})
