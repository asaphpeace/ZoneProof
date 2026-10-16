<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { api } from '@/api/client'
import LoadError from '@/components/ui/LoadError.vue'
import NextStep from '@/components/ui/NextStep.vue'

interface DomainFreshness { domain: string; domain_id: string; last_at: string | null; status: string; count: number }
interface DataBlock { key: string; label: string; provides: string; status: string; note: string | null; domains: DomainFreshness[] }
interface Integration { key: string; label: string; provides: string; configured: boolean; note: string | null }
interface Job {
  key: string; label: string; provides: string; status: string; note: string | null
  interval_seconds: number; runs: number; failures: number
  last_started: string | null; last_finished: string | null; last_duration_s: number | null; next_run: string | null
}

const data = ref<DataBlock[]>([])
const integrations = ref<Integration[]>([])
const jobs = ref<Job[]>([])
const serverStarted = ref<string | null>(null)
const scheduler = ref<{ role: string; since: string | null }>({ role: 'unknown', since: null })
const generatedAt = ref<string | null>(null)
const loading = ref(true)
const loadError = ref('')
const open = ref<Record<string, boolean>>({})

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    const r = await api.sourcesHealth()
    data.value = r.data
    integrations.value = r.integrations
    jobs.value = r.jobs
    serverStarted.value = r.server_started_at
    scheduler.value = r.scheduler || { role: 'unknown', since: null }
    generatedAt.value = r.generated_at
  } catch (e: any) {
    loadError.value = e?.message === 'Admin role required'
      ? 'Only workspace admins can see the data sources.'
      : (e?.message || 'The request failed.')
  } finally { loading.value = false }
}
onMounted(load)

const LABEL: Record<string, string> = {
  ok: 'Healthy', stale: 'Out of date', none: 'Nothing yet', failing: 'Failing',
  waiting: 'Waiting for first run', running: 'Running', not_configured: 'Not set up',
  standby: 'Run by another server', not_here: 'Off on this server',
}
const TONE: Record<string, string> = {
  ok: 'good', stale: 'warn', none: 'warn', failing: 'bad', waiting: 'muted', running: 'muted', not_configured: 'muted',
  standby: 'muted', not_here: 'muted',
}

// What each data block's page is, so a stale block points at where it is used.
const PAGE: Record<string, { to: string; label: string }> = {
  dmarc_reports: { to: 'dmarc', label: 'Open DMARC' },
  tls_reports:   { to: 'tls', label: 'Open MTA-STS & TLS' },
  certificates:  { to: 'certs', label: 'Open Certificates' },
  dns_checks:    { to: 'timeline', label: 'Open DNS Timeline' },
}

const needsAttention = computed(() =>
  data.value.filter(d => d.status !== 'ok').length
  + integrations.value.filter(i => !i.configured).length
  + jobs.value.filter(j => j.status === 'failing' || j.status === 'stale').length)

function ago(iso: string | null): string {
  if (!iso) return 'never'
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 0) return inFuture(iso)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return `${Math.floor(s / 86400)} d ago`
}
function inFuture(iso: string | null): string {
  if (!iso) return '—'
  const s = Math.round((new Date(iso).getTime() - Date.now()) / 1000)
  if (s <= 0) return 'due now'
  if (s < 3600) return `in ${Math.max(1, Math.floor(s / 60))} min`
  if (s < 86400) return `in ${Math.floor(s / 3600)} h`
  return `in ${Math.floor(s / 86400)} d`
}
const every = (s: number) => s % 86400 === 0 ? `${s / 86400} d` : s % 3600 === 0 ? `${s / 3600} h` : `${Math.round(s / 60)} min`
</script>

<template>
  <div>
    <LoadError v-if="loadError" :message="loadError" @retry="load" />

    <div class="titlerow">
      <div>
        <div class="crumb">Account / Data sources</div>
        <h1>Data sources</h1>
        <p class="sub">Where the information on every page comes from, and whether it is flowing.</p>
      </div>
      <div class="actions">
        <span v-if="!loading && !loadError" class="attn" :class="needsAttention ? 'warn' : 'good'">
          {{ needsAttention ? `${needsAttention} to look at` : 'Everything is flowing' }}
        </span>
        <button class="btn" :disabled="loading" @click="load">{{ loading ? 'Checking…' : 'Check again' }}</button>
      </div>
    </div>

    <div v-if="loading && !data.length" class="empty">Checking your data sources…</div>

    <template v-if="!loadError && data.length">
      <!-- Your data -->
      <section class="block">
        <h2>Your data</h2>
        <p class="hint">When each kind of data last arrived for your domains.</p>
        <div v-for="b in data" :key="b.key" class="row">
          <div class="row-main" @click="open[b.key] = !open[b.key]" tabindex="0" role="button" :aria-expanded="open[b.key]" @keydown.enter.prevent="open[b.key] = !open[b.key]" @keydown.space.prevent="open[b.key] = !open[b.key]">
            <div class="row-title">
              <strong>{{ b.label }}</strong>
              <span class="provides">{{ b.provides }}</span>
            </div>
            <span class="chip" :class="TONE[b.status]">{{ LABEL[b.status] }}</span>
          </div>
          <p v-if="b.note" class="note">{{ b.note }}</p>
          <div class="row-foot">
            <button class="link" @click="open[b.key] = !open[b.key]">
              {{ open[b.key] ? 'Hide' : 'Show' }} {{ b.domains.length }} domain{{ b.domains.length === 1 ? '' : 's' }}
            </button>
            <NextStep v-if="PAGE[b.key]" :to="PAGE[b.key].to" :label="PAGE[b.key].label" />
          </div>
          <table v-if="open[b.key]" class="tbl">
            <thead><tr><th>Domain</th><th>Last arrived</th><th>Received</th><th>Status</th></tr></thead>
            <tbody>
              <tr v-for="d in b.domains" :key="d.domain_id">
                <td class="mono">{{ d.domain }}</td>
                <td>{{ ago(d.last_at) }}</td>
                <td>{{ d.count ? d.count.toLocaleString() : '—' }}</td>
                <td><span class="chip small" :class="TONE[d.status]">{{ LABEL[d.status] }}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <!-- Connected services -->
      <section class="block">
        <h2>Connected services</h2>
        <p class="hint">Outside services this server uses. Only whether each is set up is shown.</p>
        <div v-for="i in integrations" :key="i.key" class="row">
          <div class="row-main static">
            <div class="row-title">
              <strong>{{ i.label }}</strong>
              <span class="provides">{{ i.provides }}</span>
            </div>
            <span class="chip" :class="i.configured ? 'good' : 'muted'">{{ i.configured ? 'Set up' : 'Not set up' }}</span>
          </div>
          <p v-if="i.note" class="note">{{ i.note }}</p>
        </div>
      </section>

      <!-- Background jobs -->
      <section class="block">
        <h2>Background jobs</h2>
        <p class="hint">
          The scheduled work that keeps the data above fresh. History is kept across restarts and shared by all servers; this server started
          {{ ago(serverStarted) }}. Jobs that are overdue, or that only act on work that is due, run shortly after start; the rest wait one interval.
        </p>
        <p v-if="scheduler.role === 'leader'" class="role good">
          This server is running the background jobs{{ scheduler.since ? ` (since ${ago(scheduler.since)})` : '' }}.
        </p>
        <p v-else-if="scheduler.role === 'standby'" class="role">
          Another server is running the background jobs and this one is standing by to take over. Run history is kept by the server that runs them, so this page cannot show it.
        </p>
        <p v-else-if="scheduler.role === 'disabled'" class="role">
          The scheduler is switched off on this server.
        </p>
        <div class="scroll" tabindex="0" role="region" aria-label="Background jobs">
          <table class="tbl jobs">
            <thead>
              <tr><th>Job</th><th>Status</th><th>Last run</th><th>Took</th><th>Next run</th><th>Every</th><th>Runs / failed</th></tr>
            </thead>
            <tbody>
              <template v-for="j in jobs" :key="j.key">
                <tr>
                  <td><strong>{{ j.label }}</strong><div class="provides">{{ j.provides }}</div></td>
                  <td><span class="chip small" :class="TONE[j.status]">{{ LABEL[j.status] }}</span></td>
                  <td>{{ ago(j.last_finished) }}</td>
                  <td>{{ j.last_duration_s !== null ? j.last_duration_s + ' s' : '—' }}</td>
                  <td>{{ j.status === 'not_configured' ? '—' : inFuture(j.next_run) }}</td>
                  <td>{{ every(j.interval_seconds) }}</td>
                  <td>{{ j.runs }} / {{ j.failures }}</td>
                </tr>
                <tr v-if="j.note" class="note-row"><td colspan="7">{{ j.note }}</td></tr>
              </template>
            </tbody>
          </table>
        </div>
      </section>

      <p class="foot">Checked {{ ago(generatedAt) }}.</p>
    </template>
  </div>
</template>

<style scoped>
.titlerow { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; flex-wrap: wrap; margin-bottom: 22px; }
.crumb { font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--faint); margin-bottom: 6px; }
h1 { margin: 0; font-size: 26px; }
.sub { margin: 6px 0 0; color: var(--muted); font-size: 14px; }
.actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.attn { font-size: 12.5px; font-weight: 600; padding: 6px 12px; border-radius: 999px; border: 1px solid var(--line); }
.attn.good { color: var(--good); } .attn.warn { color: var(--amber); }
.btn { padding: 8px 14px; border-radius: 10px; border: 1px solid var(--line2, var(--line)); background: rgba(255,255,255,.04); color: var(--txt); cursor: pointer; font-weight: 600; }
.btn:disabled { opacity: .6; cursor: default; }
.empty { padding: 40px; text-align: center; color: var(--muted); }
.block { margin-bottom: 30px; }
.block h2 { margin: 0 0 4px; font-size: 16px; }
.hint { margin: 0 0 12px; color: var(--muted); font-size: 12.5px; }
.row { border: 1px solid var(--line); border-radius: 12px; padding: 14px 16px; margin-bottom: 10px; background: rgba(255,255,255,.025); }
.row-main { display: flex; align-items: center; justify-content: space-between; gap: 12px; cursor: pointer; }
.row-main.static { cursor: default; }
.row-title { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.provides { color: var(--muted); font-size: 12.5px; font-weight: 400; }
.note { margin: 8px 0 0; font-size: 12.5px; color: var(--muted); }
.row-foot { display: flex; align-items: center; gap: 18px; margin-top: 10px; }
.link { background: none; border: none; padding: 0; color: var(--indigo, #9aa6ff); font-size: 12px; font-weight: 600; cursor: pointer; }
.chip { flex: none; font-size: 11.5px; font-weight: 700; padding: 4px 10px; border-radius: 999px; border: 1px solid var(--line); white-space: nowrap; }
.chip.small { font-size: 11px; padding: 3px 8px; }
.chip.good { color: var(--good); border-color: rgba(52,224,161,.4); background: rgba(52,224,161,.08); }
.chip.warn { color: var(--amber); border-color: rgba(245,197,66,.45); background: rgba(245,197,66,.08); }
.chip.bad { color: var(--bad); border-color: rgba(240,90,90,.5); background: rgba(240,90,90,.08); }
.chip.muted { color: var(--muted); }
.scroll { overflow-x: auto; }
.tbl { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
.tbl th { text-align: left; font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: var(--faint); font-weight: 600; padding: 6px 10px; border-bottom: 1px solid var(--line); }
.tbl td { padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
.jobs { margin-top: 0; min-width: 640px; }
.note-row td { color: var(--amber); font-size: 12.5px; padding-top: 0; }
.mono { font-family: var(--mono, monospace); }
.foot { color: var(--faint); font-size: 12px; }
.role { margin: 0 0 10px; font-size: 12.5px; color: var(--muted); }
.role.good { color: var(--good); }
</style>
