<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { api } from '@/api/client'
import { useDomainsStore } from '@/stores/domains'
import { useUiStore } from '@/stores/ui'
import AdvisorBanner from '@/components/ui/AdvisorBanner.vue'
import LoadError from '@/components/ui/LoadError.vue'
import { useScopeStore } from '@/stores/scope'
import NextStep from '@/components/ui/NextStep.vue'

const domains  = useDomainsStore()
const ui = useUiStore()
const allCerts       = ref<any[]>([])
const advisor        = ref<any>(null)
const advisorLoading = ref(false)
const loadError = ref('')
const loading        = ref(false)
const probing        = ref(false)
const probingId = ref<string | null>(null)
const scope = useScopeStore()
const filterDomain = computed<string>({
  get: () => scope.domain ?? 'all',
  set: (v) => scope.set(v === 'all' ? null : v),
})
const expandedId   = ref<string | null>(null)

onMounted(async () => {
  advisorLoading.value = true
  await domains.fetch()
  if (domains.error) { loadError.value = domains.error; advisorLoading.value = false; loading.value = false; return }
  await loadData(true)
})

async function loadData(initialLoad = false) {
  loading.value = true
  loadError.value = ''
  if (!initialLoad) advisorLoading.value = true
  try {
    allCerts.value = await api.allCerts()
  } catch (e: any) { loadError.value = e?.message || 'The certificate request failed.'; return } finally { loading.value = false }

  // Advisor: cached on initial load for instant display
  try {
    const domId = currentDomainId()
    const result = await api.advisorCertSummary(domId, initialLoad)
    advisor.value = result
    if (initialLoad) {
      api.advisorCertSummary(domId, false).then(fresh => {
        if (filterDomain.value === (domId ? domains.list.find(d => d.id === domId)?.domain : 'all')) {
          advisor.value = fresh
        }
      }).catch(() => {})
    }
  } catch { /* leave advisor null — skeleton stays */ }
  finally { advisorLoading.value = false }
}

async function probeAll() {
  probing.value = true
  try {
    // allSettled, not all — one slow/failing domain (e.g. unreachable MX,
    // a domain mid-deletion) must not silently abort probing for every
    // other domain with zero feedback to the user.
    const results = await Promise.allSettled(domains.list.map(d => api.probeCerts(d.id)))
    const failed = results.filter(r => r.status === 'rejected') as PromiseRejectedResult[]
    await loadData()
    if (failed.length) {
      ui.toast(`Probed ${results.length - failed.length}/${results.length} domains — ${failed.length} failed: ${failed[0].reason?.message || 'unknown error'}`)
    } else {
      ui.toast('Probe complete')
    }
  } catch (e: any) {
    ui.toast(e.message || 'Probe failed')
  } finally { probing.value = false }
}

async function probeDomain(domainId: string) {
  probingId.value = domainId
  try {
    await api.probeCerts(domainId)
    await loadData()
    ui.toast('Probe complete')
  } catch (e: any) {
    ui.toast(e.message || 'Probe failed')
  } finally { probingId.value = null }
}

function currentDomainId() {
  if (filterDomain.value === 'all') return undefined
  return domains.list.find(d => d.domain === filterDomain.value)?.id
}

async function reloadAdvisor() {
  advisorLoading.value = true
  try {
    advisor.value = await api.advisorCertSummary(currentDomainId(), false, true)
  } finally { advisorLoading.value = false }
}

watch(filterDomain, async (newVal) => {
  advisor.value = null  // clear stale context on domain switch
  advisorLoading.value = true
  try {
    const result = await api.advisorCertSummary(currentDomainId(), false)
    if (filterDomain.value === newVal) advisor.value = result
  } catch { /* leave advisor null — skeleton stays */ }
  finally { if (filterDomain.value === newVal) advisorLoading.value = false }
})

const visibleCerts = computed(() => {
  if (filterDomain.value === 'all') return allCerts.value
  return allCerts.value.filter(c => c.domain === filterDomain.value)
})

const criticalCount   = computed(() => allCerts.value.filter(c => c.status === 'critical' || c.status === 'expired').length)
const warningCount    = computed(() => allCerts.value.filter(c => c.status === 'expiring_soon').length)
const healthyCount    = computed(() => allCerts.value.filter(c => c.status === 'ok').length)
const errorCount      = computed(() => allCerts.value.filter(c => c.status === 'error').length)

const earliestExpiry  = computed(() => {
  const urgent = allCerts.value
    .filter(c => c.days_remaining !== null && c.days_remaining >= 0)
    .sort((a, b) => a.days_remaining - b.days_remaining)[0]
  return urgent ?? null
})

const lastProbedAt = computed(() => {
  if (!allCerts.value.length) return null
  const dates = allCerts.value.map(c => new Date(c.probed_at)).filter(d => !isNaN(d.getTime()))
  if (!dates.length) return null
  const latest = new Date(Math.max(...dates.map(d => d.getTime())))
  return latest.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
})

const domainOptions = computed(() =>
  domains.list.map(d => d.domain).sort()
)

function statusColor(status: string) {
  return status === 'ok' ? 'var(--good)'
    : status === 'expiring_soon' ? 'var(--amber)'
    : status === 'error' ? 'var(--faint)'
    : 'var(--bad)'
}

function statusLabel(status: string) {
  return { ok: 'Healthy', expiring_soon: 'Renew soon', critical: 'Critical', expired: 'Expired', error: 'Error' }[status] ?? status
}

function protocolLabel(hostType: string) {
  return hostType === 'smtp' ? 'SMTP' : 'HTTPS'
}

function protocolColor(hostType: string) {
  return hostType === 'smtp' ? '#9aa6ff' : 'var(--teal)'
}

// 90-day fixed countdown bar: full=90d, empty=0d
function countdownWidth(days: number | null) {
  if (days === null) return 0
  return Math.min(Math.max(days, 0), 90) / 90 * 100
}

function countdownColor(days: number | null, status: string) {
  if (status === 'expired') return 'var(--bad)'
  if (days === null) return 'var(--faint)'
  if (days <= 7)  return 'var(--bad)'
  if (days <= 30) return 'var(--amber)'
  return 'var(--good)'
}

function formatDate(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

function toggleExpand(id: string) {
  expandedId.value = expandedId.value === id ? null : id
}

function domainId(domain: string) {
  return domains.list.find(d => d.domain === domain)?.id
}
</script>

<template>
  <div>
    <LoadError v-if="loadError" :message="loadError" @retry="$router.go(0)" />
    <!-- Title row -->
    <div class="titlerow">
      <div>
        <div class="crumb">07 / Certificates</div>
        <h1>Certificate Health</h1>
        <div class="sub">SMTP STARTTLS &amp; HTTPS — expiry monitoring across all domains</div>
      </div>
      <div class="title-actions">
        <span v-if="lastProbedAt" class="probed-at">Last probed {{ lastProbedAt }}</span>
        <button class="btn" :disabled="probing" @click="probeAll">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
            <path d="M23 4v6h-6"/><path d="M20.49 15a9 9 0 1 1-.49-7.49"/>
          </svg>
          {{ probing ? 'Probing…' : 'Probe all' }}
        </button>
      </div>
    </div>

    <!-- Earliest expiry callout -->
    <div v-if="earliestExpiry && (earliestExpiry.days_remaining ?? 999) <= 30" class="expiry-alert">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
      <span>
        Earliest expiry: <b>{{ earliestExpiry.host }}</b> ({{ earliestExpiry.domain }}) —
        <b :style="`color:${statusColor(earliestExpiry.status)}`">
          {{ earliestExpiry.days_remaining === 0 ? 'expires today' : `${earliestExpiry.days_remaining} days remaining` }}
        </b>
      </span>
      <button
        v-if="domainId(earliestExpiry.domain)"
        class="btn-sm"
        :disabled="probingId === domainId(earliestExpiry.domain)"
        @click="probeDomain(domainId(earliestExpiry.domain)!)"
      >Re-probe</button>
    </div>

    <!-- KPI strip -->
    <div class="kpi-strip">
      <div class="kpi-item" :class="criticalCount > 0 ? 'urgent' : ''">
        <div class="kpi-val" :style="criticalCount > 0 ? 'color:var(--bad)' : ''">{{ criticalCount }}</div>
        <div class="kpi-lbl">Critical / Expired</div>
      </div>
      <div class="kpi-div" />
      <div class="kpi-item" :class="warningCount > 0 ? 'caution' : ''">
        <div class="kpi-val" :style="warningCount > 0 ? 'color:var(--amber)' : ''">{{ warningCount }}</div>
        <div class="kpi-lbl">Renew within 30 days</div>
      </div>
      <div class="kpi-div" />
      <div class="kpi-item">
        <div class="kpi-val" style="color:var(--good)">{{ healthyCount }}</div>
        <div class="kpi-lbl">Healthy (&gt; 30 days)</div>
      </div>
      <div class="kpi-div" />
      <div class="kpi-item">
        <div class="kpi-val" style="color:var(--faint)">{{ allCerts.length }}</div>
        <div class="kpi-lbl">Total probed</div>
      </div>
      <div v-if="errorCount > 0" class="kpi-div" />
      <div v-if="errorCount > 0" class="kpi-item">
        <div class="kpi-val" style="color:var(--faint)">{{ errorCount }}</div>
        <div class="kpi-lbl">Probe errors</div>
      </div>
    </div>

    <AdvisorBanner
      v-if="advisor || advisorLoading"
      :message="advisor?.message ?? ''"
      :commend="advisor?.commend"
      :is-ai="advisor?.is_ai"
      :model="advisor?.model"
      :loading="!advisor && advisorLoading"
      :refreshing="!!advisor && advisorLoading"
      @regenerate="reloadAdvisor"
      style="margin-bottom:16px"
    />

    <!-- Inventory card -->
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Certificate inventory</div>
          <div class="card-sub">Click any row to see SANs, TLS version, and issuer details</div>
        </div>

        <!-- Domain filter dropdown -->
        <div class="filter-wrap">
          <select v-model="filterDomain" class="filter-select" aria-label="Domain">
            <option value="all">All domains ({{ domains.list.length }})</option>
            <option v-for="d in domainOptions" :key="d" :value="d">{{ d }}</option>
          </select>
          <svg class="filter-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <path d="M6 9l6 6 6-6"/>
          </svg>
        </div>
      </div>

      <div v-if="loading" class="loading-state">Loading certificates…</div>

      <div v-else-if="!visibleCerts.length" class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="var(--faint)" stroke-width="1.5">
          <circle cx="12" cy="8" r="6"/><path d="M9 13l-2 8 5-3 5 3-2-8"/>
        </svg>
        <div>No certificates found.</div>
        <div class="empty-sub">Click "Probe all" to scan SMTP and HTTPS endpoints across your domains.</div>
      </div>

      <div v-else>
        <!-- Table head -->
        <div class="tbl-head">
          <span>Host / Domain</span>
          <span>Protocol</span>
          <span>Issuer</span>
          <span>Expires</span>
          <span>Countdown (90d)</span>
          <span>Status</span>
        </div>

        <!-- Rows -->
        <template v-for="c in visibleCerts" :key="c.id">
          <div :class="['tbl-row', expandedId === c.id ? 'expanded' : '']" @click="toggleExpand(c.id)" tabindex="0" role="button" :aria-expanded="expandedId === c.id" @keydown.enter.prevent="toggleExpand(c.id)" @keydown.space.prevent="toggleExpand(c.id)">
            <!-- Host -->
            <div class="cell-host">
              <span class="host-name">{{ c.host }}</span>
              <span class="host-domain">{{ c.domain }}</span>
            </div>

            <!-- Protocol -->
            <div>
              <span class="proto-pill" :style="`color:${protocolColor(c.host_type)};border-color:${protocolColor(c.host_type)}33`">
                {{ protocolLabel(c.host_type) }}
              </span>
            </div>

            <!-- Issuer (short) -->
            <div class="cell-issuer">{{ c.issuer ? c.issuer.replace(/^(.*?)(, [A-Z]{1,2}=.*)?$/, '$1').substring(0, 28) : '—' }}</div>

            <!-- Expiry date -->
            <div class="cell-date">
              <span>{{ formatDate(c.not_after) }}</span>
              <span class="days-badge" :style="`color:${countdownColor(c.days_remaining, c.status)}`">
                {{ c.status === 'expired' ? 'Expired' : c.days_remaining !== null ? `${c.days_remaining}d` : '—' }}
              </span>
            </div>

            <!-- Countdown bar (0–90d scale) -->
            <div class="cell-bar">
              <div class="bar-track">
                <div
                  class="bar-fill"
                  :style="`width:${countdownWidth(c.days_remaining)}%;background:${countdownColor(c.days_remaining, c.status)}`"
                />
              </div>
              <span class="bar-scale">90d</span>
            </div>

            <!-- Status -->
            <div class="cell-status">
              <span class="status-pill" :style="`color:${statusColor(c.status)};background:${statusColor(c.status)}18;border-color:${statusColor(c.status)}33`">
                {{ statusLabel(c.status) }}
              </span>
              <svg class="expand-chevron" :class="expandedId === c.id ? 'open' : ''" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M6 9l6 6 6-6"/>
              </svg>
            </div>
          </div>

          <!-- Expanded detail -->
          <div v-if="expandedId === c.id" class="tbl-detail">
            <div class="detail-grid">
              <div class="detail-item">
                <div class="detail-lbl">Subject CN</div>
                <div class="detail-val mono">{{ c.subject_cn || '—' }}</div>
              </div>
              <div class="detail-item">
                <div class="detail-lbl">Issuer</div>
                <div class="detail-val mono">{{ c.issuer || '—' }}</div>
              </div>
              <div class="detail-item">
                <div class="detail-lbl">TLS version</div>
                <div class="detail-val mono">{{ c.tls_version || '—' }}</div>
              </div>
              <div class="detail-item">
                <div class="detail-lbl">STARTTLS</div>
                <div class="detail-val">
                  <span v-if="c.starttls_supported === null">—</span>
                  <span v-else-if="c.starttls_supported" style="color:var(--good)">Supported</span>
                  <span v-else style="color:var(--bad)">Not supported</span>
                </div>
              </div>
              <div class="detail-item">
                <div class="detail-lbl">Hostname valid</div>
                <div class="detail-val">
                  <span v-if="c.hostname_valid === null">—</span>
                  <span v-else-if="c.hostname_valid" style="color:var(--good)">Valid</span>
                  <span v-else style="color:var(--bad)">Mismatch</span>
                </div>
              </div>
              <div class="detail-item">
                <div class="detail-lbl">Last probed</div>
                <div class="detail-val mono">{{ formatDate(c.probed_at) }}</div>
              </div>
              <div v-if="c.san" class="detail-item detail-full">
                <div class="detail-lbl">Subject Alt Names</div>
                <div class="detail-val mono san-list">{{ c.san }}</div>
              </div>
              <div v-if="c.probe_error" class="detail-item detail-full">
                <div class="detail-lbl">Probe error</div>
                <div class="detail-val mono" style="color:var(--bad)">{{ c.probe_error }}</div>
              </div>
            </div>
            <div v-if="c.domain" class="detail-links">
              <NextStep
                v-if="c.status && c.status !== 'ok'"
                to="roadmap" :domain="c.domain" label="What this blocks on the roadmap"
                title="MTA-STS enforcement waits on a healthy certificate"
              />
              <NextStep to="tls" :domain="c.domain" label="TLS delivery for this domain" />
              <NextStep to="timeline" :domain="c.domain" label="Recent DNS changes" />
            </div>
            <button
              v-if="domainId(c.domain)"
              class="btn-reprobe"
              :disabled="probingId === domainId(c.domain)"
              @click.stop="probeDomain(domainId(c.domain)!)"
            >
              {{ probingId === domainId(c.domain) ? 'Probing…' : '↻ Re-probe this domain' }}
            </button>
          </div>
        </template>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* ── Title ───────────────────────────────────────────────────── */
.titlerow { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 16px; gap: 16px; flex-wrap: wrap; }
.crumb { font-family: var(--mono); font-size: 10px; color: var(--faint); letter-spacing: 1.4px; text-transform: uppercase; }
h1 { font-family: var(--disp); font-weight: 800; font-size: 25px; letter-spacing: -.7px; margin-top: 5px; }
.sub { color: var(--muted); margin-top: 5px; font-size: 13px; }
.title-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding-top: 4px; }
.probed-at { font-family: var(--mono); font-size: 10.5px; color: var(--faint); }
.btn {
  display: flex; align-items: center; gap: 7px;
  background: linear-gradient(90deg,#5b5cf0,#4b4ce0); color: #fff; border: none;
  border-radius: 12px; padding: 10px 18px; font-family: var(--disp); font-weight: 700;
  font-size: 13px; cursor: pointer; transition: opacity .15s;
}
.btn svg { width: 14px; height: 14px; }
.btn:disabled { opacity: .55; cursor: not-allowed; }

/* ── Expiry alert ────────────────────────────────────────────── */
.expiry-alert {
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  padding: 11px 15px; margin-bottom: 14px; border-radius: 12px;
  background: rgba(255,140,66,.07); border: 1px solid rgba(255,140,66,.25);
  font-size: 13px; color: var(--muted);
}
.expiry-alert svg { width: 16px; height: 16px; color: var(--amber); flex: none; }
.expiry-alert b { color: var(--txt); }
.btn-sm {
  margin-left: auto; background: rgba(255,255,255,.07); border: 1px solid var(--line2);
  border-radius: 8px; padding: 5px 12px; font-family: var(--mono); font-size: 10.5px;
  color: var(--muted); cursor: pointer; transition: .15s; white-space: nowrap;
}
.btn-sm:hover { border-color: var(--indigo); color: var(--txt); }
.btn-sm:disabled { opacity: .5; cursor: not-allowed; }

/* ── KPI strip ───────────────────────────────────────────────── */
.kpi-strip {
  display: flex; align-items: center; gap: 0; flex-wrap: wrap;
  background: var(--glass); border: 1px solid var(--line); border-radius: 14px;
  padding: 14px 20px; margin-bottom: 16px;
}
.kpi-item { display: flex; flex-direction: column; gap: 3px; padding: 0 16px; }
.kpi-item.urgent  { }
.kpi-item.caution { }
.kpi-val { font-family: var(--disp); font-weight: 800; font-size: 26px; line-height: 1; }
.kpi-lbl { font-family: var(--mono); font-size: 9.5px; color: var(--faint); }
.kpi-div { width: 1px; height: 32px; background: var(--line); }

/* ── Card ────────────────────────────────────────────────────── */
.card {
  background: var(--glass); border: 1px solid var(--line); border-radius: 18px;
  padding: 20px; backdrop-filter: blur(12px);
  box-shadow: 0 12px 40px rgba(0,0,0,.3), inset 0 1px 0 rgba(255,255,255,.05);
}
.card-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 18px; gap: 12px; flex-wrap: wrap; }
.card-title { font-family: var(--disp); font-weight: 700; font-size: 15px; }
.card-sub { font-family: var(--mono); font-size: 10px; color: var(--faint); margin-top: 3px; }

/* ── Filter dropdown ─────────────────────────────────────────── */
.filter-wrap { position: relative; display: inline-flex; align-items: center; }
.filter-select {
  appearance: none; background: rgba(255,255,255,.04); border: 1px solid var(--line2);
  border-radius: 10px; padding: 8px 30px 8px 12px;
  font-family: var(--mono); font-size: 11.5px; color: var(--txt);
  cursor: pointer; outline: none; transition: border-color .15s;
}
.filter-select:focus { border-color: var(--indigo); }
.filter-select option { background: var(--surface-raised); }
.filter-caret { position: absolute; right: 8px; width: 13px; height: 13px; color: var(--faint); pointer-events: none; }

/* ── Table ───────────────────────────────────────────────────── */
.tbl-head {
  display: grid; grid-template-columns: 1.6fr 80px 1fr 130px 1fr 120px;
  gap: 10px; padding: 0 14px 10px; border-bottom: 1px solid var(--line);
  font-family: var(--mono); font-size: 8.5px; text-transform: uppercase;
  letter-spacing: .7px; color: var(--faint);
}
.tbl-row {
  display: grid; grid-template-columns: 1.6fr 80px 1fr 130px 1fr 120px;
  gap: 10px; align-items: center; padding: 11px 14px; border-radius: 10px;
  cursor: pointer; transition: background .12s; border-bottom: 1px solid var(--line);
}
.tbl-row:last-of-type { border-bottom: none; }
.tbl-row:hover, .tbl-row.expanded { background: rgba(255,255,255,.04); }

.cell-host { min-width: 0; }
.host-name { font-family: var(--mono); font-size: 12px; font-weight: 600; display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.host-domain { font-family: var(--mono); font-size: 9.5px; color: var(--faint); display: block; }

.proto-pill { font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: .5px; padding: 3px 8px; border-radius: 6px; border: 1px solid; }

.cell-issuer { font-family: var(--mono); font-size: 10.5px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

.cell-date { }
.cell-date span { display: block; font-family: var(--mono); font-size: 11px; }
.days-badge { font-weight: 700; font-size: 12px !important; }

.cell-bar { display: flex; align-items: center; gap: 8px; }
.bar-track { flex: 1; height: 6px; background: rgba(255,255,255,.07); border-radius: 4px; overflow: hidden; }
.bar-fill  { height: 100%; border-radius: 4px; transition: width .4s ease; }
.bar-scale { font-family: var(--mono); font-size: 9px; color: var(--faint); white-space: nowrap; }

.cell-status { display: flex; align-items: center; gap: 8px; }
.status-pill { font-family: var(--mono); font-size: 9.5px; font-weight: 700; padding: 4px 10px; border-radius: 20px; border: 1px solid; white-space: nowrap; }
.expand-chevron { width: 14px; height: 14px; color: var(--faint); flex: none; transition: transform .2s; }
.expand-chevron.open { transform: rotate(180deg); }

/* ── Expanded detail ─────────────────────────────────────────── */
.detail-links { display: flex; flex-wrap: wrap; gap: 6px 18px; margin: 0 0 12px; }
.tbl-detail {
  margin: 0 4px 4px; padding: 14px 16px; border-radius: 10px;
  background: rgba(255,255,255,.03); border: 1px solid var(--line);
}
.detail-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px 20px; margin-bottom: 14px; }
.detail-full { grid-column: 1 / -1; }
.detail-lbl { font-family: var(--mono); font-size: 9px; text-transform: uppercase; letter-spacing: .6px; color: var(--faint); margin-bottom: 3px; }
.detail-val { font-size: 12px; color: var(--txt); line-height: 1.4; }
.detail-val.mono { font-family: var(--mono); font-size: 11px; }
.san-list { word-break: break-all; color: var(--muted); }

.btn-reprobe {
  background: none; border: 1px solid var(--line2); border-radius: 8px;
  padding: 6px 14px; font-family: var(--mono); font-size: 10.5px; color: var(--teal);
  cursor: pointer; transition: .15s;
}
.btn-reprobe:hover { border-color: var(--teal); background: rgba(46,230,197,.06); }
.btn-reprobe:disabled { opacity: .5; cursor: not-allowed; }

/* ── States ──────────────────────────────────────────────────── */
.loading-state { padding: 36px; text-align: center; color: var(--muted); font-family: var(--mono); font-size: 12px; }
.empty-state { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 40px 20px; }
.empty-state svg { width: 36px; height: 36px; margin-bottom: 4px; }
.empty-state div { font-family: var(--mono); font-size: 12.5px; color: var(--muted); }
.empty-sub { font-size: 11px !important; color: var(--faint) !important; text-align: center; max-width: 340px; line-height: 1.6; }

@media (max-width: 900px) {
  .tbl-head, .tbl-row { grid-template-columns: 1.4fr 70px 100px 100px; }
  .tbl-head :nth-child(3), .tbl-row .cell-issuer,
  .tbl-head :nth-child(5), .tbl-row .cell-bar { display: none; }
  .detail-grid { grid-template-columns: 1fr 1fr; }
}
</style>
