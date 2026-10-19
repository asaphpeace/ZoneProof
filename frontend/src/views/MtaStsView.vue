<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api/client'
import { useDomainsStore } from '@/stores/domains'
import { useUiStore } from '@/stores/ui'
import KpiCard from '@/components/ui/KpiCard.vue'
import LoadError from '@/components/ui/LoadError.vue'
import AdvisorBanner from '@/components/ui/AdvisorBanner.vue'
import StatusChip from '@/components/ui/StatusChip.vue'
import DataDeadZone from '@/components/ui/DataDeadZone.vue'
import AskFollowUp from '@/components/ui/AskFollowUp.vue'
import MtaStsHostingStatus from '@/components/domain/MtaStsHostingStatus.vue'
import MxReadinessScorecard from '@/components/domain/MxReadinessScorecard.vue'
import ConceptCardButton from '@/components/ui/ConceptCardButton.vue'
import DateRangeFilter from '@/components/ui/DateRangeFilter.vue'
import { useScopeStore } from '@/stores/scope'

const ALL = '__all__'
const router  = useRouter()
const domains = useDomainsStore()
const ui = useUiStore()

const scope = useScopeStore()
const selected = computed<string>({
  get: () => scope.domain ?? ALL,
  set: (v) => scope.set(v === ALL ? null : v),
})
const days           = ref(30)
const data           = ref<any>(null)
const diff           = ref<any>(null)
const advisor        = ref<any>(null)
const advisorLoading = ref(false)
const allSummary     = ref<any[]>([])
const loading        = ref(false)
const loadError = ref('')

onMounted(async () => {
  advisorLoading.value = true
  await domains.fetch()
  if (domains.error) { loadError.value = domains.error; advisorLoading.value = false; loading.value = false; return }
  await loadData(true)
})

watch(selected, () => {
  advisor.value = null
  loadData(false)
})
watch(days, () => loadData(false))

async function loadData(initialLoad = false) {
  loading.value = true
  loadError.value = ''
  data.value = null
  if (!initialLoad) advisorLoading.value = true
  const capturedSelection = selected.value
  try {
    if (capturedSelection === ALL) {
      allSummary.value = await api.tlsDomainSummary()
    } else {
      const dom = domains.list.find(d => d.domain === capturedSelection)
      if (!dom) { loading.value = false; advisorLoading.value = false; return }
      data.value = await api.tlsData(dom.id, days.value)
    }
  } catch (e: any) { loadError.value = e?.message || 'The data request failed.'; return } finally { loading.value = false }

  // Advisor: cached on initial load for instant display, fresh on domain switch
  try {
    const dom = domains.list.find(d => d.domain === capturedSelection)
    const domId = capturedSelection === ALL ? undefined : dom?.id
    const result = await api.advisor('tls', domId, initialLoad)
    if (selected.value === capturedSelection) advisor.value = result
    if (initialLoad) {
      api.advisor('tls', domId, false).then(fresh => {
        if (selected.value === capturedSelection) advisor.value = fresh
      }).catch(() => {})
    }
  } catch { /* leave advisor null — skeleton stays */ }
  finally { if (selected.value === capturedSelection) advisorLoading.value = false }
}

async function openReview() {
  const dom = domains.list.find(d => d.domain === selected.value)
  if (!dom) return
  diff.value = await api.tlsRecordDiff(dom.id)
}

async function markPublished() {
  const dom = domains.list.find(d => d.domain === selected.value)
  if (!dom) return
  await api.tlsMarkPublished(dom.id)
  ui.toast('Marked as published — logged to the DNS timeline')
  diff.value = null
}

function copyRecord() {
  navigator.clipboard.writeText(diff.value?.proposed ?? '')
  ui.toast('Record copied to clipboard')
}

async function reloadAdvisor() {
  advisorLoading.value = true
  try {
    await domains.fetch()
    if (selected.value === ALL) {
      advisor.value = await api.advisor('tls', undefined, false, true)
    } else {
      const dom = domains.list.find(d => d.domain === selected.value)
      if (dom) advisor.value = await api.advisor('tls', dom.id, false, true)
    }
  } finally { advisorLoading.value = false }
}

// All-domains computed
const allTotal   = computed(() => allSummary.value.reduce((s, r) => s + r.total_sessions, 0))
const allFailed  = computed(() => allSummary.value.reduce((s, r) => s + r.failed_sessions, 0))
const allPassPct = computed(() => {
  const t = allTotal.value
  return t ? Math.round((t - allFailed.value) / t * 100 * 10) / 10 : 0
})
const atEnforce  = computed(() => allSummary.value.filter(r => r.mta_sts_stage === 'enforce').length)

function severityColor(sev: string) {
  if (sev === 'critical') return 'var(--bad)'
  if (sev === 'warning')  return 'var(--amber)'
  return 'var(--good)'
}
function severityLabel(sev: string) {
  if (sev === 'critical') return 'Critical'
  if (sev === 'warning')  return 'Warning'
  return 'Healthy'
}
function stageColor(stage: string) {
  if (stage === 'enforce')  return 'var(--good)'
  if (stage === 'testing')  return 'var(--amber)'
  return 'var(--muted)'
}
function passPctColor(pct: number) {
  if (pct >= 99) return 'var(--good)'
  if (pct >= 95) return 'var(--amber)'
  return 'var(--bad)'
}

const selectedDomainObj = computed(() => domains.list.find(d => d.domain === selected.value))

function goToRoadmap() {
  router.push({ path: '/roadmap', query: selected.value !== ALL ? { domain: selected.value } : {} })
}
</script>

<template>
  <div>
    <LoadError v-if="loadError" :message="loadError" @retry="$router.go(0)" />
    <!-- Header -->
    <div class="titlerow">
      <div>
        <div class="crumb">04 / MTA-STS</div>
        <h1>MTA-STS &amp; TLS Reporting</h1>
        <div class="sub">Force TLS for inbound mail · Monitor delivery failures · RFC 8461 + RFC 8460</div>
      </div>
      <button v-if="selected !== ALL" class="btn" @click="openReview">Review TLS record →</button>
    </div>

    <!-- Domain dropdown + date filter -->
    <div style="margin-bottom:16px;display:flex;align-items:center;gap:16px;flex-wrap:wrap">
      <DateRangeFilter v-model="days" />
      <select v-model="selected" class="dom-select" aria-label="Domain">
        <option :value="ALL">All domains</option>
        <option disabled value="">──────────</option>
        <option v-for="d in domains.list" :key="d.id" :value="d.domain">{{ d.domain }}</option>
      </select>
    </div>

    <!-- Managed-hosting status — only meaningful for one domain at a time -->
    <MtaStsHostingStatus v-if="selectedDomainObj" :domain-id="selectedDomainObj.id" />

    <!-- Advisor -->
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

    <!-- ── ALL DOMAINS MODE ── -->
    <template v-if="selected === ALL && !loading">
      <div class="kpis">
        <KpiCard label="Total TLS sessions"  :value="allTotal.toLocaleString()"              delta="across all domains"    dot-color="var(--indigo)" />
        <KpiCard label="Overall pass rate"   :value="allPassPct + '%'"                       delta="successful deliveries" dot-color="var(--good)"   delta-color="var(--good)" />
        <KpiCard label="Total failures"      :value="allFailed.toLocaleString()"             delta="need attention"        dot-color="var(--bad)"    delta-color="var(--bad)" />
        <KpiCard label="Domains at enforce"  :value="atEnforce + ' / ' + allSummary.length" delta="fully enforced"        dot-color="var(--teal)" />
      </div>

      <div class="card">
        <div class="ct"><h3 aria-level="2">Domain breakdown</h3><span class="sectag">all domains · last {{ days }}d</span></div>
        <div class="dom-table">
          <div class="dom-thead">
            <span>Domain</span>
            <span>MTA-STS mode</span>
            <span style="text-align:right">Sessions</span>
            <span style="text-align:right">Pass rate</span>
            <span style="text-align:right">Failures</span>
          </div>
          <div v-for="row in allSummary" :key="row.domain_id" class="dom-trow" @click="selected = row.domain" tabindex="0" role="link" @keydown.enter.prevent="selected = row.domain" @keydown.space.prevent="selected = row.domain">
            <span class="dom-name">{{ row.domain }}</span>
            <span>
              <span class="stage-badge" :style="{ color: stageColor(row.mta_sts_stage), borderColor: stageColor(row.mta_sts_stage) }">
                {{ row.mta_sts_stage.toUpperCase() }}
              </span>
            </span>
            <span style="text-align:right;font-family:var(--mono);font-size:12px">
              {{ row.total_sessions > 0 ? row.total_sessions.toLocaleString() : '—' }}
            </span>
            <span style="text-align:right">
              <span v-if="row.total_sessions > 0" class="pct-badge" :style="{ color: passPctColor(row.pass_pct) }">
                {{ row.pass_pct }}%
              </span>
              <span v-else style="color:var(--muted);font-size:12px">—</span>
            </span>
            <span style="text-align:right">
              <span v-if="row.failed_sessions > 0" style="color:var(--bad);font-family:var(--mono);font-size:12px">{{ row.failed_sessions }}</span>
              <span v-else style="color:var(--good);font-size:12px">✓</span>
            </span>
          </div>
          <div v-if="!allSummary.length" class="empty-row">No domains configured.</div>
        </div>
        <div class="table-hint">Click a row to drill into that domain.</div>
      </div>
    </template>

    <!-- ── SINGLE DOMAIN MODE ── -->
    <template v-if="selected !== ALL && data && !loading">
      <div class="kpis">
        <KpiCard
          label="MTA-STS mode"
          :value="data.mta_sts_stage?.toUpperCase() ?? '—'"
          :delta="data.mta_sts_stage === 'enforce' ? 'Fully protected — rejecting plaintext' : data.mta_sts_stage === 'testing' ? 'Monitoring only — not blocking yet' : 'No policy active'"
          dot-color="var(--teal)"
          :delta-color="data.mta_sts_stage === 'enforce' ? 'var(--good)' : data.mta_sts_stage === 'testing' ? 'var(--amber)' : 'var(--bad)'"
        />
        <KpiCard label="TLS sessions"    :value="(data.total_sessions ?? 0).toLocaleString()" :delta="`last ${days}d`"    dot-color="var(--indigo)" />
        <KpiCard label="TLS pass rate"   :value="data.pass_pct != null ? data.pass_pct + '%' : '—'" delta="successful" dot-color="var(--good)"  delta-color="var(--good)" />
        <KpiCard label="Policy failures" :value="(data.failed_sessions ?? 0).toLocaleString()"    delta="need review" dot-color="var(--bad)"   delta-color="var(--bad)" />
      </div>

      <div class="row2">

        <!-- MX Health card -->
        <div class="card">
          <div class="ct">
            <h3 aria-level="2">MX host health</h3>
            <StatusChip variant="stg" :value="data.mta_sts_stage" :label="data.mta_sts_stage?.toUpperCase()" />
          </div>

          <div v-if="data.mx_hosts?.length" class="mx-list">
            <div v-for="mx in data.mx_hosts" :key="mx.mx_host" class="mx-row">
              <div class="mx-top">
                <span class="mx-host">{{ mx.mx_host }}</span>
                <span class="sev-chip" :style="{ color: severityColor(mx.severity), borderColor: severityColor(mx.severity) }">
                  {{ severityLabel(mx.severity) }}
                </span>
              </div>
              <div class="mx-stats">
                <span>{{ mx.total_sessions.toLocaleString() }} sessions</span>
                <span :style="{ color: passPctColor(mx.pass_pct) }">{{ mx.pass_pct }}% pass</span>
                <span v-if="mx.failed_sessions > 0" style="color:var(--bad)">{{ mx.failed_sessions }} failed</span>
              </div>
              <div v-if="mx.failure_explanation" class="mx-explain">
                {{ mx.failure_explanation }}
                <AskFollowUp
                  v-if="selectedDomainObj"
                  screen="tls"
                  :domain-id="selectedDomainObj.id"
                  :seed-context="`MX host ${mx.mx_host}, ${mx.failed_sessions} failed sessions of ${mx.total_sessions} total (${mx.pass_pct}% pass). Failure: ${mx.failure_explanation}`"
                />
              </div>
            </div>
          </div>
          <DataDeadZone
            v-else-if="selected !== ALL"
            record-label="MTA-STS / TLS-RPT"
            :record-published="!!selectedDomainObj?.mta_sts_published"
            :published-since="selectedDomainObj?.added_at ?? null"
            :on-go-to-roadmap="goToRoadmap"
          />
          <div v-else style="color:var(--muted);font-size:13px;margin-bottom:16px">
            No TLS report data yet across your domains.
          </div>

          <MxReadinessScorecard v-if="data?.mx_hosts?.length" :mx-hosts="data.mx_hosts" />

          <div class="mode-box" :class="data.mta_sts_stage ?? 'none'">
            <div class="mode-title">
              MTA-STS is in <strong>{{ (data.mta_sts_stage ?? 'NONE').toUpperCase() }}</strong> mode
              <ConceptCardButton concept-id="tls.mode" :context="{ mode: data.mta_sts_stage ?? 'none' }" screen="tls" :domain-id="selectedDomainObj?.id" />
            </div>
            <div class="mode-desc" v-if="data.mta_sts_stage === 'enforce'">
              Sending servers that cannot negotiate TLS to your MX hosts are rejected outright. No plaintext fallback is permitted.
            </div>
            <div class="mode-desc" v-else-if="data.mta_sts_stage === 'testing'">
              Senders still attempt TLS but failures are only reported — mail is never rejected. Use this window to identify and fix issues before switching to enforce.
            </div>
            <div class="mode-desc" v-else>
              No MTA-STS policy is active. Inbound mail may be delivered in plaintext with no warning or visibility.
            </div>
          </div>
        </div>

        <!-- Failure analysis card -->
        <div class="card">
          <div class="ct"><h3 aria-level="2">Failure analysis</h3><span class="sectag">last {{ days }}d</span></div>

          <!-- Pass/fail bar -->
          <div v-if="data.total_sessions > 0" style="margin-bottom:20px">
            <div class="bar-labels">
              <span style="color:var(--good)">{{ data.successful_sessions.toLocaleString() }} passed</span>
              <span style="color:var(--bad)">{{ data.failed_sessions.toLocaleString() }} failed</span>
            </div>
            <div class="pf-bar">
              <div class="pf-pass" :style="{ width: data.pass_pct + '%' }" />
              <div class="pf-fail" :style="{ width: (100 - data.pass_pct) + '%' }" />
            </div>
          </div>

          <!-- Failure type breakdown -->
          <div v-if="data.fail_types?.length" style="margin-bottom:20px">
            <div class="ft-header">Failure categories</div>
            <div v-for="ft in data.fail_types" :key="ft.reason" class="ft-row">
              <div class="ft-top">
                <span class="ft-label">{{ ft.label }}</span>
                <span class="ft-count">{{ ft.count }}</span>
              </div>
              <div class="ft-bar-wrap">
                <div class="ft-bar">
                  <div class="ft-fill" :style="{ width: ft.pct + '%' }" />
                </div>
                <span class="ft-pct">{{ ft.pct }}%</span>
              </div>
            </div>
          </div>

          <!-- Per-MX failure cards -->
          <div v-if="data.fail_groups?.length">
            <div class="ft-header">Failures by MX host</div>
            <div v-for="f in data.fail_groups" :key="f.mx_host" class="fail-card">
              <div class="fail-card-top">
                <div>
                  <div class="fail-label">{{ f.mx_host }}</div>
                  <div v-if="f.reporter_org" class="fail-reporter">Reported by {{ f.reporter_org }}</div>
                </div>
                <div style="text-align:right">
                  <div class="fail-count-big" :style="{ color: severityColor(f.severity) }">{{ f.failed_sessions }}</div>
                  <div class="fail-of-total">of {{ f.total_sessions.toLocaleString() }}</div>
                </div>
              </div>
              <div class="fail-prop-bar">
                <div class="fail-prop-fill" :style="{ width: Math.min(100, (f.failed_sessions / (f.total_sessions || 1)) * 100) + '%', background: severityColor(f.severity) }" />
              </div>
              <div class="fail-explain">{{ f.failure_explanation }}</div>
            </div>
          </div>

          <div v-if="!data.fail_groups?.length && !data.fail_types?.length" style="color:var(--muted);font-size:13px">
            No failures reported — TLS delivery to all MX hosts is healthy.
          </div>
        </div>
      </div>
    </template>

    <div v-if="loading" style="padding:40px;text-align:center;color:var(--muted)">Loading TLS data…</div>

    <!-- Review TLS Record modal -->
    <Teleport to="body">
      <div v-if="diff" class="modal-overlay" @click.self="diff = null">
        <div class="modal-box">
          <div class="mh">
            <span>Review TLS record</span>
            <button class="mx-btn" @click="diff = null">✕</button>
          </div>

          <div class="review-why">
            <div class="review-why-title">What enforcing MTA-STS means</div>
            <div class="review-why-body">{{ diff.why }}</div>
          </div>

          <div class="review-gates">
            <div class="gates-label">Prerequisites before enforcing</div>
            <div v-for="g in diff.gates" :key="g.label" class="gate-row">
              <span class="gate-icon" :style="{ color: g.ok ? 'var(--good)' : 'var(--bad)' }">{{ g.ok ? '✓' : '✗' }}</span>
              <span class="gate-text" :style="{ color: g.ok ? 'var(--txt)' : 'var(--bad)' }">{{ g.label }}</span>
            </div>
          </div>

          <div v-if="!diff.ready" class="review-warning">
            ⚠ One or more prerequisites are not met. Publishing now may cause legitimate inbound mail to be rejected. Resolve the items above first.
          </div>

          <div class="review-diff">
            <div class="gates-label" style="margin-bottom:8px">Record change</div>
            <div class="diff-host">{{ diff.host }}</div>
            <div class="diff-row">
              <span class="diff-tag old">CURRENT</span>
              <code>{{ diff.current }}</code>
            </div>
            <div class="diff-row">
              <span class="diff-tag new">PROPOSED</span>
              <code>{{ diff.proposed }}</code>
            </div>
          </div>

          <div style="display:flex;gap:10px;margin-top:18px;flex-wrap:wrap">
            <button class="btn" @click="markPublished">{{ diff.ready ? 'Mark as published' : 'Publish anyway' }}</button>
            <button class="btn ghost" @click="copyRecord">Copy proposed record</button>
            <button class="btn ghost" @click="diff = null">Cancel</button>
          </div>
          <div class="review-footer">
            Record drafted by ZoneProof · you publish manually to your DNS provider.
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
.titlerow { display: flex; align-items: flex-end; justify-content: space-between; margin-bottom: 16px; gap: 16px; flex-wrap: wrap; }
.crumb { font-family: var(--mono); font-size: 10px; color: var(--faint); letter-spacing: 1.4px; text-transform: uppercase; }
h1 { font-family: var(--disp); font-weight: 800; font-size: 25px; letter-spacing: -.7px; margin-top: 5px; }
.sub { color: var(--muted); margin-top: 5px; font-size: 13px; }

.dom-select {
  background: var(--surface-raised);
  border: 1px solid var(--line2);
  border-radius: 12px;
  color: var(--txt);
  font-family: var(--disp);
  font-size: 13px;
  font-weight: 600;
  padding: 9px 36px 9px 14px;
  appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23888' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 12px center;
  cursor: pointer;
  min-width: 220px;
  color-scheme: dark;
}
.dom-select:focus { outline: none; border-color: var(--indigo); }

.kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 16px; }
.row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.card { background: var(--glass); border: 1px solid var(--line); border-radius: 18px; padding: 20px; backdrop-filter: blur(12px); box-shadow: 0 12px 40px rgba(0,0,0,.35), inset 0 1px 0 rgba(255,255,255,.05); }
.ct { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
.ct h3 { font-family: var(--disp); font-weight: 700; font-size: 15px; }
.sectag { font-family: var(--mono); font-size: 9px; letter-spacing: 1px; text-transform: uppercase; color: var(--teal); }
.btn { background: linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff; border:none; border-radius:12px; padding:10px 18px; font-family:var(--disp); font-weight:700; font-size:13px; cursor:pointer; }
.btn.ghost { background:rgba(255,255,255,.04); border:1px solid var(--line2); color:var(--txt); box-shadow:none; }
.btn.ghost:hover { border-color:var(--indigo); }

/* MX health */
.mx-list { display: flex; flex-direction: column; gap: 10px; margin-bottom: 16px; }
.mx-row { background: rgba(255,255,255,.03); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
.mx-top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }
.mx-host { font-family: var(--mono); font-size: 12px; color: var(--txt); }
.sev-chip { font-family: var(--mono); font-size: 9px; letter-spacing: .8px; text-transform: uppercase; border: 1px solid; border-radius: 6px; padding: 2px 7px; }
.mx-stats { display: flex; gap: 14px; font-size: 11.5px; color: var(--muted); margin-bottom: 4px; }
.mx-explain { font-size: 11.5px; color: var(--muted); line-height: 1.55; margin-top: 6px; padding-top: 6px; border-top: 1px solid var(--line); }

.mode-box { border-radius: 10px; padding: 12px 14px; border: 1px solid; }
.mode-box.enforce { border-color: rgba(52,211,153,.3); background: rgba(52,211,153,.06); }
.mode-box.testing { border-color: rgba(251,191,36,.3); background: rgba(251,191,36,.06); }
.mode-box.none    { border-color: rgba(248,113,113,.3); background: rgba(248,113,113,.06); }
.mode-title { font-family: var(--disp); font-weight: 700; font-size: 12px; margin-bottom: 5px; }
.mode-desc { font-size: 12px; color: var(--muted); line-height: 1.55; }

/* Pass/fail bar */
.bar-labels { display: flex; justify-content: space-between; font-size: 11.5px; margin-bottom: 6px; }
.pf-bar { display: flex; height: 7px; border-radius: 7px; overflow: hidden; background: rgba(255,255,255,.05); }
.pf-pass { background: var(--good); transition: width .4s; }
.pf-fail { background: var(--bad); transition: width .4s; }

/* Failure types */
.ft-header { font-family: var(--mono); font-size: 9px; letter-spacing: 1px; text-transform: uppercase; color: var(--faint); margin-bottom: 10px; }
.ft-row { margin-bottom: 10px; }
.ft-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
.ft-label { font-size: 12px; color: var(--txt); }
.ft-count { font-family: var(--mono); font-size: 11px; color: var(--bad); }
.ft-bar-wrap { display: flex; align-items: center; gap: 8px; }
.ft-bar { flex: 1; height: 4px; background: rgba(255,255,255,.07); border-radius: 4px; overflow: hidden; }
.ft-fill { height: 100%; background: var(--bad); border-radius: 4px; }
.ft-pct { font-family: var(--mono); font-size: 10px; color: var(--muted); min-width: 32px; text-align: right; }

/* Failure group cards */
.fail-card { background: rgba(255,255,255,.03); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; margin-bottom: 10px; }
.fail-card-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; }
.fail-label { font-family: var(--mono); font-size: 12px; color: var(--txt); margin-bottom: 3px; }
.fail-reporter { font-size: 11px; color: var(--muted); }
.fail-count-big { font-family: var(--mono); font-size: 18px; font-weight: 700; }
.fail-of-total { font-size: 10px; color: var(--muted); }
.fail-prop-bar { height: 4px; background: rgba(255,255,255,.07); border-radius: 4px; overflow: hidden; margin-bottom: 8px; }
.fail-prop-fill { height: 100%; border-radius: 4px; }
.fail-explain { font-size: 11.5px; color: var(--muted); line-height: 1.55; }

/* All-domains table */
.dom-table { width: 100%; }
.dom-thead { display: grid; grid-template-columns: 2fr 1fr 1fr 1fr 1fr; gap: 8px; padding: 0 8px 8px; font-family: var(--mono); font-size: 9px; letter-spacing: .8px; text-transform: uppercase; color: var(--faint); border-bottom: 1px solid var(--line); }
.dom-trow { display: grid; grid-template-columns: 2fr 1fr 1fr 1fr 1fr; gap: 8px; padding: 10px 8px; align-items: center; border-bottom: 1px solid var(--line); cursor: pointer; transition: background .15s; border-radius: 8px; }
.dom-trow:last-child { border-bottom: none; }
.dom-trow:hover { background: rgba(255,255,255,.03); }
.dom-name { font-family: var(--mono); font-size: 12px; color: var(--txt); }
.stage-badge { font-family: var(--mono); font-size: 9px; letter-spacing: .8px; text-transform: uppercase; border: 1px solid; border-radius: 6px; padding: 2px 7px; }
.pct-badge { font-family: var(--mono); font-size: 12px; font-weight: 700; }
.empty-row { padding: 20px 8px; color: var(--muted); font-size: 13px; }
.table-hint { font-size: 11px; color: var(--faint); margin-top: 10px; text-align: right; }

/* Modal */
.modal-overlay { position:fixed;inset:0;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);z-index:200;display:grid;place-items:center;padding:20px; }
.modal-box { width:600px;max-width:94vw;max-height:90vh;overflow-y:auto;background: var(--surface-raised);border:1px solid var(--line2);border-radius:18px;padding:24px;box-shadow:0 30px 80px rgba(0,0,0,.7); }
.mh { display:flex;align-items:center;justify-content:space-between;margin-bottom:16px; }
.mh span { font-family:var(--disp);font-weight:800;font-size:16px; }
.mx-btn { background:none;border:1px solid var(--line);border-radius:8px;color:var(--muted);width:28px;height:28px;cursor:pointer;font-size:14px; }

.review-why { background: rgba(91,92,240,.08); border: 1px solid rgba(91,92,240,.25); border-radius: 10px; padding: 14px; margin-bottom: 16px; }
.review-why-title { font-family: var(--mono); font-size: 9px; letter-spacing: 1px; text-transform: uppercase; color: var(--indigo); margin-bottom: 6px; }
.review-why-body { font-size: 12.5px; color: var(--txt); line-height: 1.6; }

.review-gates { margin-bottom: 14px; }
.gates-label { font-family: var(--mono); font-size: 9px; letter-spacing: 1px; text-transform: uppercase; color: var(--faint); margin-bottom: 8px; }
.gate-row { display: flex; align-items: flex-start; gap: 8px; margin-bottom: 7px; }
.gate-icon { font-size: 13px; flex-shrink: 0; margin-top: 1px; }
.gate-text { font-size: 12.5px; line-height: 1.45; }

.review-warning { background: rgba(251,191,36,.08); border: 1px solid rgba(251,191,36,.3); border-radius: 10px; padding: 12px 14px; font-size: 12px; color: var(--amber); margin-bottom: 14px; }

.review-diff { background: rgba(255,255,255,.03); border: 1px solid var(--line); border-radius: 10px; padding: 14px; margin-bottom: 4px; }
.diff-host { font-family: var(--mono); font-size: 10px; color: var(--faint); margin-bottom: 10px; }
.diff-row { display: flex; align-items: flex-start; gap: 10px; margin-bottom: 8px; }
.diff-row:last-child { margin-bottom: 0; }
.diff-tag { font-family: var(--mono); font-size: 8px; letter-spacing: .8px; text-transform: uppercase; border-radius: 5px; padding: 2px 6px; flex-shrink: 0; margin-top: 2px; }
.diff-tag.old { background: rgba(248,113,113,.15); color: var(--bad); }
.diff-tag.new { background: rgba(52,211,153,.15); color: var(--good); }
.diff-row code { font-family: var(--mono); font-size: 11px; color: var(--txt); line-height: 1.5; word-break: break-all; }
.review-footer { font-family:var(--mono);font-size:10px;color:var(--faint);margin-top:14px;padding-top:12px;border-top:1px solid var(--line); }

@media (max-width: 900px) {
  .kpis { grid-template-columns: repeat(2,1fr); }
  .row2 { grid-template-columns: 1fr; }
  .dom-thead, .dom-trow { grid-template-columns: 2fr 1fr 1fr; }
  .dom-thead span:nth-child(4), .dom-thead span:nth-child(5),
  .dom-trow span:nth-child(4), .dom-trow span:nth-child(5) { display: none; }
}
</style>
