<script setup lang="ts">
import { ref, computed, onMounted, nextTick, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api/client'
import { useDomainsStore } from '@/stores/domains'
import { useUiStore } from '@/stores/ui'
import AdvisorBanner from '@/components/ui/AdvisorBanner.vue'
import LoadError from '@/components/ui/LoadError.vue'
import SplitBar from '@/components/ui/SplitBar.vue'
import RecordReviewModal from '@/components/domain/RecordReviewModal.vue'
import { useScopeStore } from '@/stores/scope'

const router  = useRouter()
const domains = useDomainsStore()
const ui      = useUiStore()
const overview       = ref<any>(null)
const advisor        = ref<any>(null)
const advisorLoading = ref(false)
const loadError = ref('')
const loading        = ref(true)
const diff     = ref<any>(null)
const diffDomainId = ref<string>('')
const diffTrack    = ref<'dmarc' | 'tls'>('dmarc')

// View state
const tab        = ref<'dmarc' | 'tls'>('dmarc')
const scope = useScopeStore()
const selected = computed<string>({
  get: () => scope.domain ?? '__all__',
  set: (v) => scope.set(v === '__all__' ? null : v),
})   // '__all__' = tenant-wide
const search     = ref('')

onMounted(async () => {
  advisorLoading.value = true
  try {
    await domains.fetch()
    if (domains.error) throw new Error(domains.error)
    overview.value = await api.overview()
  } catch (e: any) { loadError.value = e?.message || 'The data request failed.' } finally { loading.value = false }

  // Advisor: load cached content immediately, then refresh in background
  try {
    const screen = tab.value === 'tls' ? 'posture_tls' : 'posture_dmarc'
    advisor.value = await api.advisor(screen, undefined, true)
    api.advisor(screen, undefined, false).then(fresh => {
      advisor.value = fresh
    }).catch(() => {})
  } catch { /* leave advisor null — skeleton stays */ }
  finally { advisorLoading.value = false }
})

// When domain selection changes, reload advisor for that domain context
watch(selected, async (newVal) => {
  advisor.value = null
  advisorLoading.value = true
  const capturedTab = tab.value
  const capturedVal = newVal
  const screen = capturedTab === 'tls' ? 'posture_tls' : 'posture_dmarc'
  const dom = domains.list.find(d => d.domain === newVal)
  const domId = newVal === '__all__' ? undefined : dom?.id
  try {
    const result = await api.advisor(screen, domId, false)
    if (selected.value === capturedVal && tab.value === capturedTab) advisor.value = result
  } catch { /* leave advisor null */ }
  finally { if (selected.value === capturedVal && tab.value === capturedTab) advisorLoading.value = false }
})

async function reloadAdvisor() {
  advisorLoading.value = true
  try {
    await domains.fetch()
    const dom = domains.list.find(d => d.domain === selected.value)
    const domId = selected.value === '__all__' ? undefined : dom?.id
    advisor.value = await api.advisor(tab.value === 'tls' ? 'posture_tls' : 'posture_dmarc', domId, false, true)
  } finally { advisorLoading.value = false }
}

async function switchAdvisor() {
  await nextTick()
  advisor.value = null  // clear stale context on tab switch
  advisorLoading.value = true
  const capturedTab = tab.value
  const dom = domains.list.find(d => d.domain === selected.value)
  const domId = selected.value === '__all__' ? undefined : dom?.id
  try {
    const result = await api.advisor(capturedTab === 'tls' ? 'posture_tls' : 'posture_dmarc', domId, false)
    if (tab.value === capturedTab) advisor.value = result
  } catch { /* leave advisor null — skeleton stays */ }
  finally { if (tab.value === capturedTab) advisorLoading.value = false }
}

// Filtered domains based on search query
const allDomains = computed<any[]>(() => overview.value?.domains ?? [])

const filteredDomains = computed(() => {
  const q = search.value.trim().toLowerCase()
  if (!q) return allDomains.value
  return allDomains.value.filter(d =>
    d.domain.toLowerCase().includes(q)
  )
})

// When a specific domain is selected AND not filtered out, show just that one
const viewDomains = computed(() => {
  if (selected.value === '__all__') return filteredDomains.value
  const d = filteredDomains.value.find(d => d.domain === selected.value)
  return d ? [d] : []
})

// DMARC aggregate totals
const dmarcTotal   = computed(() => viewDomains.value.reduce((s, d) => s + (d.volume ?? 0), 0))
const dmarcPassing = computed(() => viewDomains.value.reduce((s, d) => s + Math.round((d.volume ?? 0) * (d.dmarc_comp ?? 0) / 100), 0))
const dmarcFailing = computed(() => dmarcTotal.value - dmarcPassing.value)
const dmarcPct     = computed(() => dmarcTotal.value ? Math.round(dmarcPassing.value / dmarcTotal.value * 100) : 0)

// TLS aggregate totals
const tlsTotal    = computed(() => viewDomains.value.reduce((s, d) => s + (d.tls_sessions ?? 0), 0))
const tlsSuccess  = computed(() => viewDomains.value.reduce((s, d) => s + Math.round((d.tls_sessions ?? 0) * (d.tls_pass_pct ?? 0) / 100), 0))
const tlsFailed   = computed(() => tlsTotal.value - tlsSuccess.value)
const tlsPct      = computed(() => tlsTotal.value ? Math.round(tlsSuccess.value / tlsTotal.value * 100) : 0)

function stageColor(stage: string) {
  if (!stage) return 'var(--faint)'
  const s = stage.toLowerCase()
  if (s === 'reject' || s === 'enforce') return 'var(--good)'
  if (s === 'quarantine' || s === 'testing') return 'var(--amber)'
  return 'var(--bad)'
}

function compColor(c: number | null) {
  if (c == null) return 'var(--bad)'
  return c > 95 ? 'var(--good)' : c > 75 ? 'var(--amber)' : 'var(--bad)'
}

async function openDmarcReview(d: any) {
  const dom = domains.list.find(x => x.domain === d.domain)
  if (!dom) return
  diff.value = await api.dmarcRecordDiff(dom.id)
  diffDomainId.value = dom.id
  diffTrack.value = 'dmarc'
}

async function openTlsReview(d: any) {
  const dom = domains.list.find(x => x.domain === d.domain)
  if (!dom) return
  diff.value = await api.tlsRecordDiff(dom.id)
  diffDomainId.value = dom.id
  diffTrack.value = 'tls'
}

</script>

<template>
  <div>
    <LoadError v-if="loadError" :message="loadError" @retry="$router.go(0)" />
    <!-- Header -->
    <div class="titlerow">
      <div>
        <div class="crumb">02 / Posture</div>
        <h1>Tenant posture — {{ selected === '__all__' ? 'all domains' : selected }}</h1>
        <div class="sub">DMARC &amp; MTA-STS aggregate reports — compliant vs non-compliant sources, drillable to IP and volume.</div>
      </div>
    </div>

    <!-- Controls row: tabs + search + domain pills -->
    <div class="controls">
      <!-- Tabs -->
      <div class="tabs">
        <button class="tab" :class="{ active: tab === 'dmarc' }" @click="tab = 'dmarc'; switchAdvisor()">DMARC</button>
        <button class="tab" :class="{ active: tab === 'tls' }"   @click="tab = 'tls';  switchAdvisor()">MTA-STS / TLS</button>
      </div>

      <!-- Search -->
      <div class="search-wrap">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="search-icon">
          <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
        </svg>
        <input v-model="search" class="search-inp" placeholder="Search domain or IP…" />
        <button v-if="search" class="search-clear" @click="search = ''">×</button>
      </div>

      <!-- Domain selector -->
      <div class="domain-select-wrap">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="select-icon"><circle cx="12" cy="12" r="3"/><path d="M3 12h3m12 0h3M12 3v3m0 12v3"/></svg>
        <select v-model="selected" class="domain-select" aria-label="Domain">
          <option value="__all__">All domains</option>
          <option v-for="d in allDomains" :key="d.domain" :value="d.domain">{{ d.domain }}</option>
        </select>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="select-chev"><path d="M6 9l6 6 6-6"/></svg>
      </div>
    </div>

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

    <!-- Aggregate panels -->
    <div v-if="!loading && overview" class="agg-row">
      <!-- DMARC aggregate -->
      <div class="card agg-card" :class="{ dimmed: tab === 'tls' }" @click="tab = 'dmarc'; switchAdvisor()" tabindex="0" role="button" @keydown.enter.prevent="tab = 'dmarc'; switchAdvisor()" @keydown.space.prevent="tab = 'dmarc'; switchAdvisor()">
        <div class="agg-head">
          <span class="agg-label">DMARC aggregate</span>
          <span class="agg-scope">{{ selected === '__all__' ? 'ALL DOMAINS' : selected }}</span>
        </div>
        <div class="agg-num">{{ dmarcTotal.toLocaleString() }}</div>
        <div class="agg-sub">ALIGNED · {{ dmarcPct }}%</div>
        <div class="agg-bar-track">
          <div class="agg-bar-pass" :style="{ width: dmarcPct + '%' }" />
          <div class="agg-bar-fail" :style="{ width: (100 - dmarcPct) + '%' }" />
        </div>
        <div class="agg-legend">
          <span><span class="dot pass" />Passing <b>{{ dmarcPassing.toLocaleString() }}</b></span>
          <span><span class="dot fail" />Failing <b>{{ dmarcFailing.toLocaleString() }}</b></span>
        </div>
      </div>

      <!-- TLS aggregate -->
      <div class="card agg-card" :class="{ dimmed: tab === 'dmarc' }" @click="tab = 'tls'; switchAdvisor()" tabindex="0" role="button" @keydown.enter.prevent="tab = 'tls'; switchAdvisor()" @keydown.space.prevent="tab = 'tls'; switchAdvisor()">
        <div class="agg-head">
          <span class="agg-label">MTA-STS / TLS aggregate</span>
          <span class="agg-scope">{{ selected === '__all__' ? 'ALL DOMAINS' : selected }}</span>
        </div>
        <div class="agg-num">{{ tlsTotal.toLocaleString() }}</div>
        <div class="agg-sub">NEGOTIATED · {{ tlsPct }}%</div>
        <div class="agg-bar-track">
          <div class="agg-bar-pass" :style="{ width: tlsPct + '%' }" />
          <div class="agg-bar-fail" :style="{ width: (100 - tlsPct) + '%' }" />
        </div>
        <div class="agg-legend">
          <span><span class="dot pass" />Success <b>{{ tlsSuccess.toLocaleString() }}</b></span>
          <span><span class="dot fail" />Failed <b>{{ tlsFailed.toLocaleString() }}</b></span>
        </div>
      </div>
    </div>

    <!-- Domain breakdown table -->
    <div v-if="!loading && overview" class="card" style="margin-top:14px">
      <div class="ct">
        <h3 aria-level="2">By domain</h3>
        <div class="ct-right">
          <span class="sectag">EXPAND → SOURCES → IP → VOLUME</span>
        </div>
      </div>

      <!-- No results -->
      <div v-if="!viewDomains.length" class="empty">No domains match your search.</div>

      <!-- Table -->
      <template v-else>
        <!-- DMARC tab -->
        <template v-if="tab === 'dmarc'">
          <div class="thead">
            <span>Domain</span>
            <span>Policy</span>
            <span>Volume</span>
            <span>Compliance</span>
            <span>Action</span>
          </div>
          <div v-for="d in viewDomains" :key="d.domain" class="trow">
            <div class="dname">
              <span class="dini">{{ d.domain[0].toUpperCase() }}</span>
              <div>
                <div>{{ d.domain }}</div>
                <div class="dsub">{{ d.dmarc_stage }}</div>
              </div>
            </div>
            <div>
              <span class="stage-badge" :style="{ color: stageColor(d.dmarc_stage), borderColor: stageColor(d.dmarc_stage) + '44', background: stageColor(d.dmarc_stage) + '18' }">
                {{ (d.dmarc_stage || 'none').toUpperCase() }}
              </span>
            </div>
            <div class="mono">{{ (d.volume ?? 0).toLocaleString() }}</div>
            <div class="comp-cell">
              <div class="comp-bar-track">
                <div class="comp-bar-fill" :style="{ width: (d.dmarc_comp ?? 0) + '%', background: compColor(d.dmarc_comp) }" />
              </div>
              <span class="mono" :style="{ color: compColor(d.dmarc_comp) }">
                {{ d.dmarc_comp != null ? d.dmarc_comp + '%' : 'no record' }}
              </span>
            </div>
            <button class="action-btn" @click="openDmarcReview(d)">Review record →</button>
          </div>
        </template>

        <!-- TLS tab -->
        <template v-else>
          <div class="thead">
            <span>Domain</span>
            <span>MTA-STS mode</span>
            <span>Sessions</span>
            <span>TLS pass rate</span>
            <span>Action</span>
          </div>
          <div v-for="d in viewDomains" :key="d.domain" class="trow">
            <div class="dname">
              <span class="dini">{{ d.domain[0].toUpperCase() }}</span>
              <div>
                <div>{{ d.domain }}</div>
                <div class="dsub">{{ d.mta_sts_stage }}</div>
              </div>
            </div>
            <div>
              <span class="stage-badge" :style="{ color: stageColor(d.mta_sts_stage), borderColor: stageColor(d.mta_sts_stage) + '44', background: stageColor(d.mta_sts_stage) + '18' }">
                {{ (d.mta_sts_stage || 'none').toUpperCase() }}
              </span>
            </div>
            <div class="mono">{{ (d.tls_sessions ?? 0).toLocaleString() }}</div>
            <div class="comp-cell">
              <div class="comp-bar-track">
                <div class="comp-bar-fill" :style="{ width: (d.tls_pass_pct ?? 0) + '%', background: compColor(d.tls_pass_pct) }" />
              </div>
              <span class="mono" :style="{ color: compColor(d.tls_pass_pct) }">
                {{ d.tls_pass_pct != null ? d.tls_pass_pct + '%' : '—' }}
              </span>
            </div>
            <button class="action-btn" @click="openTlsReview(d)">Review TLS →</button>
          </div>
        </template>
      </template>
    </div>

    <div v-if="loading" class="loading-msg">Loading posture…</div>

    <Teleport to="body">
      <div v-if="diff" class="modal-overlay" @click.self="diff = null">
        <div class="modal-box">
          <div class="mh">
            <span>{{ diffTrack === 'tls' ? 'Review TLS record' : 'Review DMARC record' }}</span>
            <button class="mx-btn" @click="diff = null">✕</button>
          </div>
          <RecordReviewModal :diff="diff" :domain-id="diffDomainId" :track="diffTrack" @close="diff = null" />
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
.titlerow { margin-bottom: 14px; }
.crumb { font-family: var(--mono); font-size: 10px; color: var(--faint); letter-spacing: 1.4px; text-transform: uppercase; }
h1 { font-family: var(--disp); font-weight: 800; font-size: 23px; letter-spacing: -.6px; margin-top: 4px; }
.sub { color: var(--muted); margin-top: 4px; font-size: 13px; }

/* Controls */
.controls { display: flex; align-items: center; gap: 14px; margin-bottom: 16px; flex-wrap: wrap; }

.tabs { display: flex; background: rgba(255,255,255,.04); border: 1px solid var(--line); border-radius: 12px; padding: 3px; gap: 2px; flex: none; }
.tab { background: none; border: none; color: var(--muted); font-family: var(--mono); font-size: 11px; font-weight: 600; letter-spacing: .5px; padding: 7px 16px; border-radius: 9px; cursor: pointer; transition: .15s; }
.tab.active { background: rgba(91,92,240,.25); color: var(--txt); }
.tab:hover:not(.active) { color: var(--txt); }

.search-wrap { position: relative; display: flex; align-items: center; flex: none; }
.search-icon { width: 14px; height: 14px; position: absolute; left: 11px; color: var(--faint); pointer-events: none; }
.search-inp { background: rgba(255,255,255,.04); border: 1px solid var(--line2); border-radius: 10px; color: var(--txt); font-family: var(--body); font-size: 12.5px; padding: 8px 32px 8px 32px; outline: none; width: 220px; }
.search-inp::placeholder { color: var(--faint); }
.search-inp:focus { border-color: var(--teal); }
.search-clear { position: absolute; right: 9px; background: none; border: none; color: var(--faint); cursor: pointer; font-size: 16px; line-height: 1; padding: 0; }
.search-clear:hover { color: var(--txt); }

.domain-select-wrap { position: relative; display: flex; align-items: center; }
.select-icon { width: 14px; height: 14px; position: absolute; left: 10px; color: var(--faint); pointer-events: none; }
.domain-select { appearance: none; background: rgba(255,255,255,.04); border: 1px solid var(--line2); border-radius: 10px; color: var(--txt); font-family: var(--mono); font-size: 12px; padding: 8px 34px 8px 30px; outline: none; cursor: pointer; min-width: 190px; }
.domain-select:focus { border-color: var(--teal); }
.domain-select option { background: #16182a; color: var(--txt); }
.select-chev { width: 14px; height: 14px; position: absolute; right: 10px; color: var(--faint); pointer-events: none; }

/* Aggregate panels */
.agg-row { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
@media (max-width: 700px) { .agg-row { grid-template-columns: 1fr; } }

.card { background: var(--glass); border: 1px solid var(--line); border-radius: 18px; padding: 20px; backdrop-filter: blur(12px); box-shadow: 0 12px 40px rgba(0,0,0,.35), inset 0 1px 0 rgba(255,255,255,.05); }
.agg-card { cursor: pointer; transition: opacity .2s, border-color .2s; }
.agg-card.dimmed { opacity: .45; }
.agg-card:hover { border-color: var(--line2); }

.agg-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
.agg-label { font-family: var(--disp); font-weight: 700; font-size: 14px; }
.agg-scope { font-family: var(--mono); font-size: 9px; letter-spacing: 1px; text-transform: uppercase; color: var(--faint); }
.agg-num { font-family: var(--disp); font-weight: 900; font-size: 36px; letter-spacing: -1.5px; line-height: 1; }
.agg-sub { font-family: var(--mono); font-size: 9.5px; letter-spacing: 1px; color: var(--muted); margin: 4px 0 14px; }
.agg-bar-track { display: flex; height: 14px; border-radius: 7px; overflow: hidden; gap: 2px; }
.agg-bar-pass { background: #34e0a1; border-radius: 7px 0 0 7px; transition: width .5s ease; }
.agg-bar-fail { background: #ff5050; border-radius: 0 7px 7px 0; flex: 1; transition: width .5s ease; }
.agg-legend { display: flex; gap: 20px; margin-top: 10px; font-size: 12px; color: var(--muted); }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 5px; }
.dot.pass { background: #34e0a1; }
.dot.fail { background: #ff5050; }

/* Table */
.ct { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; }
.ct h3 { font-family: var(--disp); font-weight: 700; font-size: 15px; }
.ct-right { display: flex; align-items: center; gap: 14px; }
.sectag { font-family: var(--mono); font-size: 9px; letter-spacing: 1px; text-transform: uppercase; color: var(--teal); }

.thead { display: grid; grid-template-columns: 1.8fr 1fr 0.8fr 1.3fr 1fr; gap: 12px; align-items: center; font-family: var(--mono); font-size: 9px; letter-spacing: .8px; text-transform: uppercase; color: var(--faint); padding: 0 10px 10px; border-bottom: 1px solid var(--line); }
.trow { display: grid; grid-template-columns: 1.8fr 1fr 0.8fr 1.3fr 1fr; gap: 12px; align-items: center; padding: 11px 10px; border-radius: 10px; transition: .15s; border: 1px solid transparent; }
.trow:hover { background: rgba(255,255,255,.04); border-color: var(--line); }

.dname { font-family: var(--mono); font-size: 12.5px; font-weight: 600; display: flex; align-items: center; gap: 10px; }
.dini { width: 28px; height: 28px; border-radius: 8px; background: rgba(255,255,255,.07); display: grid; place-items: center; font-family: var(--disp); font-weight: 700; font-size: 12px; flex: none; }
.dsub { font-family: var(--mono); font-size: 9px; color: var(--faint); margin-top: 2px; }
.mono { font-family: var(--mono); font-size: 12px; }

.stage-badge { font-family: var(--mono); font-size: 9.5px; letter-spacing: .5px; padding: 3px 10px; border-radius: 20px; border: 1px solid; }

.comp-cell { display: flex; align-items: center; gap: 10px; }
.comp-bar-track { flex: 1; height: 4px; background: rgba(255,255,255,.08); border-radius: 4px; overflow: hidden; max-width: 80px; }
.comp-bar-fill { height: 100%; border-radius: 4px; transition: width .4s ease; }

.action-btn { background: none; border: 1px solid var(--line2); color: var(--muted); font-family: var(--mono); font-size: 10.5px; padding: 5px 12px; border-radius: 8px; cursor: pointer; transition: .15s; white-space: nowrap; }
.action-btn:hover { border-color: var(--teal); color: var(--teal); }

.empty { color: var(--faint); font-size: 13px; padding: 24px 0; text-align: center; }
.loading-msg { padding: 40px; text-align: center; color: var(--muted); font-size: 13px; }

.modal-overlay { position:fixed;inset:0;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);z-index:200;display:grid;place-items:center;padding:20px; }
.modal-box { width:580px;max-width:94vw;max-height:88vh;overflow-y:auto;background: var(--surface-raised);border:1px solid var(--line2);border-radius:18px;padding:24px;box-shadow:0 30px 80px rgba(0,0,0,.7); }
.mh { display:flex;align-items:center;justify-content:space-between;margin-bottom:16px; }
.mh span { font-family:var(--disp);font-weight:800;font-size:16px; }
.mx-btn { background:none;border:1px solid var(--line);border-radius:8px;color:var(--muted);width:28px;height:28px;cursor:pointer;font-size:14px; }
</style>
