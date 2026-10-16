<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '@/api/client'
import { useDomainsStore } from '@/stores/domains'
import AdvisorBanner from '@/components/ui/AdvisorBanner.vue'
import LoadError from '@/components/ui/LoadError.vue'
import SourceTable from '@/components/domain/SourceTable.vue'
import DmarcAuthDrawer from '@/components/domain/DmarcAuthDrawer.vue'
import RecordReviewModal from '@/components/domain/RecordReviewModal.vue'
import DataDeadZone from '@/components/ui/DataDeadZone.vue'
import ConceptCardButton from '@/components/ui/ConceptCardButton.vue'
import DateRangeFilter from '@/components/ui/DateRangeFilter.vue'
import ReportTimeline from '@/components/ui/ReportTimeline.vue'
import { useScopeStore } from '@/stores/scope'

const route   = useRoute()
const router  = useRouter()
const domains = useDomainsStore()

const ALL = '__all__'
const scope = useScopeStore()
const selected = computed<string>({
  get: () => scope.domain ?? ALL,
  set: (v) => scope.set(v === ALL ? null : v),
})
const days            = ref(30)
const timelineFilter  = ref<{ fromDate: string | null, toDate: string | null, reporters: string[] }>({ fromDate: null, toDate: null, reporters: [] })
const data            = ref<any>(null)
const diff            = ref<any>(null)
const advisor         = ref<any>(null)
const advisorLoading  = ref(false)
const loading         = ref(false)
const loadError       = ref('')
const drawerIp        = ref<any>(null)

onMounted(async () => {
  advisorLoading.value = true
  await domains.fetch()
  if (domains.error) { loadError.value = domains.error; advisorLoading.value = false; loading.value = false; return }
  await loadData(true)
})

watch(selected, () => {
  advisor.value = null
  timelineFilter.value = { fromDate: null, toDate: null, reporters: [] }
  loadData(false)
})
watch(days, () => loadData(false))

function onTimelineChange(f: { fromDate: string | null, toDate: string | null, reporters: string[] }) {
  timelineFilter.value = f
  loadData(false)
}

const filteredSources = computed(() => {
  const sources = data.value?.sources ?? []
  const reps = timelineFilter.value.reporters
  if (!reps.length) return sources
  return sources.filter((s: any) => reps.includes(s.source_org))
})

const filteredSubdomainGroups = computed(() => {
  const groups = data.value?.subdomain_groups ?? []
  const reps = timelineFilter.value.reporters
  if (!reps.length) return groups
  return groups.map((g: any) => ({
    ...g,
    sources: g.sources.filter((s: any) => reps.includes(s.source_org)),
  })).filter((g: any) => g.sources.length > 0)
})

async function loadData(initialLoad = false) {
  loading.value = true
  loadError.value = ''
  data.value = null
  if (!initialLoad) advisorLoading.value = true
  const capturedSelection = selected.value
  const { fromDate, toDate } = timelineFilter.value
  try {
    if (capturedSelection === ALL) {
      const results = await Promise.all(domains.list.map(d => api.dmarcData(d.id, { days: days.value })))
      data.value = mergeOverviews(results)
    } else {
      const dom = domains.list.find(d => d.domain === capturedSelection)
      if (!dom) { loading.value = false; advisorLoading.value = false; return }
      data.value = await api.dmarcData(dom.id, { fromDate, toDate })
    }
  } catch (e: any) { loadError.value = e?.message || 'The data request failed.'; return } finally { loading.value = false }

  // Advisor loads independently — never blocks main content
  // On initial load: use cache so advisor shows instantly; then fire a background refresh
  try {
    const dom = domains.list.find(d => d.domain === capturedSelection)
    const domId = capturedSelection === ALL ? undefined : dom?.id
    const result = await api.advisor('dmarc', domId, initialLoad)
    if (selected.value === capturedSelection) advisor.value = result
    // After showing cached content, fire a background fresh generation
    if (initialLoad) {
      api.advisor('dmarc', domId, false).then(fresh => {
        if (selected.value === capturedSelection) advisor.value = fresh
      }).catch(() => {})
    }
  } catch { /* leave advisor null — skeleton stays */ }
  finally { if (selected.value === capturedSelection) advisorLoading.value = false }
}

function mergeOverviews(results: any[]): any {
  // Aggregate compliance numbers across all domains
  const compliance = results.reduce((acc, r) => {
    const c = r.compliance ?? {}
    acc.total          += c.total          ?? 0
    acc.pass_count     += c.pass_count     ?? 0
    acc.fail_count     += c.fail_count     ?? 0
    acc.unaligned_count+= c.unaligned_count?? 0
    acc.dkim_pass      += Math.round((c.total ?? 0) * (c.dkim_pct ?? 0) / 100)
    acc.spf_pass       += Math.round((c.total ?? 0) * (c.spf_pct  ?? 0) / 100)
    return acc
  }, { total: 0, pass_count: 0, fail_count: 0, unaligned_count: 0, dkim_pass: 0, spf_pass: 0 })

  const t = compliance.total
  compliance.compliance_pct = t ? Math.round(compliance.pass_count / t * 100) : null
  compliance.dkim_pct       = t ? Math.round(compliance.dkim_pass  / t * 100) : null
  compliance.spf_pct        = t ? Math.round(compliance.spf_pass   / t * 100) : null

  // Merge all source lists — tag each source with its originating domain
  const sources = results.flatMap((r, i) =>
    (r.sources ?? []).map((s: any) => ({
      ...s,
      source_org: domains.list[i] ? `${s.source_org} (${domains.list[i].domain})` : s.source_org,
    }))
  ).sort((a: any, b: any) => b.volume - a.volume)

  return { domain: 'All domains', policy: null, pct: 100, compliance, sources }
}

async function loadDiff() {
  const dom = domains.list.find(d => d.domain === selected.value)
  if (!dom) return
  diff.value = await api.dmarcRecordDiff(dom.id)
}

async function reloadAdvisor() {
  advisorLoading.value = true
  try {
    await domains.fetch()
    if (selected.value === ALL) {
      advisor.value = await api.advisor('dmarc', undefined, false, true)
    } else {
      const dom = domains.list.find(d => d.domain === selected.value)
      if (dom) advisor.value = await api.advisor('dmarc', dom.id, false, true)
    }
  } finally { advisorLoading.value = false }
}

// Pass/fail bar values
const compliance  = computed(() => data.value?.compliance ?? {})
const total       = computed(() => compliance.value.total ?? 0)
const passing     = computed(() => compliance.value.pass_count ?? 0)
const unaligned   = computed(() => compliance.value.unaligned_count ?? 0)
const failing     = computed(() => compliance.value.fail_count ?? 0)
const passPct     = computed(() => total.value ? Math.round(passing.value / total.value * 100) : 0)
const unalPct     = computed(() => total.value ? Math.round(unaligned.value / total.value * 100) : 0)
const failPct     = computed(() => Math.max(0, 100 - passPct.value - unalPct.value))

const dkimPct    = computed(() => compliance.value.dkim_pct ?? 0)
const spfPct     = computed(() => compliance.value.spf_pct ?? 0)
const dmarcPct   = computed(() => compliance.value.compliance_pct ?? 0)

const selectedDomainObj = computed(() => domains.list.find(d => d.domain === selected.value))

function goToRoadmap() {
  router.push({ path: '/roadmap', query: selected.value !== ALL ? { domain: selected.value } : {} })
}

// Fold sources by the subdomain that actually sent them — most subdomains
// never need to be separately monitored, since their mail is reported
// under the parent's rua address via DMARC's tree-walk behaviour. Only
// meaningful for a single selected domain (the "All domains" merge already
// flattens everything with a different tagging scheme).
const openGroups = ref<Set<string>>(new Set())
const addingSubdomain = ref<string | null>(null)

const hasSubdomainFold = computed(() =>
  selected.value !== ALL && (filteredSubdomainGroups.value?.length ?? 0) > 1
)

watch(data, (d) => {
  if (d?.subdomain_groups?.length) {
    const primary = d.subdomain_groups.find((g: any) => g.is_primary)
    openGroups.value = new Set(primary ? [primary.header_from] : [])
  }
})

function toggleGroup(headerFrom: string) {
  const next = new Set(openGroups.value)
  if (next.has(headerFrom)) next.delete(headerFrom)
  else next.add(headerFrom)
  openGroups.value = next
}

async function monitorSubdomain(hostname: string) {
  addingSubdomain.value = hostname
  try {
    await api.wizardStart(hostname)
    await api.wizardConfirm(hostname)
    await domains.fetch()
    if (data.value?.subdomain_groups) {
      const g = data.value.subdomain_groups.find((g: any) => g.header_from === hostname)
      if (g) g.is_monitored = true
    }
  } finally {
    addingSubdomain.value = null
  }
}
</script>

<template>
  <div>
    <LoadError v-if="loadError" :message="loadError" @retry="$router.go(0)" />
    <!-- Header -->
    <div class="titlerow">
      <div>
        <div class="crumb">03 / DMARC Analyzer</div>
        <h1>
          Who is sending as {{ selected === '__all__' ? 'your domains' : (selected || '…') }}?
          <ConceptCardButton concept-id="dmarc.authentication_overview" screen="dmarc" :domain-id="selectedDomainObj?.id" />
        </h1>
        <div class="sub">Source → IP → authentication status per aggregated volume. Expand any row, then any IP.</div>
      </div>
      <button v-if="selected !== '__all__'" class="btn" @click="loadDiff">Review record →</button>
    </div>

    <!-- Timeline filter (single domain) or date pills (all domains) -->
    <ReportTimeline
      v-if="selected !== '__all__' && selectedDomainObj"
      :domain-id="selectedDomainObj.id"
      @change="onTimelineChange"
    />
    <div v-else-if="selected === '__all__'" style="margin-bottom:12px">
      <DateRangeFilter v-model="days" />
    </div>

    <!-- Domain dropdown -->
    <div class="domain-bar">
      <div class="domain-select-wrap">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="sel-icon"><circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/></svg>
        <select v-model="selected" class="domain-select" aria-label="Domain">
          <option value="__all__">All domains</option>
          <option disabled style="color:var(--faint)">──────────</option>
          <option v-for="d in domains.list" :key="d.domain" :value="d.domain">{{ d.domain }}</option>
        </select>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="sel-chev"><path d="M6 9l6 6 6-6"/></svg>
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

    <!-- Pass vs fail bar -->
    <div v-if="data" class="card traffic-card">
      <div class="tc-head">
        <span class="tc-title">Pass vs fail traffic</span>
        <span class="tc-total">{{ total.toLocaleString() }} messages</span>
      </div>
      <div class="tc-big">
        <span class="tc-num">{{ passing.toLocaleString() }}</span>
        <span class="tc-sub">DMARC PASS · {{ passPct }}%</span>
      </div>
      <div class="tc-bar">
        <div class="tc-seg pass"      :style="{ flex: passPct }" />
        <div class="tc-seg unaligned" :style="{ flex: unalPct }" />
        <div class="tc-seg fail"      :style="{ flex: failPct }" />
      </div>
      <div class="tc-legend">
        <span><span class="dot pass" />Passing (aligned) <b>{{ passing.toLocaleString() }}</b></span>
        <span><span class="dot unaligned" />Legit, unaligned <b>{{ unaligned.toLocaleString() }}</b></span>
        <span><span class="dot fail" />Failing / spoof <b>{{ (failing - unaligned).toLocaleString() }}</b></span>
      </div>
    </div>

    <!-- DKIM / SPF / DMARC auth stat bars -->
    <div v-if="data" class="auth-stats">
      <div class="auth-stat-card card">
        <div class="as-label">DKIM verification</div>
        <div class="as-bar-wrap">
          <div class="as-bar-track">
            <div class="as-bar-fill good" :style="{ width: dkimPct + '%' }" />
          </div>
          <span class="as-pct good">{{ dkimPct }}% aligned</span>
        </div>
        <div class="as-sub">
          <span class="as-tag good">{{ dkimPct }}% pass</span>
          <span class="as-tag fail">{{ (100 - dkimPct).toFixed(1) }}% fail</span>
        </div>
        <div class="as-hint">SHARE OF VOLUME</div>
      </div>

      <div class="auth-stat-card card">
        <div class="as-label">SPF verification</div>
        <div class="as-bar-wrap">
          <div class="as-bar-track">
            <div class="as-bar-fill good" :style="{ width: spfPct + '%' }" />
          </div>
          <span class="as-pct good">{{ spfPct }}% aligned</span>
        </div>
        <div class="as-sub">
          <span class="as-tag good">{{ spfPct }}% pass</span>
          <span class="as-tag fail">{{ (100 - spfPct).toFixed(1) }}% fail</span>
        </div>
        <div class="as-hint">SHARE OF VOLUME</div>
      </div>

      <div class="auth-stat-card card">
        <div class="as-label">
          DMARC compliance
          <ConceptCardButton concept-id="dmarc.compliance" :context="{ compliance_pct: dmarcPct }" screen="dmarc" :domain-id="selectedDomainObj?.id" />
        </div>
        <div class="as-bar-wrap">
          <div class="as-bar-track">
            <div class="as-bar-fill" :class="dmarcPct > 95 ? 'good' : dmarcPct > 75 ? 'warn' : 'bad'" :style="{ width: dmarcPct + '%' }" />
          </div>
          <span class="as-pct" :class="dmarcPct > 95 ? 'good' : dmarcPct > 75 ? 'warn' : 'bad'">{{ dmarcPct }}%</span>
        </div>
        <div class="as-sub">
          <span class="as-tag good">{{ dmarcPct }}% pass</span>
          <span class="as-tag fail">{{ (100 - dmarcPct).toFixed(1) }}% fail</span>
        </div>
        <div class="as-hint">SHARE OF VOLUME</div>
      </div>
    </div>

    <!-- Sending sources table -->
    <div class="card" style="margin-top:14px">
      <div class="ct">
        <h3 aria-level="2">Sending sources</h3>
        <span class="sectag">SOURCE → IP → AUTH PER VOLUME</span>
      </div>
      <div v-if="loading" style="padding:28px;color:var(--muted);text-align:center">Loading…</div>

      <!-- Folded by subdomain — the common case once a domain has real traffic,
           since most subdomains never need to be separately monitored. -->
      <div v-else-if="hasSubdomainFold" class="subfold-list">
        <div v-for="g in filteredSubdomainGroups" :key="g.header_from" class="subfold">
          <div class="subfold-head" @click="toggleGroup(g.header_from)" tabindex="0" role="button" @keydown.enter.prevent="toggleGroup(g.header_from)" @keydown.space.prevent="toggleGroup(g.header_from)">
            <svg class="subfold-chev" :class="{ open: openGroups.has(g.header_from) }" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M9 18l6-6-6-6"/>
            </svg>
            <span class="subfold-name">{{ g.header_from }}</span>
            <span v-if="g.is_primary" class="subfold-tag primary">primary domain</span>
            <span v-else-if="g.is_monitored" class="subfold-tag monitored">monitored</span>
            <span v-else class="subfold-tag unmonitored">not separately monitored</span>
            <span class="subfold-vol">{{ g.volume.toLocaleString() }} msgs</span>
            <button
              v-if="!g.is_primary && !g.is_monitored"
              class="subfold-add"
              :disabled="addingSubdomain === g.header_from"
              @click.stop="monitorSubdomain(g.header_from)"
            >{{ addingSubdomain === g.header_from ? 'Adding…' : 'Monitor this' }}</button>
          </div>
          <div v-if="openGroups.has(g.header_from)" class="subfold-body">
            <SourceTable :sources="g.sources" @open-drawer="drawerIp = $event" />
          </div>
        </div>
      </div>

      <SourceTable
        v-else-if="filteredSources.length"
        :sources="filteredSources"
        @open-drawer="drawerIp = $event"
      />
      <DataDeadZone
        v-else-if="selected !== '__all__'"
        record-label="DMARC"
        :record-published="!!selectedDomainObj?.dmarc_record_published"
        :published-since="selectedDomainObj?.added_at ?? null"
        :on-go-to-roadmap="goToRoadmap"
      />
      <div v-else style="padding:28px;color:var(--muted)">No report data yet across your domains.</div>
    </div>

    <!-- Auth detail drawer -->
    <DmarcAuthDrawer
      v-if="drawerIp"
      :ip="drawerIp"
      :domain-id="selectedDomainObj?.id"
      @close="drawerIp = null"
    />

    <!-- Record diff modal -->
    <Teleport to="body">
      <div v-if="diff" class="modal-overlay" @click.self="diff = null">
        <div class="modal-box">
          <div class="mh"><span>Review DMARC record</span><button class="mx" @click="diff = null">✕</button></div>
          <RecordReviewModal :diff="diff" :domain-id="domains.list.find(d=>d.domain===selected)?.id" track="dmarc" @close="diff = null" />
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
.titlerow { display: flex; align-items: flex-end; justify-content: space-between; margin-bottom: 14px; gap: 16px; flex-wrap: wrap; }
.crumb { font-family: var(--mono); font-size: 10px; color: var(--faint); letter-spacing: 1.4px; text-transform: uppercase; }
h1 { font-family: var(--disp); font-weight: 800; font-size: 23px; letter-spacing: -.6px; margin-top: 4px; }
.sub { color: var(--muted); margin-top: 4px; font-size: 13px; }
.btn { background: linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff; border:none; border-radius:12px; padding:10px 18px; font-family:var(--disp); font-weight:700; font-size:13px; cursor:pointer; flex:none; }

/* Domain dropdown */
.domain-bar { margin-bottom: 16px; }
.domain-select-wrap { position: relative; display: inline-flex; align-items: center; }
.sel-icon { width: 13px; height: 13px; position: absolute; left: 10px; color: var(--faint); pointer-events: none; }
.domain-select { appearance: none; background: rgba(255,255,255,.04); border: 1px solid var(--line2); border-radius: 10px; color: var(--txt); font-family: var(--mono); font-size: 12px; padding: 8px 34px 8px 28px; outline: none; cursor: pointer; min-width: 200px; }
.domain-select:focus { border-color: var(--teal); }
.domain-select option { background: #16182a; }
.sel-chev { width: 13px; height: 13px; position: absolute; right: 10px; color: var(--faint); pointer-events: none; }

/* Card */
.card { background: var(--glass); border: 1px solid var(--line); border-radius: 18px; padding: 20px; backdrop-filter: blur(12px); box-shadow: 0 12px 40px rgba(0,0,0,.35), inset 0 1px 0 rgba(255,255,255,.05); }

/* Pass vs fail bar */
.traffic-card { margin-bottom: 14px; }
.tc-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; }
.tc-title { font-family: var(--disp); font-weight: 700; font-size: 15px; }
.tc-total { font-family: var(--mono); font-size: 9.5px; letter-spacing: 1px; text-transform: uppercase; color: var(--faint); }
.tc-big { margin-bottom: 12px; }
.tc-num { font-family: var(--disp); font-weight: 900; font-size: 38px; letter-spacing: -1.5px; display: block; line-height: 1; }
.tc-sub { font-family: var(--mono); font-size: 9.5px; letter-spacing: 1px; color: var(--muted); display: block; margin-top: 4px; }
.tc-bar { display: flex; height: 14px; border-radius: 7px; overflow: hidden; gap: 2px; }
.tc-seg { min-width: 2px; transition: flex .5s ease; }
.tc-seg.pass      { background: #34e0a1; }
.tc-seg.unaligned { background: #f5c542; }
.tc-seg.fail      { background: #ff5050; }
.tc-legend { display: flex; gap: 20px; margin-top: 10px; font-size: 12px; color: var(--muted); flex-wrap: wrap; }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 5px; }
.dot.pass      { background: #34e0a1; }
.dot.unaligned { background: #f5c542; }
.dot.fail      { background: #ff5050; }

/* Auth stat bars */
.auth-stats { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; margin-bottom: 14px; }
@media (max-width: 900px) { .auth-stats { grid-template-columns: 1fr; } }
.auth-stat-card { padding: 16px 18px; }
.as-label { font-family: var(--disp); font-weight: 700; font-size: 14px; margin-bottom: 12px; }
.as-bar-wrap { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
.as-bar-track { flex: 1; height: 7px; background: rgba(255,255,255,.08); border-radius: 5px; overflow: hidden; }
.as-bar-fill { height: 100%; border-radius: 5px; transition: width .5s ease; }
.as-bar-fill.good { background: #34e0a1; }
.as-bar-fill.warn { background: #f5c542; }
.as-bar-fill.bad  { background: #ff5050; }
.as-pct { font-family: var(--mono); font-size: 11px; font-weight: 700; white-space: nowrap; }
.as-pct.good { color: var(--good); }
.as-pct.warn { color: var(--amber); }
.as-pct.bad  { color: var(--bad); }
.as-sub { display: flex; gap: 10px; }
.as-tag { font-family: var(--mono); font-size: 9.5px; letter-spacing: .5px; padding: 2px 8px; border-radius: 6px; }
.as-tag.good { background: rgba(52,224,161,.12); color: var(--good); }
.as-tag.fail { background: rgba(255,80,80,.1); color: var(--bad); }
.as-hint { font-family: var(--mono); font-size: 8.5px; letter-spacing: 1px; color: var(--faint); text-transform: uppercase; margin-top: 8px; text-align: right; }

/* Source table card */
.ct { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; }
.ct h3 { font-family: var(--disp); font-weight: 700; font-size: 15px; }
.sectag { font-family: var(--mono); font-size: 9px; letter-spacing: 1px; text-transform: uppercase; color: var(--teal); }

/* Subdomain fold */
.subfold-list { display: flex; flex-direction: column; gap: 8px; }
.subfold { border: 1px solid var(--line); border-radius: 14px; overflow: hidden; }
.subfold-head {
  display: flex; align-items: center; gap: 10px; padding: 13px 14px; cursor: pointer;
  background: rgba(255,255,255,.02); transition: background .15s; flex-wrap: wrap;
}
.subfold-head:hover { background: rgba(255,255,255,.045); }
.subfold-chev { width: 14px; height: 14px; color: var(--faint); transition: transform .2s; flex: none; }
.subfold-chev.open { transform: rotate(90deg); color: var(--teal); }
.subfold-name { font-family: var(--mono); font-size: 13px; font-weight: 600; color: var(--txt); }
.subfold-tag {
  font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: .4px;
  padding: 3px 9px; border-radius: 8px; flex: none;
}
.subfold-tag.primary     { background: rgba(91,92,240,.16); color: #9aa6ff; }
.subfold-tag.monitored   { background: rgba(52,224,161,.14); color: var(--good); }
.subfold-tag.unmonitored { background: rgba(245,197,66,.14); color: var(--amber); }
.subfold-vol { font-family: var(--mono); font-size: 11px; color: var(--faint); margin-left: auto; }
.subfold-add {
  background: rgba(91,92,240,.16); border: 1px solid rgba(91,92,240,.35); color: #9aa6ff;
  border-radius: 8px; padding: 5px 12px; font-size: 11px; font-weight: 700; cursor: pointer; flex: none;
}
.subfold-add:disabled { opacity: .6; cursor: not-allowed; }
.subfold-body { padding: 14px; border-top: 1px solid var(--line); }

/* Modal */
.modal-overlay { position:fixed;inset:0;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);z-index:200;display:grid;place-items:center;padding:20px; }
.modal-box { width:580px;max-width:94vw;max-height:88vh;overflow-y:auto;background:#0c0e1c;border:1px solid var(--line2);border-radius:18px;padding:24px;box-shadow:0 30px 80px rgba(0,0,0,.7); }
.mh { display:flex;align-items:center;justify-content:space-between;margin-bottom:16px; }
.mh span { font-family:var(--disp);font-weight:800;font-size:16px; }
.mx { background:none;border:1px solid var(--line);border-radius:8px;color:var(--muted);width:28px;height:28px;cursor:pointer;font-size:14px; }
</style>
