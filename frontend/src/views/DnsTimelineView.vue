<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { api } from '@/api/client'
import { useDomainsStore } from '@/stores/domains'
import TimelineEntry from '@/components/ui/TimelineEntry.vue'
import AdvisorBanner from '@/components/ui/AdvisorBanner.vue'
import DateRangeFilter from '@/components/ui/DateRangeFilter.vue'
import LoadError from '@/components/ui/LoadError.vue'
import { useScopeStore } from '@/stores/scope'

const domains      = useDomainsStore()
const timeline     = ref<any[]>([])
const loading      = ref(false)
const syncing      = ref(false)
const filterType   = ref<string>('all')
const scope = useScopeStore()
const domainFilter = computed<string>({
  get: () => scope.domain ?? 'all',
  set: (v) => scope.set(v === 'all' ? null : v),
})
const days         = ref<number | null>(null)
const offset       = ref(0)
const totalCount   = ref(0)
const lastSyncedAt = ref<string | null>(null)
const advisor        = ref<any>(null)
const advisorLoading = ref(false)
const loadError = ref('')

const PAGE_SIZE = 50
const RECORD_TYPES = ['all', 'DMARC', 'SPF', 'MX', 'MTA-STS', 'TLS-RPT', 'DKIM', 'CNAME']

async function loadAdvisor(domainId?: string, cachedOnly = false, force = false) {
  if (!cachedOnly) {
    advisor.value = null
    advisorLoading.value = true
  }
  try {
    const result = await api.advisorDnsSummary(domainId, cachedOnly, force)
    advisor.value = result
    if (cachedOnly) {
      // Passive background refresh — never force, so it skips the API
      // call entirely when nothing's changed since the cached version.
      const captured = domainId
      api.advisorDnsSummary(domainId, false).then(fresh => {
        if (domainFilter.value === (captured ?? 'all')) advisor.value = fresh
      }).catch(() => {})
    }
  } catch { /* leave null */ }
  finally { advisorLoading.value = false }
}

onMounted(async () => {
  await domains.fetch()
  if (domains.error) { loadError.value = domains.error; advisorLoading.value = false; loading.value = false; return }
  await loadTimeline()
  const dom = selectedDomain()
  await loadAdvisor(dom?.id, true)
})

watch(domainFilter, () => {
  const dom = selectedDomain()
  loadAdvisor(dom?.id)
})

function selectedDomain() {
  return domains.list.find(d => d.domain === domainFilter.value)
}

async function loadTimeline(append = false) {
  loading.value = true
  loadError.value = ''
  try {
    const dom = selectedDomain()
    const [entries, countRes] = await Promise.all([
      dom
        ? api.dnsTimeline(dom.id, PAGE_SIZE, append ? offset.value : 0, days.value)
        : api.dnsTenantTimeline(PAGE_SIZE, append ? offset.value : 0, days.value),
      dom
        ? api.dnsTimelineCount(dom.id, days.value)
        : api.dnsTenantCount(days.value),
    ])
    if (append) {
      timeline.value = [...timeline.value, ...entries]
    } else {
      timeline.value = entries
      offset.value = 0
    }
    totalCount.value = countRes.count ?? 0
  } catch (e: any) {
    loadError.value = e?.message || 'The timeline request failed.'
  } finally {
    loading.value = false
  }
}

async function loadMore() {
  offset.value += PAGE_SIZE
  await loadTimeline(true)
}

async function changeDomain() {
  offset.value = 0
  filterType.value = 'all'
  await loadTimeline()
}
watch(domainFilter, () => { changeDomain() })

watch(days, () => {
  offset.value = 0
  loadTimeline()
})

async function syncNow() {
  const dom = selectedDomain()
  if (!dom && domains.list.length === 0) return
  syncing.value = true
  try {
    const targets = dom ? [dom] : domains.list
    await Promise.all(targets.map(d => api.syncDomainDns(d.id)))
    lastSyncedAt.value = new Date().toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
    await loadTimeline()
  } finally { syncing.value = false }
}

const filtered = computed(() => {
  if (filterType.value === 'all') return timeline.value
  return timeline.value.filter(e => e.record_type === filterType.value)
})

const alertCount   = computed(() => timeline.value.filter(e => e.is_security_alert).length)
const addedCount   = computed(() => timeline.value.filter(e => e.change_type === 'added').length)
const modifiedCount = computed(() => timeline.value.filter(e => e.change_type === 'modified').length)
const removedCount = computed(() => timeline.value.filter(e => e.change_type === 'removed').length)

const hasMore = computed(() => timeline.value.length < totalCount.value)

// UTC date string "YYYY-MM-DD" from any Date
function utcDateStr(d: Date): string {
  return d.toISOString().slice(0, 10)
}

// Group filtered entries by UTC calendar date
const grouped = computed(() => {
  const todayStr     = utcDateStr(new Date())
  const yesterday    = new Date(); yesterday.setUTCDate(yesterday.getUTCDate() - 1)
  const yesterdayStr = utcDateStr(yesterday)

  const groups: { date: string; dateKey: string; entries: any[] }[] = []
  let lastKey = ''
  for (const e of filtered.value) {
    const d = new Date(e.detected_at)
    const key = utcDateStr(d)
    const label = key === todayStr
      ? 'Today'
      : key === yesterdayStr
      ? 'Yesterday'
      : d.toLocaleDateString('en-GB', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric', timeZone: 'UTC' })
    if (key !== lastKey) {
      groups.push({ date: label, dateKey: key, entries: [] })
      lastKey = key
    }
    groups[groups.length - 1].entries.push(e)
  }
  return groups
})
</script>

<template>
  <div>
    <LoadError v-if="loadError" :message="loadError" @retry="$router.go(0)" />
    <!-- Title row -->
    <div class="titlerow">
      <div>
        <div class="crumb">07 / DNS Timeline</div>
        <h1>DNS Change Log</h1>
        <div class="sub">Every record change detected across your domains — full before/after history</div>
      </div>
      <div class="title-actions">
        <span v-if="lastSyncedAt" class="synced-at">Checked at {{ lastSyncedAt }}</span>
        <button class="btn" :disabled="syncing" @click="syncNow">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
            <path d="M23 4v6h-6"/><path d="M20.49 15a9 9 0 1 1-.49-7.49"/>
          </svg>
          {{ syncing ? 'Checking…' : 'Check now' }}
        </button>
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
      @regenerate="loadAdvisor(selectedDomain()?.id, false, true)"
      style="margin-bottom:16px"
    />

    <!-- KPI strip -->
    <div class="kpi-strip">
      <div class="kpi-item" :class="alertCount > 0 ? 'alert-item' : ''">
        <div class="kpi-val" :style="alertCount > 0 ? 'color:var(--bad)' : 'color:var(--muted)'">{{ alertCount }}</div>
        <div class="kpi-lbl">Security alerts</div>
      </div>
      <div class="kpi-div" />
      <div class="kpi-item">
        <div class="kpi-val" style="color:var(--good)">{{ addedCount }}</div>
        <div class="kpi-lbl">Records added</div>
      </div>
      <div class="kpi-div" />
      <div class="kpi-item">
        <div class="kpi-val" style="color:var(--amber)">{{ modifiedCount }}</div>
        <div class="kpi-lbl">Records modified</div>
      </div>
      <div class="kpi-div" />
      <div class="kpi-item">
        <div class="kpi-val" style="color:var(--bad)">{{ removedCount }}</div>
        <div class="kpi-lbl">Records removed</div>
      </div>
      <div class="kpi-div" />
      <div class="kpi-item">
        <div class="kpi-val" style="color:var(--faint)">{{ totalCount }}</div>
        <div class="kpi-lbl">Total events</div>
      </div>
    </div>

    <!-- Controls row: date filter + domain dropdown + record type filter -->
    <div class="controls">
      <DateRangeFilter v-model="days" />
      <!-- Domain dropdown -->
      <div class="select-wrap">
        <svg class="sel-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/>
        </svg>
        <select v-model="domainFilter" class="domain-select" aria-label="Domain">
          <option value="all">All domains</option>
          <option v-for="d in domains.list" :key="d.domain" :value="d.domain">{{ d.domain }}</option>
        </select>
        <svg class="sel-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M6 9l6 6 6-6"/>
        </svg>
      </div>

      <!-- Record type filter pills -->
      <div class="type-filters">
        <span class="filter-label">Filter</span>
        <button
          v-for="t in RECORD_TYPES" :key="t"
          :class="['type-pill', filterType === t ? 'active' : '']"
          @click="filterType = t"
        >{{ t }}</button>
      </div>
    </div>

    <!-- Timeline card -->
    <div class="card">
      <div v-if="loading && !timeline.length" class="loading-state">
        <div class="loading-pulse" />
        Loading timeline…
      </div>

      <div v-else-if="!filtered.length" class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="var(--faint)" stroke-width="1.5">
          <circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>
        </svg>
        <div v-if="timeline.length > 0 && filterType !== 'all'">
          No <b>{{ filterType }}</b> events match the current filter.
          <span class="empty-hint" @click="filterType = 'all'" tabindex="0" role="button" @keydown.enter.prevent="filterType = 'all'" @keydown.space.prevent="filterType = 'all'">Show all {{ totalCount }} events →</span>
        </div>
        <div v-else>No DNS change events found.</div>
        <div class="empty-sub">
          Click "Check now" to scan live DNS records. Changes are detected automatically on each check.
        </div>
      </div>

      <template v-else>
        <!-- Date-grouped entries -->
        <div v-for="(group, gi) in grouped" :key="group.date">
          <div class="date-divider">
            <span class="date-label">{{ group.date }}</span>
            <span v-if="gi === grouped.length - 1 && group.entries.every(e => e.change_type === 'added')" class="baseline-badge" title="These are the records ZoneProof found when this domain was first scanned — not changes from a prior state.">Initial scan</span>
          </div>
          <TimelineEntry
            v-for="entry in group.entries"
            :key="entry.id"
            :entry="entry"
          />
        </div>

        <!-- Load more -->
        <div v-if="hasMore" class="load-more">
          <button class="load-more-btn" :disabled="loading" @click="loadMore">
            {{ loading ? 'Loading…' : `Load more  (${totalCount - timeline.length} remaining)` }}
          </button>
        </div>
        <div v-else class="end-of-log">
          <span>— end of log — {{ totalCount }} events total</span>
        </div>
      </template>
    </div>
  </div>
</template>

<style scoped>
/* ── Title ───────────────────────────────────────────────────── */
.titlerow { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 16px; gap: 16px; flex-wrap: wrap; }
.crumb { font-family: var(--mono); font-size: 10px; color: var(--faint); letter-spacing: 1.4px; text-transform: uppercase; }
h1 { font-family: var(--disp); font-weight: 800; font-size: 25px; letter-spacing: -.7px; margin-top: 5px; }
.sub { color: var(--muted); margin-top: 5px; font-size: 13px; }
.title-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding-top: 6px; }
.synced-at { font-family: var(--mono); font-size: 10.5px; color: var(--faint); }
.btn {
  display: flex; align-items: center; gap: 7px;
  background: linear-gradient(90deg,#5b5cf0,#4b4ce0); color: #fff; border: none;
  border-radius: 12px; padding: 10px 18px; font-family: var(--disp); font-weight: 700;
  font-size: 13px; cursor: pointer; transition: opacity .15s;
}
.btn svg { width: 14px; height: 14px; }
.btn:disabled { opacity: .55; cursor: not-allowed; }

/* ── KPI strip ───────────────────────────────────────────────── */
.kpi-strip {
  display: flex; align-items: center; flex-wrap: wrap; gap: 0;
  background: var(--glass); border: 1px solid var(--line); border-radius: 14px;
  padding: 14px 20px; margin-bottom: 14px;
}
.kpi-item { display: flex; flex-direction: column; gap: 3px; padding: 0 16px; }
.kpi-val { font-family: var(--disp); font-weight: 800; font-size: 24px; line-height: 1; }
.kpi-lbl { font-family: var(--mono); font-size: 9.5px; color: var(--faint); }
.kpi-div { width: 1px; height: 30px; background: var(--line); }

/* ── Controls ────────────────────────────────────────────────── */
.controls { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; flex-wrap: wrap; }

.select-wrap { position: relative; display: inline-flex; align-items: center; }
.sel-icon  { position: absolute; left: 11px; width: 14px; height: 14px; color: var(--faint); pointer-events: none; }
.sel-caret { position: absolute; right: 9px; width: 13px; height: 13px; color: var(--faint); pointer-events: none; }
.domain-select {
  appearance: none; background: var(--glass); border: 1px solid var(--line2);
  border-radius: 11px; padding: 9px 32px 9px 32px;
  font-family: var(--mono); font-size: 12px; font-weight: 600; color: var(--txt);
  cursor: pointer; outline: none; transition: border-color .15s; min-width: 200px;
}
.domain-select:focus { border-color: var(--indigo); }
.domain-select option { background: var(--surface-raised); }

.type-filters { display: flex; align-items: center; gap: 5px; flex-wrap: wrap; }
.filter-label { font-family: var(--mono); font-size: 9px; letter-spacing: .8px; text-transform: uppercase; color: var(--faint); margin-right: 4px; }
.type-pill {
  font-family: var(--mono); font-size: 9.5px; padding: 5px 12px; border-radius: 20px;
  border: 1px solid var(--line2); background: transparent; color: var(--muted);
  cursor: pointer; transition: .13s;
}
.type-pill:hover { color: var(--txt); border-color: rgba(91,92,240,.5); }
.type-pill.active { background: rgba(91,92,240,.18); border-color: rgba(91,92,240,.5); color: #9aa6ff; }

/* ── Card ────────────────────────────────────────────────────── */
.card {
  background: var(--glass); border: 1px solid var(--line); border-radius: 18px;
  padding: 20px; backdrop-filter: blur(12px);
  box-shadow: 0 12px 40px rgba(0,0,0,.3), inset 0 1px 0 rgba(255,255,255,.05);
}

/* ── Date divider ────────────────────────────────────────────── */
.date-divider {
  display: flex; align-items: center; gap: 12px; padding: 14px 0 8px 36px;
}
.date-divider::after { content: ''; flex: 1; height: 1px; background: var(--line); }
.date-label { font-family: var(--mono); font-size: 10px; letter-spacing: .8px; text-transform: uppercase; color: var(--faint); white-space: nowrap; }

/* ── Load more / end ─────────────────────────────────────────── */
.load-more { display: flex; justify-content: center; padding: 16px 0 4px; }
.load-more-btn {
  background: rgba(255,255,255,.05); border: 1px solid var(--line2); border-radius: 10px;
  padding: 9px 22px; font-family: var(--mono); font-size: 11.5px; color: var(--muted);
  cursor: pointer; transition: .15s;
}
.load-more-btn:hover { border-color: var(--indigo); color: var(--txt); }
.load-more-btn:disabled { opacity: .5; cursor: not-allowed; }
.end-of-log { text-align: center; padding: 16px 0 4px; font-family: var(--mono); font-size: 10px; color: var(--faint); }

/* ── States ──────────────────────────────────────────────────── */
.loading-state { display: flex; align-items: center; gap: 10px; padding: 36px; justify-content: center; color: var(--muted); font-family: var(--mono); font-size: 12px; }
.loading-pulse { width: 10px; height: 10px; border-radius: 50%; background: var(--indigo); animation: blink 1.2s ease-in-out infinite; }
@keyframes blink { 50% { opacity: .2; } }

.empty-state { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 44px 20px; }
.empty-state svg { width: 36px; height: 36px; margin-bottom: 4px; }
.empty-state div { font-family: var(--mono); font-size: 12.5px; color: var(--muted); }
.empty-sub { font-size: 11px !important; color: var(--faint) !important; text-align: center; max-width: 360px; line-height: 1.6; }
.empty-hint { color: var(--teal); cursor: pointer; margin-left: 6px; text-decoration: underline; }
.baseline-badge {
  font-family: var(--mono); font-size: 9px; letter-spacing: .6px; text-transform: uppercase;
  color: var(--faint); background: rgba(255,255,255,.04); border: 1px solid var(--line2);
  border-radius: 5px; padding: 2px 6px; margin-left: 6px;
}
</style>
