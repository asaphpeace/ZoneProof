<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '@/api/client'
import { useDomainsStore } from '@/stores/domains'
import RoadmapTrack from '@/components/domain/RoadmapTrack.vue'
import RecordReviewModal from '@/components/domain/RecordReviewModal.vue'
import EnforcementReadinessCard from '@/components/domain/EnforcementReadinessCard.vue'
import LoadError from '@/components/ui/LoadError.vue'
import { useScopeStore } from '@/stores/scope'

const route   = useRoute()
const domains = useDomainsStore()

const scope = useScopeStore()
const fallbackDomain = ref('')
const selected = computed<string>({
  get: () => scope.domain && domains.list.some(d => d.domain === scope.domain) ? scope.domain : fallbackDomain.value,
  set: (v) => scope.set(v || null),
})
const dmarcData   = ref<any>(null)
const tlsData     = ref<any>(null)
const diff        = ref<any>(null)
const diffTrack   = ref<'dmarc' | 'tls'>('dmarc')
const advisor     = ref<any>(null)
const recommendations = ref<any[]>([])
const simulation  = ref<any>(null)
const simulationLoading = ref(false)
const loading     = ref(false)
const loadError   = ref('')
// Per-source readiness for the checklist. Loaded with the page so the checklist is there
// before anyone asks for a preview; null when there is nothing to simulate (for example at reject).
const readiness   = ref<any[] | null>(null)

const DMARC_STAGE_IDX = { none: 0, monitor: 1, quarantine: 2, reject: 3, bimi: 4 } as Record<string,number>
const MTA_STAGE_IDX   = { none: 0, testing: 1, enforce: 2 } as Record<string,number>

// Portfolio summary: how many domains at each stage
const portfolioSummary = computed(() => {
  const list = domains.list
  return {
    reject:     list.filter(d => d.dmarc_stage === 'reject').length,
    quarantine: list.filter(d => d.dmarc_stage === 'quarantine').length,
    monitor:    list.filter(d => d.dmarc_stage === 'monitor' || d.dmarc_stage === 'none' && d.dmarc_record_published).length,
    noRecord:   list.filter(d => !d.dmarc_record_published && d.dmarc_stage === 'none').length,
    mtaEnforce: list.filter(d => d.mta_sts_stage === 'enforce').length,
    mtaNone:    list.filter(d => !d.mta_sts_stage || d.mta_sts_stage === 'none').length,
    total:      list.length,
  }
})

const selectedDomain = computed(() => domains.list.find(d => d.domain === selected.value))
const dmarcStage = computed(() => DMARC_STAGE_IDX[selectedDomain.value?.dmarc_stage ?? 'none'] ?? 0)
const mtaStage   = computed(() => MTA_STAGE_IDX[selectedDomain.value?.mta_sts_stage ?? 'none'] ?? 0)

// Derived blocking signals from loaded data
const dmarcComp = computed<number | null>(() => dmarcData.value?.compliance?.compliance_pct ?? null)
const dmarcFailSources = computed<number>(() =>
  dmarcData.value?.sources?.filter((s: any) => s.fail_count > 0 && s.classification !== 'authorized').length ?? 0
)
const tlsPassPct = computed<number | null>(() => {
  if (!tlsData.value) return null
  const total = tlsData.value.total_sessions
  const succ  = tlsData.value.successful_sessions
  return total ? Math.round(succ / total * 1000) / 10 : null
})
const tlsFailReason = computed<string | null>(() =>
  tlsData.value?.fail_types?.[0]?.reason ?? null
)

onMounted(async () => {
  await domains.fetch()
  if (domains.error) { loadError.value = domains.error; loading.value = false; return }
  // The shared scope (including a ?domain= link) is applied by the shell. With
  // "all domains" this page still needs one, so it shows the first without
  // changing what the other pages are showing.
  if (domains.list.length) fallbackDomain.value = domains.list[0].domain
  await loadData()
})

watch(selected, () => { simulation.value = null; loadData() })

async function previewDmarc() {
  const dom = selectedDomain.value
  if (!dom) return
  simulationLoading.value = true
  try {
    simulation.value = await api.simulateDmarcPolicy(dom.id)
  } finally {
    simulationLoading.value = false
  }
}

async function loadData() {
  const dom = selectedDomain.value
  if (!dom) return
  loading.value = true
  loadError.value = ''
  advisor.value = null
  readiness.value = null
  try {
    [dmarcData.value, tlsData.value, advisor.value, recommendations.value] = await Promise.all([
      api.dmarcData(dom.id),
      api.tlsData(dom.id),
      api.advisor('roadmap', dom.id),
      api.domainRecommendations(dom.id),
    ])
    // Not part of the page's own load: a domain at reject has nothing to simulate and answers 400.
    api.simulateDmarcPolicy(dom.id)
      .then((sim: any) => { if (selectedDomain.value?.id === dom.id) readiness.value = sim?.source_readiness ?? null })
      .catch(() => { readiness.value = null })
  } catch (e: any) { loadError.value = e?.message || 'The data request failed.' } finally { loading.value = false }
}

async function reviewDmarc() {
  const dom = selectedDomain.value
  if (!dom) return
  diff.value = await api.dmarcRecordDiff(dom.id)
  diffTrack.value = 'dmarc'
}

async function reviewMta() {
  const dom = selectedDomain.value
  if (!dom) return
  // The diff endpoint re-syncs live MTA-STS state server-side and may correct
  // domain.mta_sts_stage (e.g. a policy already exists outside the app) —
  // refresh the domain list so the stage badge / CTA label on this page
  // reflect that immediately rather than on next page load.
  diff.value = await api.tlsRecordDiff(dom.id)
  await domains.fetch()
  diffTrack.value = 'tls'
}

async function reloadAdvisor() {
  advisor.value = null
  const dom = selectedDomain.value
  if (dom) {
    await api.syncDomainDns(dom.id)
    await domains.fetch()
    advisor.value = await api.advisor('roadmap', dom.id, false, true)
  }
}
</script>

<template>
  <div>
    <LoadError v-if="loadError" :message="loadError" @retry="$router.go(0)" />
    <div class="titlerow">
      <div>
        <div class="crumb">05 / Roadmap</div>
        <h1>Email Security Roadmap</h1>
        <div class="sub">Step-by-step guidance to full protection across every domain</div>
      </div>
    </div>

    <!-- Portfolio summary strip -->
    <div v-if="domains.list.length > 1" class="portfolio-strip">
      <div class="ps-item">
        <span class="ps-val">{{ portfolioSummary.reject }}</span>
        <span class="ps-lbl">Fakes blocked</span>
        <span class="ps-dot good" />
      </div>
      <div class="ps-div" />
      <div class="ps-item">
        <span class="ps-val">{{ portfolioSummary.quarantine }}</span>
        <span class="ps-lbl">Spam filter</span>
        <span class="ps-dot warn" />
      </div>
      <div class="ps-div" />
      <div class="ps-item">
        <span class="ps-val">{{ portfolioSummary.monitor }}</span>
        <span class="ps-lbl">Watching only</span>
        <span class="ps-dot amber" />
      </div>
      <div class="ps-div" />
      <div class="ps-item">
        <span class="ps-val">{{ portfolioSummary.noRecord }}</span>
        <span class="ps-lbl">No protection</span>
        <span class="ps-dot bad" />
      </div>
      <div class="ps-spacer" />
      <div class="ps-item">
        <span class="ps-val teal">{{ portfolioSummary.mtaEnforce }}</span>
        <span class="ps-lbl">Inbound enforced</span>
      </div>
      <div class="ps-div" />
      <div class="ps-item">
        <span class="ps-val muted">{{ portfolioSummary.mtaNone }}</span>
        <span class="ps-lbl">No inbound policy</span>
      </div>
    </div>

    <!-- Domain selector -->
    <div class="domain-select-wrap">
      <svg class="ds-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="9"/><path d="M12 8v4l3 3"/>
      </svg>
      <select v-model="selected" class="domain-select" aria-label="Domain">
        <option v-for="d in domains.list" :key="d.domain" :value="d.domain">
          {{ d.domain }}
        </option>
      </select>
      <svg class="ds-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M6 9l6 6 6-6"/>
      </svg>
    </div>

    <!-- Roadmap tracks (advisor banner is now embedded inside) -->
    <RoadmapTrack
      v-if="!loading || dmarcData"
      :domain="selected"
      :dmarc-stage="dmarcStage"
      :mta-stage="mtaStage"
      :dmarc-comp="dmarcComp"
      :dmarc-fail-sources="dmarcFailSources"
      :tls-pass-pct="tlsPassPct"
      :tls-fail-reason="tlsFailReason"
      :advisor-message="advisor?.message ?? null"
      :advisor-commend="advisor?.commend ?? false"
      :advisor-loading="loading && !advisor"
      :advisor-model="advisor?.model"
      :recommendations="recommendations"
      :simulation="simulation"
      :simulation-loading="simulationLoading"
      :on-review-dmarc="reviewDmarc"
      :on-review-mta="reviewMta"
      :on-regen-advisor="reloadAdvisor"
      :on-preview-dmarc="previewDmarc"
    />

    <EnforcementReadinessCard
      v-if="(simulation?.source_readiness ?? readiness)?.length && selectedDomain"
      :domain-id="selectedDomain.id"
      :source-readiness="(simulation?.source_readiness ?? readiness)!"
    />

    <div v-if="loading && !dmarcData" class="loading-state">Loading roadmap…</div>

    <!-- Record review modal -->
    <Teleport to="body">
      <div v-if="diff" class="modal-overlay" @click.self="diff = null">
        <div class="modal-box">
          <div class="mh">
            <span>{{ diffTrack === 'dmarc' ? 'Review DMARC record' : 'Review MTA-STS record' }}</span>
            <button class="mx" @click="diff = null">✕</button>
          </div>
          <RecordReviewModal
            :diff="diff"
            :domain-id="selectedDomain?.id"
            :track="diffTrack"
            @close="diff = null"
          />
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
.titlerow { margin-bottom: 16px; }
.crumb { font-family: var(--mono); font-size: 10px; color: var(--faint); letter-spacing: 1.4px; text-transform: uppercase; }
h1 { font-family: var(--disp); font-weight: 800; font-size: 25px; letter-spacing: -.7px; margin-top: 5px; }
.sub { color: var(--muted); margin-top: 5px; font-size: 13px; }

/* ── Portfolio strip ─────────────────────────────────────────── */
.portfolio-strip {
  display: flex; align-items: center; gap: 0;
  background: var(--glass); border: 1px solid var(--line); border-radius: 14px;
  padding: 12px 18px; margin-bottom: 14px; flex-wrap: wrap; gap: 4px;
}
.ps-item { display: flex; align-items: center; gap: 7px; padding: 2px 10px; }
.ps-val { font-family: var(--disp); font-weight: 800; font-size: 18px; }
.ps-val.teal  { color: var(--teal); }
.ps-val.muted { color: var(--muted); }
.ps-lbl { font-family: var(--mono); font-size: 10px; color: var(--faint); }
.ps-dot { width: 7px; height: 7px; border-radius: 50%; }
.ps-dot.good  { background: var(--good); }
.ps-dot.warn  { background: #9aa6ff; }
.ps-dot.amber { background: var(--amber); }
.ps-dot.bad   { background: var(--bad); }
.ps-div { width: 1px; height: 22px; background: var(--line); margin: 0 4px; }
.ps-spacer { flex: 1; min-width: 20px; }

/* ── Domain dropdown ─────────────────────────────────────────── */
.domain-select-wrap {
  position: relative; display: inline-flex; align-items: center;
  margin-bottom: 18px; min-width: 260px; max-width: 420px; width: 100%;
}
.ds-icon {
  position: absolute; left: 12px; width: 15px; height: 15px;
  color: var(--faint); pointer-events: none;
}
.domain-select {
  width: 100%; appearance: none; background: var(--glass);
  border: 1px solid var(--line2); border-radius: 12px;
  padding: 10px 36px 10px 36px;
  font-family: var(--mono); font-size: 12.5px; font-weight: 600; color: var(--txt);
  cursor: pointer; outline: none; transition: border-color .15s;
}
.domain-select:hover  { border-color: var(--indigo); }
.domain-select:focus  { border-color: var(--indigo); box-shadow: 0 0 0 3px rgba(91,92,240,.18); }
.domain-select option { background: var(--surface-raised); color: var(--txt); }
.ds-caret {
  position: absolute; right: 12px; width: 15px; height: 15px;
  color: var(--faint); pointer-events: none;
}

.loading-state { padding: 48px; text-align: center; color: var(--muted); font-family: var(--mono); font-size: 12px; }

/* ── Modal ───────────────────────────────────────────────────── */
.modal-overlay { position:fixed;inset:0;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);z-index:200;display:grid;place-items:center;padding:20px; }
.modal-box { width:580px;max-width:94vw;max-height:88vh;overflow-y:auto;background: var(--surface-raised);border:1px solid var(--line2);border-radius:18px;padding:24px;box-shadow:0 30px 80px rgba(0,0,0,.7); }
.mh { display:flex;align-items:center;justify-content:space-between;margin-bottom:16px; }
.mh span { font-family:var(--disp);font-weight:800;font-size:16px; }
.mx { background:none;border:1px solid var(--line);border-radius:8px;color:var(--muted);width:28px;height:28px;cursor:pointer;font-size:14px; }
</style>
