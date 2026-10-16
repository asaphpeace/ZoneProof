<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api/client'
import { useDomainsStore } from '@/stores/domains'
import { useUiStore } from '@/stores/ui'
import SentinelRing from '@/components/ui/SentinelRing.vue'
import LoadError from '@/components/ui/LoadError.vue'
import ThreatSurface from '@/components/ui/ThreatSurface.vue'
import PortfolioReadinessRollup from '@/components/domain/PortfolioReadinessRollup.vue'
import DomainTable from '@/components/domain/DomainTable.vue'
import ReportWizard from '@/components/ui/ReportWizard.vue'
import ScanDomainModal from '@/components/ui/ScanDomainModal.vue'
import AdvisorBanner from '@/components/ui/AdvisorBanner.vue'
import AddDomainWizard from '@/components/wizard/AddDomainWizard.vue'
import DateRangeFilter from '@/components/ui/DateRangeFilter.vue'

const router  = useRouter()
const domains = useDomainsStore()
const ui      = useUiStore()
const days    = ref(30)

const showReport = ref(false)
const showScan   = ref(false)
const showWizard = ref(false)

async function loadThreat() {
  threat.value = await api.threatSurface(days.value)
}

watch(days, loadThreat)

async function onWizardClose() {
  showWizard.value = false
  loading.value = true
  try {
    await domains.fetch()
    if (domains.error) throw new Error(domains.error)
    ;[overview.value, threat.value] = await Promise.all([
      api.overview(),
      api.threatSurface(days.value),
    ])
  } catch (e: any) { loadError.value = e?.message || 'The data request failed.' } finally { loading.value = false }
}

const overview       = ref<any>(null)
const threat         = ref<any>(null)
const loading        = ref(true)
const advisor        = ref<any>(null)
const advisorLoading = ref(false)
const loadError = ref('')
// Brand Guard card: shown only when the workspace protects at least one brand. Failure here must never affect the rest of the page.
const brand = ref<any>(null)
async function loadBrand() {
  try { const s = await api.brandGuardSummary(); brand.value = s && s.brands > 0 ? s : null } catch { brand.value = null }
}
const brandExposure = computed(() => overview.value?.sentinel?.pillar_brand_exposure ?? null)

onMounted(async () => {
  advisorLoading.value = true
  loadBrand()
  try {
    await domains.fetch()
    if (domains.error) throw new Error(domains.error)
    ;[overview.value, threat.value] = await Promise.all([
      api.overview(),
      api.threatSurface(days.value),
    ])
  } catch (e: any) { loadError.value = e?.message || 'The data request failed.' } finally { loading.value = false }

  // Load cached advisor immediately, refresh in background
  try {
    advisor.value = await api.advisor('overview', undefined, true)
    api.advisor('overview', undefined, false).then(fresh => {
      advisor.value = fresh
    }).catch(() => {})
  } catch { /* leave null */ }
  finally { advisorLoading.value = false }
})

async function reloadAdvisor() {
  advisorLoading.value = true
  try {
    advisor.value = await api.advisor('overview', undefined, false, true)
  } catch (e: any) {
    ui.toast(e?.message || 'Advisor failed — check your API key or Ollama')
  } finally {
    advisorLoading.value = false
  }
}

function openDomain(d: any) {
  router.push({ name: 'dmarc', query: { domain: d.domain } })
}

const o = computed(() => overview.value)

function pct(n: number, total: number) {
  return total ? Math.round(n / total * 100) : 0
}

// Coverage bar: combine DMARC and MTA-STS totals for compact display
const dmarcTotal = computed(() => o.value
  ? o.value.dmarc_none_count + o.value.dmarc_monitor_count + o.value.dmarc_quarantine_count + o.value.dmarc_reject_count
  : 0)
const tlsTotal = computed(() => o.value
  ? o.value.tls_none_count + o.value.tls_testing_count + o.value.tls_enforce_count
  : 0)
</script>

<template>
  <div>
    <LoadError v-if="loadError" :message="loadError" @retry="$router.go(0)" />
    <!-- ── First-run empty state ─────────────────────────────────────────── -->
    <div v-if="!loading && domains.list.length === 0" class="firstrun">
      <div class="fr-glow" />
      <div class="fr-logo">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <h2 class="fr-title">Welcome to ZoneProof</h2>
      <p class="fr-sub">
        Add your first domain to start monitoring DMARC enforcement, MTA-STS protection,
        certificate health, and get your ZoneProof Score.
      </p>
      <div class="fr-steps">
        <div class="fr-step">
          <span class="fr-step-num">1</span>
          <span>Add a domain and copy the DMARC record</span>
        </div>
        <div class="fr-step-sep">→</div>
        <div class="fr-step">
          <span class="fr-step-num">2</span>
          <span>Publish the record at your DNS registrar</span>
        </div>
        <div class="fr-step-sep">→</div>
        <div class="fr-step">
          <span class="fr-step-num">3</span>
          <span>Reports flow in — ZoneProof scores and guides you</span>
        </div>
      </div>
      <button class="fr-btn" @click="showWizard = true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
          <path d="M12 5v14M5 12h14"/>
        </svg>
        Add your first domain
      </button>
      <div class="fr-note">Takes about 2 minutes · no credit card required</div>
    </div>

    <!-- ── Header ─────────────────────────────────────────────────────────── -->
    <div v-if="domains.list.length > 0 || loading" class="titlerow">
      <div>
        <div class="crumb">01 / Portfolio</div>
        <h1>All monitored domains</h1>
        <div v-if="o" class="sub">
          {{ o.tenant_name }} · {{ o.total_domains }} domain{{ o.total_domains !== 1 ? 's' : '' }} ·
          <b style="color:var(--txt)">{{ o.total_volume.toLocaleString() }}</b> messages ·
          <b style="color:var(--txt)">{{ o.total_tls_sessions.toLocaleString() }}</b> TLS sessions
        </div>
      </div>
      <div class="header-actions">
        <DateRangeFilter v-model="days" />
        <button class="action-btn scan" @click="showScan = true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
            <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
          </svg>
          Scan domain
        </button>
        <button class="action-btn report" @click="showReport = true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
            <line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/>
          </svg>
          Generate report
        </button>
      </div>
    </div>

    <ScanDomainModal v-if="showScan" @close="showScan = false" />
    <ReportWizard   v-if="showReport" @close="showReport = false" />
    <AddDomainWizard v-if="showWizard" @close="onWizardClose" />

    <!-- ── Hero band: score + 3 KPIs ─────────────────────────────────────── -->
    <template v-if="domains.list.length > 0 || loading">
    <div class="hero-band">

      <!-- Left: ZoneProof Score ring -->
      <div class="card hero-score">
        <div class="hero-eyebrow">
          <span class="sentinel-tag">ZONEPROOF SCORE</span>
          <span class="sentinel-ctx" v-if="o">
            {{ o.sentinel.volume_weighted ? 'volume-weighted' : 'equal weight' }}
          </span>
        </div>
        <SentinelRing
          v-if="o"
          :score="o.sentinel.score"
          :grade="o.sentinel.grade"
          :grade-color="o.sentinel.grade_color"
          :grade-label="o.sentinel.grade_label"
          :pillar-dmarc="o.sentinel.pillar_dmarc"
          :pillar-tls="o.sentinel.pillar_tls"
          :pillar-certs="o.sentinel.pillar_certs"
          :delta="o.sentinel.delta"
          :volume-weighted="o.sentinel.volume_weighted"
        />
        <div v-else-if="loading" class="skel" style="height:140px" />
      </div>

      <!-- Right: 3 action KPIs + cert chips -->
      <div class="hero-kpis">

        <!-- Openly spoofable -->
        <div class="kpi-card" :class="{ danger: o && o.unprotected > 0 }">
          <div class="kpi-label">Openly spoofable</div>
          <div class="kpi-big" :style="`color:${o && o.unprotected > 0 ? 'var(--bad)' : 'var(--good)'}`">
            {{ o?.unprotected ?? '—' }}
            <span class="kpi-denom" v-if="o"> / {{ o.total_domains }}</span>
          </div>
          <div class="kpi-sub" :style="`color:${o && o.unprotected > 0 ? 'var(--bad)' : 'var(--muted)'}`">
            {{ o && o.unprotected > 0 ? 'no DMARC — fakes not blocked' : 'all domains have DMARC' }}
          </div>
        </div>

        <!-- MX cert alerts -->
        <div class="kpi-card" :class="{ danger: o && o.cert_alerts > 0 }">
          <div class="kpi-label">MX cert alerts</div>
          <div class="kpi-big" :style="`color:${o && o.cert_alerts > 0 ? 'var(--bad)' : 'var(--good)'}`">
            {{ o?.cert_alerts ?? '—' }}
          </div>
          <div class="kpi-sub" :style="`color:${o && o.cert_alerts > 0 ? 'var(--amber)' : 'var(--muted)'}`">
            {{ o && o.cert_alerts > 0 ? 'expiring — renew to keep TLS working' : 'all certs healthy' }}
          </div>
        </div>

        <!-- Avg TLS delivery -->
        <div class="kpi-card">
          <div class="kpi-label">Avg delivery success</div>
          <div class="kpi-big"
            :style="`color:${o?.avg_tls_pass_pct != null ? (o.avg_tls_pass_pct >= 99 ? '#2ee6c5' : o.avg_tls_pass_pct >= 90 ? 'var(--amber)' : 'var(--bad)') : 'var(--faint)'}`">
            {{ o?.avg_tls_pass_pct != null ? o.avg_tls_pass_pct + '%' : '—' }}
          </div>
          <div class="kpi-sub" style="color:var(--muted)">of inbound TLS connections</div>
        </div>

        <!-- Cert alert chips (inline, only when relevant) -->
        <div v-if="o && o.cert_alerts > 0" class="cert-chips">
          <span
            v-for="c in o.cert_expiry_list" :key="c.domain"
            class="cert-chip"
            :style="`background:${c.status === 'expired' || c.status === 'critical' ? 'rgba(255,77,109,.12)' : 'rgba(245,197,66,.12)'};
                     color:${c.status === 'expired' || c.status === 'critical' ? 'var(--bad)' : 'var(--amber)'}`"
          >
            {{ c.domain }} ·
            {{ c.status === 'expired' ? 'EXPIRED' : c.days_remaining != null ? `${c.days_remaining}d left` : c.status }}
          </span>
        </div>

      </div>
    </div>

    <!-- ── Brand Guard ──────────────────────────────────────────────────── -->
    <RouterLink v-if="brand" :to="{ name: 'brand-guard' }" class="card brand-card" aria-label="Open Brand Guard">
      <div class="bc-head"><h3 aria-level="2">Brand protection</h3><span v-if="brandExposure !== null" class="bc-score" :title="'Exposure score from live look-alikes, overdue cases and pending decisions. The point values are judgement calls.'">Exposure {{ Math.round(brandExposure) }}/100</span></div>
      <div class="bc-grid">
        <div><b>{{ brand.open_candidates }}</b><span>need a decision</span></div>
        <div><b>{{ brand.confirmed + brand.takedown }}</b><span>open cases</span></div>
        <div><b>{{ brand.new_24h }}</b><span>new in 24 h</span></div>
        <div><b>{{ brand.went_live_7d }}</b><span>went live this week</span></div>
      </div>
    </RouterLink>

    <!-- ── Portfolio readiness rollup ───────────────────────────────────── -->
    <PortfolioReadinessRollup />

    <!-- ── Threat surface ────────────────────────────────────────────────── -->
    <div class="card threat-card">
      <ThreatSurface v-if="threat" :data="threat" />
      <div v-else-if="loading" class="skel" style="height:100px" />
      <div v-else class="empty">No threat data available.</div>
    </div>

    <!-- ── Intelligence Summary (Advisor) ──────────────────────────────── -->
    <AdvisorBanner
      v-if="advisor || advisorLoading"
      :message="advisor?.message ?? ''"
      :commend="advisor?.commend"
      :is-ai="advisor?.is_ai"
      :model="advisor?.model"
      :loading="!advisor && advisorLoading"
      :refreshing="!!advisor && advisorLoading"
      class="narrative-card"
      @regenerate="reloadAdvisor"
    />

    <!-- ── Domain portfolio ──────────────────────────────────────────────── -->
    <div class="card portfolio-card">

      <!-- Table header -->
      <div class="pt-head">
        <div>
          <h3 aria-level="2">Domain portfolio</h3>
          <div class="pt-sub">Hover grade badge for rubric · click row to open full analysis</div>
        </div>
        <div class="grade-legend">
          <span class="gl-item"><span class="gl-badge" style="background:#34e0a1">A</span>90–100</span>
          <span class="gl-item"><span class="gl-badge" style="background:#2ee6c5">B</span>80–89</span>
          <span class="gl-item"><span class="gl-badge" style="background:#f5c542">C</span>70–79</span>
          <span class="gl-item"><span class="gl-badge" style="background:#f5a23d">D</span>50–69</span>
          <span class="gl-item"><span class="gl-badge" style="background:#ff4d6d">F</span>0–49</span>
        </div>
      </div>

      <!-- Coverage bar (replaces the two dist cards) -->
      <div v-if="o" class="coverage-row">
        <div class="cov-track-wrap">
          <div class="cov-label">DMARC</div>
          <div class="cov-track">
            <div class="cov-seg red"    :style="`flex:${o.dmarc_none_count}`"       v-if="o.dmarc_none_count"       :title="`No record: ${o.dmarc_none_count}`" />
            <div class="cov-seg amber"  :style="`flex:${o.dmarc_monitor_count}`"    v-if="o.dmarc_monitor_count"    :title="`Monitoring: ${o.dmarc_monitor_count}`" />
            <div class="cov-seg indigo" :style="`flex:${o.dmarc_quarantine_count}`" v-if="o.dmarc_quarantine_count" :title="`Quarantine: ${o.dmarc_quarantine_count}`" />
            <div class="cov-seg good"   :style="`flex:${o.dmarc_reject_count}`"     v-if="o.dmarc_reject_count"     :title="`Reject: ${o.dmarc_reject_count}`" />
            <div class="cov-seg empty"  style="flex:1"                              v-if="dmarcTotal === 0" />
          </div>
          <div class="cov-legend">
            <span v-if="o.dmarc_none_count"       class="cleg"><span class="cleg-dot red"   />None <b>{{ o.dmarc_none_count }}</b></span>
            <span v-if="o.dmarc_monitor_count"    class="cleg"><span class="cleg-dot amber" />Monitor <b>{{ o.dmarc_monitor_count }}</b></span>
            <span v-if="o.dmarc_quarantine_count" class="cleg"><span class="cleg-dot indigo"/>Quarantine <b>{{ o.dmarc_quarantine_count }}</b></span>
            <span v-if="o.dmarc_reject_count"     class="cleg"><span class="cleg-dot good"  />Reject <b>{{ o.dmarc_reject_count }}</b></span>
          </div>
        </div>

        <div class="cov-divider" />

        <div class="cov-track-wrap">
          <div class="cov-label">MTA-STS</div>
          <div class="cov-track thin">
            <div class="cov-seg red"   :style="`flex:${o.tls_none_count}`"    v-if="o.tls_none_count"    :title="`No policy: ${o.tls_none_count}`" />
            <div class="cov-seg amber" :style="`flex:${o.tls_testing_count}`" v-if="o.tls_testing_count" :title="`Testing: ${o.tls_testing_count}`" />
            <div class="cov-seg teal"  :style="`flex:${o.tls_enforce_count}`" v-if="o.tls_enforce_count" :title="`Enforce: ${o.tls_enforce_count}`" />
            <div class="cov-seg empty" style="flex:1"                         v-if="tlsTotal === 0" />
          </div>
          <div class="cov-legend">
            <span v-if="o.tls_none_count"    class="cleg"><span class="cleg-dot red"  />None <b>{{ o.tls_none_count }}</b></span>
            <span v-if="o.tls_testing_count" class="cleg"><span class="cleg-dot amber"/>Testing <b>{{ o.tls_testing_count }}</b></span>
            <span v-if="o.tls_enforce_count" class="cleg"><span class="cleg-dot teal" />Enforce <b>{{ o.tls_enforce_count }}</b></span>
          </div>
        </div>
      </div>

      <DomainTable v-if="o && !loading" :domains="o.domains" @open="openDomain" />
      <div v-else-if="loading" class="empty">Loading domains…</div>
      <div v-else class="empty">No domains found.</div>

    </div>
    </template><!-- end v-if domains -->
  </div>
</template>

<style scoped>
/* ── Base ───────────────────────────────────────────────────── */
.card {
  background: var(--glass); border: 1px solid var(--line); border-radius: 18px;
  padding: 20px; backdrop-filter: blur(12px);
  box-shadow: 0 12px 40px rgba(0,0,0,.35), inset 0 1px 0 rgba(255,255,255,.05);
}
.skel { background: rgba(255,255,255,.03); border-radius: 10px; animation: pulse 1.4s ease-in-out infinite; }
@keyframes pulse { 0%,100% { opacity:.6 } 50% { opacity:1 } }
.empty { padding: 28px; text-align: center; color: var(--muted); font-size: 13px; }

/* ── Header ─────────────────────────────────────────────────── */
.titlerow {
  display: flex; align-items: flex-end; justify-content: space-between;
  margin-bottom: 16px; gap: 16px; flex-wrap: wrap;
}
.crumb { font-family: var(--mono); font-size: 10px; color: var(--faint); letter-spacing: 1.4px; text-transform: uppercase; }
h1 { font-family: var(--disp); font-weight: 800; font-size: 25px; letter-spacing: -.7px; margin-top: 5px; }
.sub { color: var(--muted); margin-top: 5px; font-size: 13px; }

.header-actions { display: flex; gap: 8px; align-items: center; flex: none; align-self: flex-end; flex-wrap: wrap; }

.action-btn {
  display: flex; align-items: center; gap: 7px;
  border-radius: 12px; padding: 9px 16px;
  font-family: var(--disp); font-weight: 700; font-size: 13px;
  cursor: pointer; transition: .15s; white-space: nowrap; border: 1px solid;
}
.action-btn svg { width: 15px; height: 15px; }

.action-btn.scan {
  background: rgba(46,230,197,.1); border-color: rgba(46,230,197,.35); color: #2ee6c5;
}
.action-btn.scan:hover { background: rgba(46,230,197,.2); border-color: rgba(46,230,197,.6); color: #fff; }

.action-btn.report {
  background: rgba(91,92,240,.12); border-color: rgba(91,92,240,.4); color: #9aa6ff;
}
.action-btn.report:hover { background: rgba(91,92,240,.22); border-color: rgba(91,92,240,.7); color: #fff; }

/* ── Hero band ──────────────────────────────────────────────── */
.hero-band {
  display: grid; grid-template-columns: auto 1fr; gap: 14px;
  margin-bottom: 14px; align-items: start;
}
@media (max-width: 860px) { .hero-band { grid-template-columns: 1fr; } }

.hero-score { padding: 22px 26px; }
.hero-eyebrow { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
.sentinel-tag {
  font-family: var(--mono); font-size: 9px; letter-spacing: 1.4px; text-transform: uppercase;
  color: var(--faint); border: 1px solid var(--line2); border-radius: 6px; padding: 3px 8px;
}
.sentinel-ctx { font-family: var(--mono); font-size: 10.5px; color: var(--faint); }

.hero-kpis {
  display: grid; grid-template-rows: repeat(3, auto) auto;
  gap: 10px;
}

/* ── KPI cards (right column) ───────────────────────────────── */
.kpi-card {
  background: var(--glass); border: 1px solid var(--line); border-radius: 14px;
  padding: 14px 16px; backdrop-filter: blur(12px);
  box-shadow: 0 6px 24px rgba(0,0,0,.22), inset 0 1px 0 rgba(255,255,255,.04);
}
.kpi-card.danger { border-color: rgba(255,77,109,.35); background: rgba(255,77,109,.05); }
.kpi-label { font-family: var(--mono); font-size: 9px; letter-spacing: .6px; text-transform: uppercase; color: var(--faint); margin-bottom: 6px; }
.kpi-big   { font-family: var(--disp); font-weight: 900; font-size: 24px; letter-spacing: -1px; line-height: 1; }
.kpi-denom { font-size: 13px; font-weight: 400; color: var(--faint); }
.kpi-sub   { font-family: var(--mono); font-size: 10px; margin-top: 3px; }

.cert-chips { display: flex; gap: 6px; flex-wrap: wrap; padding: 2px 0; }
.cert-chip { font-family: var(--mono); font-size: 9.5px; font-weight: 700; padding: 4px 10px; border-radius: 8px; }

/* ── Threat card ────────────────────────────────────────────── */
.threat-card { margin-bottom: 14px; }
.brand-card { display: block; margin-bottom: 14px; text-decoration: none; color: inherit; }
.brand-card:hover { border-color: var(--indigo); }
.bc-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; margin-bottom: 10px; }
.bc-head h3 { margin: 0; font-size: 15px; }
.bc-score { font: 700 11px var(--mono); padding: 2px 10px; border-radius: 999px; background: rgba(91,92,240,.16); color: #b9c0ff; }
.bc-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }
.bc-grid b { display: block; font-size: 24px; }
.bc-grid span { font-size: 12px; color: var(--muted); }
.narrative-card { margin-bottom: 14px; }

/* ── Portfolio card ─────────────────────────────────────────── */
.portfolio-card { }

.pt-head {
  display: flex; align-items: flex-start; justify-content: space-between;
  margin-bottom: 14px; gap: 16px; flex-wrap: wrap;
}
.pt-head h3 { font-family: var(--disp); font-weight: 700; font-size: 15px; }
.pt-sub { font-family: var(--mono); font-size: 9px; letter-spacing: .5px; color: var(--faint); margin-top: 4px; }

.grade-legend { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.gl-item { display: flex; align-items: center; gap: 4px; font-family: var(--mono); font-size: 9.5px; color: var(--faint); }
.gl-badge {
  width: 18px; height: 20px; display: grid; place-items: center;
  font-family: var(--disp); font-weight: 800; font-size: 9px; color: #06060f;
  clip-path: polygon(50% 0, 100% 16%, 100% 60%, 50% 100%, 0 60%, 0 16%); flex: none;
}

/* ── Coverage bar ───────────────────────────────────────────── */
.coverage-row {
  display: flex; align-items: center; gap: 20px;
  padding: 12px 14px; background: rgba(255,255,255,.025);
  border: 1px solid var(--line); border-radius: 12px;
  margin-bottom: 14px; flex-wrap: wrap; gap: 12px;
}
.cov-divider { width: 1px; height: 40px; background: var(--line); flex: none; }
@media (max-width: 700px) { .cov-divider { display: none; } }

.cov-track-wrap { flex: 1; min-width: 180px; display: flex; flex-direction: column; gap: 5px; }
.cov-label { font-family: var(--mono); font-size: 8.5px; letter-spacing: .7px; text-transform: uppercase; color: var(--faint); }
.cov-track { display: flex; height: 8px; border-radius: 5px; overflow: hidden; gap: 2px; }
.cov-track.thin { height: 6px; }
.cov-seg { min-width: 3px; border-radius: 2px; transition: flex .5s ease; }
.cov-seg.red    { background: #ff4d6d; }
.cov-seg.amber  { background: #f5c542; }
.cov-seg.indigo { background: #7c8cf8; }
.cov-seg.good   { background: #34e0a1; }
.cov-seg.teal   { background: #2ee6c5; }
.cov-seg.empty  { background: rgba(255,255,255,.06); }

.cov-legend { display: flex; gap: 10px; flex-wrap: wrap; }
.cleg { font-family: var(--mono); font-size: 9.5px; color: var(--muted); display: flex; align-items: center; gap: 5px; }
.cleg b { color: var(--txt); }
.cleg-dot { width: 6px; height: 6px; border-radius: 50%; flex: none; }
.cleg-dot.red    { background: #ff4d6d; }
.cleg-dot.amber  { background: #f5c542; }
.cleg-dot.indigo { background: #7c8cf8; }
.cleg-dot.good   { background: #34e0a1; }
.cleg-dot.teal   { background: #2ee6c5; }

/* ── First-run empty state ──────────────────────────────────── */
.firstrun {
  position: relative; overflow: hidden;
  display: flex; flex-direction: column; align-items: center;
  text-align: center; padding: 80px 40px 60px;
  background: var(--glass); border: 1px solid var(--line2); border-radius: 22px;
  margin-top: 8px;
}
.fr-glow {
  position: absolute; top: -80px; left: 50%; transform: translateX(-50%);
  width: 500px; height: 300px;
  background: radial-gradient(ellipse at 50% 0%, rgba(46,230,197,.18) 0%, transparent 70%);
  pointer-events: none;
}
.fr-logo {
  width: 56px; height: 56px; border-radius: 18px; display: grid; place-items: center;
  background: radial-gradient(circle at 30% 25%, #2ef5d4, #5b5cf0);
  color: #06060f; margin-bottom: 24px; position: relative;
}
.fr-logo svg { width: 26px; height: 26px; }
.fr-title {
  font-family: var(--disp); font-weight: 900; font-size: 28px;
  letter-spacing: -.5px; margin-bottom: 12px;
}
.fr-sub {
  color: var(--muted); font-size: 14px; line-height: 1.65;
  max-width: 480px; margin-bottom: 36px;
}
.fr-steps {
  display: flex; align-items: center; gap: 8px;
  flex-wrap: wrap; justify-content: center; margin-bottom: 36px;
}
.fr-step {
  display: flex; align-items: center; gap: 10px;
  background: rgba(255,255,255,.04); border: 1px solid var(--line2);
  border-radius: 12px; padding: 10px 16px;
  font-size: 13px; color: var(--muted); max-width: 200px; text-align: left;
}
.fr-step-num {
  width: 22px; height: 22px; flex: none; border-radius: 50%;
  background: rgba(91,92,240,.2); border: 1px solid rgba(91,92,240,.4);
  color: #9aa6ff; font-family: var(--mono); font-size: 11px; font-weight: 700;
  display: grid; place-items: center;
}
.fr-step-sep { color: var(--faint); font-size: 16px; }
.fr-btn {
  display: flex; align-items: center; gap: 8px;
  background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff;
  border: none; border-radius: 14px; padding: 13px 28px;
  font-family: var(--disp); font-weight: 800; font-size: 15px;
  cursor: pointer; transition: opacity .15s; margin-bottom: 14px;
}
.fr-btn:hover { opacity: .88; }
.fr-btn svg { width: 16px; height: 16px; }
.fr-note { font-family: var(--mono); font-size: 11px; color: var(--faint); }

</style>
