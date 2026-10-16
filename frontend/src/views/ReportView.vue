<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '@/api/client'

const route      = useRoute()
const data       = ref<any>(null)
const loading    = ref(true)
const error      = ref<string | null>(null)
const periodDays = Number(route.query.period ?? 30)

onMounted(async () => {
  try {
    data.value = await api.reportData(periodDays)
  } catch (e: any) {
    error.value = e.message ?? 'Failed to load report data'
  } finally {
    loading.value = false
  }
})

function exportPdf() {
  window.print()
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' })
}
function fmtShort(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

const STAGE_LABEL: Record<string, string> = {
  reject: 'Reject', quarantine: 'Quarantine', monitor: 'Monitor', none: 'None',
}
const MTA_LABEL: Record<string, string> = {
  enforce: 'Enforce', testing: 'Testing', none: 'None',
}
function certLabel(status: string | null, days: number | null) {
  if (!status || status === 'ok') return '✓ Healthy'
  if (status === 'expired') return '✗ Expired'
  if (status === 'critical') return `⚠ ${days}d`
  if (status === 'expiring_soon') return `${days}d left`
  return status
}

// ── Sparkline ──────────────────────────────────────────────────────────────
function sparkPts(trend: any[], W = 260, H = 48): string {
  if (!trend || trend.length < 2) return ''
  return trend.map((p, i) => {
    const x = (i / (trend.length - 1)) * W
    const y = H - (p.score / 100) * H
    return `${x.toFixed(1)},${y.toFixed(1)}`
  }).join(' ')
}
function sparkArea(trend: any[], W = 260, H = 48): string {
  if (!trend || trend.length < 2) return ''
  const pts = trend.map((p, i) => {
    const x = (i / (trend.length - 1)) * W
    const y = H - (p.score / 100) * H
    return `${x.toFixed(1)},${y.toFixed(1)}`
  })
  return `M0,${H} L${pts.join(' L')} L${W},${H} Z`
}
function sparkDots(trend: any[], W = 260, H = 48) {
  if (!trend || trend.length < 2) return []
  return trend.map((p, i) => ({
    x: (i / (trend.length - 1)) * W,
    y: H - (p.score / 100) * H,
    score: p.score, week: p.week,
  }))
}

// ── Helpers ────────────────────────────────────────────────────────────────
const trendDelta = computed(() => {
  const t = data.value?.score_trend
  if (!t || t.length < 2) return null
  return t[t.length - 1].score - t[0].score
})
function effortBg(e: string) {
  return { Low: 'rgba(52,224,161,.15)', Medium: 'rgba(245,197,66,.15)', High: 'rgba(255,77,109,.15)' }[e] ?? 'rgba(255,255,255,.06)'
}
function effortCol(e: string) {
  return { Low: '#34e0a1', Medium: '#f5c542', High: '#ff4d6d' }[e] ?? '#9098b5'
}
function impactBg(i: string) {
  return { Low: 'rgba(144,152,181,.1)', Medium: 'rgba(46,230,197,.12)', High: 'rgba(91,92,240,.18)' }[i] ?? 'rgba(255,255,255,.06)'
}
function impactCol(i: string) {
  return { Low: '#9098b5', Medium: '#2ee6c5', High: '#8b8ff8' }[i] ?? '#9098b5'
}
function stageCol(s: string) {
  return { reject: '#34e0a1', quarantine: '#5b5cf0', monitor: '#f5c542', none: '#ff4d6d', enforce: '#34e0a1', testing: '#f5c542' }[s] ?? '#9098b5'
}
function stageBg(s: string) {
  return { reject: 'rgba(52,224,161,.12)', quarantine: 'rgba(91,92,240,.12)', monitor: 'rgba(245,197,66,.12)', none: 'rgba(255,77,109,.12)', enforce: 'rgba(52,224,161,.12)', testing: 'rgba(245,197,66,.12)' }[s] ?? 'rgba(255,255,255,.06)'
}

// posture indicator for a cell value
function postureIcon(val: string | number | null, type: 'dmarc' | 'dkim' | 'mta' | 'cert'): string {
  if (type === 'dmarc') {
    if (val === 'reject') return '✓'
    if (val === 'quarantine') return '◑'
    if (val === 'monitor') return '◔'
    return '✗'
  }
  if (type === 'mta') {
    if (val === 'enforce') return '✓'
    if (val === 'testing') return '◑'
    return '✗'
  }
  if (type === 'cert') {
    if (!val || val === 'ok') return '✓'
    if (val === 'expiring_soon') return '◑'
    return '✗'
  }
  // dkim % number
  const n = Number(val)
  if (isNaN(n)) return '—'
  if (n >= 95) return '✓'
  if (n >= 70) return '◑'
  return '✗'
}
function postureColor(val: string | number | null, type: 'dmarc' | 'dkim' | 'mta' | 'cert'): string {
  const icon = postureIcon(val, type)
  if (icon === '✓') return '#34e0a1'
  if (icon === '◑') return '#f5c542'
  if (icon === '✗') return '#ff4d6d'
  return '#5b6285'
}
</script>

<template>
  <!-- Loading / error (screen-only) -->
  <div v-if="loading" class="r-loading">
    <div class="r-spinner" />
    <p>Building your report…</p>
  </div>
  <div v-else-if="error" class="r-loading">
    <p style="color:#ff4d6d">{{ error }}</p>
    <p style="font-size:12px;color:#5b6285">Make sure you are logged in and try again.</p>
  </div>

  <div v-else-if="data" class="r-root">

    <!-- ── Floating export button (screen only) ───────────────────── -->
    <button class="r-export-btn no-print" @click="exportPdf">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
        <polyline points="7 10 12 15 17 10"/>
        <line x1="12" y1="15" x2="12" y2="3"/>
      </svg>
      Export PDF
    </button>

    <!-- ══════════════════════════════════════════
         COVER
    ══════════════════════════════════════════ -->
    <section class="r-page r-cover">

      <!-- Brand row -->
      <div class="r-brand-row">
        <div class="r-brand-logo"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 8V5a2 2 0 0 1 2-2h3M16 3h3a2 2 0 0 1 2 2v3M21 16v3a2 2 0 0 1-2 2h-3M8 21H5a2 2 0 0 1-2-2v-3"/><path d="M8 12.5l2.8 2.8L16.5 9"/></svg></div>
        <div class="r-brand-text">
          <div class="r-brand-name">Zone<span class="accent">Proof</span></div>
          <div class="r-brand-tag">DMARC · MTA-STS · Email Security</div>
        </div>
        <div class="r-brand-meta">
          <div class="r-report-label">EMAIL SECURITY REPORT</div>
          <div class="r-report-period">{{ data.period_days }}-day period · {{ fmtDate(data.generated_at) }}</div>
        </div>
      </div>

      <!-- Verdict -->
      <div class="r-verdict">
        <div class="r-verdict-ws">{{ data.workspace_name }}</div>
        <div class="r-verdict-text">{{ data.headline_verdict }}</div>
      </div>

      <!-- Score + sparkline -->
      <div class="r-score-row">
        <div class="r-score-block">
          <div class="r-ring" :style="`--gc: ${data.sentinel.grade_color}`">
            <div class="r-ring-num">{{ data.sentinel.score }}</div>
            <div class="r-ring-sub">/ 100</div>
          </div>
          <div class="r-score-info">
            <div class="r-grade" :style="`color:${data.sentinel.grade_color}`">Grade {{ data.sentinel.grade }}</div>
            <div class="r-grade-lbl">{{ data.sentinel.grade_label }}</div>
            <div v-if="trendDelta !== null" class="r-delta" :class="trendDelta >= 0 ? 'pos' : 'neg'">
              {{ trendDelta >= 0 ? '▲' : '▼' }} {{ Math.abs(trendDelta) }} pts over {{ data.score_trend.length }} weeks
            </div>
          </div>
        </div>

        <div class="r-spark-block" v-if="data.score_trend.length >= 2">
          <div class="r-spark-label">Score trend · {{ data.score_trend.length }} weeks</div>
          <svg viewBox="0 0 260 48" class="r-spark-svg" preserveAspectRatio="none">
            <defs>
              <linearGradient id="cov-fill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" :stop-color="data.sentinel.grade_color" stop-opacity="0.3"/>
                <stop offset="100%" :stop-color="data.sentinel.grade_color" stop-opacity="0.02"/>
              </linearGradient>
            </defs>
            <path :d="sparkArea(data.score_trend)" fill="url(#cov-fill)"/>
            <polyline :points="sparkPts(data.score_trend)" fill="none" :stroke="data.sentinel.grade_color" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
            <circle v-for="pt in sparkDots(data.score_trend)" :key="pt.week" :cx="pt.x" :cy="pt.y" r="2.5" :fill="data.sentinel.grade_color"/>
          </svg>
          <div class="r-spark-axis">
            <span>{{ fmtShort(data.score_trend[0].week) }}</span>
            <span>{{ fmtShort(data.score_trend[data.score_trend.length - 1].week) }}</span>
          </div>
        </div>
      </div>

      <!-- Pillars -->
      <div class="r-pillars">
        <div class="r-pillar">
          <div class="r-pillar-val">{{ data.sentinel.pillar_dmarc.toFixed(1) }}<span class="r-pillar-max">/60</span></div>
          <div class="r-pillar-lbl">Outbound identity</div>
          <div class="r-pillar-sub">DMARC enforcement</div>
        </div>
        <div class="r-pillar-sep"/>
        <div class="r-pillar">
          <div class="r-pillar-val">{{ data.sentinel.pillar_tls.toFixed(1) }}<span class="r-pillar-max">/25</span></div>
          <div class="r-pillar-lbl">Inbound delivery</div>
          <div class="r-pillar-sub">MTA-STS enforcement</div>
        </div>
        <div class="r-pillar-sep"/>
        <div class="r-pillar">
          <div class="r-pillar-val">{{ data.sentinel.pillar_certs.toFixed(1) }}<span class="r-pillar-max">/15</span></div>
          <div class="r-pillar-lbl">Certificate health</div>
          <div class="r-pillar-sub">TLS cert validity</div>
        </div>
      </div>

      <!-- KPI strip -->
      <div class="r-kpis">
        <div class="r-kpi">
          <div class="r-kpi-val">{{ data.total_domains }}</div>
          <div class="r-kpi-lbl">Monitored</div>
        </div>
        <div class="r-kpi-sep"/>
        <div class="r-kpi">
          <div class="r-kpi-val" :style="data.dmarc_reject_count === data.total_domains ? 'color:#34e0a1' : ''">{{ data.dmarc_reject_count }}</div>
          <div class="r-kpi-lbl">Fully protected</div>
        </div>
        <div class="r-kpi-sep"/>
        <div class="r-kpi">
          <div class="r-kpi-val" :style="data.dmarc_none_count > 0 ? 'color:#ff4d6d' : 'color:#34e0a1'">{{ data.dmarc_none_count }}</div>
          <div class="r-kpi-lbl">Openly spoofable</div>
        </div>
        <div class="r-kpi-sep"/>
        <div class="r-kpi">
          <div class="r-kpi-val" :style="data.threat.total_attempts > 0 ? 'color:#ff4d6d' : ''">{{ data.threat.total_attempts.toLocaleString() }}</div>
          <div class="r-kpi-lbl">Impersonation attempts</div>
        </div>
        <div class="r-kpi-sep"/>
        <div class="r-kpi">
          <div class="r-kpi-val" :style="data.cert_alerts > 0 ? 'color:#f5c542' : ''">{{ data.cert_alerts }}</div>
          <div class="r-kpi-lbl">Cert alerts</div>
        </div>
      </div>

      <div class="r-footer"><span>{{ data.workspace_name }} · Confidential</span><span>ZoneProof · {{ fmtDate(data.generated_at) }}</span></div>
    </section>

    <!-- ══════════════════════════════════════════
         01 EXECUTIVE SUMMARY
    ══════════════════════════════════════════ -->
    <section class="r-page">
      <div class="r-sec-hdr">
        <div class="r-sec-num">01</div>
        <div>
          <div class="r-sec-title">Executive Summary</div>
          <div class="r-sec-sub">Portfolio posture, trajectory, and key risks — last {{ data.period_days }} days</div>
        </div>
      </div>

      <!-- AI narrative (3 paragraphs) or rule-based fallback -->
      <div v-if="data.narrative" class="r-narrative-wrap">
        <div class="r-narrative-badge">
          <span v-if="data.narrative.is_ai" class="r-ai-badge">✦ ZoneProof AI · {{ data.narrative.generated_at ? new Date(data.narrative.generated_at).toLocaleDateString() : '' }}</span>
          <span v-else class="r-ai-badge rule">Analysis</span>
        </div>
        <p class="r-narrative">{{ data.narrative.summary }}</p>
        <p class="r-narrative">{{ data.narrative.threats }}</p>
        <p class="r-narrative last">{{ data.narrative.actions }}</p>
      </div>
      <div v-else class="r-narrative">{{ data.executive_narrative }}</div>

      <div class="r-auth-grid">
        <div class="r-auth-card">
          <div class="r-auth-val" :style="data.avg_dmarc_comp != null && data.avg_dmarc_comp < 90 ? 'color:#f5c542' : 'color:#34e0a1'">
            {{ data.avg_dmarc_comp != null ? data.avg_dmarc_comp + '%' : '—' }}
          </div>
          <div class="r-auth-lbl">Avg DMARC compliance</div>
          <div class="r-auth-sub">SPF or DKIM aligned</div>
        </div>
        <div class="r-auth-card">
          <div class="r-auth-val" :style="data.avg_dkim_pass_pct != null && data.avg_dkim_pass_pct < 90 ? 'color:#f5c542' : 'color:#34e0a1'">
            {{ data.avg_dkim_pass_pct != null ? data.avg_dkim_pass_pct + '%' : '—' }}
          </div>
          <div class="r-auth-lbl">Avg DKIM pass rate</div>
          <div class="r-auth-sub">Signed &amp; aligned messages</div>
        </div>
        <div class="r-auth-card">
          <div class="r-auth-val" :style="data.avg_tls_pass_pct != null && data.avg_tls_pass_pct < 95 ? 'color:#f5c542' : 'color:#34e0a1'">
            {{ data.avg_tls_pass_pct != null ? data.avg_tls_pass_pct + '%' : '—' }}
          </div>
          <div class="r-auth-lbl">Avg TLS delivery success</div>
          <div class="r-auth-sub">Inbound sessions encrypted</div>
        </div>
        <div class="r-auth-card">
          <div class="r-auth-val" :style="data.threat.exposed > 0 ? 'color:#ff4d6d' : 'color:#34e0a1'">
            {{ data.threat.has_data ? data.threat.blocked_pct + '%' : '—' }}
          </div>
          <div class="r-auth-lbl">Impersonation blocked</div>
          <div class="r-auth-sub">Stopped by DMARC enforcement</div>
        </div>
      </div>

      <!-- Trend chart -->
      <div v-if="data.score_trend.length >= 2" class="r-trend-wrap">
        <div class="r-subsec-lbl">ZoneProof Score — {{ data.score_trend.length }}-week trajectory</div>
        <svg viewBox="0 0 560 70" class="r-trend-svg" preserveAspectRatio="none">
          <defs>
            <linearGradient id="t-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" :stop-color="data.sentinel.grade_color" stop-opacity="0.2"/>
              <stop offset="100%" :stop-color="data.sentinel.grade_color" stop-opacity="0"/>
            </linearGradient>
          </defs>
          <line x1="0" :y1="70-50*0.7" x2="560" :y2="70-50*0.7" stroke="rgba(255,255,255,.07)" stroke-width="1" stroke-dasharray="4,3"/>
          <line x1="0" :y1="70-75*0.7" x2="560" :y2="70-75*0.7" stroke="rgba(255,255,255,.07)" stroke-width="1" stroke-dasharray="4,3"/>
          <path :d="sparkArea(data.score_trend, 560, 70)" fill="url(#t-fill)"/>
          <polyline :points="sparkPts(data.score_trend, 560, 70)" fill="none" :stroke="data.sentinel.grade_color" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>
          <circle v-for="pt in sparkDots(data.score_trend, 560, 70)" :key="pt.week" :cx="pt.x" :cy="pt.y" r="3.5" :fill="data.sentinel.grade_color"/>
        </svg>
        <div class="r-trend-footer">
          <div class="r-trend-end">
            <span class="r-te-lbl">{{ fmtShort(data.score_trend[0].week) }}</span>
            <span class="r-te-val">{{ data.score_trend[0].score }}</span>
          </div>
          <div class="r-trend-delta" :class="trendDelta !== null && trendDelta >= 0 ? 'pos' : 'neg'" v-if="trendDelta !== null">
            {{ trendDelta >= 0 ? '+' : '' }}{{ trendDelta }} pts
          </div>
          <div class="r-trend-end r-right">
            <span class="r-te-lbl">{{ fmtShort(data.score_trend[data.score_trend.length - 1].week) }}</span>
            <span class="r-te-val" :style="`color:${data.sentinel.grade_color}`">{{ data.score_trend[data.score_trend.length - 1].score }}</span>
          </div>
        </div>
      </div>

      <div class="r-footer"><span>{{ data.workspace_name }} · Confidential</span><span>Page 2</span></div>
    </section>

    <!-- ══════════════════════════════════════════
         02 SENDING INFRASTRUCTURE
    ══════════════════════════════════════════ -->
    <section class="r-page">
      <div class="r-sec-hdr">
        <div class="r-sec-num">02</div>
        <div>
          <div class="r-sec-title">Sending Infrastructure</div>
          <div class="r-sec-sub">Who is sending email on behalf of your domains — authorized, misconfigured, and unauthorized</div>
        </div>
      </div>

      <div class="r-buckets">
        <div class="r-bucket" style="border-color:rgba(52,224,161,.25);background:rgba(52,224,161,.06)">
          <div class="r-bucket-n" style="color:#34e0a1">{{ data.sender_inventory.authorized_compliant.length }}</div>
          <div class="r-bucket-lbl">Authorized &amp; compliant</div>
          <div class="r-bucket-sub">DMARC pass ≥ 95%</div>
        </div>
        <div class="r-bucket" style="border-color:rgba(245,197,66,.25);background:rgba(245,197,66,.06)">
          <div class="r-bucket-n" style="color:#f5c542">{{ data.sender_inventory.authorized_noncompliant.length }}</div>
          <div class="r-bucket-lbl">Authorized, needs fix</div>
          <div class="r-bucket-sub">Known senders failing auth</div>
        </div>
        <div class="r-bucket" style="border-color:rgba(255,77,109,.25);background:rgba(255,77,109,.06)">
          <div class="r-bucket-n" style="color:#ff4d6d">{{ data.sender_inventory.unauthorized.length }}</div>
          <div class="r-bucket-lbl">Unauthorized</div>
          <div class="r-bucket-sub">Unrecognised or spoofing</div>
        </div>
      </div>

      <div v-if="data.sender_inventory.authorized_compliant.length + data.sender_inventory.authorized_noncompliant.length > 0">
        <div class="r-subsec-lbl">Authorized sending sources</div>
        <table class="r-table">
          <thead><tr>
            <th>Organisation / Source</th><th class="r-right">Volume</th>
            <th class="r-right">DMARC%</th><th class="r-right">DKIM%</th><th class="r-right">SPF%</th><th class="r-center">Status</th>
          </tr></thead>
          <tbody>
            <tr v-for="s in [...data.sender_inventory.authorized_compliant, ...data.sender_inventory.authorized_noncompliant]" :key="s.org">
              <td class="r-td-bold">{{ s.org }}</td>
              <td class="r-right r-mono">{{ s.volume.toLocaleString() }}</td>
              <td class="r-right r-mono" :style="`color:${s.pass_pct >= 95 ? '#34e0a1' : '#ff4d6d'}`">{{ s.pass_pct }}%</td>
              <td class="r-right r-mono" :style="`color:${s.dkim_aligned_pct >= 90 ? '#34e0a1' : '#f5c542'}`">{{ s.dkim_aligned_pct }}%</td>
              <td class="r-right r-mono" :style="`color:${s.spf_aligned_pct >= 90 ? '#34e0a1' : '#f5c542'}`">{{ s.spf_aligned_pct }}%</td>
              <td class="r-center">
                <span class="r-badge" :style="`background:${s.pass_pct>=95?'rgba(52,224,161,.15)':'rgba(245,197,66,.15)'};color:${s.pass_pct>=95?'#34e0a1':'#f5c542'}`">
                  {{ s.pass_pct >= 95 ? 'Compliant' : 'Fix needed' }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="data.sender_inventory.unauthorized.length > 0">
        <div class="r-subsec-lbl" style="color:#ff4d6d">Unauthorized sources</div>
        <div class="r-alert-note">These senders are not authorised. They represent phishing infrastructure, misconfigured third-party tools, or active spoofing attempts against your domains.</div>
        <table class="r-table">
          <thead><tr>
            <th>Organisation / Source</th><th>IP address</th><th class="r-right">Volume</th><th class="r-right">DMARC%</th><th class="r-center">Status</th>
          </tr></thead>
          <tbody>
            <tr v-for="s in data.sender_inventory.unauthorized" :key="s.org">
              <td class="r-td-bold">{{ s.org }}</td>
              <td class="r-mono r-faint">{{ s.top_ip }}</td>
              <td class="r-right r-mono">{{ s.volume.toLocaleString() }}</td>
              <td class="r-right r-mono" style="color:#ff4d6d">{{ s.pass_pct }}%</td>
              <td class="r-center"><span class="r-badge" style="background:rgba(255,77,109,.15);color:#ff4d6d">Unauthorized</span></td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="!data.sender_inventory.authorized_compliant.length && !data.sender_inventory.authorized_noncompliant.length && !data.sender_inventory.unauthorized.length" class="r-empty">
        No sending source data for this period. Ensure DMARC RUA reporting addresses are configured.
      </div>

      <div class="r-footer"><span>{{ data.workspace_name }} · Confidential</span><span>Page 3</span></div>
    </section>

    <!-- ══════════════════════════════════════════
         03 DOMAIN PORTFOLIO
    ══════════════════════════════════════════ -->
    <section class="r-page">
      <div class="r-sec-hdr">
        <div class="r-sec-num">03</div>
        <div>
          <div class="r-sec-title">Domain Portfolio</div>
          <div class="r-sec-sub">Security posture across all {{ data.total_domains }} monitored domains</div>
        </div>
      </div>

      <!-- Posture matrix -->
      <div class="r-posture-matrix">
        <div class="r-posture-hdr">
          <span>Domain</span><span class="r-center">Grade</span>
          <span class="r-center">DMARC</span><span class="r-center">DKIM</span>
          <span class="r-center">MTA-STS</span><span class="r-center">Cert</span>
          <span>Primary issue</span>
        </div>
        <div v-for="d in data.domains" :key="d.domain" class="r-posture-row">
          <span class="r-td-bold">{{ d.domain }}</span>
          <span class="r-center">
            <span class="r-grade-badge" :style="`color:${d.grade_color};border-color:${d.grade_color}40`">{{ d.grade }}</span>
          </span>
          <span class="r-center">
            <span class="r-posture-cell" :style="`color:${postureColor(d.dmarc_stage,'dmarc')}`">
              {{ postureIcon(d.dmarc_stage,'dmarc') }}
              <span class="r-cell-sub">{{ STAGE_LABEL[d.dmarc_stage] ?? d.dmarc_stage }}</span>
            </span>
          </span>
          <span class="r-center">
            <span class="r-posture-cell" :style="`color:${postureColor(d.dkim_pass_pct,'dkim')}`">
              {{ postureIcon(d.dkim_pass_pct,'dkim') }}
              <span class="r-cell-sub">{{ d.dkim_pass_pct != null ? d.dkim_pass_pct+'%' : '—' }}</span>
            </span>
          </span>
          <span class="r-center">
            <span class="r-posture-cell" :style="`color:${postureColor(d.mta_sts_stage,'mta')}`">
              {{ postureIcon(d.mta_sts_stage,'mta') }}
              <span class="r-cell-sub">{{ MTA_LABEL[d.mta_sts_stage] ?? d.mta_sts_stage }}</span>
            </span>
          </span>
          <span class="r-center">
            <span class="r-posture-cell" :style="`color:${postureColor(d.cert_status,'cert')}`">
              {{ postureIcon(d.cert_status,'cert') }}
              <span class="r-cell-sub">{{ certLabel(d.cert_status, d.min_cert_days) }}</span>
            </span>
          </span>
          <span class="r-td-issue">{{ d.primary_issue ?? '—' }}</span>
        </div>
      </div>

      <!-- Grade legend -->
      <div class="r-legend">
        <span class="r-legend-lbl">Grade scale:</span>
        <span v-for="[g, c, l] in [['A','#34e0a1','90–100'],['B','#5b5cf0','75–89'],['C','#f5c542','55–74'],['D','#ff8c42','35–54'],['F','#ff4d6d','0–34']]" :key="g" class="r-legend-item">
          <span class="r-grade-badge" :style="`color:${c};border-color:${c}40`">{{ g }}</span>{{ l }}
        </span>
        <span class="r-posture-legend">
          <span style="color:#34e0a1">✓ Fully enforced</span>
          <span style="color:#f5c542">◑ Partial / testing</span>
          <span style="color:#ff4d6d">✗ Not configured</span>
        </span>
      </div>

      <div class="r-footer"><span>{{ data.workspace_name }} · Confidential</span><span>Page 4</span></div>
    </section>

    <!-- ══════════════════════════════════════════
         04 TLS & INBOUND DELIVERY
    ══════════════════════════════════════════ -->
    <section class="r-page">
      <div class="r-sec-hdr">
        <div class="r-sec-num">04</div>
        <div>
          <div class="r-sec-title">TLS &amp; Inbound Delivery</div>
          <div class="r-sec-sub">MTA-STS enforcement status and encrypted delivery rates across your domain portfolio</div>
        </div>
      </div>

      <!-- MTA-STS enforcement breakdown -->
      <div class="r-buckets">
        <div class="r-bucket" style="border-color:rgba(52,224,161,.25);background:rgba(52,224,161,.06)">
          <div class="r-bucket-n" style="color:#34e0a1">{{ data.tls_enforce_count }}</div>
          <div class="r-bucket-lbl">MTA-STS enforced</div>
          <div class="r-bucket-sub">Inbound TLS required or delivery rejected</div>
        </div>
        <div class="r-bucket" style="border-color:rgba(245,197,66,.25);background:rgba(245,197,66,.06)">
          <div class="r-bucket-n" style="color:#f5c542">{{ data.tls_testing_count }}</div>
          <div class="r-bucket-lbl">MTA-STS testing</div>
          <div class="r-bucket-sub">TLS failures reported, not blocked</div>
        </div>
        <div class="r-bucket" style="border-color:rgba(255,77,109,.25);background:rgba(255,77,109,.06)">
          <div class="r-bucket-n" style="color:#ff4d6d">{{ data.tls_none_count }}</div>
          <div class="r-bucket-lbl">No MTA-STS policy</div>
          <div class="r-bucket-sub">Inbound delivery unencrypted</div>
        </div>
      </div>

      <!-- Avg TLS stats -->
      <div class="r-auth-grid">
        <div class="r-auth-card">
          <div class="r-auth-val" :style="data.avg_tls_pass_pct != null && data.avg_tls_pass_pct < 95 ? 'color:#f5c542' : 'color:#34e0a1'">
            {{ data.avg_tls_pass_pct != null ? data.avg_tls_pass_pct + '%' : '—' }}
          </div>
          <div class="r-auth-lbl">Avg TLS session success</div>
          <div class="r-auth-sub">Across all monitored domains</div>
        </div>
        <div class="r-auth-card">
          <div class="r-auth-val">{{ data.total_tls_sessions.toLocaleString() }}</div>
          <div class="r-auth-lbl">Total TLS sessions</div>
          <div class="r-auth-sub">Inbound delivery attempts in period</div>
        </div>
        <div class="r-auth-card">
          <div class="r-auth-val" :style="data.tls_enforce_count === data.total_domains ? 'color:#34e0a1' : 'color:#f5c542'">
            {{ data.total_domains > 0 ? Math.round(data.tls_enforce_count / data.total_domains * 100) + '%' : '—' }}
          </div>
          <div class="r-auth-lbl">Domains at enforce</div>
          <div class="r-auth-sub">{{ data.tls_enforce_count }} of {{ data.total_domains }} domains</div>
        </div>
        <div class="r-auth-card">
          <div class="r-auth-val" :style="data.cert_alerts > 0 ? 'color:#f5c542' : 'color:#34e0a1'">{{ data.cert_alerts }}</div>
          <div class="r-auth-lbl">Certificate alerts</div>
          <div class="r-auth-sub">Expired or expiring soon</div>
        </div>
      </div>

      <!-- Per-domain TLS table -->
      <div class="r-subsec-lbl" style="margin-top:4px">Per-domain TLS posture</div>
      <table class="r-table">
        <thead><tr>
          <th>Domain</th>
          <th class="r-center">MTA-STS policy</th>
          <th class="r-right">TLS pass rate</th>
          <th class="r-center">Certificate</th>
          <th class="r-right">Cert days left</th>
        </tr></thead>
        <tbody>
          <tr v-for="d in data.domains" :key="d.domain">
            <td class="r-td-bold">{{ d.domain }}</td>
            <td class="r-center">
              <span class="r-badge" :style="`background:${stageBg(d.mta_sts_stage)};color:${stageCol(d.mta_sts_stage)}`">
                {{ MTA_LABEL[d.mta_sts_stage] ?? d.mta_sts_stage }}
              </span>
            </td>
            <td class="r-right r-mono" :style="`color:${d.tls_pass_pct != null && d.tls_pass_pct < 95 ? '#f5c542' : '#34e0a1'}`">
              {{ d.tls_pass_pct != null ? d.tls_pass_pct + '%' : '—' }}
            </td>
            <td class="r-center r-mono"
              :style="`color:${d.cert_status==='expired'||d.cert_status==='critical'?'#ff4d6d':d.cert_status==='expiring_soon'?'#f5c542':'#34e0a1'}`">
              {{ certLabel(d.cert_status, d.min_cert_days) }}
            </td>
            <td class="r-right r-mono">{{ d.min_cert_days != null ? d.min_cert_days + 'd' : '—' }}</td>
          </tr>
        </tbody>
      </table>

      <!-- Cert expiry list -->
      <div v-if="data.cert_expiry_list.length > 0">
        <div class="r-subsec-lbl" style="color:#f5c542;margin-top:8px">Certificate alerts requiring action</div>
        <table class="r-table">
          <thead><tr><th>Domain</th><th>Status</th><th class="r-right">Days remaining</th></tr></thead>
          <tbody>
            <tr v-for="c in data.cert_expiry_list" :key="c.domain">
              <td class="r-td-bold">{{ c.domain }}</td>
              <td :style="`color:${c.status==='expired'||c.status==='critical'?'#ff4d6d':'#f5c542'}`">
                {{ c.status.replace('_', ' ').toUpperCase() }}
              </td>
              <td class="r-right r-mono">{{ c.days_remaining != null ? c.days_remaining : 'Expired' }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="r-footer"><span>{{ data.workspace_name }} · Confidential</span><span>Page 5</span></div>
    </section>

    <!-- ══════════════════════════════════════════
         05 THREAT SURFACE
    ══════════════════════════════════════════ -->
    <section class="r-page">
      <div class="r-sec-hdr">
        <div class="r-sec-num">05</div>
        <div>
          <div class="r-sec-title">Threat Surface</div>
          <div class="r-sec-sub">Impersonation attempts detected across your domains — last {{ data.period_days }} days</div>
        </div>
      </div>

      <div v-if="data.threat.has_data">
        <div class="r-auth-grid" style="margin-bottom:0">
          <div class="r-auth-card">
            <div class="r-auth-val" :style="data.threat.total_attempts > 0 ? 'color:#ff4d6d' : ''">
              {{ data.threat.total_attempts.toLocaleString() }}
            </div>
            <div class="r-auth-lbl">Total attempts</div>
            <div class="r-auth-sub">DMARC-failing suspicious senders</div>
          </div>
          <div class="r-auth-card">
            <div class="r-auth-val" style="color:#34e0a1">{{ data.threat.blocked.toLocaleString() }}</div>
            <div class="r-auth-lbl">Blocked ({{ data.threat.blocked_pct }}%)</div>
            <div class="r-auth-sub">Stopped by DMARC enforcement</div>
          </div>
          <div class="r-auth-card">
            <div class="r-auth-val" :style="data.threat.exposed > 0 ? 'color:#ff4d6d' : 'color:#34e0a1'">
              {{ data.threat.exposed.toLocaleString() }}
            </div>
            <div class="r-auth-lbl">Reached inboxes</div>
            <div class="r-auth-sub">No enforcement on affected domains</div>
          </div>
          <div class="r-auth-card">
            <div class="r-auth-val">{{ data.threat.unique_orgs || data.threat.unique_ips }}</div>
            <div class="r-auth-lbl">Unique sources</div>
            <div class="r-auth-sub">Distinct attacking organisations / IPs</div>
          </div>
        </div>

        <div class="r-threat-ctx" :class="data.threat.exposed > 0 ? 'danger' : 'ok'">
          <b>{{ data.threat.total_attempts.toLocaleString() }}</b> impersonation attempts detected.
          <b>{{ data.threat.blocked.toLocaleString() }} ({{ data.threat.blocked_pct }}%)</b> were blocked by DMARC enforcement.
          <span v-if="data.threat.exposed > 0">
            <b style="color:#ff4d6d">{{ data.threat.exposed.toLocaleString() }}</b> messages reached recipients because
            {{ data.threat.top_targeted.filter((t: any) => t.exposed > 0).map((t: any) => t.domain).slice(0,3).join(', ') }}
            {{ data.threat.top_targeted.filter((t: any) => t.exposed > 0).length === 1 ? 'has' : 'have' }} no DMARC enforcement.
          </span>
          <span v-else> All detected attempts were blocked — no spoofed mail reached recipients.</span>
        </div>

        <div class="r-subsec-lbl">Most targeted domains</div>
        <table class="r-table" v-if="data.threat.top_targeted.length">
          <thead><tr>
            <th>Domain</th><th>DMARC</th>
            <th class="r-right">Attempts</th><th class="r-right">Blocked</th><th class="r-right">Exposed</th><th class="r-right">Block rate</th>
          </tr></thead>
          <tbody>
            <tr v-for="t in data.threat.top_targeted" :key="t.domain">
              <td class="r-td-bold">{{ t.domain }}</td>
              <td><span class="r-badge" :style="`background:${stageBg(t.dmarc_stage)};color:${stageCol(t.dmarc_stage)}`">{{ STAGE_LABEL[t.dmarc_stage] ?? t.dmarc_stage }}</span></td>
              <td class="r-right r-mono">{{ t.attempts.toLocaleString() }}</td>
              <td class="r-right r-mono" style="color:#34e0a1">{{ t.blocked.toLocaleString() }}</td>
              <td class="r-right r-mono" :style="t.exposed > 0 ? 'color:#ff4d6d' : ''">{{ t.exposed.toLocaleString() }}</td>
              <td class="r-right r-mono">{{ t.blocked_pct }}%</td>
            </tr>
          </tbody>
        </table>

        <div class="r-subsec-lbl" style="margin-top:12px" v-if="data.threat.top_sources.length">Top attack sources</div>
        <table class="r-table" v-if="data.threat.top_sources.length">
          <thead><tr><th>Organisation / Source</th><th>IP address</th><th class="r-right">Attempts</th></tr></thead>
          <tbody>
            <tr v-for="s in data.threat.top_sources" :key="s.source_ip">
              <td class="r-td-bold">{{ s.source_org || 'Unknown' }}</td>
              <td class="r-mono r-faint">{{ s.source_ip }}<span v-if="s.rdns"> · {{ s.rdns }}</span></td>
              <td class="r-right r-mono">{{ s.attempts.toLocaleString() }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-else class="r-clear-state">
        <div class="r-clear-icon">✓</div>
        <div class="r-clear-title">No impersonation attempts detected</div>
        <div class="r-clear-sub">DMARC reporting is active and no suspicious senders were identified in this period.</div>
      </div>

      <div class="r-footer"><span>{{ data.workspace_name }} · Confidential</span><span>Page 6</span></div>
    </section>

    <!-- ══════════════════════════════════════════
         06 RECOMMENDATIONS
    ══════════════════════════════════════════ -->
    <section class="r-page">
      <div class="r-sec-hdr">
        <div class="r-sec-num">06</div>
        <div>
          <div class="r-sec-title">Recommendations</div>
          <div class="r-sec-sub">Sequenced by risk — address the top items first</div>
        </div>
      </div>

      <div v-if="data.recommendations.length === 0" class="r-clear-state">
        <div class="r-clear-icon">✓</div>
        <div class="r-clear-title">No open issues</div>
        <div class="r-clear-sub">All domains are fully enforced on outbound identity and inbound delivery.</div>
      </div>

      <div v-else class="r-recs">
        <div v-for="r in data.recommendations" :key="`${r.domain}-${r.category}`" class="r-rec">
          <div class="r-rec-num">{{ String(r.priority).padStart(2,'0') }}</div>
          <div class="r-rec-body">
            <div class="r-rec-row">
              <span class="r-rec-domain">{{ r.domain }}</span>
              <span class="r-rec-cat">{{ r.category.toUpperCase() }}</span>
            </div>
            <div class="r-rec-action">{{ r.action }}</div>
            <div class="r-rec-detail">{{ r.detail }}</div>
          </div>
          <div class="r-rec-badges">
            <div class="r-rec-b">
              <span class="r-rb-lbl">Effort</span>
              <span class="r-rb-val" :style="`background:${effortBg(r.effort)};color:${effortCol(r.effort)}`">{{ r.effort }}</span>
            </div>
            <div class="r-rec-b">
              <span class="r-rb-lbl">Impact</span>
              <span class="r-rb-val" :style="`background:${impactBg(r.impact)};color:${impactCol(r.impact)}`">{{ r.impact }}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="r-signoff">
        <div class="r-signoff-line"/>
        <div class="r-signoff-text">
          This report was generated automatically by ZoneProof on {{ fmtDate(data.generated_at) }}.
          Data reflects DMARC aggregate reports, TLS-RPT reports, live DNS polling, and certificate probes
          collected during the {{ data.period_days }}-day period ending {{ fmtDate(data.generated_at) }}.
        </div>
      </div>

      <div class="r-footer"><span>{{ data.workspace_name }} · Confidential</span><span>Page 7</span></div>
    </section>

    <!-- ══════════════════════════════════════════
         APPENDIX
    ══════════════════════════════════════════ -->
    <section class="r-page r-appendix">
      <div class="r-sec-hdr" style="border-bottom-color:rgba(255,255,255,.1)">
        <div class="r-sec-num" style="color:#5b6285">A</div>
        <div>
          <div class="r-sec-title" style="color:#9098b5">Technical Reference</div>
          <div class="r-sec-sub">Raw data for security engineers and administrators</div>
        </div>
      </div>

      <div class="r-subsec-lbl">Complete domain data</div>
      <table class="r-table r-table-sm">
        <thead><tr>
          <th>Domain</th><th>DMARC</th><th class="r-right">DMARC%</th>
          <th class="r-right">DKIM%</th><th>MTA-STS</th><th class="r-right">TLS%</th>
          <th class="r-right">Volume</th><th class="r-center">Cert</th><th class="r-center">Grade</th>
        </tr></thead>
        <tbody>
          <tr v-for="d in data.domains" :key="d.domain">
            <td class="r-td-bold">{{ d.domain }}</td>
            <td><span class="r-badge" :style="`background:${stageBg(d.dmarc_stage)};color:${stageCol(d.dmarc_stage)}`">{{ STAGE_LABEL[d.dmarc_stage] ?? d.dmarc_stage }}</span></td>
            <td class="r-right r-mono">{{ d.dmarc_comp != null ? d.dmarc_comp+'%' : '—' }}</td>
            <td class="r-right r-mono">{{ d.dkim_pass_pct != null ? d.dkim_pass_pct+'%' : '—' }}</td>
            <td><span class="r-badge" :style="`background:${stageBg(d.mta_sts_stage)};color:${stageCol(d.mta_sts_stage)}`">{{ MTA_LABEL[d.mta_sts_stage] ?? d.mta_sts_stage }}</span></td>
            <td class="r-right r-mono">{{ d.tls_pass_pct != null ? d.tls_pass_pct+'%' : '—' }}</td>
            <td class="r-right r-mono">{{ d.volume.toLocaleString() }}</td>
            <td class="r-center r-mono"
              :style="`color:${d.cert_status==='expired'||d.cert_status==='critical'?'#ff4d6d':d.cert_status==='expiring_soon'?'#f5c542':'#34e0a1'}`">
              {{ certLabel(d.cert_status, d.min_cert_days) }}
            </td>
            <td class="r-center">
              <span class="r-grade-badge" :style="`color:${d.grade_color};border-color:${d.grade_color}40`">{{ d.grade }}</span>
            </td>
          </tr>
        </tbody>
      </table>

      <div class="r-meta">
        <div class="r-subsec-lbl" style="margin-top:16px">Report metadata</div>
        <div class="r-meta-row"><span class="r-meta-k">Workspace</span><span>{{ data.workspace_name }}</span></div>
        <div class="r-meta-row"><span class="r-meta-k">Generated</span><span>{{ fmtDate(data.generated_at) }}</span></div>
        <div class="r-meta-row"><span class="r-meta-k">Period</span><span>Last {{ data.period_days }} days</span></div>
        <div class="r-meta-row"><span class="r-meta-k">Domains monitored</span><span>{{ data.total_domains }}</span></div>
        <div class="r-meta-row"><span class="r-meta-k">Total DMARC volume</span><span>{{ data.total_volume.toLocaleString() }} messages</span></div>
        <div class="r-meta-row"><span class="r-meta-k">Total TLS sessions</span><span>{{ data.total_tls_sessions.toLocaleString() }}</span></div>
        <div class="r-meta-row"><span class="r-meta-k">Score trend points</span><span>{{ data.score_trend.length }} weeks of data</span></div>
      </div>

      <div class="r-footer"><span>{{ data.workspace_name }} · Confidential</span><span>Page 8</span></div>
    </section>

  </div>
</template>

<style>
/* ── Base (inherits app tokens.css, no body override) ─────────────── */
.r-loading {
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  height: 100vh; gap: 14px; color: var(--muted);
}
.r-spinner {
  width: 34px; height: 34px; border: 3px solid rgba(255,255,255,.1);
  border-top-color: var(--indigo); border-radius: 50%;
  animation: r-spin .8s linear infinite;
}
@keyframes r-spin { to { transform: rotate(360deg); } }

/* ── Export button ────────────────────────────────────────────────── */
.r-export-btn {
  position: fixed; top: 20px; right: 24px; z-index: 100;
  display: flex; align-items: center; gap: 8px;
  background: linear-gradient(90deg, #5b5cf0, #4b4ce0);
  color: #fff; border: none; border-radius: 12px;
  padding: 10px 18px; font-family: var(--disp); font-weight: 700;
  font-size: 13px; cursor: pointer; transition: opacity .15s;
  box-shadow: 0 4px 20px rgba(91,92,240,.4);
}
.r-export-btn:hover { opacity: .88; }
.r-export-btn svg { width: 15px; height: 15px; }

/* ── Report root ──────────────────────────────────────────────────── */
.r-root {
  width: 100%; max-width: 900px; margin: 0 auto;
  padding: 32px 24px 64px;
  display: flex; flex-direction: column; gap: 0;
}

/* ── Pages ────────────────────────────────────────────────────────── */
.r-page {
  display: flex; flex-direction: column; gap: 18px;
  padding: 36px 40px 28px;
  background: rgba(255,255,255,.025);
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 20px;
  margin-bottom: 20px;
  position: relative;
}
.r-appendix { background: rgba(255,255,255,.015); }

/* ── Cover ────────────────────────────────────────────────────────── */
.r-cover {
  background: linear-gradient(160deg, rgba(91,92,240,.08), rgba(46,230,197,.05), rgba(255,255,255,.02));
  border-color: rgba(91,92,240,.2);
}
.r-brand-row { display: flex; align-items: center; gap: 12px; }
.r-brand-logo {
  width: 38px; height: 38px; border-radius: 11px;
  background: var(--accent);
  display: grid; place-items: center;
  font-weight: 900; font-size: 18px; color: #fff; flex: none;
}
.r-brand-name { font-family: var(--disp); font-size: 17px; font-weight: 800; color: var(--txt); }
.r-brand-name .accent { color: var(--accent-soft); }
.r-brand-tag { font-family: var(--mono); font-size: 8.5px; letter-spacing: 1.2px; text-transform: uppercase; color: var(--faint); margin-top: 2px; }
.r-brand-meta { margin-left: auto; text-align: right; }
.r-report-label { font-family: var(--mono); font-size: 9px; letter-spacing: 1.8px; text-transform: uppercase; color: var(--teal); font-weight: 700; }
.r-report-period { font-family: var(--mono); font-size: 10px; color: var(--faint); margin-top: 2px; }

.r-verdict { border-top: 1px solid rgba(91,92,240,.3); border-bottom: 1px solid rgba(255,255,255,.07); padding: 20px 0 18px; }
.r-verdict-ws { font-family: var(--mono); font-size: 10px; letter-spacing: .8px; text-transform: uppercase; color: var(--faint); margin-bottom: 7px; }
.r-verdict-text { font-family: var(--disp); font-size: 20px; font-weight: 800; color: var(--txt); line-height: 1.3; letter-spacing: -.3px; }

.r-score-row { display: flex; gap: 24px; align-items: center; }
.r-score-block { display: flex; gap: 18px; align-items: center; flex: none; }
.r-ring {
  width: 86px; height: 86px; border-radius: 50%; flex: none;
  background: conic-gradient(var(--gc) 0%, rgba(255,255,255,.08) 0%);
  border: 5px solid var(--gc);
  display: grid; place-items: center;
  box-shadow: 0 0 24px color-mix(in srgb, var(--gc) 30%, transparent);
}
.r-ring-num { font-family: var(--disp); font-size: 23px; font-weight: 900; color: var(--txt); line-height: 1; }
.r-ring-sub { font-family: var(--mono); font-size: 9px; color: var(--faint); }
.r-grade { font-family: var(--disp); font-size: 20px; font-weight: 900; }
.r-grade-lbl { font-size: 11px; color: var(--muted); margin-bottom: 6px; }
.r-delta { font-family: var(--mono); font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 10px; display: inline-block; }
.r-delta.pos { background: rgba(52,224,161,.15); color: #34e0a1; }
.r-delta.neg { background: rgba(255,77,109,.12); color: #ff4d6d; }

.r-spark-block { flex: 1; min-width: 0; }
.r-spark-label { font-family: var(--mono); font-size: 8.5px; letter-spacing: .6px; text-transform: uppercase; color: var(--faint); margin-bottom: 6px; }
.r-spark-svg { width: 100%; height: 48px; display: block; }
.r-spark-axis { display: flex; justify-content: space-between; font-family: var(--mono); font-size: 8px; color: var(--faint); margin-top: 3px; }

.r-pillars { display: flex; align-items: center; background: rgba(255,255,255,.03); border: 1px solid rgba(255,255,255,.07); border-radius: 14px; padding: 16px 20px; }
.r-pillar { flex: 1; text-align: center; }
.r-pillar-sep { width: 1px; height: 44px; background: rgba(255,255,255,.08); }
.r-pillar-val { font-family: var(--disp); font-size: 20px; font-weight: 900; color: var(--txt); }
.r-pillar-max { font-family: var(--mono); font-size: 10px; color: var(--faint); font-weight: 400; }
.r-pillar-lbl { font-size: 11px; font-weight: 600; color: var(--muted); margin-top: 3px; }
.r-pillar-sub { font-family: var(--mono); font-size: 8.5px; color: var(--faint); }

.r-kpis { display: flex; align-items: center; border: 1px solid rgba(255,255,255,.07); border-radius: 12px; overflow: hidden; }
.r-kpi { flex: 1; padding: 12px 14px; text-align: center; }
.r-kpi-val { font-family: var(--disp); font-size: 20px; font-weight: 900; color: var(--txt); line-height: 1; }
.r-kpi-lbl { font-family: var(--mono); font-size: 8.5px; color: var(--faint); margin-top: 3px; }
.r-kpi-sep { width: 1px; height: 36px; background: rgba(255,255,255,.07); flex: none; }

/* ── Section header ───────────────────────────────────────────────── */
.r-sec-hdr { display: flex; gap: 14px; align-items: flex-start; padding-bottom: 14px; border-bottom: 1px solid rgba(91,92,240,.3); }
.r-sec-num { font-family: var(--mono); font-size: 10px; font-weight: 700; color: var(--teal); letter-spacing: 1px; padding-top: 4px; }
.r-sec-title { font-family: var(--disp); font-size: 18px; font-weight: 800; color: var(--txt); }
.r-sec-sub { font-family: var(--mono); font-size: 10px; color: var(--faint); margin-top: 2px; }

.r-subsec-lbl { font-family: var(--mono); font-size: 8.5px; letter-spacing: .8px; text-transform: uppercase; color: var(--faint); font-weight: 600; }

/* ── Narrative ────────────────────────────────────────────────────── */
.r-narrative-wrap { display: flex; flex-direction: column; gap: 0; }
.r-narrative-badge { margin-bottom: 8px; }
.r-ai-badge {
  font-family: var(--mono); font-size: 9px; letter-spacing: .6px; text-transform: uppercase;
  color: #2ee6c5; background: rgba(46,230,197,.08); border: 1px solid rgba(46,230,197,.2);
  border-radius: 20px; padding: 3px 10px;
}
.r-ai-badge.rule { color: #5b6285; background: transparent; border-color: rgba(255,255,255,.1); }
.r-narrative {
  padding: 10px 16px; font-size: 12.5px; line-height: 1.75; color: var(--muted);
  background: rgba(91,92,240,.07); border-left: 3px solid var(--indigo);
  border-radius: 0; margin: 0; border-bottom: 1px solid rgba(91,92,240,.08);
}
.r-narrative.last { border-radius: 0 0 10px 0; border-bottom: none; }
.r-narrative-wrap > .r-narrative:first-of-type { border-radius: 0 10px 0 0; }

/* ── Auth / metric cards ──────────────────────────────────────────── */
.r-auth-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 8px; }
.r-auth-card {
  padding: 14px 16px; background: rgba(255,255,255,.03);
  border: 1px solid rgba(255,255,255,.07); border-radius: 12px;
}
.r-auth-val { font-family: var(--disp); font-size: 22px; font-weight: 900; color: var(--txt); line-height: 1; margin-bottom: 4px; }
.r-auth-lbl { font-size: 10px; font-weight: 600; color: var(--muted); }
.r-auth-sub { font-family: var(--mono); font-size: 8.5px; color: var(--faint); margin-top: 2px; line-height: 1.4; }

/* ── Trend ────────────────────────────────────────────────────────── */
.r-trend-wrap {}
.r-trend-svg { width: 100%; height: 70px; display: block; }
.r-trend-footer { display: flex; align-items: center; justify-content: space-between; margin-top: 6px; }
.r-trend-end { display: flex; flex-direction: column; gap: 1px; }
.r-right { align-items: flex-end !important; text-align: right !important; }
.r-te-lbl { font-family: var(--mono); font-size: 8px; color: var(--faint); }
.r-te-val { font-family: var(--disp); font-size: 15px; font-weight: 800; color: var(--txt); }
.r-trend-delta { font-family: var(--mono); font-size: 11px; font-weight: 700; padding: 3px 12px; border-radius: 20px; }
.r-trend-delta.pos { background: rgba(52,224,161,.15); color: #34e0a1; }
.r-trend-delta.neg { background: rgba(255,77,109,.12); color: #ff4d6d; }

/* ── Buckets ──────────────────────────────────────────────────────── */
.r-buckets { display: grid; grid-template-columns: repeat(3,1fr); gap: 10px; }
.r-bucket { padding: 16px 18px; border-radius: 12px; border: 1px solid; }
.r-bucket-n { font-family: var(--disp); font-size: 30px; font-weight: 900; line-height: 1; margin-bottom: 5px; }
.r-bucket-lbl { font-size: 11px; font-weight: 700; color: var(--txt); }
.r-bucket-sub { font-family: var(--mono); font-size: 9px; color: var(--faint); margin-top: 2px; }

/* ── Tables ───────────────────────────────────────────────────────── */
.r-table { width: 100%; border-collapse: collapse; font-size: 11px; }
.r-table thead tr { border-bottom: 1px solid rgba(255,255,255,.1); }
.r-table th { padding: 7px 10px; text-align: left; font-family: var(--mono); font-size: 8.5px; letter-spacing: .4px; text-transform: uppercase; color: var(--faint); font-weight: 600; }
.r-table td { padding: 9px 10px; border-bottom: 1px solid rgba(255,255,255,.05); vertical-align: middle; color: var(--muted); }
.r-table tr:last-child td { border-bottom: none; }
.r-table tr:hover td { background: rgba(255,255,255,.02); }
.r-table-sm td { padding: 7px 10px; }
.r-td-bold { font-weight: 600; color: var(--txt) !important; }
.r-td-issue { font-family: var(--mono); font-size: 9.5px; color: var(--faint); max-width: 220px; }
.r-mono { font-family: var(--mono); }
.r-faint { color: var(--faint) !important; font-size: 9.5px; }
.r-center { text-align: center !important; }

/* ── Posture matrix ───────────────────────────────────────────────── */
.r-posture-matrix { display: flex; flex-direction: column; gap: 0; border: 1px solid rgba(255,255,255,.07); border-radius: 12px; overflow: hidden; }
.r-posture-hdr {
  display: grid; grid-template-columns: 2fr 0.6fr 0.8fr 0.8fr 0.8fr 0.8fr 2fr;
  gap: 0; padding: 8px 14px;
  background: rgba(255,255,255,.04);
  font-family: var(--mono); font-size: 8.5px; letter-spacing: .4px; text-transform: uppercase; color: var(--faint);
  border-bottom: 1px solid rgba(255,255,255,.08);
}
.r-posture-row {
  display: grid; grid-template-columns: 2fr 0.6fr 0.8fr 0.8fr 0.8fr 0.8fr 2fr;
  gap: 0; padding: 9px 14px;
  border-bottom: 1px solid rgba(255,255,255,.04);
  align-items: center;
  transition: background .1s;
}
.r-posture-row:last-child { border-bottom: none; }
.r-posture-row:hover { background: rgba(255,255,255,.025); }
.r-posture-cell { display: flex; flex-direction: column; align-items: center; font-size: 13px; font-weight: 700; gap: 1px; }
.r-cell-sub { font-family: var(--mono); font-size: 7.5px; color: var(--faint); font-weight: 400; }

/* ── Grade badge ──────────────────────────────────────────────────── */
.r-grade-badge { font-family: var(--mono); font-size: 10px; font-weight: 800; padding: 2px 8px; border-radius: 20px; border: 1.5px solid; }

/* ── Badges (inline) ──────────────────────────────────────────────── */
.r-badge { font-family: var(--mono); font-size: 9px; font-weight: 700; padding: 2px 8px; border-radius: 6px; white-space: nowrap; }

/* ── Legend ───────────────────────────────────────────────────────── */
.r-legend { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding: 8px 12px; background: rgba(255,255,255,.02); border: 1px solid rgba(255,255,255,.06); border-radius: 8px; font-family: var(--mono); font-size: 9px; }
.r-legend-lbl { color: var(--faint); font-weight: 600; }
.r-legend-item { display: flex; align-items: center; gap: 5px; color: var(--faint); }
.r-posture-legend { margin-left: auto; display: flex; gap: 12px; font-size: 9px; }

/* ── Threat ───────────────────────────────────────────────────────── */
.r-threat-ctx { padding: 12px 14px; border-radius: 10px; font-size: 12px; line-height: 1.65; }
.r-threat-ctx.danger { background: rgba(255,77,109,.07); border: 1px solid rgba(255,77,109,.2); color: var(--muted); }
.r-threat-ctx.ok { background: rgba(52,224,161,.06); border: 1px solid rgba(52,224,161,.2); color: var(--muted); }
.r-threat-ctx b { color: var(--txt); }

/* ── Recommendations ──────────────────────────────────────────────── */
.r-recs { display: flex; flex-direction: column; gap: 8px; }
.r-rec {
  display: flex; gap: 14px; align-items: flex-start;
  padding: 14px 16px; border-radius: 12px;
  background: rgba(255,255,255,.03); border: 1px solid rgba(255,255,255,.07);
}
.r-rec-num { font-family: var(--mono); font-size: 13px; font-weight: 800; color: var(--indigo); width: 28px; flex: none; padding-top: 1px; }
.r-rec-body { flex: 1; min-width: 0; }
.r-rec-row { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.r-rec-domain { font-size: 11px; font-weight: 700; color: var(--txt); }
.r-rec-cat { font-family: var(--mono); font-size: 8px; letter-spacing: .5px; text-transform: uppercase; color: var(--faint); background: rgba(255,255,255,.06); padding: 2px 6px; border-radius: 4px; }
.r-rec-action { font-size: 12.5px; font-weight: 600; color: var(--txt); margin-bottom: 3px; }
.r-rec-detail { font-family: var(--mono); font-size: 10px; color: var(--faint); line-height: 1.55; }
.r-rec-badges { display: flex; flex-direction: column; gap: 6px; flex: none; }
.r-rec-b { display: flex; flex-direction: column; align-items: flex-end; gap: 2px; }
.r-rb-lbl { font-family: var(--mono); font-size: 7.5px; text-transform: uppercase; letter-spacing: .4px; color: var(--faint); }
.r-rb-val { font-family: var(--mono); font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 6px; }

/* ── Alert note ───────────────────────────────────────────────────── */
.r-alert-note {
  font-family: var(--mono); font-size: 10px; line-height: 1.55; color: var(--muted);
  background: rgba(255,77,109,.07); border: 1px solid rgba(255,77,109,.18);
  border-radius: 8px; padding: 9px 12px; margin-bottom: 8px;
}

/* ── Empty / clear states ─────────────────────────────────────────── */
.r-empty { font-family: var(--mono); font-size: 11px; color: var(--faint); padding: 20px; text-align: center; background: rgba(255,255,255,.02); border-radius: 8px; border: 1px solid rgba(255,255,255,.06); }
.r-clear-state { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 40px; }
.r-clear-icon { font-size: 28px; color: #34e0a1; }
.r-clear-title { font-family: var(--disp); font-size: 15px; font-weight: 700; color: var(--txt); }
.r-clear-sub { font-family: var(--mono); font-size: 10px; color: var(--faint); text-align: center; }

/* ── Sign-off ─────────────────────────────────────────────────────── */
.r-signoff { margin-top: 4px; }
.r-signoff-line { height: 1px; background: rgba(255,255,255,.07); margin-bottom: 10px; }
.r-signoff-text { font-family: var(--mono); font-size: 9px; color: var(--faint); line-height: 1.65; }

/* ── Appendix ─────────────────────────────────────────────────────── */
.r-meta {}
.r-meta-row { display: flex; gap: 16px; padding: 5px 0; border-bottom: 1px solid rgba(255,255,255,.04); font-size: 11px; }
.r-meta-k { font-family: var(--mono); font-size: 9px; text-transform: uppercase; letter-spacing: .3px; color: var(--faint); width: 160px; flex: none; }

/* ── Footer ───────────────────────────────────────────────────────── */
.r-footer {
  display: flex; justify-content: space-between;
  font-family: var(--mono); font-size: 8px; color: var(--faint); letter-spacing: .3px;
  border-top: 1px solid rgba(255,255,255,.06); padding-top: 10px; margin-top: auto;
}

/* ── Print — light theme on white paper ───────────────────────────── */
@media print {
  .no-print { display: none !important; }
  .r-export-btn { display: none !important; }

  /* Base: white paper, near-black text */
  body, html { background: #ffffff !important; color: #111827 !important; }

  /* CSS variables — everything resolves to dark-on-white */
  :root {
    --txt:   #111827 !important;
    --muted: #374151 !important;
    --faint: #4b5563 !important;
    --line:  #d1d5db !important;
    --line2: #e5e7eb !important;
    --glass: #f3f4f6 !important;
    --teal:  #0d9488 !important;
    --indigo:#4338ca !important;
    --good:  #15803d !important;
    --warn:  #92400e !important;
    --bad:   #991b1b !important;
  }

  /* ── Page containers ── */
  .r-root { max-width: 100%; padding: 0; gap: 0; }
  .r-page {
    background: #ffffff !important;
    border: none !important;
    box-shadow: none !important;
    border-radius: 0 !important;
    page-break-after: always;
    page-break-inside: avoid;
    margin: 0 !important;
    padding: 18mm 20mm 14mm !important;
    min-height: 297mm;
    justify-content: flex-start;
  }
  .r-page:last-child { page-break-after: avoid; }
  .r-appendix { background: #ffffff !important; }

  /* ── Cover ── */
  .r-cover {
    background: #f8faff !important;
    border-bottom: 3px solid #4338ca !important;
  }
  .r-brand-logo { background: #5b5cf0 !important; }
  .r-brand-name  { color: #111827 !important; }
  .r-brand-name .accent { color: #4b4ce0 !important; }
  .r-brand-tag   { color: #4b5563 !important; }
  .r-report-label{ color: #4338ca !important; }
  .r-report-period { color: #4b5563 !important; }
  .r-verdict { border-top-color: #c7d2fe !important; border-bottom-color: #e5e7eb !important; }
  .r-verdict-ws  { color: #4b5563 !important; }
  .r-verdict-text{ color: #111827 !important; }
  .r-ring { background: none !important; border-width: 4px !important; box-shadow: none !important; }
  .r-ring-num    { color: #111827 !important; }
  .r-ring-sub    { color: #4b5563 !important; }
  .r-grade-lbl   { color: #374151 !important; }
  .r-delta.pos   { background: #dcfce7 !important; color: #15803d !important; }
  .r-delta.neg   { background: #fee2e2 !important; color: #991b1b !important; }
  .r-spark-label { color: #4b5563 !important; }
  .r-spark-axis  { color: #6b7280 !important; }

  /* Pillars box */
  .r-pillars {
    background: #f3f4f6 !important;
    border: 1px solid #d1d5db !important;
  }
  .r-pillar-val  { color: #111827 !important; }
  .r-pillar-max  { color: #6b7280 !important; }
  .r-pillar-lbl  { color: #374151 !important; }
  .r-pillar-sub  { color: #6b7280 !important; }
  .r-pillar-sep  { background: #d1d5db !important; }

  /* KPI strip */
  .r-kpis { border: 1px solid #d1d5db !important; background: #f9fafb !important; }
  .r-kpi-val  { color: #111827 !important; }
  .r-kpi-lbl  { color: #4b5563 !important; }
  .r-kpi-sep  { background: #d1d5db !important; }

  /* Footer */
  .r-footer { color: #6b7280 !important; border-top-color: #d1d5db !important; }

  /* ── Section header ── */
  .r-sec-hdr { border-bottom: 2px solid #4338ca !important; }
  .r-sec-num    { color: #4338ca !important; }
  .r-sec-title  { color: #111827 !important; }
  .r-sec-sub    { color: #4b5563 !important; }
  .r-subsec-lbl { color: #4b5563 !important; }

  /* ── Narrative ── */
  .r-narrative {
    color: #1f2937 !important;
    background: #eef2ff !important;
    border-left: 3px solid #4338ca !important;
  }
  .r-ai-badge {
    color: #0d9488 !important;
    background: #f0fdfb !important;
    border-color: #5eead4 !important;
  }
  .r-ai-badge.rule { color: #6b7280 !important; border-color: #d1d5db !important; }

  /* ── Auth metric cards ── */
  .r-auth-grid { gap: 8px !important; }
  .r-auth-card {
    background: #f3f4f6 !important;
    border: 1px solid #d1d5db !important;
    border-radius: 10px !important;
  }
  .r-auth-lbl { color: #374151 !important; }
  .r-auth-sub { color: #6b7280 !important; }

  /* ── Trend chart ── */
  .r-trend-wrap {
    background: #f9fafb !important;
    border: 1px solid #d1d5db !important;
    border-radius: 10px !important;
    padding: 12px !important;
  }
  .r-trend-footer { border-top-color: #e5e7eb !important; }
  .r-te-lbl  { color: #6b7280 !important; }
  .r-te-val  { color: #111827 !important; }
  .r-trend-delta.pos { color: #15803d !important; }
  .r-trend-delta.neg { color: #991b1b !important; }

  /* Gridlines inside SVG — make visible on white */
  .r-trend-svg line { stroke: #e5e7eb !important; }

  /* ── Sender buckets ── */
  .r-buckets { gap: 8px !important; }
  .r-bucket  { border-width: 1px !important; border-radius: 10px !important; }
  .r-bucket-lbl { color: #374151 !important; }
  .r-bucket-sub { color: #6b7280 !important; }

  /* ── Tables ── */
  .r-tbl, .r-table, .r-table-sm {
    border: 1px solid #d1d5db !important;
    border-radius: 8px !important;
    overflow: hidden !important;
  }
  .r-tbl th, .r-table th, .r-table-sm th {
    color: #374151 !important;
    background: #f3f4f6 !important;
    border-bottom: 1px solid #d1d5db !important;
  }
  .r-tbl td, .r-table td, .r-table-sm td {
    color: #1f2937 !important;
    border-bottom: 1px solid #f3f4f6 !important;
  }
  .r-tbl tr:last-child td, .r-table tr:last-child td { border-bottom: none !important; }
  .r-td-bold { color: #111827 !important; font-weight: 600 !important; }
  .r-mono    { color: #374151 !important; }

  /* ── Domain posture cards (page 3) ── */
  .r-dom-card {
    background: #f9fafb !important;
    border: 1px solid #d1d5db !important;
  }
  .r-dom-issue { color: #374151 !important; background: #fef9c3 !important; border-left-color: #92400e !important; }
  .r-dom-ok    { color: #374151 !important; background: #f0fdf4 !important; border-left-color: #15803d !important; }

  /* ── Threat section ── */
  .r-threat-row { border-bottom-color: #e5e7eb !important; }
  .r-threat-label { color: #4b5563 !important; }
  .r-threat-bar-bg { background: #e5e7eb !important; }

  /* ── Cert alerts ── */
  .r-cert-row { border-bottom-color: #e5e7eb !important; }
  .r-alert-note {
    background: #fff1f2 !important;
    border-color: #fecdd3 !important;
    color: #991b1b !important;
  }

  /* ── Recommendations ── */
  .r-rec {
    background: #f9fafb !important;
    border: 1px solid #d1d5db !important;
    border-radius: 10px !important;
  }
  .r-rec-num    { color: #6b7280 !important; }
  .r-rec-domain { color: #111827 !important; }
  .r-rec-cat    { color: #4b5563 !important; background: #e5e7eb !important; }
  .r-rec-action { color: #111827 !important; }
  .r-rec-detail { color: #374151 !important; }
  .r-rb-lbl     { color: #6b7280 !important; }

  /* ── Sign-off ── */
  .r-signoff-line { background: #d1d5db !important; }
  .r-signoff-text { color: #6b7280 !important; }

  /* ── Empty / clear states ── */
  .r-empty      { color: #6b7280 !important; background: #f9fafb !important; border-color: #d1d5db !important; }
  .r-clear-icon { color: #15803d !important; }
  .r-clear-title { color: #111827 !important; }
  .r-clear-sub  { color: #6b7280 !important; }

  /* ── Appendix ── */
  .r-meta-row   { border-bottom-color: #e5e7eb !important; }
  .r-meta-k     { color: #6b7280 !important; }

  /* ── Badge chips ── */
  .r-badge      { border: 1px solid currentColor !important; }
  .r-grade-badge { border-width: 1px !important; }

  @page { size: A4; margin: 0; background: #ffffff; }
}
</style>
