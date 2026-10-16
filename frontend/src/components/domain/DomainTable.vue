<script setup lang="ts">
import { ref, computed } from 'vue'
import ShieldScore from '@/components/ui/ShieldScore.vue'

const props = defineProps<{ domains: any[] }>()
const emit = defineEmits<{ open: [domain: any] }>()

// ── Sorting ───────────────────────────────────────────────────────────────────
type SortKey = 'domain' | 'posture_score' | 'volume' | 'dmarc_comp'
const sortKey = ref<SortKey>('posture_score')
const sortDir = ref<1 | -1>(-1)

function setSort(k: SortKey) {
  if (sortKey.value === k) sortDir.value = sortDir.value === 1 ? -1 : 1
  else { sortKey.value = k; sortDir.value = k === 'domain' ? 1 : -1 }
}

const sorted = computed(() => [...props.domains].sort((a, b) => {
  let av = a[sortKey.value] ?? (sortDir.value === 1 ? '￿' : -Infinity)
  let bv = b[sortKey.value] ?? (sortDir.value === 1 ? '￿' : -Infinity)
  return av < bv ? -sortDir.value : av > bv ? sortDir.value : 0
}))

// ── Human-readable labels ─────────────────────────────────────────────────────
// DMARC = outbound identity (who can send as you) → indigo axis
const DMARC_HUMAN: Record<string, string> = {
  reject:     'Fakes blocked',
  quarantine: 'Fakes sent to spam',
  monitor:    'Fakes not stopped',
  none:       'Anyone can impersonate you',
}
// MTA-STS = inbound delivery (how mail reaches you) → teal axis
const MTA_HUMAN: Record<string, string> = {
  enforce: 'Encrypted delivery required',
  testing: 'Delivery encryption monitored',
  none:    'Unencrypted delivery allowed',
}

// Severity colours within each axis
const DMARC_COLOR: Record<string, string> = {
  reject:     '#9aa6ff',   // indigo — fully enforced
  quarantine: '#7c8cf8',   // indigo — partial enforcement
  monitor:    '#f5c542',   // amber  — watching but not acting
  none:       '#ff4d6d',   // red    — no protection
}
const MTA_COLOR: Record<string, string> = {
  enforce: '#2ee6c5',   // teal   — fully enforced
  testing: '#7dd9cc',   // teal/muted — monitoring
  none:    '#ff4d6d',   // red    — no protection
}

function dmarcLabel(d: any) {
  return DMARC_HUMAN[d.dmarc_stage] ?? 'Anyone can impersonate you'
}
function dmarcColor(d: any) {
  return DMARC_COLOR[d.dmarc_stage] ?? '#ff4d6d'
}
function mtaLabel(d: any) {
  return MTA_HUMAN[d.mta_sts_stage] ?? 'Unencrypted delivery allowed'
}
function mtaColor(d: any) {
  return MTA_COLOR[d.mta_sts_stage] ?? '#ff4d6d'
}

// ── Primary issue — most urgent actionable problem ────────────────────────────
type Severity = 'ok' | 'warn' | 'bad'
interface Issue { text: string; severity: Severity; axis: 'dmarc' | 'tls' | 'cert' | 'ok' }

function primaryIssue(d: any): Issue {
  if (!d.dmarc_stage || d.dmarc_stage === 'none')
    return { text: 'Publish a DMARC record to stop impersonation', severity: 'bad', axis: 'dmarc' }
  if (d.cert_status === 'expired')
    return { text: 'MX certificate expired — mail delivery failing', severity: 'bad', axis: 'cert' }
  if (d.cert_status === 'critical' && d.min_cert_days != null)
    return { text: `MX certificate expires in ${d.min_cert_days} days — renew now`, severity: 'bad', axis: 'cert' }
  if (d.cert_status === 'expiring_soon' && d.min_cert_days != null)
    return { text: `MX certificate expires in ${d.min_cert_days} days`, severity: 'warn', axis: 'cert' }
  if (d.dmarc_comp != null && d.dmarc_comp < 75)
    return { text: `Only ${d.dmarc_comp}% of your mail authenticates — fix sending sources`, severity: 'bad', axis: 'dmarc' }
  if (d.dmarc_stage === 'monitor')
    return { text: 'DMARC monitoring only — advance to quarantine to stop fakes', severity: 'warn', axis: 'dmarc' }
  if (!d.mta_sts_stage || d.mta_sts_stage === 'none')
    return { text: 'Publish MTA-STS to require encrypted inbound delivery', severity: 'warn', axis: 'tls' }
  if (d.tls_pass_pct != null && d.tls_pass_pct < 90 && d.mta_sts_stage === 'enforce')
    return { text: `${d.tls_pass_pct}% of deliveries succeed — check MX certificate`, severity: 'bad', axis: 'tls' }
  if (d.dmarc_comp != null && d.dmarc_comp < 95)
    return { text: `${d.dmarc_comp}% of your mail authenticates — align remaining senders`, severity: 'warn', axis: 'dmarc' }
  if (d.mta_sts_stage === 'testing')
    return { text: 'MTA-STS in test mode — ready to enforce encrypted delivery?', severity: 'warn', axis: 'tls' }
  return { text: 'Fully enforced on both axes', severity: 'ok', axis: 'ok' }
}

const issueColor = (issue: Issue) => {
  if (issue.severity === 'ok')   return 'var(--good)'
  if (issue.severity === 'bad')  return 'var(--bad)'
  // warn: colour by axis so user knows which system to look at
  return issue.axis === 'dmarc' ? '#9aa6ff' : issue.axis === 'tls' ? '#2ee6c5' : 'var(--amber)'
}
const issueIcon = (sev: Severity) => sev === 'ok' ? '✓' : sev === 'warn' ? '◐' : '⚠'

// ── Volume helpers ────────────────────────────────────────────────────────────
function fmtVol(n: number) {
  if (!n) return '—'
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M'
  if (n >= 1_000)     return (n / 1_000).toFixed(0) + 'k'
  return String(n)
}
const passPct = (d: any) => d.dmarc_comp ?? 0
const failPct = (d: any) => d.dmarc_comp != null ? Math.max(0, 100 - d.dmarc_comp) : 100
</script>

<template>
  <div>
    <!-- ── Column headers ───────────────────────────────────────────────── -->
    <div class="thead">
      <span class="th" style="padding-left:4px">Grade</span>
      <span class="th sortable" @click="setSort('domain')" tabindex="0" role="button" @keydown.enter.prevent="setSort('domain')" @keydown.space.prevent="setSort('domain')">
        Domain
        <span class="sort-ind" :class="{ active: sortKey === 'domain' }">
          {{ sortKey === 'domain' ? (sortDir === 1 ? '↑' : '↓') : '↕' }}
        </span>
      </span>
      <span class="th dmarc-hd">
        <span class="axis-dot dmarc" />
        Outbound · who can send as you
      </span>
      <span class="th tls-hd">
        <span class="axis-dot tls" />
        Inbound · how mail reaches you
      </span>
      <span class="th sortable" @click="setSort('volume')" tabindex="0" role="button" @keydown.enter.prevent="setSort('volume')" @keydown.space.prevent="setSort('volume')">
        Volume
        <span class="sort-ind" :class="{ active: sortKey === 'volume' }">
          {{ sortKey === 'volume' ? (sortDir === 1 ? '↑' : '↓') : '↕' }}
        </span>
      </span>
      <span class="th sortable" @click="setSort('posture_score')" tabindex="0" role="button" @keydown.enter.prevent="setSort('posture_score')" @keydown.space.prevent="setSort('posture_score')">
        Action needed
        <span class="sort-ind" :class="{ active: sortKey === 'posture_score' }">
          {{ sortKey === 'posture_score' ? (sortDir === 1 ? '↑' : '↓') : '↕' }}
        </span>
      </span>
      <span class="th" />
    </div>

    <!-- ── Rows ─────────────────────────────────────────────────────────── -->
    <div
      v-for="d in sorted"
      :key="d.domain"
      class="row"
      @click="emit('open', d)"
    >
      <!-- Grade -->
      <div class="cell-grade" :title="`Posture score: ${d.posture_score}/100`">
        <ShieldScore :grade="d.grade" :color="d.grade_color" />
      </div>

      <!-- Domain name -->
      <div class="cell-domain">
        <div class="domain-name">{{ d.domain }}</div>
        <div class="domain-sub" v-if="d.tls_pass_pct != null && d.mta_sts_stage !== 'none'">
          {{ d.tls_pass_pct }}% TLS · {{ d.tls_sessions.toLocaleString() }} sessions
        </div>
      </div>

      <!-- DMARC / Outbound axis (indigo) -->
      <div class="cell-axis">
        <div class="axis-label dmarc" :style="`color:${dmarcColor(d)}`">
          {{ dmarcLabel(d) }}
        </div>
        <div class="axis-meta" v-if="d.dmarc_comp != null">
          {{ d.dmarc_comp }}% of mail authenticated
        </div>
        <div class="axis-meta" v-else style="color:var(--faint)">
          No report data
        </div>
      </div>

      <!-- MTA-STS / Inbound axis (teal) -->
      <div class="cell-axis">
        <div class="axis-label tls" :style="`color:${mtaColor(d)}`">
          {{ mtaLabel(d) }}
        </div>
        <div class="axis-meta" v-if="d.tls_pass_pct != null && d.mta_sts_stage !== 'none'">
          {{ d.tls_pass_pct }}% of deliveries encrypted
        </div>
        <div class="axis-meta" v-else-if="d.mta_sts_stage === 'none'" style="color:var(--faint)">
          No policy published
        </div>
        <div v-if="d.mta_sts_stage !== 'none'" class="hosting-badge" :class="d.mta_sts_hosting_mode === 'managed' ? 'managed' : 'self'">
          {{ d.mta_sts_hosting_mode === 'managed' ? 'ZoneProof-hosted' : 'Self-hosted' }}
        </div>
      </div>

      <!-- Volume + pass/fail bar -->
      <div class="cell-volume">
        <div class="vol-header">
          <span class="vol-number">{{ fmtVol(d.volume) }}</span>
          <span class="vol-label" v-if="d.volume > 0">msgs</span>
        </div>
        <div v-if="d.volume > 0 && d.dmarc_comp != null" class="vol-bar">
          <div class="vol-seg pass" :style="`flex:${passPct(d)}`" />
          <div class="vol-seg fail" :style="`flex:${failPct(d)}`" v-if="failPct(d) > 0" />
        </div>
        <div class="vol-sub" v-if="d.volume > 0 && d.dmarc_comp != null">
          <span style="color:var(--good)">{{ d.dmarc_comp }}% pass</span>
          <template v-if="failPct(d) > 0">
            <span style="color:var(--faint)"> · </span>
            <span style="color:var(--bad)">{{ failPct(d).toFixed(0) }}% fail</span>
          </template>
        </div>
        <div class="vol-sub" v-else-if="d.volume === 0" style="color:var(--faint)">
          no reports yet
        </div>
      </div>

      <!-- Primary issue -->
      <div class="cell-issue">
        <span class="issue-icon" :style="`color:${issueColor(primaryIssue(d))}`">
          {{ issueIcon(primaryIssue(d).severity) }}
        </span>
        <span class="issue-text" :style="`color:${issueColor(primaryIssue(d))}`">
          {{ primaryIssue(d).text }}
        </span>
      </div>

      <!-- Arrow -->
      <svg viewBox="0 0 24 24" fill="none" stroke="var(--faint)" stroke-width="2"
        style="width:14px;height:14px;flex:none;margin-left:4px">
        <path d="M9 18l6-6-6-6"/>
      </svg>
    </div>

    <div v-if="!domains.length" class="empty">
      No domains yet — add your first domain to get started.
    </div>
  </div>
</template>

<style scoped>
/* ── Header ──────────────────────────────────────────────────────────────── */
.thead {
  display: grid;
  grid-template-columns: 44px .9fr 1.1fr 1.1fr .7fr 1.5fr 18px;
  gap: 14px; align-items: center;
  font-family: var(--mono); font-size: 9px; letter-spacing: .7px; text-transform: uppercase;
  color: var(--faint); padding: 0 12px 11px; border-bottom: 1px solid var(--line);
}
.th { display: flex; align-items: center; gap: 5px; }
.th.sortable { cursor: pointer; user-select: none; transition: color .12s; }
.th.sortable:hover { color: var(--txt); }
.th.dmarc-hd { color: #7c8cf8; }
.th.tls-hd   { color: #2ee6c5; }
.sort-ind { opacity: .35; font-size: 8px; }
.sort-ind.active { opacity: 1; color: var(--teal); }

.axis-dot {
  width: 6px; height: 6px; border-radius: 50%; flex: none;
}
.axis-dot.dmarc { background: #5b5cf0; }
.axis-dot.tls   { background: #2ee6c5; }

/* ── Row ─────────────────────────────────────────────────────────────────── */
.row {
  display: grid;
  grid-template-columns: 44px .9fr 1.1fr 1.1fr .7fr 1.5fr 18px;
  gap: 14px; align-items: center;
  padding: 13px 12px; border-radius: 12px;
  cursor: pointer; transition: background .12s, border-color .12s;
  border: 1px solid transparent;
}
.row:hover { background: rgba(255,255,255,.035); border-color: var(--line); }

/* ── Grade ───────────────────────────────────────────────────────────────── */
.cell-grade { display: flex; align-items: center; justify-content: center; }

/* ── Domain ──────────────────────────────────────────────────────────────── */
.cell-domain { min-width: 0; }
.domain-name {
  font-family: var(--mono); font-size: 12.5px; font-weight: 600;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.domain-sub {
  font-family: var(--mono); font-size: 9px; color: var(--faint); margin-top: 3px;
}

/* ── Axis cells (DMARC + MTA-STS) ───────────────────────────────────────── */
.cell-axis { min-width: 0; }
.axis-label {
  font-family: var(--mono); font-size: 11.5px; font-weight: 700;
  line-height: 1.3; margin-bottom: 3px;
}
.axis-meta {
  font-family: var(--mono); font-size: 9.5px; color: var(--muted);
}

/* ── Volume ──────────────────────────────────────────────────────────────── */
.cell-volume { min-width: 0; }
.vol-header { display: flex; align-items: baseline; gap: 4px; margin-bottom: 5px; }
.vol-number {
  font-family: var(--disp); font-weight: 800; font-size: 18px;
  letter-spacing: -.5px; line-height: 1;
}
.vol-label { font-family: var(--mono); font-size: 9.5px; color: var(--faint); }
.vol-bar {
  display: flex; height: 4px; border-radius: 3px; overflow: hidden; gap: 1px;
  margin-bottom: 4px;
}
.vol-seg { min-width: 2px; border-radius: 2px; transition: flex .5s ease; }
.vol-seg.pass { background: #5b5cf0; }   /* indigo — DMARC pass is outbound auth */
.vol-seg.fail { background: var(--bad); }
.vol-sub { font-family: var(--mono); font-size: 9.5px; }

/* ── Primary issue ───────────────────────────────────────────────────────── */
.cell-issue { display: flex; align-items: flex-start; gap: 6px; min-width: 0; }
.issue-icon { font-size: 12px; flex: none; line-height: 1.5; }
.issue-text {
  font-family: var(--mono); font-size: 11px; line-height: 1.5; font-weight: 600;
}

/* ── Empty ───────────────────────────────────────────────────────────────── */
.empty { padding: 32px; text-align: center; color: var(--muted); font-size: 13px; }

/* ── Hosting badge ───────────────────────────────────────────────────────── */
.hosting-badge {
  display: inline-flex; align-items: center; margin-top: 4px;
  font-family: var(--mono); font-size: 9px; text-transform: uppercase;
  letter-spacing: .5px; padding: 2px 7px; border-radius: 20px;
}
.hosting-badge.managed {
  background: rgba(46,230,197,.12); border: 1px solid rgba(46,230,197,.25); color: var(--teal);
}
.hosting-badge.self {
  background: rgba(255,255,255,.05); border: 1px solid var(--line2); color: var(--faint);
}
</style>
