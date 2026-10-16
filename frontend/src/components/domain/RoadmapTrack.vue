<script setup lang="ts">
import StepTracker from '@/components/ui/StepTracker.vue'
import NextStep from '@/components/ui/NextStep.vue'

const props = defineProps<{
  domain: string
  dmarcStage: number   // 0-4
  mtaStage: number     // 0-2
  dmarcComp: number | null
  dmarcFailSources: number
  tlsPassPct: number | null
  tlsFailReason: string | null
  advisorMessage: string | null
  advisorCommend: boolean
  advisorLoading: boolean
  advisorModel?: string
  recommendations?: RecommendationItem[]
  onReviewDmarc?: () => void
  onReviewMta?: () => void
  onRegenAdvisor?: () => void
  onPreviewDmarc?: () => void
  simulation?: SimulationResult | null
  simulationLoading?: boolean
}>()

interface SimulationResult {
  target_stage: string
  total_volume: number
  affected_volume: number
  affected_pct: number
  safe: boolean
  by_classification: Record<string, number>
  authorized_sources_affected: { source_org: string; classification: string; affected_count: number }[]
}

interface RecommendationItem {
  direction: 'advance' | 'hold' | 'regression'
  severity: 'info' | 'warn' | 'critical'
  category: 'dmarc' | 'tls' | 'cert'
  title: string
  body: string
  blocking_reason: string | null
}

// Human-readable step labels
const DMARC_STEPS = [
  'No record',
  'Watching',
  'Spam filter',
  'Fakes blocked',
  'BIMI',
]

const MTA_STEPS = [
  'No policy',
  'Monitoring',
  'Enforced',
]

// What the user achieves at each stage — shown inside the step node tooltip / aria
const DMARC_OUTCOMES = [
  'Anyone can send email pretending to be you',
  'You can see who is sending as your domain',
  'Suspicious email lands in spam instead of inboxes',
  'All unauthorised email is rejected before delivery',
  'Your logo appears in email clients that support BIMI',
]

const MTA_OUTCOMES = [
  'Email delivered to you may arrive unencrypted',
  'You can see whether senders encrypt their connection',
  'All senders must use TLS or delivery is rejected',
]

// Effort hints per transition
const DMARC_EFFORT = ['', '~15 min', '~1–2 weeks of monitoring', '~2–4 weeks at quarantine', '']
const MTA_EFFORT   = ['', '~15 min', '~1 week in testing mode']

interface BlockingIssue {
  text: string
  severity: 'warn' | 'block'
  // Where the evidence for this blocker lives.
  link?: { to: string; label: string }
}

// Where each kind of recommendation is explained in full.
const REC_LINK: Record<string, { to: string; label: string }> = {
  dmarc: { to: 'dmarc', label: 'See the senders' },
  tls:   { to: 'tls',   label: 'See the TLS failures' },
  cert:  { to: 'certs', label: 'See the certificates' },
}

function dmarcBlockers(): BlockingIssue[] {
  const issues: BlockingIssue[] = []
  const s = props.dmarcStage
  if (s === 1 && props.dmarcComp !== null && props.dmarcComp < 95) {
    issues.push({
      text: `${(100 - props.dmarcComp).toFixed(1)}% of mail is failing DMARC — align sending sources before advancing`,
      severity: 'block',
      link: { to: 'dmarc', label: 'See which senders fail' },
    })
  }
  if (s === 1 && props.dmarcFailSources > 0) {
    issues.push({
      text: `${props.dmarcFailSources} unaligned sender${props.dmarcFailSources > 1 ? 's' : ''} detected — fix SPF/DKIM alignment first`,
      severity: 'warn',
      link: { to: 'dmarc', label: 'See the senders' },
    })
  }
  if (s === 2 && props.dmarcComp !== null && props.dmarcComp < 98) {
    issues.push({
      text: `${(100 - props.dmarcComp).toFixed(1)}% of mail still fails — resolve before moving to reject or legitimate mail may be lost`,
      severity: 'block',
      link: { to: 'dmarc', label: 'See which senders fail' },
    })
  }
  return issues
}

function mtaBlockers(): BlockingIssue[] {
  const issues: BlockingIssue[] = []
  if (props.mtaStage === 1 && props.tlsFailReason) {
    const labels: Record<string, string> = {
      'certificate-expired': 'MX certificate is expired — renew before enforcing',
      'certificate-not-trusted': 'MX certificate is not trusted — fix before enforcing',
      'starttls-not-supported': 'STARTTLS not offered on your MX — required before enforce',
      'certificate-host-mismatch': 'MX certificate hostname mismatch — fix before enforcing',
    }
    const isCert = props.tlsFailReason.startsWith('certificate') || props.tlsFailReason === 'starttls-not-supported'
    issues.push({
      text: labels[props.tlsFailReason] ?? `TLS issue detected (${props.tlsFailReason}) — resolve before enforcing`,
      severity: 'block',
      link: isCert ? { to: 'certs', label: 'See the certificate' } : { to: 'tls', label: 'See the TLS failures' },
    })
  }
  if (props.mtaStage === 1 && props.tlsPassPct !== null && props.tlsPassPct < 95) {
    issues.push({
      text: `Only ${props.tlsPassPct}% of inbound sessions pass TLS — investigate failures before enforcing`,
      severity: props.tlsPassPct < 80 ? 'block' : 'warn',
      link: { to: 'tls', label: 'See the TLS failures' },
    })
  }
  return issues
}

function dmarcNextStep(): string {
  const s = props.dmarcStage
  if (s === 0) return 'Publish a DMARC record in monitor mode. You\'ll start receiving reports about every sender using your domain — no mail is affected yet.'
  if (s === 1) return 'Once you\'ve identified and aligned all legitimate senders, move to quarantine. Suspicious email will go to spam instead of inboxes.'
  if (s === 2) return 'After running at quarantine with low failure rates, advance to reject. Fakes will be blocked before they reach recipients.'
  if (s === 3) return 'You\'re fully protected. Next milestone: BIMI — publish a verified logo to display your brand mark in supporting email clients.'
  return 'Maximum protection achieved.'
}

function mtaNextStep(): string {
  const s = props.mtaStage
  if (s === 0) return 'Publish an MTA-STS policy in testing mode and add a TLS-RPT record. You\'ll see which senders encrypt connections to your mail server.'
  if (s === 1) return 'Once TLS pass rates are consistently high and your MX certificate is healthy, flip the policy to enforce. Senders that can\'t use TLS will be rejected.'
  return 'Fully enforced. All inbound mail must use TLS. Keep your MX certificate renewed.'
}

const canAdvanceDmarc = (s: number) => s < 3 && dmarcBlockers().filter(b => b.severity === 'block').length === 0
const canAdvanceMta   = (s: number) => s < 2 && mtaBlockers().filter(b => b.severity === 'block').length === 0
</script>

<template>
  <div>
    <!-- Advisor banner — merged into track context -->
    <div v-if="advisorLoading || advisorMessage" :class="['advisor-row', advisorCommend ? 'commend' : '']">
      <div class="adv-orb" />
      <div style="flex:1;min-width:0">
        <div class="adv-who">ZoneProof Advisor · AI</div>
        <div v-if="advisorLoading" class="adv-skel" />
        <div v-else class="adv-msg" v-html="advisorMessage" />
        <div class="adv-foot">
          ✦ AI-generated · grounded on your reports
          <span v-if="advisorModel" class="adv-model">{{ advisorModel }}</span>
          <span class="adv-re" @click="onRegenAdvisor?.()" tabindex="0" role="button" @keydown.enter.prevent="onRegenAdvisor?.()" @keydown.space.prevent="onRegenAdvisor?.()">↻ Regenerate</span>
        </div>
      </div>
    </div>

    <!-- Recommendation engine verdict — why this domain can/can't advance right now -->
    <div v-if="recommendations && recommendations.length" class="rec-panel">
      <div class="rec-panel-head">Advancement check</div>
      <div
        v-for="r in recommendations" :key="r.title"
        :class="['rec-item', r.direction]"
      >
        <span class="rec-dir-tag" :class="r.direction">{{ r.direction }}</span>
        <div class="rec-body">
          <div class="rec-title">{{ r.title }}</div>
          <div class="rec-text">{{ r.body }}</div>
          <div v-if="r.blocking_reason" class="rec-blocking">Blocked by: {{ r.blocking_reason }}</div>
          <NextStep v-if="REC_LINK[r.category]" :to="REC_LINK[r.category].to" :label="REC_LINK[r.category].label" :domain="domain" />
        </div>
      </div>
    </div>

    <!-- Two-track grid -->
    <div class="r2">

      <!-- ── DMARC track ─────────────────────────────────────── -->
      <div class="card dmarc-card">
        <div class="track-header">
          <div class="track-label">
            <svg viewBox="0 0 24 24" fill="none" stroke="#9aa6ff" stroke-width="2">
              <path d="M22 6l-10 7L2 6"/><rect x="2" y="4" width="20" height="16" rx="2"/>
            </svg>
            <div>
              <div class="track-title">Outbound identity</div>
              <div class="track-sub">Who can send email as you</div>
            </div>
          </div>
          <div class="stage-pill indigo">{{ DMARC_STEPS[dmarcStage] }}</div>
        </div>

        <!-- Step tracker with human labels -->
        <StepTracker :steps="DMARC_STEPS" :current="dmarcStage" />

        <!-- Current stage outcome -->
        <div class="outcome-row">
          <div class="outcome-dot" :class="dmarcStage >= 3 ? 'good' : dmarcStage >= 2 ? 'warn' : 'bad'" />
          <span class="outcome-text">{{ DMARC_OUTCOMES[dmarcStage] }}</span>
        </div>

        <!-- Compliance pulse (when monitoring) -->
        <div v-if="dmarcStage >= 1 && dmarcComp !== null" class="stat-row">
          <div class="stat">
            <div class="stat-val" :class="dmarcComp >= 98 ? 'good' : dmarcComp >= 90 ? 'warn' : 'bad'">
              {{ dmarcComp }}%
            </div>
            <div class="stat-lbl">of mail authenticates</div>
          </div>
          <div class="stat" v-if="dmarcFailSources > 0">
            <div class="stat-val bad">{{ dmarcFailSources }}</div>
            <div class="stat-lbl">unaligned sender{{ dmarcFailSources > 1 ? 's' : '' }}</div>
            <NextStep to="dmarc" label="See which" :domain="domain" />
          </div>
          <div class="stat" v-else>
            <div class="stat-val good">All clear</div>
            <div class="stat-lbl">senders aligned</div>
          </div>
        </div>

        <!-- Blockers -->
        <div v-for="b in dmarcBlockers()" :key="b.text" :class="['blocker', b.severity]">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="blocker-icon">
            <path v-if="b.severity === 'block'" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path v-else d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line v-if="b.severity==='warn'" x1="12" y1="9" x2="12" y2="13"/><line v-if="b.severity==='warn'" x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          {{ b.text }}
          <NextStep v-if="b.link" class="blocker-link" :to="b.link.to" :label="b.link.label" :domain="domain" />
        </div>

        <!-- Next step guidance -->
        <div class="next-box indigo-box">
          <div class="next-label">Next step</div>
          <div class="next-text">{{ dmarcNextStep() }}</div>
          <div v-if="dmarcStage < 3 && DMARC_EFFORT[dmarcStage + 1]" class="effort-tag">
            ⏱ {{ DMARC_EFFORT[dmarcStage + 1] }}
          </div>
        </div>

        <!-- Dry-run preview result — "will this break my email?" answered with data,
             not a promise, before the user touches DNS. -->
        <div v-if="simulationLoading" class="sim-panel sim-loading">Simulating impact against your collected traffic…</div>
        <div v-else-if="simulation && simulation.total_volume === 0" class="sim-panel sim-nodata">
          <div class="sim-head">
            <span class="sim-icon">⚠</span>
            <span>No report data yet — cannot assess impact</span>
          </div>
          <div class="sim-detail sim-warn-txt">
            No DMARC aggregate reports have arrived for this domain yet. Wait until real senders
            appear in your traffic data before advancing policy — otherwise you risk blocking
            legitimate mail you haven't identified yet.
          </div>
        </div>
        <div v-else-if="simulation" :class="['sim-panel', simulation.safe ? 'sim-safe' : 'sim-risk']">
          <div class="sim-head">
            <span class="sim-icon">{{ simulation.safe ? '✓' : '⚠' }}</span>
            <span>
              Preview: moving to p={{ simulation.target_stage }} would act on
              {{ simulation.affected_pct }}% of your traffic ({{ simulation.affected_volume.toLocaleString() }}
              of {{ simulation.total_volume.toLocaleString() }} messages)
            </span>
          </div>
          <div v-if="simulation.safe" class="sim-detail sim-good">
            0 authorized senders would be affected — safe to advance based on the last 30 days of data.
          </div>
          <div v-else class="sim-detail sim-bad">
            {{ simulation.authorized_sources_affected.length }} authorized sender{{ simulation.authorized_sources_affected.length > 1 ? 's' : '' }} would be blocked:
            {{ simulation.authorized_sources_affected.map(s => `${s.source_org} (${s.affected_count.toLocaleString()})`).join(', ') }}
            — fix alignment for these before advancing.
          </div>
        </div>

        <!-- CTA -->
        <div v-if="dmarcStage < 3" class="cta-row">
          <button
            v-if="(dmarcStage === 1 || dmarcStage === 2) && !simulation"
            class="btn-ghost"
            :disabled="simulationLoading"
            @click="onPreviewDmarc?.()"
          >
            Preview impact before advancing
          </button>
          <button
            class="btn-primary"
            :disabled="!canAdvanceDmarc(dmarcStage)"
            :title="!canAdvanceDmarc(dmarcStage) ? 'Resolve blocking issues above first' : ''"
            @click="onReviewDmarc?.()"
          >
            Review record → {{ DMARC_STEPS[dmarcStage + 1] }}
          </button>
          <span v-if="!canAdvanceDmarc(dmarcStage)" class="cta-blocked">Fix issues above first</span>
        </div>
        <div v-else class="done-row">
          <svg viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5">
            <path d="M20 6L9 17l-5-5"/>
          </svg>
          Fully protected — BIMI is next
        </div>
      </div>

      <!-- ── MTA-STS track ───────────────────────────────────── -->
      <div class="card tls-card">
        <div class="track-header">
          <div class="track-label">
            <svg viewBox="0 0 24 24" fill="none" stroke="#2ee6c5" stroke-width="2">
              <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            <div>
              <div class="track-title">Inbound delivery</div>
              <div class="track-sub">How mail reaches your server</div>
            </div>
          </div>
          <div class="stage-pill" :class="mtaStage >= 2 ? 'teal' : 'faint'">{{ MTA_STEPS[mtaStage] }}</div>
        </div>

        <StepTracker :steps="MTA_STEPS" :current="mtaStage" />

        <!-- Current stage outcome -->
        <div class="outcome-row">
          <div class="outcome-dot" :class="mtaStage >= 2 ? 'good' : mtaStage === 1 ? 'warn' : 'bad'" />
          <span class="outcome-text">{{ MTA_OUTCOMES[mtaStage] }}</span>
        </div>

        <!-- TLS stats (when monitoring) -->
        <div v-if="mtaStage >= 1 && tlsPassPct !== null" class="stat-row">
          <div class="stat">
            <div class="stat-val" :class="tlsPassPct >= 99 ? 'good' : tlsPassPct >= 90 ? 'warn' : 'bad'">
              {{ tlsPassPct }}%
            </div>
            <div class="stat-lbl">sessions encrypted</div>
          </div>
          <div class="stat" v-if="tlsFailReason">
            <div class="stat-val bad">Issue</div>
            <div class="stat-lbl">{{ tlsFailReason.replace(/-/g, ' ') }}</div>
          </div>
          <div class="stat" v-else>
            <div class="stat-val good">No issues</div>
            <div class="stat-lbl">TLS failure reasons</div>
          </div>
        </div>

        <!-- Blockers -->
        <div v-for="b in mtaBlockers()" :key="b.text" :class="['blocker', b.severity]">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="blocker-icon">
            <path v-if="b.severity === 'block'" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path v-else d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line v-if="b.severity==='warn'" x1="12" y1="9" x2="12" y2="13"/><line v-if="b.severity==='warn'" x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          {{ b.text }}
          <NextStep v-if="b.link" class="blocker-link" :to="b.link.to" :label="b.link.label" :domain="domain" />
        </div>

        <!-- Next step guidance -->
        <div class="next-box teal-box">
          <div class="next-label">Next step</div>
          <div class="next-text">{{ mtaNextStep() }}</div>
          <div v-if="mtaStage < 2 && MTA_EFFORT[mtaStage + 1]" class="effort-tag">
            ⏱ {{ MTA_EFFORT[mtaStage + 1] }}
          </div>
        </div>

        <!-- CTA -->
        <div v-if="mtaStage < 2" class="cta-row">
          <button
            class="btn-primary teal"
            :disabled="!canAdvanceMta(mtaStage)"
            :title="!canAdvanceMta(mtaStage) ? 'Resolve blocking issues above first' : ''"
            @click="onReviewMta?.()"
          >
            {{ mtaStage === 0 ? 'Publish MTA-STS policy' : 'Review record → Enforce' }}
          </button>
          <span v-if="!canAdvanceMta(mtaStage)" class="cta-blocked">Fix issues above first</span>
        </div>
        <div v-else class="done-row">
          <svg viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2.5">
            <path d="M20 6L9 17l-5-5"/>
          </svg>
          Enforced — maintain your MX certificate
        </div>
      </div>

    </div>

    <!-- BIMI milestone — integrated as a continuation card -->
    <div v-if="dmarcStage >= 3" class="card bimi-card">
      <div class="bimi-inner">
        <div class="bimi-orb">★</div>
        <div>
          <div class="bimi-title">BIMI — Brand Indicators for Message Identification</div>
          <div class="bimi-body">
            You've reached <b>p=reject</b> — all unauthorised email is blocked. BIMI is the final milestone: publish a BIMI DNS record pointing to a verified SVG logo, and your brand mark will appear in Gmail, Apple Mail, Yahoo, and other supporting clients.
          </div>
          <div class="bimi-steps">
            <div class="bimi-step">
              <span class="bimi-num">1</span>
              <span>Obtain a Verified Mark Certificate (VMC) from DigiCert or Entrust</span>
            </div>
            <div class="bimi-step">
              <span class="bimi-num">2</span>
              <span>Create a square SVG logo in the BIMI SVG profile</span>
            </div>
            <div class="bimi-step">
              <span class="bimi-num">3</span>
              <span>Publish <code>default._bimi.{{ domain }}</code> TXT record</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* ── Advisor row ────────────────────────────────────────────── */
.advisor-row {
  display: flex; gap: 14px; align-items: flex-start;
  background: linear-gradient(160deg, rgba(91,92,240,.09), rgba(255,255,255,.012));
  border: 1px solid var(--line2); border-radius: 16px; padding: 15px 18px;
  margin-bottom: 16px; backdrop-filter: blur(12px);
}
.advisor-row.commend {
  background: linear-gradient(160deg, rgba(52,224,161,.08), rgba(255,255,255,.012));
  border-color: rgba(52,224,161,.3);
}
.adv-orb {
  width: 28px; height: 28px; border-radius: 50%; flex: none; margin-top: 2px;
  background: radial-gradient(circle at 30% 30%, #6ff7e0, #5b5cf0);
  box-shadow: 0 0 16px rgba(46,230,197,.45);
  animation: pulse 2.6s ease-in-out infinite;
}
.adv-who { font-family: var(--mono); font-size: 9px; letter-spacing: 1px; text-transform: uppercase; color: var(--teal); margin-bottom: 5px; }
.adv-msg { font-size: 13px; line-height: 1.65; color: #dbe0f2; }
.adv-msg :deep(b) { color: var(--teal); }
.adv-skel { height: 16px; width: 75%; border-radius: 6px; background: rgba(255,255,255,.07); }
.adv-foot { font-family: var(--mono); font-size: 9px; color: var(--faint); margin-top: 10px; display: flex; gap: 10px; }
.adv-re { color: var(--teal); cursor: pointer; }
.adv-re:hover { text-decoration: underline; }
.adv-model { opacity: .55; }
@keyframes pulse { 50% { box-shadow: 0 0 26px rgba(91,92,240,.75); } }

/* ── Recommendation engine panel ───────────────────────────────── */
.rec-panel {
  display: flex; flex-direction: column; gap: 8px; margin-bottom: 16px;
  background: var(--glass); border: 1px solid var(--line); border-radius: 16px; padding: 14px 16px;
}
.rec-panel-head { font-family: var(--mono); font-size: 9px; letter-spacing: 1.2px; text-transform: uppercase; color: var(--faint); }
.rec-item { display: flex; gap: 11px; align-items: flex-start; padding: 9px 10px; border-radius: 11px; }
.rec-item.advance    { background: rgba(46,230,197,.06); border: 1px solid rgba(46,230,197,.2); }
.rec-item.hold       { background: rgba(255,255,255,.025); border: 1px solid var(--line); }
.rec-item.regression { background: rgba(255,77,109,.07); border: 1px solid rgba(255,77,109,.22); }
.rec-dir-tag {
  font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: .4px; text-transform: uppercase;
  padding: 3px 9px; border-radius: 8px; flex: none; margin-top: 1px;
}
.rec-dir-tag.advance    { background: rgba(46,230,197,.16); color: var(--teal); }
.rec-dir-tag.hold       { background: rgba(255,255,255,.08); color: var(--faint); }
.rec-dir-tag.regression { background: rgba(255,77,109,.18); color: var(--bad); }
.rec-body { flex: 1; min-width: 0; }
.rec-title { font-size: 12.5px; font-weight: 600; color: var(--txt); margin-bottom: 2px; }
.rec-text { font-size: 12px; color: var(--muted); line-height: 1.55; }
.rec-blocking { font-size: 11.5px; color: var(--amber); margin-top: 4px; line-height: 1.5; }

/* ── Grid ───────────────────────────────────────────────────── */
.r2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
@media (max-width: 860px) { .r2 { grid-template-columns: 1fr; } }

/* ── Cards ──────────────────────────────────────────────────── */
.card {
  background: var(--glass); border: 1px solid var(--line); border-radius: 18px;
  padding: 20px; backdrop-filter: blur(12px);
  box-shadow: 0 12px 40px rgba(0,0,0,.28), inset 0 1px 0 rgba(255,255,255,.05);
  display: flex; flex-direction: column; gap: 14px;
}
.dmarc-card { border-top: 2px solid rgba(91,92,240,.4); }
.tls-card   { border-top: 2px solid rgba(46,230,197,.35); }

/* ── Track header ───────────────────────────────────────────── */
.track-header { display: flex; align-items: center; justify-content: space-between; }
.track-label { display: flex; align-items: center; gap: 11px; }
.track-label svg { width: 18px; height: 18px; flex: none; }
.track-title { font-family: var(--disp); font-weight: 700; font-size: 14px; }
.track-sub { font-family: var(--mono); font-size: 9.5px; color: var(--faint); margin-top: 1px; }

.stage-pill {
  font-family: var(--mono); font-size: 9px; font-weight: 700; letter-spacing: .5px;
  padding: 4px 11px; border-radius: 20px;
}
.stage-pill.indigo { background: rgba(91,92,240,.15); color: #9aa6ff; }
.stage-pill.teal   { background: rgba(46,230,197,.15); color: var(--teal); }
.stage-pill.faint  { background: rgba(255,255,255,.06); color: var(--muted); }

/* ── Outcome row ────────────────────────────────────────────── */
.outcome-row { display: flex; align-items: center; gap: 9px; }
.outcome-dot { width: 8px; height: 8px; border-radius: 50%; flex: none; }
.outcome-dot.good { background: var(--good); box-shadow: 0 0 8px rgba(52,224,161,.6); }
.outcome-dot.warn { background: var(--amber); box-shadow: 0 0 8px rgba(245,197,66,.5); }
.outcome-dot.bad  { background: var(--bad); box-shadow: 0 0 8px rgba(255,77,109,.4); }
.outcome-text { font-size: 12.5px; color: var(--muted); line-height: 1.4; }

/* ── Stat row ───────────────────────────────────────────────── */
.stat-row { display: flex; gap: 20px; padding: 12px 14px; background: rgba(255,255,255,.03); border-radius: 12px; border: 1px solid var(--line); }
.stat { display: flex; flex-direction: column; gap: 2px; }
.stat-val { font-family: var(--disp); font-weight: 800; font-size: 20px; line-height: 1; }
.stat-val.good { color: var(--good); }
.stat-val.warn { color: var(--amber); }
.stat-val.bad  { color: var(--bad); }
.stat-lbl { font-family: var(--mono); font-size: 9.5px; color: var(--faint); }

/* ── Blockers ───────────────────────────────────────────────── */
.blocker {
  display: flex; align-items: flex-start; gap: 9px;
  padding: 10px 13px; border-radius: 11px; font-size: 12px; line-height: 1.5;
}
.blocker.block { background: rgba(255,77,109,.08); border: 1px solid rgba(255,77,109,.25); color: #ffb3c1; }
.blocker.warn  { background: rgba(245,197,66,.08); border: 1px solid rgba(245,197,66,.25); color: #f5e49a; }
.blocker-icon  { width: 15px; height: 15px; flex: none; margin-top: 1px; }
.blocker.block .blocker-icon { color: var(--bad); }
.blocker.warn  .blocker-icon { color: var(--amber); }

/* ── Next step box ──────────────────────────────────────────── */
.next-box { padding: 13px 15px; border-radius: 13px; display: flex; flex-direction: column; gap: 6px; }
.indigo-box { background: rgba(91,92,240,.08); border: 1px solid rgba(91,92,240,.22); }
.teal-box   { background: rgba(46,230,197,.06); border: 1px solid rgba(46,230,197,.2); }
.next-label { font-family: var(--mono); font-size: 9px; letter-spacing: .8px; text-transform: uppercase; color: var(--faint); }
.next-text  { font-size: 12.5px; line-height: 1.6; color: var(--muted); }
.effort-tag { font-family: var(--mono); font-size: 10px; color: var(--faint); }

/* ── Dry-run simulation panel ──────────────────────────────────── */
.sim-panel { padding: 13px 15px; border-radius: 13px; font-size: 12.5px; line-height: 1.55; }
.sim-loading { background: rgba(255,255,255,.03); border: 1px solid var(--line); color: var(--muted); font-family: var(--mono); font-size: 11.5px; }
.sim-safe { background: rgba(52,224,161,.07); border: 1px solid rgba(52,224,161,.22); }
.sim-risk { background: rgba(245,197,66,.07); border: 1px solid rgba(245,197,66,.25); }
.sim-nodata { background: rgba(245,197,66,.07); border: 1px solid rgba(245,197,66,.25); }
.sim-warn-txt { color: #f5e49a; }
.sim-head { display: flex; gap: 9px; align-items: flex-start; color: var(--txt); font-weight: 600; }
.sim-icon { flex: none; }
.sim-detail { margin-top: 7px; padding-left: 23px; }
.sim-good { color: var(--good); }
.sim-bad { color: #f5e49a; }

/* ── CTA ────────────────────────────────────────────────────── */
.blocker-link { margin-left: auto; padding-left: 12px; }
.cta-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.btn-primary {
  background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff; border: none;
  border-radius: 12px; padding: 10px 18px; font-family: var(--disp); font-weight: 700;
  font-size: 12.5px; cursor: pointer; transition: opacity .15s;
}
.btn-primary.teal { background: linear-gradient(90deg, #2ee6c5, #5b5cf0); color: #04201b; }
.btn-primary:disabled { opacity: .4; cursor: not-allowed; }
.btn-ghost {
  background: transparent; color: var(--muted); border: 1px solid var(--line2);
  border-radius: 12px; padding: 10px 16px; font-family: var(--disp); font-weight: 600;
  font-size: 12.5px; cursor: pointer; transition: border-color .15s, color .15s;
}
.btn-ghost:hover:not(:disabled) { border-color: #9aa6ff; color: var(--txt); }
.btn-ghost:disabled { opacity: .5; cursor: not-allowed; }
.cta-blocked { font-family: var(--mono); font-size: 10px; color: var(--bad); }

.done-row {
  display: flex; align-items: center; gap: 8px; padding: 9px 12px; border-radius: 11px;
  background: rgba(52,224,161,.07); border: 1px solid rgba(52,224,161,.2);
  font-family: var(--mono); font-size: 11.5px; color: var(--good);
}
.done-row svg { width: 15px; height: 15px; flex: none; }

/* ── BIMI card ──────────────────────────────────────────────── */
.bimi-card { border-color: rgba(91,92,240,.35); border-top: 2px solid #f5c542; }
.bimi-inner { display: flex; gap: 16px; align-items: flex-start; }
.bimi-orb {
  width: 46px; height: 46px; border-radius: 50%; flex: none;
  background: linear-gradient(135deg, #5b5cf0, #2ee6c5);
  display: grid; place-items: center; font-size: 21px;
  box-shadow: 0 0 22px rgba(91,92,240,.45);
}
.bimi-title { font-family: var(--disp); font-weight: 800; font-size: 14.5px; margin-bottom: 7px; }
.bimi-body  { font-size: 12.5px; color: var(--muted); line-height: 1.6; margin-bottom: 14px; }
.bimi-body b { color: var(--txt); }
.bimi-steps { display: flex; flex-direction: column; gap: 8px; }
.bimi-step  { display: flex; align-items: flex-start; gap: 10px; font-size: 12px; color: var(--muted); }
.bimi-num   {
  width: 20px; height: 20px; border-radius: 50%; flex: none;
  background: rgba(245,197,66,.15); border: 1px solid rgba(245,197,66,.3);
  display: grid; place-items: center; font-family: var(--mono); font-size: 9px;
  font-weight: 700; color: #f5c542;
}
code { font-family: var(--mono); font-size: 10.5px; color: #9aa6ff; background: rgba(91,92,240,.1); padding: 1px 5px; border-radius: 4px; }
</style>
