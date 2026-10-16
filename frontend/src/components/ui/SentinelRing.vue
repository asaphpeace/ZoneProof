<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  score: number
  grade: string
  gradeColor: string
  gradeLabel: string
  pillarDmarc: number
  pillarTls: number
  pillarCerts: number
  delta?: number | null
  volumeWeighted?: boolean
}>()

// Arc ring geometry
const R = 54
const CIRCUMFERENCE = 2 * Math.PI * R
const arc = computed(() => CIRCUMFERENCE * (props.score / 100))
const gap = computed(() => CIRCUMFERENCE - arc.value)

// Pillar bar widths (max: dmarc=60, tls=25, certs=15)
const dmarcPct  = computed(() => Math.min(100, (props.pillarDmarc  / 60)  * 100))
const tlsPct    = computed(() => Math.min(100, (props.pillarTls    / 25)  * 100))
const certsPct  = computed(() => Math.min(100, (props.pillarCerts  / 15)  * 100))

const deltaSign = computed(() => props.delta == null ? null : props.delta >= 0 ? '+' : '')
const deltaColor = computed(() => props.delta == null ? 'var(--faint)' : props.delta > 0 ? 'var(--good)' : props.delta < 0 ? 'var(--bad)' : 'var(--muted)')

// Score anchoring (GUIDED_ONBOARDING_PLAN.md Part 3 #8) — deliberately NOT a
// fabricated "most businesses your size score X" claim, since ZoneProof has
// no real peer/benchmark dataset to back that. Instead: an honest, derived
// answer to "what's pulling this down" — whichever pillar has the largest
// gap between its current points and its max, computed from the same
// numbers already shown in the breakdown below.
const PILLAR_MAX = { dmarc: 60, tls: 25, certs: 15 } as const
const biggestOpportunity = computed(() => {
  const gaps = [
    { key: 'DMARC enforcement', gap: PILLAR_MAX.dmarc - props.pillarDmarc },
    { key: 'MTA-STS / TLS', gap: PILLAR_MAX.tls - props.pillarTls },
    { key: 'Certificate health', gap: PILLAR_MAX.certs - props.pillarCerts },
  ]
  const top = gaps.reduce((a, b) => (b.gap > a.gap ? b : a))
  return top.gap >= 1 ? top : null
})
</script>

<template>
  <div class="sentinel-wrap">

    <!-- Left: ring -->
    <div class="ring-side">
      <svg class="ring-svg" viewBox="0 0 128 128">
        <!-- track -->
        <circle cx="64" cy="64" :r="R" fill="none" stroke="rgba(255,255,255,.07)" stroke-width="10" />
        <!-- filled arc -->
        <circle
          cx="64" cy="64" :r="R" fill="none"
          :stroke="gradeColor"
          stroke-width="10"
          stroke-linecap="round"
          :stroke-dasharray="`${arc} ${gap}`"
          transform="rotate(-90 64 64)"
          style="transition: stroke-dasharray .8s ease, stroke .5s ease"
        />
        <!-- score -->
        <text x="64" y="59" text-anchor="middle" class="ring-score" :fill="gradeColor">{{ score }}</text>
        <text x="64" y="76" text-anchor="middle" class="ring-grade" fill="rgba(255,255,255,.45)">{{ grade }}</text>
      </svg>

      <div class="ring-label" :style="`color:${gradeColor}`">{{ gradeLabel }}</div>

      <div v-if="delta != null" class="ring-delta" :style="`color:${deltaColor}`">
        {{ deltaSign }}{{ delta }} pts vs last week
      </div>
      <div v-else class="ring-delta" style="color:var(--faint)">
        First measurement
      </div>
      <div v-if="biggestOpportunity" class="ring-anchor">
        {{ biggestOpportunity.gap.toFixed(0) }} pts available in {{ biggestOpportunity.key }}
      </div>
    </div>

    <!-- Right: pillar breakdown -->
    <div class="pillars">
      <div class="pillar-title">Score breakdown</div>

      <div class="pillar-row">
        <span class="pillar-label">DMARC enforcement</span>
        <div class="pillar-track">
          <div class="pillar-fill dmarc" :style="`width:${dmarcPct}%`" />
        </div>
        <span class="pillar-pts">{{ pillarDmarc.toFixed(1) }}<span class="pillar-max">/60</span></span>
      </div>

      <div class="pillar-row">
        <span class="pillar-label">MTA-STS / TLS</span>
        <div class="pillar-track">
          <div class="pillar-fill tls" :style="`width:${tlsPct}%`" />
        </div>
        <span class="pillar-pts">{{ pillarTls.toFixed(1) }}<span class="pillar-max">/25</span></span>
      </div>

      <div class="pillar-row">
        <span class="pillar-label">Certificate health</span>
        <div class="pillar-track">
          <div class="pillar-fill certs" :style="`width:${certsPct}%`" />
        </div>
        <span class="pillar-pts">{{ pillarCerts.toFixed(1) }}<span class="pillar-max">/15</span></span>
      </div>

      <div class="pillar-footnote">
        {{ volumeWeighted ? 'Weighted by mail volume' : 'Equal weight per domain' }}
        · 100 pts max
      </div>
    </div>

  </div>
</template>

<style scoped>
.sentinel-wrap {
  display: flex; align-items: center; gap: 32px; flex-wrap: wrap;
}

/* ── Ring ─────────────────────────────────────────────────── */
.ring-side { display: flex; flex-direction: column; align-items: center; gap: 6px; flex: none; }
.ring-svg  { width: 128px; height: 128px; }

.ring-score {
  font-family: var(--disp); font-weight: 900; font-size: 28px;
  letter-spacing: -1px;
}
.ring-grade {
  font-family: var(--disp); font-weight: 700; font-size: 13px;
}

.ring-label {
  font-family: var(--disp); font-weight: 700; font-size: 13px;
  text-align: center; letter-spacing: -.2px;
}
.ring-delta {
  font-family: var(--mono); font-size: 10px; text-align: center;
}
.ring-anchor {
  font-family: var(--mono); font-size: 9.5px; text-align: center; color: #9aa6ff;
  margin-top: 2px; max-width: 140px; line-height: 1.4;
}

/* ── Pillars ──────────────────────────────────────────────── */
.pillars { flex: 1; min-width: 200px; }

.pillar-title {
  font-family: var(--mono); font-size: 9px; letter-spacing: 1px;
  text-transform: uppercase; color: var(--faint); margin-bottom: 14px;
}

.pillar-row {
  display: grid; grid-template-columns: 130px 1fr 52px;
  align-items: center; gap: 10px; margin-bottom: 11px;
}

.pillar-label {
  font-family: var(--mono); font-size: 11px; color: var(--muted);
  white-space: nowrap;
}

.pillar-track {
  height: 6px; background: rgba(255,255,255,.07); border-radius: 4px; overflow: hidden;
}
.pillar-fill {
  height: 100%; border-radius: 4px; transition: width .7s ease;
}
.pillar-fill.dmarc { background: linear-gradient(90deg, #5b5cf0, #4b4ce0); }
.pillar-fill.tls   { background: linear-gradient(90deg, #2ee6c5, #34e0a1); }
.pillar-fill.certs { background: linear-gradient(90deg, #f5c542, #ff8c42); }

.pillar-pts {
  font-family: var(--disp); font-weight: 700; font-size: 13px;
  color: var(--txt); text-align: right;
}
.pillar-max {
  font-size: 10px; color: var(--faint); font-weight: 400;
}

.pillar-footnote {
  font-family: var(--mono); font-size: 9px; color: var(--faint);
  margin-top: 6px;
}
</style>
