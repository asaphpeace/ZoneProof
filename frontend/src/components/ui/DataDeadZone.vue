<script setup lang="ts">
import { computed } from 'vue'

// Part 3 #2 (GUIDED_ONBOARDING_PLAN.md) — the gap between "record published"
// and "first report arrives" (24-48h+, sometimes longer for low-volume
// domains) used to render as a flat "No report data yet", indistinguishable
// from something being broken. This makes the wait itself a known, named
// state instead of an empty one.
const props = defineProps<{
  recordLabel: string          // "DMARC" | "MTA-STS" / TLS-RPT"
  recordPublished: boolean
  publishedSince: string | null   // ISO timestamp — domain.added_at, used as
                                    // the best available proxy for when the
                                    // record went live
  onGoToRoadmap?: () => void
}>()

const hoursElapsed = computed(() => {
  if (!props.publishedSince) return null
  const ms = Date.now() - new Date(props.publishedSince).getTime()
  return Math.max(0, Math.floor(ms / 3_600_000))
})

const daysElapsed = computed(() => hoursElapsed.value === null ? null : Math.floor(hoursElapsed.value / 24))

// Within the normal arrival window — reassure, don't alarm.
const isNormalWait = computed(() => hoursElapsed.value !== null && hoursElapsed.value < 48)
// Past a week with nothing — the normal window has long since passed; this
// deserves a different, more actionable message, not the same reassurance.
const isOverdue = computed(() => daysElapsed.value !== null && daysElapsed.value >= 7)
</script>

<template>
  <div class="dz">
    <!-- Case 1: nothing published yet — different problem, different message -->
    <template v-if="!recordPublished">
      <div class="dz-icon dz-icon-muted">○</div>
      <div class="dz-title">No {{ recordLabel }} record published yet</div>
      <div class="dz-body">
        Publish a {{ recordLabel }} record to start receiving reports — nothing is being
        monitored for this domain until that's done.
      </div>
      <button v-if="onGoToRoadmap" class="dz-cta" @click="onGoToRoadmap">Go to Roadmap →</button>
    </template>

    <!-- Case 2: published, within the normal 24-48h+ arrival window -->
    <template v-else-if="isNormalWait">
      <div class="dz-icon dz-icon-pulse">◌</div>
      <div class="dz-title">We're listening now</div>
      <div class="dz-body">
        Your {{ recordLabel }} record is live. Reports typically start arriving within
        24–48 hours — sometimes longer for low-volume domains, since reports only
        cover periods when mail was actually sent.
        <span v-if="hoursElapsed !== null" class="dz-elapsed">{{ hoursElapsed }}h since setup.</span>
      </div>
    </template>

    <!-- Case 3: published, well past the normal window — different message, not the same reassurance -->
    <template v-else-if="isOverdue">
      <div class="dz-icon dz-icon-warn">!</div>
      <div class="dz-title">Still no reports after {{ daysElapsed }} days</div>
      <div class="dz-body">
        This is longer than the normal arrival window. Check that your reporting
        address is correctly configured in the published record, and that mail is
        actually flowing for this domain — a domain with very low send volume may
        simply have nothing to report yet.
      </div>
    </template>

    <!-- Case 4: published, past 48h but under a week — quieter, no urgency -->
    <template v-else>
      <div class="dz-icon dz-icon-pulse">◌</div>
      <div class="dz-title">Still waiting on the first report</div>
      <div class="dz-body">
        Past the typical 48-hour window, but this is still within normal range for
        domains with lighter mail volume.
        <span v-if="daysElapsed !== null" class="dz-elapsed">{{ daysElapsed }}d since setup.</span>
      </div>
    </template>
  </div>
</template>

<style scoped>
.dz {
  display: flex; flex-direction: column; align-items: center; text-align: center;
  gap: 8px; padding: 32px 24px;
}
.dz-icon {
  width: 34px; height: 34px; border-radius: 50%; display: grid; place-items: center;
  font-size: 16px; font-weight: 700; margin-bottom: 4px;
}
.dz-icon-muted { background: rgba(255,255,255,.06); color: var(--faint); }
.dz-icon-pulse { background: rgba(91,92,240,.12); color: #9aa6ff; animation: dz-pulse 2.2s ease-in-out infinite; }
.dz-icon-warn  { background: rgba(245,197,66,.14); color: var(--amber); }
@keyframes dz-pulse { 50% { opacity: .45; } }
.dz-title { font-family: var(--disp); font-weight: 700; font-size: 14.5px; color: var(--txt); }
.dz-body { font-size: 12.5px; color: var(--muted); line-height: 1.6; max-width: 420px; }
.dz-elapsed { display: block; margin-top: 6px; font-family: var(--mono); font-size: 10.5px; color: var(--faint); }
.dz-cta {
  margin-top: 10px; background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff; border: none;
  border-radius: 10px; padding: 8px 16px; font-family: var(--disp); font-weight: 700;
  font-size: 12px; cursor: pointer;
}
</style>
