<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useBrandGuardStore } from '@/stores/brandGuard'
import BrandFrame from '@/components/brand/BrandFrame.vue'
import BrandHeader from '@/components/brand/BrandHeader.vue'
import SourceStrip from '@/components/brand/SourceStrip.vue'
import VerdictPill from '@/components/brand/VerdictPill.vue'
import LifecycleDots from '@/components/brand/LifecycleDots.vue'
import CandidateDrawer from '@/components/brand/CandidateDrawer.vue'
import { useCandidateDrawer } from '@/components/brand/useCandidateDrawer'
import { BADGE_HELP, FOUND_VIA, humanHours, timeAgo, typeChip } from '@/components/brand/brandLabels'

// Home answers one question: what needs me right now. The queue comes first; the numbers and coverage sit beside and
// below it. Everything shown is something Brand Guard actually does today.
const store = useBrandGuardStore()
const SHOWN = 8
const queue = computed(() => store.candidates.slice(0, SHOWN))
const remaining = computed(() => Math.max(0, store.candidates.length - queue.value.length))
const dormant = computed(() => store.summary?.dormant ?? 0)
const drawer = useCandidateDrawer(computed(() => store.candidates))
const profile = computed(() => store.profile)

onMounted(async () => {
  await store.ensureLoaded()
  if (store.profile && store.candidatesFilter !== 'open') await store.loadCandidates('open')
})

const kpis = computed(() => {
  const s = store.summary
  if (!s) return []
  const detect = s.median_detect_hours
  return [
    { label: 'Needs attention', value: s.open_candidates, sub: s.new_24h ? `${s.new_24h} new in the last 24 h` : 'none new in 24 h', dot: 'var(--indigo)' },
    { label: 'Went live · 7 days', value: s.went_live_7d, sub: 'look-alikes we watched start resolving', dot: 'var(--bad)' },
    { label: 'In case', value: s.confirmed + s.takedown, sub: `${s.confirmed} confirmed · ${s.takedown} takedown requested`, dot: 'var(--warn)' },
    {
      label: 'Time to detect', value: humanHours(detect), dot: 'var(--good)',
      sub: detect === null ? 'Not enough new registrations yet' : `median, registration to first sighting (${s.median_detect_n} domain${s.median_detect_n === 1 ? '' : 's'})`,
    },
  ]
})

const coverage = computed(() => {
  const p = profile.value
  if (!p) return []
  return [
    { k: 'Name variations', v: 'Generated from your brand names and keywords, on every scan' },
    { k: 'Certificates', v: !p.ct_enabled ? 'Not on your plan (Pro)' : store.sources.some(s => s.source === 'ct_stream' && s.status !== 'down') ? 'Live: new certificates for look-alike names, within seconds' : 'New certificates for look-alike names, on every scan' },
    { k: 'New registrations', v: p.ct_enabled ? 'A daily sample of newly registered names' : 'Not on your plan (Pro)' },
    { k: 'Your own reports', v: 'Emails your team reports and your DMARC reports' },
  ]
})
</script>

<template>
  <BrandFrame>
    <template v-if="profile">
      <BrandHeader title="Brand Guard"
        :sub="`Look-alike domains impersonating ${profile.brand_name} (${profile.primary_domain}). Last scan ${timeAgo(profile.last_scanned_at)}.`">
        <template #actions>
          <RouterLink class="ghost" :to="{ name: 'brand-guard-profile' }">Brand profile</RouterLink>
        </template>
      </BrandHeader>

      <SourceStrip :sources="store.sources" class="strip" />
      <p v-for="w in profile.warnings || []" :key="w" class="note">{{ w }}</p>

      <div class="grid">
        <section class="card queue" aria-labelledby="att">
          <div class="qh">
            <div><h2 id="att">Needs your attention</h2><span class="hint">Most urgent first. Open one to see the evidence.</span></div>
            <RouterLink :to="{ name: 'brand-guard-candidates' }" class="more">All candidates →</RouterLink>
          </div>
          <div v-if="!queue.length" class="empty">Nothing needs you. No unreviewed look-alike has shown signs of life, which is good news.</div>
          <div v-for="c in queue" :key="c.id" class="qr">
            <div class="main">
              <div class="l1">
                <span class="dom">{{ c.candidate_domain_unicode }}</span>
                <VerdictPill :verdict="c.verdict" />
                <span class="conf" :title="c.confidence.reason">{{ c.confidence.label }} confidence</span>
              </div>
              <div class="why">{{ c.why }}</div>
              <div class="chips">
                <span v-if="typeChip(c.abuse_type)" class="chip" :class="typeChip(c.abuse_type)!.tone === 'red' ? 'blocklist' : ''" :title="(c.abuse_type.reasons || []).join(' ')">{{ typeChip(c.abuse_type)!.text }}</span>
                <span v-for="b in c.enrichment?.badges || []" :key="b.label" class="chip" :class="b.kind" :title="BADGE_HELP[b.kind]">{{ b.label }}</span>
                <span v-for="s in c.sources" :key="s" class="chip dim">{{ FOUND_VIA[s] ?? s }}</span>
              </div>
            </div>
            <div class="side">
              <div class="life"><LifecycleDots :stage="c.stage" :tone="c.verdict.tone" /><span class="age">first seen {{ timeAgo(c.first_seen_at) }}</span></div>
              <button type="button" class="review" @click="drawer.open(c.id)">Review</button>
            </div>
          </div>
          <div v-if="store.candidates.length" class="qf">
            <span v-if="remaining > 0">{{ remaining }} more need{{ remaining === 1 ? 's' : '' }} a look. <RouterLink :to="{ name: 'brand-guard-candidates' }" class="more">View all candidates →</RouterLink></span>
            <span v-else>That is everything that needs you.</span>
            <span v-if="dormant > 0" class="dorm">{{ dormant }} registered look-alike{{ dormant === 1 ? ' is' : 's are' }} dormant: no website or mail yet, re-checked on every scan.</span>
          </div>
        </section>

        <aside class="rail" aria-label="Coverage and campaigns">
          <section class="card" aria-labelledby="bg-camp">
            <div class="ch"><h2 id="bg-camp">Campaigns</h2><span class="hint">{{ store.campaigns.length }} found</span></div>
            <template v-if="store.campaigns.length">
              <RouterLink v-for="c in store.campaigns.slice(0, 2)" :key="c.id" :to="{ name: 'brand-guard-campaigns', query: { id: c.id } }" class="camp">
                <span class="cl"><b class="mono">{{ c.name }}</b><VerdictPill :verdict="c.verdict" /></span>
                <span class="cw">{{ c.why }}</span>
              </RouterLink>
              <RouterLink :to="{ name: 'brand-guard-campaigns' }" class="more">All campaigns →</RouterLink>
            </template>
            <p v-else class="hint">No look-alikes share an operator right now.</p>
          </section>
          <section class="card">
            <h2>What we watch</h2>
            <ul class="cov">
              <li v-for="c in coverage" :key="c.k"><b>{{ c.k }}</b><span>{{ c.v }}</span></li>
            </ul>
            <RouterLink :to="{ name: 'brand-guard-profile' }" class="more">See what we do not watch →</RouterLink>
          </section>
        </aside>
      </div>

      <div v-if="kpis.length" class="kpis">
        <div v-for="k in kpis" :key="k.label" class="kpi">
          <div class="kt"><span class="kl">{{ k.label }}</span><i :style="{ background: k.dot }" /></div>
          <div class="kv">{{ k.value }}</div>
          <div class="ks">{{ k.sub }}</div>
        </div>
      </div>

      <CandidateDrawer v-if="drawer.openId.value" :candidate-id="drawer.openId.value" :prev-id="drawer.prevId.value" :next-id="drawer.nextId.value"
        :position="drawer.position.value" @close="drawer.close" @go="drawer.go" @changed="store.refreshAfterChange" />
    </template>
  </BrandFrame>
</template>

<style scoped>
.ghost { display: inline-flex; align-items: center; min-height: 40px; padding: 0 16px; border-radius: 10px; border: 1px solid var(--line2); color: var(--txt); text-decoration: none; font: 600 13px var(--body); }
.ghost:hover { border-color: var(--indigo); }
.strip { margin-bottom: 16px; }
.note { margin: 0 0 12px; background: rgba(245,197,66,.08); border: 1px solid rgba(245,197,66,.25); color: var(--warn); border-radius: 10px; padding: 8px 12px; font-size: 12.5px; }
.grid { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); gap: 18px; align-items: start; margin-bottom: 18px; }
.card { background: var(--glass); border: 1px solid var(--line); border-radius: 16px; overflow: hidden; }
.rail .card { padding: 18px 20px; display: flex; flex-direction: column; gap: 12px; }
h2 { margin: 0; font-family: var(--disp); font-size: 16px; font-weight: 700; }
.qh { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; padding: 16px 20px; border-bottom: 1px solid var(--line); flex-wrap: wrap; }
.hint { display: block; margin-top: 3px; font-size: 12.5px; color: var(--muted); }
.more { font-size: 12.5px; font-weight: 600; color: var(--indigo); text-decoration: none; }
.empty { padding: 36px 20px; text-align: center; color: var(--muted); font-size: 13px; }
.qr { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 16px; align-items: center; padding: 14px 20px; border-bottom: 1px solid var(--line); }
.qr:hover { background: rgba(255,255,255,.025); }
.main { display: flex; flex-direction: column; gap: 7px; min-width: 0; }
.l1 { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.dom { font-family: var(--mono); font-size: 14.5px; font-weight: 600; word-break: break-all; }
.conf { font-size: 12px; color: var(--muted); cursor: help; }
.why { font-size: 13.5px; line-height: 1.5; color: #c9cee3; }
.chips { display: flex; gap: 6px; flex-wrap: wrap; }
.chip { font-family: var(--mono); font-size: 10.5px; padding: 2px 8px; border-radius: 10px; background: rgba(255,255,255,.06); color: var(--muted); }
.chip.blocklist, .chip.reported, .chip.spoofer { background: rgba(255,77,109,.16); color: #ff8da1; }
.chip.yours, .chip.popular, .chip.parked { background: rgba(52,224,161,.12); color: var(--good); }
.side { display: flex; align-items: center; gap: 16px; }
.life { display: flex; flex-direction: column; align-items: flex-end; gap: 4px; }
.age { font-family: var(--mono); font-size: 10.5px; color: var(--faint); }
.review { min-height: 36px; padding: 0 16px; border-radius: 10px; border: 1px solid var(--line2); background: transparent; color: var(--txt); font: 600 13px var(--body); cursor: pointer; }
.review:hover { border-color: var(--indigo); }
.qf { padding: 14px 20px; font-size: 12.5px; color: var(--muted); display: flex; flex-direction: column; gap: 4px; }
.ch { display: flex; justify-content: space-between; align-items: baseline; }
.camp { display: flex; flex-direction: column; gap: 6px; padding: 11px 12px; border-radius: 10px; background: rgba(255,255,255,.04); text-decoration: none; color: var(--txt); }
.camp:hover { background: rgba(255,255,255,.07); }
.cl { display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; }
.cl b { font-size: 12.5px; font-weight: 600; }
.cw { font-size: 12px; color: var(--muted); line-height: 1.45; }
.mono { font-family: var(--mono); }
.cov { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 12px; }
.cov li { display: flex; flex-direction: column; gap: 2px; font-size: 12.5px; color: var(--muted); }
.cov b { color: var(--txt); font-weight: 600; font-size: 13px; }
.kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
.kpi { background: var(--glass); border: 1px solid var(--line); border-radius: 14px; padding: 16px 18px; display: flex; flex-direction: column; gap: 6px; }
.kt { display: flex; justify-content: space-between; align-items: center; }
.kl { font-family: var(--mono); font-size: 10.5px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
.kt i { width: 8px; height: 8px; border-radius: 50%; }
.kv { font-family: var(--disp); font-weight: 800; font-size: 26px; letter-spacing: -.5px; }
.ks { font-size: 12.5px; color: var(--muted); line-height: 1.4; }
@media (max-width: 1000px) { .grid { grid-template-columns: 1fr; } .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 640px) { .qr { grid-template-columns: 1fr; } .side { justify-content: space-between; } .kpis { grid-template-columns: 1fr; } }
</style>
