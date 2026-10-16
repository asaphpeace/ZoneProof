<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '@/api/client'
import { useBrandGuardStore } from '@/stores/brandGuard'
import { useUiStore } from '@/stores/ui'
import BrandFrame from '@/components/brand/BrandFrame.vue'
import BrandHeader from '@/components/brand/BrandHeader.vue'
import VerdictPill from '@/components/brand/VerdictPill.vue'
import LifecycleDots from '@/components/brand/LifecycleDots.vue'
import ClusterGraph from '@/components/brand/ClusterGraph.vue'
import DecisionButtons from '@/components/brand/DecisionButtons.vue'
import CandidateDrawer from '@/components/brand/CandidateDrawer.vue'
import { useCandidateDrawer } from '@/components/brand/useCandidateDrawer'
import { TONE, fmtShort, timeAgo } from '@/components/brand/brandLabels'

// A campaign is a set of look-alikes that appear to share an operator. The list is on the left; the chosen one on the right.
// Acting on a campaign means deciding for all its members at once; one wrong member can be taken out, and stays out.
const store = useBrandGuardStore()
const ui = useUiStore()
const route = useRoute()
const router = useRouter()

const detail = ref<any>(null)
const loadingDetail = ref(false)
const members = computed(() => detail.value?.members ?? [])
const selectedId = computed(() => (typeof route.query.id === 'string' ? route.query.id : (store.campaigns[0]?.id ?? '')))
const drawer = useCandidateDrawer(members)

onMounted(async () => {
  await store.ensureLoaded()
  await store.loadCampaigns()
})

async function loadDetail() {
  if (!selectedId.value) { detail.value = null; return }
  loadingDetail.value = true
  try { detail.value = await api.brandCampaign(selectedId.value) }
  catch { detail.value = null }
  finally { loadingDetail.value = false }
}
watch(selectedId, loadDetail, { immediate: true })
watch(() => store.campaigns.length, loadDetail)

function pick(id: string) { router.push({ query: { id } }) }

async function afterDecision() {
  await store.loadCampaigns()
  await loadDetail()
}

async function removeMember(m: any) {
  try {
    await api.brandCampaignRemove(detail.value.id, m.id)
    ui.toast(`${m.candidate_domain_unicode} taken out of this campaign`)
    await afterDecision()
  } catch (e: any) { ui.toast(e.message || 'Could not remove it', 'error') }
}

// Known-bad members: a person confirmed them, or a public feed lists them. Everyone else in the group inherits some suspicion from them.
const seeds = computed<string[]>(() => members.value.filter((m: any) => ['confirmed', 'takedown'].includes(m.status) || m.abuse_type?.basis === 'reported').map((m: any) => m.candidate_domain))
const guiltOf = computed<Record<string, number>>(() => Object.fromEntries(members.value.filter((m: any) => m.enrichment?.guilt).map((m: any) => [m.candidate_domain, m.enrichment.guilt.score])))
const tone = (c: any) => TONE[c.verdict?.tone] ?? TONE.slate
const FACT_HELP: Record<string, string> = {
  registration_batch: 'Registered within 30 minutes of each other. Attackers register in batches, though owners defending a brand do too.',
  shared_certificate: 'One TLS certificate covers all of them, so one operator set them up.',
  shared_nameservers: 'The same nameservers. Shared DNS platforms (parking, Cloudflare) are not counted.',
  shared_server: 'The same server address. Known shared-hosting addresses are not counted.',
}
function factValue(f: any) {
  if (f.kind === 'registration_batch') return f.value ? `${fmtShort(f.value.from)} to ${fmtShort(f.value.to)}` : 'close together'
  if (Array.isArray(f.value)) return f.value.join(', ')
  return f.value ?? ''
}
function strength(f: any) { return f.count === f.of ? 'All ' + f.of : `${f.count} of ${f.of}` }
</script>

<template>
  <BrandFrame>
    <template v-if="store.profile">
      <BrandHeader title="Campaigns" crumb="Campaigns"
        sub="Look-alikes that share infrastructure, grouped so you can act on one attacker instead of one domain at a time." />

      <div v-if="!store.campaigns.length" class="empty">
        <b>No campaigns yet.</b>
        <p>A campaign appears when two or more look-alikes of your brand share something an attacker would reuse: the same nameservers, the same server, one certificate, or registration within minutes of each other. None do right now.</p>
      </div>

      <div v-else class="grid">
        <section aria-label="Campaign list" class="list">
          <button v-for="c in store.campaigns" :key="c.id" type="button" class="cc" :class="{ on: c.id === selectedId }" :aria-current="c.id === selectedId ? 'true' : undefined" @click="pick(c.id)">
            <span class="l1"><span class="nm">{{ c.name }}</span><VerdictPill :verdict="c.verdict" /></span>
            <span class="why">{{ c.why }}</span>
            <span class="meta"><span>{{ c.member_count }} domains</span><span>{{ c.live_count }} live</span><span>since {{ timeAgo(c.first_seen_at) }}</span></span>
          </button>
          <p class="rule">Looks like one operator when 3 or more different things match, possibly related when 2 match, and not enough evidence when only 1 does. A look-alike you mark as not a threat leaves its campaign.</p>
        </section>

        <section v-if="detail" class="card" aria-labelledby="cd">
          <header class="ch">
            <div class="row">
              <h2 id="cd" class="nm">{{ detail.name }}</h2>
              <VerdictPill :verdict="detail.verdict" size="md" />
            </div>
            <p class="sum">{{ detail.why }} {{ detail.live_count }} of {{ detail.member_count }} resolve{{ detail.live_count === 1 ? 's' : '' }} now.</p>
            <DecisionButtons :items="members" compact @decided="afterDecision" />
            <p class="note">One decision applies to every member shown below. Take a member out first if it does not belong.</p>
          </header>

          <div class="sec">
            <h3>Members</h3>
            <div v-for="m in members" :key="m.id" class="mr">
              <div class="mi">
                <button type="button" class="dom" @click="drawer.open(m.id)">{{ m.candidate_domain_unicode }}</button>
                <span class="mwhy">{{ m.why }}</span>
                <span v-if="seeds.includes(m.candidate_domain)" class="kb">Known bad</span>
                <span v-else-if="m.enrichment?.guilt" class="lk" :title="m.enrichment.guilt.path.map((p: any) => `${p.to} shares ${p.via_label} with ${p.from}`).join('; ')">Linked to {{ m.enrichment.guilt.seed }}: suspicion {{ Math.round(m.enrichment.guilt.score * 100) }}%</span>
              </div>
              <VerdictPill :verdict="m.verdict" />
              <LifecycleDots :stage="m.stage" :tone="m.verdict.tone" />
              <button type="button" class="out" :aria-label="`Take ${m.candidate_domain_unicode} out of this campaign`" title="Not part of this campaign" @click="removeMember(m)">Take out</button>
            </div>
          </div>

          <div v-if="detail.graph?.shared?.length" class="sec">
            <h3>What links them</h3>
            <ClusterGraph :graph="detail.graph" :seeds="seeds" :guilt="guiltOf" />
          </div>

          <div class="sec">
            <h3>Why they are grouped</h3>
            <div class="facts">
              <div v-for="(f, i) in detail.facts" :key="i" class="fact" :style="{ borderColor: f.count === f.of ? tone(detail).bd : undefined }">
                <div class="fh"><b>{{ f.label }}</b><span>{{ strength(f) }}</span></div>
                <div v-if="factValue(f)" class="mono fv">{{ factValue(f) }}</div>
                <p class="fhelp">{{ FACT_HELP[f.kind] }}</p>
              </div>
            </div>
          </div>

          <div class="sec">
            <h3>Watching</h3>
            <p class="plain">After every scan, new look-alikes that share these facts join this campaign automatically, and the campaign's verdict is recalculated.</p>
          </div>
        </section>
        <section v-else class="card"><p class="plain pad">{{ loadingDetail ? 'Loading…' : 'Choose a campaign.' }}</p></section>
      </div>

      <CandidateDrawer v-if="drawer.openId.value" :candidate-id="drawer.openId.value" :prev-id="drawer.prevId.value" :next-id="drawer.nextId.value"
        :position="drawer.position.value" @close="drawer.close" @go="drawer.go" @changed="afterDecision" />
    </template>
  </BrandFrame>
</template>

<style scoped>
.empty { background: var(--glass); border: 1px solid var(--line); border-radius: 16px; padding: 32px; max-width: 640px; }
.empty b { font-family: var(--disp); font-size: 16px; }
.empty p { margin: 8px 0 0; font-size: 13.5px; color: var(--muted); line-height: 1.6; }
.grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.7fr); gap: 20px; align-items: start; }
.list { display: flex; flex-direction: column; gap: 12px; }
.cc { text-align: left; display: flex; flex-direction: column; gap: 9px; padding: 15px 17px; border-radius: 14px; background: var(--glass); border: 1px solid var(--line); color: var(--txt); cursor: pointer; font: inherit; }
.cc:hover { border-color: var(--line2); }
.cc.on { border-color: var(--indigo); background: rgba(91,92,240,.12); }
.l1 { display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap; }
.nm { font-family: var(--mono); font-weight: 600; font-size: 14px; margin: 0; }
.why { font-size: 13px; color: #c9cee3; line-height: 1.5; }
.meta { display: flex; gap: 14px; flex-wrap: wrap; font-family: var(--mono); font-size: 11px; color: var(--muted); }
.rule { margin: 2px 2px 0; font-size: 12px; color: var(--muted); line-height: 1.55; }
.card { background: var(--glass); border: 1px solid var(--line); border-radius: 16px; overflow: hidden; }
.ch { padding: 20px 22px; border-bottom: 1px solid var(--line); display: flex; flex-direction: column; gap: 12px; }
.row { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
.row .nm { font-size: 19px; }
.sum { margin: 0; font-size: 14px; line-height: 1.55; }
.note { margin: 0; font-size: 12px; color: var(--muted); }
.sec { padding: 18px 22px; border-bottom: 1px solid var(--line); display: flex; flex-direction: column; gap: 10px; }
.sec:last-child { border-bottom: 0; }
h3 { margin: 0; font-family: var(--mono); font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
.mr { display: grid; grid-template-columns: minmax(0, 1fr) auto auto auto; gap: 14px; align-items: center; padding: 10px 12px; border-radius: 10px; background: rgba(255,255,255,.035); }
.mi { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.dom { background: none; border: 0; padding: 0; text-align: left; color: #fff; font: 600 13.5px var(--mono); cursor: pointer; word-break: break-all; }
.dom:hover { color: var(--indigo); }
.mwhy { font-size: 12px; color: var(--muted); }
.kb { align-self: flex-start; font: 700 10.5px var(--mono); padding: 1px 8px; border-radius: 8px; background: rgba(255,77,109,.16); color: #ff8da1; }
.lk { align-self: flex-start; font: 600 10.5px var(--mono); padding: 1px 8px; border-radius: 8px; background: rgba(245,197,66,.14); color: #f7d27a; cursor: help; }
.out { min-height: 30px; padding: 0 10px; border-radius: 8px; border: 1px solid var(--line2); background: transparent; color: var(--muted); font: 600 11.5px var(--body); cursor: pointer; }
.out:hover { color: var(--txt); border-color: var(--indigo); }
.facts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.fact { padding: 12px 14px; border-radius: 10px; border: 1px solid var(--line2); display: flex; flex-direction: column; gap: 6px; min-width: 0; }
.fh { display: flex; justify-content: space-between; gap: 8px; font-size: 13px; }
.fh span { font-size: 11.5px; font-weight: 700; color: var(--muted); }
.fv { font-size: 12px; color: #c9cee3; word-break: break-all; }
.mono { font-family: var(--mono); }
.fhelp { margin: 0; font-size: 12px; color: var(--muted); line-height: 1.5; }
.plain { margin: 0; font-size: 13.5px; color: #c9cee3; line-height: 1.6; }
.pad { padding: 24px; }
@media (max-width: 1000px) { .grid { grid-template-columns: 1fr; } }
@media (max-width: 640px) { .mr { grid-template-columns: 1fr; } .facts { grid-template-columns: 1fr; } }
</style>
