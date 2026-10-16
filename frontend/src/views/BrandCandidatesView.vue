<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { FILTERS, useBrandGuardStore } from '@/stores/brandGuard'
import BrandFrame from '@/components/brand/BrandFrame.vue'
import BrandHeader from '@/components/brand/BrandHeader.vue'
import VerdictPill from '@/components/brand/VerdictPill.vue'
import LifecycleDots from '@/components/brand/LifecycleDots.vue'
import CandidateDrawer from '@/components/brand/CandidateDrawer.vue'
import DecisionButtons from '@/components/brand/DecisionButtons.vue'
import { useCandidateDrawer } from '@/components/brand/useCandidateDrawer'
import { BADGE_HELP, CLASS_LABEL, FOUND_VIA, fmtShort, typeChip } from '@/components/brand/brandLabels'

const store = useBrandGuardStore()
const PAGE = 25

const confidence = ref('any')
const query = ref('')
const page = ref(0)
const selected = ref<Set<string>>(new Set())

const shown = computed(() => {
  const q = query.value.trim().toLowerCase()
  return store.candidates.filter(c =>
    (confidence.value === 'any' || c.confidence.level === confidence.value)
    && (!q || c.candidate_domain.includes(q) || c.candidate_domain_unicode.includes(q)))
})
const pages = computed(() => Math.max(1, Math.ceil(shown.value.length / PAGE)))
const rows = computed(() => shown.value.slice(page.value * PAGE, (page.value + 1) * PAGE))
const drawer = useCandidateDrawer(shown)

watch([confidence, query, () => store.candidatesFilter], () => { page.value = 0; selected.value = new Set() })

onMounted(async () => { await store.ensureLoaded() })

async function setFilter(v: string) { await store.loadCandidates(v) }

function toggle(id: string) {
  const next = new Set(selected.value)
  next.has(id) ? next.delete(id) : next.add(id)
  selected.value = next
}
function toggleAll(on: boolean) { selected.value = on ? new Set(rows.value.map(c => c.id)) : new Set() }

const picked = computed(() => store.candidates.filter(c => selected.value.has(c.id)))
const sameVerdict = computed(() => new Set(picked.value.map(c => c.verdict.key)).size <= 1)
const allOnPage = computed(() => rows.value.length > 0 && rows.value.every(c => selected.value.has(c.id)))

function afterBulk() { selected.value = new Set() }
</script>

<template>
  <BrandFrame>
    <template v-if="store.profile">
      <BrandHeader title="Candidates" crumb="Candidates" sub="Every look-alike we have found, with a verdict and the reason for it. Most urgent first." />

      <div class="bar">
        <div class="pills" role="group" aria-label="Filter by status">
          <button v-for="f in FILTERS" :key="f.value" type="button" class="pill" :class="{ on: store.candidatesFilter === f.value }" :aria-pressed="store.candidatesFilter === f.value" @click="setFilter(f.value)">{{ f.label }}</button>
        </div>
        <span class="grow" />
        <label class="sr" for="bgc-conf">Confidence</label>
        <select id="bgc-conf" v-model="confidence" class="sel">
          <option value="any">Any confidence</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
        </select>
        <label class="sr" for="bgc-q">Filter candidates</label>
        <input id="bgc-q" v-model="query" type="search" class="sel q" placeholder="Filter by domain…" />
      </div>

      <div v-if="picked.length" class="bulk" role="region" aria-label="Bulk actions">
        <b>{{ picked.length }} selected</b>
        <span v-if="sameVerdict" class="bn">Same verdict, so one decision applies to all of them.</span>
        <span v-else class="bn warn">These have different verdicts. Select candidates with the same verdict to act on them together.</span>
        <span class="grow" />
        <DecisionButtons v-if="sameVerdict" :items="picked" compact @decided="afterBulk" />
        <button type="button" class="clear" @click="selected = new Set()">Clear</button>
      </div>

      <div class="card">
        <div v-if="!shown.length" class="empty">
          {{ store.candidatesFilter === 'open' ? 'Nothing needs attention. No unreviewed look-alike has shown signs of life.' : 'No candidates in this view.' }}
        </div>
        <div v-else class="scroll">
          <table>
            <thead>
              <tr>
                <th class="c"><input type="checkbox" :checked="allOnPage" aria-label="Select all on this page" @change="toggleAll(($event.target as HTMLInputElement).checked)" /></th>
                <th>Domain</th><th>Verdict</th><th>Lifecycle</th><th>Why</th><th>First seen</th><th><span class="sr">Open</span></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="c in rows" :key="c.id" :class="{ sel: selected.has(c.id) }">
                <td class="c"><input type="checkbox" :checked="selected.has(c.id)" :aria-label="`Select ${c.candidate_domain_unicode}`" @change="toggle(c.id)" /></td>
                <td>
                  <div class="dom">{{ c.candidate_domain_unicode }}</div>
                  <div class="chips">
                    <span v-if="c.threat_class" class="chip">{{ CLASS_LABEL[c.threat_class] ?? c.threat_class }}</span>
                    <span v-if="typeChip(c.abuse_type)" class="chip" :class="typeChip(c.abuse_type)!.tone === 'red' ? 'blocklist' : ''" :title="(c.abuse_type.reasons || []).join(' ')">{{ typeChip(c.abuse_type)!.text }}</span>
                    <span v-for="b in c.enrichment?.badges || []" :key="b.label" class="chip" :class="b.kind" :title="BADGE_HELP[b.kind]">{{ b.label }}</span>
                    <span v-for="s in c.sources" :key="s" class="chip dim">{{ FOUND_VIA[s] ?? s }}</span>
                  </div>
                </td>
                <td>
                  <VerdictPill :verdict="c.verdict" />
                  <div class="cf" :title="c.confidence.reason">{{ c.confidence.label }} confidence</div>
                  <div v-if="c.decision.key !== 'open'" class="dc">{{ c.decision.reason_label ? `${c.decision.label}: ${c.decision.reason_label}` : c.decision.label }}</div>
                </td>
                <td><LifecycleDots :stage="c.stage" :tone="c.verdict.tone" /></td>
                <td class="why">{{ c.why }}</td>
                <td class="seen">{{ fmtShort(c.first_seen_at) }}</td>
                <td><button type="button" class="open" :aria-label="`Open ${c.candidate_domain_unicode}`" @click="drawer.open(c.id)">›</button></td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="foot">
          <span>Showing {{ rows.length }} of {{ shown.length }}<template v-if="store.candidatesFilter !== 'all'"> in this view</template></span>
          <span class="pg">
            <button type="button" class="pgb" :disabled="page === 0" @click="page--">Previous</button>
            <span>{{ page + 1 }} / {{ pages }}</span>
            <button type="button" class="pgb" :disabled="page >= pages - 1" @click="page++">Next</button>
          </span>
        </div>
      </div>

      <CandidateDrawer v-if="drawer.openId.value" :candidate-id="drawer.openId.value" :prev-id="drawer.prevId.value" :next-id="drawer.nextId.value"
        :position="drawer.position.value" @close="drawer.close" @go="drawer.go" @changed="store.refreshAfterChange" />
    </template>
  </BrandFrame>
</template>

<style scoped>
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
.bar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }
.grow { flex-grow: 1; }
.pills { display: flex; gap: 8px; flex-wrap: wrap; }
.pill { min-height: 34px; padding: 0 14px; border-radius: 20px; border: 1px solid var(--line2); background: rgba(255,255,255,.02); color: var(--muted); font: 600 12px var(--mono); cursor: pointer; }
.pill:hover { color: var(--txt); border-color: var(--indigo); }
.pill.on { background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff; border-color: transparent; }
.sel { height: 38px; padding: 0 12px; border-radius: 10px; background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--txt); font: 500 13px var(--body); }
.sel.q { width: 220px; }
.bulk { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding: 10px 14px; margin-bottom: 14px; border-radius: 12px; background: rgba(91,92,240,.12); border: 1px solid rgba(91,92,240,.4); }
.bn { font-size: 12.5px; color: #c4c9ee; }
.bn.warn { color: var(--warn); }
.clear { background: none; border: 0; color: var(--muted); font-size: 12.5px; cursor: pointer; text-decoration: underline; }
.card { background: var(--glass); border: 1px solid var(--line); border-radius: 16px; overflow: hidden; }
.empty { padding: 44px 20px; text-align: center; color: var(--muted); font-size: 13px; }
.scroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; min-width: 860px; }
th { text-align: left; padding: 11px 14px; font: 500 10.5px var(--mono); letter-spacing: .1em; text-transform: uppercase; color: var(--muted); border-bottom: 1px solid var(--line); }
td { padding: 13px 14px; border-bottom: 1px solid var(--line); vertical-align: middle; font-size: 13px; }
tr:hover td { background: rgba(255,255,255,.025); }
tr.sel td { background: rgba(91,92,240,.1); }
.c { width: 40px; }
input[type='checkbox'] { width: 17px; height: 17px; accent-color: var(--indigo); }
.dom { font-family: var(--mono); font-size: 13.5px; font-weight: 600; word-break: break-all; }
.chips { display: flex; gap: 5px; flex-wrap: wrap; margin-top: 6px; }
.chip { font-family: var(--mono); font-size: 10.5px; padding: 2px 8px; border-radius: 8px; background: rgba(91,92,240,.14); color: #b9c0ff; }
.chip.dim { background: rgba(255,255,255,.06); color: var(--muted); }
.chip.blocklist, .chip.reported, .chip.spoofer { background: rgba(255,77,109,.16); color: #ff8da1; }
.chip.yours, .chip.popular, .chip.parked { background: rgba(52,224,161,.12); color: var(--good); }
.cf { margin-top: 5px; font-size: 12px; color: var(--muted); cursor: help; }
.dc { margin-top: 4px; font-size: 11.5px; font-weight: 700; color: #b9c0ff; }
.why { color: #c9cee3; line-height: 1.45; max-width: 380px; }
.seen { font-family: var(--mono); font-size: 11.5px; color: var(--muted); white-space: nowrap; }
.open { width: 34px; height: 34px; border-radius: 9px; border: 1px solid var(--line2); background: transparent; color: var(--txt); font-size: 18px; cursor: pointer; }
.open:hover { border-color: var(--indigo); }
.foot { display: flex; justify-content: space-between; align-items: center; padding: 12px 18px; font-size: 12.5px; color: var(--muted); gap: 12px; flex-wrap: wrap; }
.pg { display: inline-flex; align-items: center; gap: 10px; }
.pgb { min-height: 32px; padding: 0 12px; border-radius: 9px; border: 1px solid var(--line2); background: transparent; color: var(--txt); font: 600 12px var(--body); cursor: pointer; }
.pgb:disabled { opacity: .4; cursor: default; }
</style>
