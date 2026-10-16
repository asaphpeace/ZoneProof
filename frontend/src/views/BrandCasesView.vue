<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { api } from '@/api/client'
import { useBrandGuardStore } from '@/stores/brandGuard'
import BrandFrame from '@/components/brand/BrandFrame.vue'
import BrandHeader from '@/components/brand/BrandHeader.vue'
import VerdictPill from '@/components/brand/VerdictPill.vue'
import CandidateDrawer from '@/components/brand/CandidateDrawer.vue'
import { useCandidateDrawer } from '@/components/brand/useCandidateDrawer'
import { SLA_TONE, fmtShort, slaText } from '@/components/brand/brandLabels'

const store = useBrandGuardStore()
const rows = ref<any[]>([])
const loading = ref(false)
const error = ref('')
const mine = ref(false)

// Open work first (soonest deadline on top), then cases that came back, then the closed ones.
const GROUPS = [
  { key: 'open', title: 'Open', help: 'Confirmed or in takedown. Soonest deadline first.', statuses: ['confirmed', 'takedown'] },
  { key: 'reopened', title: 'Came back', help: 'Closed as removed, but resolving again.', statuses: ['monitoring'] },
  { key: 'closed', title: 'Closed', help: 'Removed. Watched for a comeback.', statuses: ['removed'] },
]
const STATUS_LABEL: Record<string, string> = { confirmed: 'Confirmed', takedown: 'In takedown', monitoring: 'Came back', removed: 'Removed' }
const grouped = computed(() => GROUPS.map(g => ({ ...g, items: rows.value.filter(c => g.statuses.includes(c.status)) })))
const overdue = computed(() => rows.value.filter(c => c.sla?.state === 'breached' && ['confirmed', 'takedown'].includes(c.status)).length)
const flat = computed(() => grouped.value.flatMap(g => g.items))
const drawer = useCandidateDrawer(flat)

async function load() {
  loading.value = true
  error.value = ''
  try {
    rows.value = await api.brandCandidates({ profile_id: store.profile?.id, status: 'cases', assigned_to: mine.value ? 'me' : undefined, limit: 500 })
  } catch (e: any) {
    error.value = e.message || 'Could not load cases'
  } finally {
    loading.value = false
  }
}
async function changed() { await Promise.all([load(), store.refreshAfterChange()]) }

watch([mine, () => store.profile?.id], load)
onMounted(async () => { await store.ensureLoaded(); await load() })
</script>

<template>
  <BrandFrame>
    <template v-if="store.profile">
      <BrandHeader title="Cases" crumb="Cases" sub="Look-alikes your team has taken on: who owns each one, how long is left, and what has happened." />

      <div class="bar">
        <span v-if="overdue" class="late">{{ overdue }} overdue</span>
        <span v-else class="ok">Nothing overdue</span>
        <span class="grow" />
        <label class="mine"><input v-model="mine" type="checkbox" /> Only mine</label>
      </div>

      <p v-if="error" class="err" role="alert">{{ error }}</p>
      <div v-if="!loading && !rows.length && !error" class="card empty">
        No cases yet. Confirm a look-alike on the Candidates page and it appears here with an owner and a deadline.
      </div>

      <section v-for="g in grouped" v-show="g.items.length" :key="g.key" class="card grp">
        <header><h3>{{ g.title }} <span class="n">{{ g.items.length }}</span></h3><span class="help">{{ g.help }}</span></header>
        <table>
          <thead><tr><th>Domain</th><th>Stage</th><th>Verdict</th><th>Owner</th><th>Deadline</th><th><span class="sr">Open</span></th></tr></thead>
          <tbody>
            <tr v-for="c in g.items" :key="c.id" class="row" @click="drawer.open(c.id)" tabindex="0" @keydown.enter.prevent="drawer.open(c.id)" @keydown.space.prevent="drawer.open(c.id)">
              <td><div class="dom">{{ c.candidate_domain_unicode }}</div><div v-if="c.campaign_name" class="sub">{{ c.campaign_name }}</div></td>
              <td>{{ STATUS_LABEL[c.status] ?? c.status }}<div class="sub">since {{ fmtShort(c.reviewed_at) }}</div></td>
              <td><VerdictPill :verdict="c.verdict" /></td>
              <td>{{ c.assignee?.name ?? '' }}<span v-if="!c.assignee" class="none">Unassigned</span></td>
              <td><span v-if="slaText(c.sla)" class="sla" :class="SLA_TONE[c.sla.state]">{{ slaText(c.sla) }}</span></td>
              <td><button type="button" class="open" :aria-label="`Open ${c.candidate_domain_unicode}`" @click.stop="drawer.open(c.id)">›</button></td>
            </tr>
          </tbody>
        </table>
      </section>

      <CandidateDrawer v-if="drawer.openId.value" :candidate-id="drawer.openId.value" :prev-id="drawer.prevId.value" :next-id="drawer.nextId.value"
        :position="drawer.position.value" @close="drawer.close" @go="drawer.go" @changed="changed" />
    </template>
  </BrandFrame>
</template>

<style scoped>
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
.bar { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; }
.grow { flex-grow: 1; }
.late { font: 700 12px var(--mono); padding: 3px 10px; border-radius: 999px; background: rgba(255,77,109,.16); color: #ff8da1; }
.ok { font: 600 12px var(--mono); color: var(--muted); }
.mine { font-size: 13px; color: var(--muted); display: flex; gap: 6px; align-items: center; cursor: pointer; }
.err { color: #ff8da1; }
.card { background: rgba(255,255,255,.02); border: 1px solid var(--line2); border-radius: 14px; margin-bottom: 16px; overflow: hidden; }
.empty { padding: 28px; color: var(--muted); }
.grp header { display: flex; align-items: baseline; gap: 12px; padding: 14px 16px 6px; }
.grp h3 { margin: 0; font-size: 14px; }
.n { font: 600 12px var(--mono); color: var(--muted); margin-left: 6px; }
.help { font-size: 12px; color: var(--faint); }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; font: 600 11px var(--mono); color: var(--faint); padding: 8px 16px; text-transform: uppercase; letter-spacing: .06em; }
td { padding: 10px 16px; border-top: 1px solid var(--line2); vertical-align: top; font-size: 13px; }
.row { cursor: pointer; }
.row:hover { background: rgba(91,92,240,.06); }
.dom { font: 600 13px var(--mono); }
.sub { font-size: 11.5px; color: var(--faint); margin-top: 2px; }
.none { color: var(--faint); }
.sla { font: 700 11px var(--mono); padding: 2px 9px; border-radius: 999px; white-space: nowrap; }
.sla.ok { background: rgba(60,200,150,.14); color: #6fe0b8; }
.sla.warn { background: rgba(245,197,66,.14); color: #f7d27a; }
.sla.bad { background: rgba(255,77,109,.16); color: #ff8da1; }
.open { background: none; border: 0; color: var(--muted); font-size: 20px; cursor: pointer; }
</style>
