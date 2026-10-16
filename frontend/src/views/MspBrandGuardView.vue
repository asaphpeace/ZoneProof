<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from '@/api/client'

// One row per client: how much brand-impersonation work there is across the book, most urgent client first.
// Evidence packs download under the MSP's own name (white label): the client's data, the MSP's letterhead.
const data = ref<{ clients: any[]; totals: any } | null>(null)
const loading = ref(true)
const error = ref('')
const openId = ref('')
const cases = ref<Record<string, any[]>>({})
const busy = ref('')

onMounted(async () => {
  try { data.value = await api.mspBrandRollup() } catch (e: any) { error.value = e.message || 'Could not load the roll-up' } finally { loading.value = false }
})

const t = computed(() => data.value?.totals ?? { brands: 0, needs_attention: 0, confirmed: 0, takedown: 0, overdue: 0 })

async function toggle(c: any) {
  if (openId.value === c.client_id) { openId.value = ''; return }
  openId.value = c.client_id
  if (!cases.value[c.client_id]) {
    try { cases.value[c.client_id] = await api.mspClientBrandCases(c.client_id) } catch (e: any) { error.value = e.message }
  }
}
async function pack(clientId: string, candidateId: string, format: 'pdf' | 'json') {
  busy.value = candidateId + format
  try { await api.mspClientEvidencePack(clientId, candidateId, format) } catch (e: any) { error.value = e.message } finally { busy.value = '' }
}
const when = (iso: string | null) => (iso ? new Date(iso).toLocaleDateString() : 'never')
</script>

<template>
  <div>
    <div class="crumb">MSP / Brand Guard</div>
    <div class="page-head">
      <div>
        <h1>Brand Guard across clients</h1>
        <p class="sub">Look-alike domains found for each client's brand. Most urgent client first.</p>
      </div>
      <RouterLink :to="{ name: 'msp' }" class="back">Back to clients</RouterLink>
    </div>

    <p v-if="error" class="err" role="alert">{{ error }}</p>
    <p v-if="loading" class="muted">Loading…</p>
    <template v-else-if="data">
      <div class="tiles">
        <div class="tile"><b>{{ t.brands }}</b><span>brands protected</span></div>
        <div class="tile" :class="{ bad: t.overdue }"><b>{{ t.overdue }}</b><span>cases overdue</span></div>
        <div class="tile"><b>{{ t.needs_attention }}</b><span>need a decision</span></div>
        <div class="tile"><b>{{ t.confirmed + t.takedown }}</b><span>open cases</span></div>
      </div>

      <p v-if="!data.clients.length" class="muted">You have no clients yet.</p>
      <table v-else>
        <thead><tr><th>Client</th><th>Brands</th><th>Need a decision</th><th>Open cases</th><th>Overdue</th><th>Last scan</th><th><span class="sr">Details</span></th></tr></thead>
        <tbody>
          <template v-for="c in data.clients" :key="c.client_id">
            <tr class="row" @click="toggle(c)" tabindex="0" @keydown.enter.prevent="toggle(c)" @keydown.space.prevent="toggle(c)">
              <td><b>{{ c.name }}</b><div v-if="c.brand_name" class="sub2">{{ c.brand_name }}</div></td>
              <td>{{ c.brands }}</td>
              <td>{{ c.needs_attention }}</td>
              <td>{{ c.confirmed + c.takedown }}</td>
              <td><span v-if="c.overdue" class="late">{{ c.overdue }}</span><span v-else class="muted">0</span></td>
              <td>{{ when(c.last_scanned_at) }}</td>
              <td><button type="button" class="open" :aria-expanded="openId === c.client_id" :aria-label="`Cases for ${c.name}`">{{ openId === c.client_id ? '⌃' : '⌄' }}</button></td>
            </tr>
            <tr v-if="openId === c.client_id" class="detail">
              <td colspan="7">
                <p v-if="!(cases[c.client_id] || []).length" class="muted">No confirmed look-alikes for this client.</p>
                <ul v-else>
                  <li v-for="k in cases[c.client_id]" :key="k.id">
                    <span class="mono">{{ k.domain }}</span><span class="st">{{ k.status }}</span>
                    <span class="grow" />
                    <button type="button" class="btn" :disabled="!!busy" @click="pack(c.client_id, k.id, 'pdf')">{{ busy === k.id + 'pdf' ? 'Building…' : 'Evidence pack (PDF)' }}</button>
                    <button type="button" class="btn" :disabled="!!busy" @click="pack(c.client_id, k.id, 'json')">JSON</button>
                  </li>
                </ul>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </template>
  </div>
</template>

<style scoped>
.page-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap; }
.back { font: 600 12px var(--mono); color: var(--muted); text-decoration: none; border: 1px solid var(--line2); border-radius: 8px; padding: 6px 12px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 16px 0; }
.tile { border: 1px solid var(--line2); border-radius: 12px; padding: 14px; background: rgba(255,255,255,.02); }
.tile b { display: block; font-size: 26px; }
.tile span { font-size: 12px; color: var(--muted); }
.tile.bad b { color: #ff8da1; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; font: 600 11px var(--mono); color: var(--faint); padding: 8px 12px; text-transform: uppercase; letter-spacing: .06em; }
td { padding: 10px 12px; border-top: 1px solid var(--line2); font-size: 13px; vertical-align: top; }
.row { cursor: pointer; }
.row:hover { background: rgba(91,92,240,.06); }
.sub2 { font-size: 11.5px; color: var(--faint); }
.late { font: 700 12px var(--mono); padding: 2px 9px; border-radius: 999px; background: rgba(255,77,109,.16); color: #ff8da1; }
.muted { color: var(--muted); }
.err { color: #ff8da1; }
.open { background: none; border: 0; color: var(--muted); font-size: 18px; cursor: pointer; }
.detail td { background: rgba(255,255,255,.015); }
.detail ul { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }
.detail li { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.mono { font-family: var(--mono); font-weight: 600; }
.st { font: 700 10.5px var(--mono); padding: 2px 9px; border-radius: 999px; background: rgba(91,92,240,.16); color: #b9c0ff; }
.grow { flex-grow: 1; }
.btn { background: rgba(255,255,255,.04); color: var(--txt); border: 1px solid var(--line2); border-radius: 8px; padding: 4px 10px; font: 600 11px var(--mono); cursor: pointer; }
.btn:disabled { opacity: .5; }
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
</style>
