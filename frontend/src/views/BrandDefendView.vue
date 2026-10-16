<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { api } from '@/api/client'
import { useBrandGuardStore } from '@/stores/brandGuard'
import BrandFrame from '@/components/brand/BrandFrame.vue'
import BrandHeader from '@/components/brand/BrandHeader.vue'

// Two ways to cut a look-alike off before a takedown lands: load a block rule into your own filters, and report the address to the
// browser-protection services. ZoneProof only prepares the file or the link; a person loads it or submits the report.
const store = useBrandGuardStore()
const include = ref<'confirmed' | 'likely'>('confirmed')
const counts = ref<Record<string, number>>({})
const busy = ref('')
const error = ref('')
const note = ref('')

const FORMATS = [
  { key: 'm365', title: 'Microsoft 365', help: 'A PowerShell script for the Tenant Allow/Block List. An admin reviews and runs it.' },
  { key: 'rpz', title: 'DNS (RPZ zone)', help: 'Makes the names and everything under them fail to resolve. For BIND, Unbound or Knot.' },
  { key: 'chrome', title: 'Chrome and Edge policy', help: 'A URLBlocklist policy in JSON, for managed browsers.' },
  { key: 'plain', title: 'Plain list', help: 'One domain per line. For Google Workspace blocked senders, a proxy, or any filter that takes a list.' },
  { key: 'csv', title: 'CSV', help: 'The same list as a spreadsheet.' },
]

const advice = ref<any>(null)
const advising = ref(false)
async function advise() {
  if (!store.profile) return
  advising.value = true
  error.value = ''
  try { advice.value = await api.brandDefensive(store.profile.id) } catch (e: any) { error.value = e.message || 'Could not check names' } finally { advising.value = false }
}

const cases = ref<any[]>([])
const open = ref('')
const links = ref<Record<string, any[]>>({})

async function load() {
  error.value = ''
  try {
    const res = await Promise.all(FORMATS.map(f => api.brandBlocklist(f.key, include.value, store.profile?.id, false)))
    counts.value = Object.fromEntries(FORMATS.map((f, i) => [f.key, res[i].count]))
    cases.value = await api.brandCandidates({ profile_id: store.profile?.id, status: 'cases', limit: 200 })
    cases.value = cases.value.filter(c => ['confirmed', 'takedown'].includes(c.status))
  } catch (e: any) { error.value = e.message || 'Could not load' }
}
watch([include, () => store.profile?.id], load)
watch(() => store.profile?.id, () => { advice.value = null })
onMounted(async () => { await store.ensureLoaded(); await load() })

const total = computed(() => counts.value.plain ?? 0)

async function download(key: string) {
  busy.value = key
  try { await api.brandBlocklistDownload(key, include.value, store.profile?.id) } catch (e: any) { error.value = e.message } finally { busy.value = '' }
}
async function copy(key: string) {
  busy.value = key
  note.value = ''
  try {
    const r = await api.brandBlocklist(key, include.value, store.profile?.id, false)
    await navigator.clipboard.writeText(r.text)
    note.value = `Copied the ${FORMATS.find(f => f.key === key)!.title} rules.`
  } catch (e: any) { error.value = e.message || 'Could not copy' } finally { busy.value = '' }
}

async function toggle(c: any) {
  if (open.value === c.id) { open.value = ''; return }
  open.value = c.id
  if (!links.value[c.id]) links.value[c.id] = await api.brandReportLinks(c.id)
}
async function reported(c: any, service: string) {
  try { await api.brandSubmissionCreate(c.id, service); links.value[c.id] = await api.brandReportLinks(c.id) } catch (e: any) { error.value = e.message }
}
async function move(c: any, sub: any, status: string) {
  try { await api.brandSubmissionMove(sub.id, status); links.value[c.id] = await api.brandReportLinks(c.id) } catch (e: any) { error.value = e.message }
}
async function copyText(t: string) { try { await navigator.clipboard.writeText(t); note.value = 'Copied.' } catch { error.value = 'Could not copy.' } }
const STATUS_LABEL: Record<string, string> = { submitted: 'Reported, waiting', listed: 'Listed', declined: 'Declined' }
const MOVE_LABEL: Record<string, string> = { listed: 'It was listed', declined: 'They declined', submitted: 'Report again' }
</script>

<template>
  <BrandFrame>
    <template v-if="store.profile">
      <BrandHeader title="Defend" crumb="Defend" sub="Cut a look-alike off now, without waiting for a takedown. ZoneProof prepares the file or the link; you load it or send the report." />
      <p v-if="error" class="err" role="alert">{{ error }}</p>
      <p v-if="note" class="ok" role="status">{{ note }}</p>

      <section class="card">
        <header>
          <h3>Block them in your own filters</h3>
          <div class="seg" role="group" aria-label="Which names to include">
            <button type="button" :class="{ on: include === 'confirmed' }" :aria-pressed="include === 'confirmed'" @click="include = 'confirmed'">Confirmed only</button>
            <button type="button" :class="{ on: include === 'likely' }" :aria-pressed="include === 'likely'" @click="include = 'likely'">Also likely ones</button>
          </div>
        </header>
        <p class="help">{{ total }} {{ total === 1 ? 'name' : 'names' }} for {{ store.profile.brand_name }}.
          <template v-if="include === 'likely'"> This includes look-alikes nobody has reviewed yet, so a few may be legitimate.</template>
          <template v-else> Only look-alikes a person confirmed or sent to takedown.</template></p>
        <ul class="fmts">
          <li v-for="f in FORMATS" :key="f.key">
            <div><b>{{ f.title }}</b><div class="fh">{{ f.help }}</div></div>
            <div class="acts">
              <button type="button" class="btn" :disabled="!total || !!busy" @click="download(f.key)">Download</button>
              <button type="button" class="btn" :disabled="!total || !!busy" @click="copy(f.key)">Copy</button>
            </div>
          </li>
        </ul>
        <p v-if="!total" class="help">Nothing to export yet. Confirm a look-alike on the Candidates page first.</p>
      </section>

      <section class="card">
        <header>
          <h3>Names worth registering first</h3>
          <button type="button" class="btn primary" :disabled="advising" @click="advise">{{ advising ? 'Checking names…' : advice ? 'Check again' : 'Find names to register' }}</button>
        </header>
        <p class="help">Buying the most likely look-alikes yourself takes them away from attackers. This is a ranked starting point, not a prediction: kinds of look-alike and suffixes are weighted by judgement, then raised when the same kind is already used against your brand.</p>
        <template v-if="advice">
          <p v-if="!advice.names.length" class="help">No unregistered names found among the {{ advice.checked }} most likely. {{ advice.taken }} are already taken.</p>
          <ul v-else class="adv">
            <li v-for="n in advice.names" :key="n.domain">
              <div><span class="mono">{{ n.domain }}</span><div class="fh">{{ n.reasons.join('. ') }}.</div></div>
              <span class="avail">Appears unregistered</span>
            </li>
          </ul>
          <p class="help">Checked {{ advice.checked }} names: {{ advice.names.length }} appear free, {{ advice.taken }} taken<template v-if="advice.unknown">, {{ advice.unknown }} DNS could not answer</template>. "Appears unregistered" means the name did not resolve. Confirm with your registrar before relying on it.</p>
        </template>
      </section>

      <section class="card">
        <header><h3>Report to browser protection</h3></header>
        <p class="help">Google Safe Browsing, Microsoft SmartScreen and Netcraft feed most browsers and security products, and often act faster than a registrar. They check the live page, so a name that serves nothing yet may be declined.</p>
        <p v-if="!cases.length" class="help">No confirmed look-alikes to report.</p>
        <ul v-else class="cases">
          <li v-for="c in cases" :key="c.id">
            <button type="button" class="row" :aria-expanded="open === c.id" @click="toggle(c)"><span class="mono">{{ c.candidate_domain_unicode }}</span><span class="chev">{{ open === c.id ? '⌃' : '⌄' }}</span></button>
            <ul v-if="open === c.id && links[c.id]" class="svc">
              <li v-for="l in links[c.id]" :key="l.service">
                <div><b>{{ l.label }}</b><div class="fh">{{ l.note }}</div></div>
                <div class="acts">
                  <a class="btn" :href="l.url" target="_blank" rel="noopener noreferrer">Open report page</a>
                  <button type="button" class="btn" @click="copyText(l.paste)">Copy address</button>
                  <template v-if="!l.submission"><button type="button" class="btn primary" @click="reported(c, l.service)">I reported it</button></template>
                  <template v-else>
                    <span class="st" :class="l.submission.status">{{ STATUS_LABEL[l.submission.status] }}</span>
                    <button v-for="n in l.submission.allowed_next" :key="n" type="button" class="btn" @click="move(c, l.submission, n)">{{ MOVE_LABEL[n] }}</button>
                  </template>
                </div>
              </li>
            </ul>
          </li>
        </ul>
      </section>
    </template>
  </BrandFrame>
</template>

<style scoped>
.card { border: 1px solid var(--line2); border-radius: 14px; padding: 16px; margin-bottom: 16px; background: rgba(255,255,255,.02); }
.card header { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
h3 { margin: 0; font-size: 15px; }
.help { font-size: 12.5px; color: var(--muted); margin: 8px 0; }
.err { color: #ff8da1; }
.ok { color: #6fe0b8; font-size: 12.5px; }
.seg { display: flex; gap: 6px; }
.seg button { min-height: 32px; padding: 0 12px; border-radius: 18px; border: 1px solid var(--line2); background: rgba(255,255,255,.02); color: var(--muted); font: 600 12px var(--mono); cursor: pointer; }
.seg button.on { background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff; border-color: transparent; }
ul { list-style: none; padding: 0; margin: 0; }
.fmts li, .svc li { display: flex; justify-content: space-between; gap: 12px; align-items: center; flex-wrap: wrap; padding: 10px 0; border-top: 1px solid var(--line2); }
.fh { font-size: 12px; color: var(--faint); margin-top: 2px; max-width: 560px; }
.acts { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.btn { background: rgba(255,255,255,.04); color: var(--txt); border: 1px solid var(--line2); border-radius: 8px; padding: 5px 11px; font: 600 11.5px var(--mono); cursor: pointer; text-decoration: none; }
.btn.primary { background: linear-gradient(90deg, #5b5cf0, #4b4ce0); border-color: transparent; color: #fff; }
.btn:disabled { opacity: .45; cursor: default; }
.cases > li { border-top: 1px solid var(--line2); }
.row { width: 100%; display: flex; justify-content: space-between; background: none; border: 0; color: var(--txt); padding: 10px 0; cursor: pointer; }
.mono { font-family: var(--mono); font-weight: 600; font-size: 13px; }
.chev { color: var(--muted); }
.svc { padding: 0 0 8px 12px; }
.adv li { display: flex; justify-content: space-between; gap: 12px; align-items: center; padding: 9px 0; border-top: 1px solid var(--line2); }
.avail { font: 700 10.5px var(--mono); padding: 2px 9px; border-radius: 999px; background: rgba(60,200,150,.14); color: #6fe0b8; white-space: nowrap; }
.st { font: 700 10.5px var(--mono); padding: 2px 9px; border-radius: 999px; background: rgba(91,92,240,.16); color: #b9c0ff; }
.st.listed { background: rgba(60,200,150,.14); color: #6fe0b8; }
.st.declined { background: rgba(255,77,109,.16); color: #ff8da1; }
</style>
