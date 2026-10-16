<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { api } from '@/api/client'
import VerdictPill from './VerdictPill.vue'
import DecisionButtons from './DecisionButtons.vue'
import DerivationNode from './DerivationNode.vue'
import TakedownPanel from './TakedownPanel.vue'
import { BADGE_HELP, CLASS_LABEL, FOUND_VIA, SLA_TONE, STEP_STATUS, fmtDate, fmtShort, probeLines, slaText, typeChip } from './brandLabels'

const props = defineProps<{ candidateId: string; prevId?: string | null; nextId?: string | null; position?: string }>()
const emit = defineEmits<{ close: []; go: [id: string]; changed: [] }>()

const detail = ref<any>(null)
const timeline = ref<any>(null)
const loading = ref(true)
const failed = ref('')
const panel = ref<HTMLElement | null>(null)
let seq = 0

async function load() {
  const mine = ++seq
  loading.value = true
  failed.value = ''
  try {
    const [d, t] = await Promise.all([api.brandCandidate(props.candidateId), api.brandTimeline(props.candidateId)])
    if (mine !== seq) return
    detail.value = d
    timeline.value = t
  } catch (e: any) {
    if (mine === seq) failed.value = e.message || 'Could not load this candidate'
  } finally {
    if (mine === seq) { loading.value = false; await nextTick(); panel.value?.querySelector<HTMLElement>('[data-scroll]')?.scrollTo({ top: 0 }) }
  }
}
watch(() => props.candidateId, load, { immediate: true })

// The rendered look at its page (screenshot, text, forms): third-party content from the sandboxed renderer, loaded after the candidate.
const capture = ref<any>(null)
const shotUrl = ref<string | null>(null)
const refUrl = ref<string | null>(null)       // the customer's own page, to compare with
let capSeq = 0
function dropShot() {
  for (const r of [shotUrl, refUrl]) if (r.value) { URL.revokeObjectURL(r.value); r.value = null }
}
async function loadCapture() {
  const mine = ++capSeq
  dropShot()
  capture.value = null
  try {
    const c = await api.brandCapture(props.candidateId)
    if (mine !== capSeq) return
    capture.value = c
    const [shot, ref] = await Promise.all([
      c.available && c.has_screenshot ? api.brandCaptureImage(props.candidateId) : Promise.resolve(null),
      c.available && c.reference_available && c.profile_id ? api.brandReferenceImage(c.profile_id) : Promise.resolve(null),
    ])
    if (mine !== capSeq) { for (const u of [shot, ref]) if (u) URL.revokeObjectURL(u); return }
    shotUrl.value = shot
    refUrl.value = ref
  } catch { if (mine === capSeq) capture.value = null }       // informational: the drawer never fails because of it
}
watch(() => props.candidateId, loadCapture, { immediate: true })
onBeforeUnmount(dropShot)

const view = computed(() => detail.value?.evidence_view ?? { for: [], against: [], context: [], not_found: [], narrative: [] })
const tone = computed(() => detail.value?.verdict?.tone ?? 'slate')
const team = ref<any[]>([])
const assigning = ref(false)
onMounted(async () => { try { team.value = await api.team() } catch { team.value = [] } })
async function assign(userId: string) {
  assigning.value = true
  try { detail.value = { ...detail.value, ...(await api.brandAssign(props.candidateId, userId || null)) }; timeline.value = await api.brandTimeline(props.candidateId); emit('changed') }
  catch (e: any) { failed.value = e.message || 'Could not assign' }
  finally { assigning.value = false }
}
const packing = ref('')
async function downloadPack(format: 'pdf' | 'json') {
  packing.value = format
  try { await api.brandEvidencePack(props.candidateId, format) }
  catch (e: any) { failed.value = e.message || 'Could not build the evidence pack' }
  finally { packing.value = '' }
}
const decided = computed(() => detail.value && detail.value.decision?.key !== 'open')

const MAIL_SIGNALS = new Set(['spf_published', 'dkim_published', 'dmarc_published', 'esp_sender', 'copied_dkim_key', 'forwarding_mx', 'mirrors_mail_provider', 'defensive_mail_posture'])
const mailLines = computed(() => {
  const all = [...view.value.for, ...view.value.against, ...view.value.context]
  return all.filter((e: any) => MAIL_SIGNALS.has(e.signal))
})
const siblings = computed<string[]>(() => {
  const ev = (detail.value?.evidence ?? []).find((e: any) => e.data?.siblings?.length)
  return ev?.data?.siblings ?? []
})
const campaignLine = computed(() => (detail.value?.evidence ?? []).find((e: any) => ['batch_registered', 'shared_certificate', 'shared_nameservers_cluster', 'shared_server_cluster'].includes(e.signal)))

// A person's decision is shown on top of the verdict, never instead of it.
const decisionText = computed(() => {
  const d = detail.value?.decision
  if (!d || d.key === 'open') return ''
  return d.reason_label ? `${d.label}: ${d.reason_label}` : d.label
})

function refTo(n: number) {
  panel.value?.querySelector<HTMLElement>(`#ev-${n}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
}

function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape') { emit('close'); return }
  const t = e.target as HTMLElement | null
  if (t && ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName)) return
  if (e.key === 'j' && props.nextId) emit('go', props.nextId)
  if (e.key === 'k' && props.prevId) emit('go', props.prevId)
}
onMounted(() => { window.addEventListener('keydown', onKey); panel.value?.focus() })
onBeforeUnmount(() => window.removeEventListener('keydown', onKey))

function changed() { load(); emit('changed') }
const factList = computed(() => {
  const d = detail.value
  if (!d) return []
  const e = d.enrichment || {}
  return [
    ['First seen', fmtDate(d.first_seen_at)],
    e.registered_at ? ['Registered', fmtDate(e.registered_at)] : null,
    e.registration?.registrar ? ['Registrar', e.registration.registrar] : null,
    ['Web', e.has_a || e.has_aaaa ? 'Resolves' : 'Does not resolve'],
    ['Mail', e.has_mx ? 'Has mail servers' : 'No mail servers'],
    d.threat_class ? ['Pattern', CLASS_LABEL[d.threat_class] ?? d.threat_class] : null,
  ].filter(Boolean) as string[][]
})
</script>

<template>
  <div class="overlay" @click.self="emit('close')">
    <aside ref="panel" class="drawer" role="dialog" aria-modal="true" aria-labelledby="bgd-title" tabindex="-1">
      <header class="head">
        <div class="top">
          <span class="lbl">Candidate<template v-if="detail"> · first seen {{ fmtShort(detail.first_seen_at) }}</template></span>
          <span class="nav">
            <span v-if="position" class="pos">{{ position }}</span>
            <button type="button" class="ico" :disabled="!prevId" aria-label="Previous candidate (k)" title="Previous (k)" @click="prevId && emit('go', prevId)">‹</button>
            <button type="button" class="ico" :disabled="!nextId" aria-label="Next candidate (j)" title="Next (j)" @click="nextId && emit('go', nextId)">›</button>
            <button type="button" class="ico" aria-label="Close" title="Close (Esc)" @click="emit('close')">×</button>
          </span>
        </div>
        <template v-if="detail">
          <h2 id="bgd-title" class="dom">{{ detail.candidate_domain_unicode }}</h2>
          <div v-if="detail.candidate_domain_unicode !== detail.candidate_domain" class="idn">IDN · {{ detail.candidate_domain }}</div>
          <div class="verdict-row">
            <VerdictPill :verdict="detail.verdict" size="md" />
            <span class="conf" :title="detail.confidence.reason">{{ detail.confidence.label }} confidence · {{ view.for.length }} for, {{ view.against.length }} against</span>
            <span v-if="decisionText" class="decided">{{ decisionText }}</span>
          </div>
          <p class="why">{{ detail.why }}</p>
          <p v-if="detail.reasoning?.components?.length" class="strength" :title="detail.reasoning.notes?.join(' ')">
            <b>{{ detail.reasoning.label }}.</b>
            Roughly ×{{ detail.reasoning.ratio >= 100 ? Math.round(detail.reasoning.ratio) : detail.reasoning.ratio }} more typical of known-bad new domains than of ordinary new registrations
            <template v-if="detail.reasoning.ratio_measured !== detail.reasoning.ratio">(×{{ detail.reasoning.ratio_measured }} on measured signals alone)</template>.
            <span v-if="detail.reasoning.notes?.length" class="assumed">{{ detail.reasoning.notes[0] }}</span>
          </p>
          <div class="chips">
            <span v-for="b in detail.enrichment?.badges || []" :key="b.label" class="chip" :class="b.kind" :title="BADGE_HELP[b.kind]">{{ b.label }}</span>
            <span v-if="typeChip(detail.abuse_type)" class="chip type" :class="typeChip(detail.abuse_type)!.tone" :title="(detail.abuse_type.reasons || []).join(' ')">{{ typeChip(detail.abuse_type)!.text }}</span>
            <span v-for="s in detail.sources" :key="s" class="chip dim">Found via: {{ FOUND_VIA[s] ?? s }}</span>
          </div>
          <DecisionButtons :items="[detail]" @decided="changed" />
          <div class="owner">
            <label>Owner
              <select :value="detail.assignee?.id ?? ''" :disabled="assigning" @change="assign(($event.target as HTMLSelectElement).value)">
                <option value="">Unassigned</option>
                <option v-for="m in team" :key="m.id" :value="m.id">{{ m.full_name || m.email }}</option>
              </select>
            </label>
            <span class="pack">
              Evidence pack:
              <button type="button" :disabled="!!packing" @click="downloadPack('pdf')">{{ packing === 'pdf' ? 'Building…' : 'PDF' }}</button>
              <button type="button" :disabled="!!packing" @click="downloadPack('json')">JSON</button>
            </span>
            <span v-if="slaText(detail.sla)" class="sla" :class="SLA_TONE[detail.sla.state]" title="Target hours are assumed by urgency (high 4 h, medium 24 h, low 72 h), not measured.">{{ slaText(detail.sla) }}</span>
          </div>
        </template>
        <h2 v-else id="bgd-title" class="dom skel">Loading candidate</h2>
      </header>

      <div class="body" data-scroll>
        <p v-if="failed" class="err">{{ failed }}</p>
        <template v-else-if="detail">
          <section v-if="view.narrative.length" aria-labelledby="bgd-sum" class="card">
            <div class="cap"><h3 id="bgd-sum">Summary</h3><span>Built from the facts below. Each sentence is numbered to its evidence.</span></div>
            <p class="narr">
              <template v-for="(s, i) in view.narrative" :key="i">
                {{ s.text }}<button v-for="r in s.refs" :key="r" type="button" class="ref" :aria-label="`Evidence ${r}`" @click="refTo(r)">{{ r }}</button>{{ ' ' }}
              </template>
            </p>
          </section>

          <section v-if="detail.threat?.narrative" aria-labelledby="bgd-threat" class="card">
            <div class="cap"><h3 id="bgd-threat">What it could do, and how it was set up</h3><span>{{ detail.threat.narrative.summary }}</span></div>
            <p class="imp"><b>{{ detail.threat.impact.level.charAt(0).toUpperCase() + detail.threat.impact.level.slice(1) }} impact.</b> {{ detail.threat.impact.text }}
              <template v-for="k in detail.threat.impact.reach.known" :key="k"> {{ k }}</template>
              <span class="assumed">{{ detail.threat.impact.reach.cannot_measure }}</span></p>
            <ol class="steps">
              <li v-for="(s, i) in detail.threat.narrative.steps" :key="s.key" :class="s.status">
                <span class="si">{{ i + 1 }}</span>
                <div class="sb">
                  <div class="st">{{ s.text }}</div>
                  <div class="sm"><span class="chip" :class="STEP_STATUS[s.status]?.tone">{{ STEP_STATUS[s.status]?.label }}</span>
                    <span class="tech" :title="s.technique.tactic">{{ s.technique.id }} · {{ s.technique.name }}</span></div>
                  <div v-if="s.note" class="sn">{{ s.note }}</div>
                </div>
              </li>
            </ol>
            <p class="assumed">{{ detail.threat.narrative.caveat }} {{ detail.threat.abuse_type.not_used[0] }}</p>
          </section>

          <section v-if="detail.enrichment?.probe" aria-labelledby="bgd-probe">
            <div class="cap"><h3 id="bgd-probe">What its web page showed</h3><span>Loaded once from an isolated machine, read only: nothing was typed or submitted</span></div>
            <ul class="probe">
              <li v-for="(l, i) in probeLines(detail.enrichment.probe)" :key="i" :class="l.tone">{{ l.text }}</li>
            </ul>
            <p class="nfnote">Seen {{ fmtDate(detail.enrichment.probe.at) }}. A page can show scanners something different from what real visitors see, so a clean result does not clear a look-alike.</p>
          </section>

          <section v-if="capture?.available" aria-labelledby="bgd-capture">
            <div class="cap"><h3 id="bgd-capture">How its page looked</h3><span>Analysed in isolation: a disposable browser, nothing typed or submitted</span></div>
            <div v-if="shotUrl && refUrl" class="compare">
              <figure><img :src="refUrl" class="shot" alt="Your own page, taken in the same isolated browser" /><figcaption>Your page</figcaption></figure>
              <figure><img :src="shotUrl" class="shot" alt="The look-alike's page, taken in an isolated browser" /><figcaption>This look-alike</figcaption></figure>
            </div>
            <img v-else-if="shotUrl" :src="shotUrl" class="shot" alt="Screenshot of the look-alike's page, taken in an isolated browser" />
            <p v-else-if="capture.has_screenshot" class="nfnote">The screenshot could not be loaded.</p>
            <ul class="probe">
              <li v-if="capture.title" class="plain">Title when rendered: "{{ capture.title }}"</li>
              <li v-for="(f, i) in capture.forms" :key="i" :class="f.inputs.includes('password') ? 'bad' : 'plain'">
                {{ f.inputs.includes('password') ? 'Password form' : 'Form' }}{{ f.action ? ` that sends to ${f.action}` : ' with no destination (a script handles it)' }}
              </li>
              <li v-if="capture.nav_chain.length > 1" class="warn">It redirected {{ capture.nav_chain.length - 1 }} time(s) before the page loaded.</li>
              <li v-if="capture.stats?.blocked" class="plain">{{ capture.stats.blocked }} request(s) from the page were blocked by the isolation rules.</li>
            </ul>
            <details v-if="capture.text_excerpt" class="rtext">
              <summary>Text on the page (untrusted, as the page wrote it)</summary>
              <p>{{ capture.text_excerpt }}</p>
            </details>
            <p class="nfnote">Captured {{ fmtDate(capture.captured_at) }}. {{ capture.kept_for_case ? 'Kept while this look-alike is a case.' : `Deleted ${fmtDate(capture.retain_until)} unless it becomes a case.` }} It may show other people's data: it is visible only to your workspace.</p>
          </section>

          <section v-if="detail.derivation?.kind" aria-labelledby="bgd-proof">
            <details class="proof">
              <summary class="cap"><h3 id="bgd-proof">How we got here</h3><span>The rule that fired, and every fact under it</span></summary>
              <ul class="tree"><DerivationNode :node="detail.derivation" /></ul>
            </details>
          </section>

          <section aria-labelledby="bgd-ev">
            <div class="cap"><h3 id="bgd-ev">Evidence</h3></div>
            <div class="cols">
              <div class="col for">
                <div class="colh">For impersonation · {{ view.for.length }}</div>
                <p v-if="!view.for.length" class="empty">Nothing beyond a possible name match.</p>
                <div v-for="e in view.for" :id="`ev-${e.n}`" :key="e.id" class="ev">
                  <div class="t"><span class="n">{{ e.n }}</span> {{ e.summary }}</div>
                  <span class="src">{{ e.source }}<template v-if="e.observed_at"> · {{ fmtShort(e.observed_at) }}</template></span>
                </div>
              </div>
              <div class="col against">
                <div class="colh">Against · {{ view.against.length }}</div>
                <p v-if="!view.against.length" class="empty">No sign it is harmless.</p>
                <div v-for="e in view.against" :id="`ev-${e.n}`" :key="e.id" class="ev">
                  <div class="t"><span class="n">{{ e.n }}</span> {{ e.summary }}</div>
                  <span class="src">{{ e.source }}<template v-if="e.observed_at"> · {{ fmtShort(e.observed_at) }}</template></span>
                </div>
              </div>
            </div>
            <div class="nf">
              <div class="colh">Checked, nothing found · not checked</div>
              <p class="nfnote">These are not evidence either way. A missing sign usually proves little.</p>
              <ul>
                <li v-for="(n, i) in view.not_found" :key="i" :class="n.kind"><span>{{ n.text }}</span><em>{{ n.source }}</em></li>
              </ul>
            </div>
          </section>

          <section aria-labelledby="bgd-mail">
            <div class="cap"><h3 id="bgd-mail">Can it send email as you?</h3></div>
            <div class="rows">
              <div class="r"><span class="k">Web</span><span>{{ detail.enrichment?.has_a || detail.enrichment?.has_aaaa ? 'Resolves to a server' : 'Does not resolve' }}</span></div>
              <div class="r"><span class="k">Mail servers</span><span>{{ detail.enrichment?.has_mx ? 'Can receive email' : 'None published' }}</span></div>
              <div v-for="m in mailLines" :key="m.id" class="r"><span class="k">{{ m.source }}</span><span :class="{ good: m.weight < 0 }">{{ m.summary }}</span></div>
            </div>
          </section>

          <section aria-labelledby="bgd-td">
            <div class="cap"><h3 id="bgd-td">Take it down</h3><span>Who can remove it, and a draft you review</span></div>
            <TakedownPanel :candidate-id="candidateId" @changed="load" />
          </section>

          <section v-if="campaignLine" aria-labelledby="bgd-rel">
            <div class="cap"><h3 id="bgd-rel">Related domains</h3></div>
            <p v-if="detail.campaign_id" class="rel">Part of the <RouterLink :to="{ name: 'brand-guard-campaigns', query: { id: detail.campaign_id } }" class="camp">{{ detail.campaign_name }}</RouterLink>. Open it to decide for the whole group at once.</p>
            <p class="rel">{{ campaignLine.summary }}</p>
            <div v-if="siblings.length" class="sibs"><span v-for="s in siblings" :key="s" class="mono sib">{{ s }}</span></div>
          </section>

          <section v-if="timeline" aria-labelledby="bgd-lc">
            <div class="cap"><h3 id="bgd-lc">Lifecycle</h3><span>{{ timeline.stage_label }}</span></div>
            <ol class="ladder">
              <li v-for="r in timeline.ladder" :key="r.stage" :class="{ on: r.reached, cur: r.current }">
                <i /><b>{{ r.label }}</b>
                <small>{{ r.reached ? (r.baseline ? 'already true when first seen' : 'first seen ' + fmtShort(r.first_seen_at)) : 'not seen' }}</small>
              </li>
            </ol>
            <ul v-if="timeline.events?.length" class="events">
              <li v-for="e in timeline.events" :key="e.id">{{ e.summary }}<small>noticed {{ fmtShort(e.occurred_at) }}<template v-if="e.window_start"> · it changed some time after {{ fmtShort(e.window_start) }}</template></small></li>
            </ul>
          </section>

          <section aria-labelledby="bgd-facts">
            <div class="cap"><h3 id="bgd-facts">Facts</h3></div>
            <div class="rows"><div v-for="f in factList" :key="f[0]" class="r"><span class="k">{{ f[0] }}</span><span>{{ f[1] }}</span></div></div>
          </section>
        </template>
      </div>
    </aside>
  </div>
</template>

<style scoped>
.overlay { position: fixed; inset: 0; z-index: 90; background: rgba(4,6,14,.6); display: flex; justify-content: flex-end; }
.drawer { width: 680px; max-width: 100%; height: 100%; background: #0c0e1c; border-left: 1px solid var(--line2); box-shadow: -24px 0 60px rgba(0,0,0,.5); display: flex; flex-direction: column; outline: none; }
.head { padding: 18px 26px 16px; border-bottom: 1px solid var(--line); display: flex; flex-direction: column; gap: 10px; }
.top { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.lbl { font-family: var(--mono); font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
.nav { display: inline-flex; align-items: center; gap: 6px; }
.pos { font-family: var(--mono); font-size: 11px; color: var(--muted); margin-right: 4px; }
.ico { width: 36px; height: 36px; border-radius: 10px; border: 1px solid var(--line2); background: transparent; color: var(--txt); font-size: 18px; line-height: 1; cursor: pointer; }
.ico:disabled { opacity: .35; cursor: default; }
.ico:hover:not(:disabled) { border-color: var(--indigo); }
.dom { margin: 0; font-family: var(--mono); font-size: 21px; font-weight: 600; word-break: break-all; }
.idn { font-family: var(--mono); font-size: 11px; color: var(--amber); }
.verdict-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.conf { font-size: 13px; color: var(--muted); cursor: help; }
.strength { margin: 0; font-size: 12.5px; color: var(--muted); line-height: 1.5; }
.strength b { color: var(--txt); }
.assumed { display: block; margin-top: 2px; color: var(--faint); }
.owner { display: flex; align-items: center; gap: 12px; margin-top: 10px; flex-wrap: wrap; font-size: 12px; color: var(--muted); }
.owner select { margin-left: 6px; background: var(--surface-2, #12162a); color: inherit; border: 1px solid var(--border, #2a2f4a); border-radius: 8px; padding: 4px 8px; font: inherit; }
.pack { display: inline-flex; gap: 6px; align-items: center; }
.pack button { background: rgba(255,255,255,.04); color: var(--txt); border: 1px solid var(--line2); border-radius: 8px; padding: 3px 10px; font: 600 11px var(--mono); cursor: pointer; }
.pack button:hover:not(:disabled) { border-color: var(--indigo); }
.pack button:disabled { opacity: .5; cursor: default; }
.sla { font: 700 11px var(--mono); padding: 2px 9px; border-radius: 999px; }
.sla.ok { background: rgba(60,200,150,.14); color: #6fe0b8; }
.sla.warn { background: rgba(245,197,66,.14); color: #f7d27a; }
.sla.bad { background: rgba(255,77,109,.16); color: #ff8da1; }
.decided { font-size: 12px; font-weight: 700; padding: 3px 10px; border-radius: 999px; background: rgba(91,92,240,.16); color: #b9c0ff; }
.why { margin: 0; font-size: 14.5px; line-height: 1.55; }
.chips { display: flex; gap: 6px; flex-wrap: wrap; }
.chip { font-family: var(--mono); font-size: 10.5px; padding: 3px 9px; border-radius: 10px; background: rgba(255,255,255,.06); color: var(--muted); }
.chip.blocklist, .chip.reported, .chip.spoofer { background: rgba(255,77,109,.16); color: #ff8da1; }
.chip.yours, .chip.popular, .chip.parked { background: rgba(52,224,161,.12); color: var(--good); }
.body { flex: 1; overflow: auto; padding: 20px 26px 36px; display: flex; flex-direction: column; gap: 24px; }
.card { padding: 14px 16px; border-radius: 12px; background: rgba(255,255,255,.03); border: 1px solid var(--line); }
.cap { display: flex; justify-content: space-between; align-items: baseline; gap: 10px; margin-bottom: 8px; }
.cap h3 { margin: 0; font-family: var(--mono); font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
.cap span { font-size: 12px; color: var(--faint); }
.imp { margin: 0 0 10px; font-size: 13.5px; line-height: 1.6; }
.steps { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
.steps li { display: grid; grid-template-columns: 24px 1fr; gap: 10px; }
.si { width: 22px; height: 22px; border-radius: 50%; border: 1.5px solid var(--faint); display: grid; place-items: center; font: 600 11px var(--mono); color: var(--muted); }
.steps li.observed .si { border-color: var(--bad); color: var(--bad); }
.steps li.suspected .si { border-color: var(--warn); color: var(--warn); }
.st { font-size: 13.5px; line-height: 1.45; }
.sm { display: flex; gap: 8px; align-items: center; margin-top: 3px; flex-wrap: wrap; }
.tech { font-family: var(--mono); font-size: 10.5px; color: var(--faint); }
.sn { font-size: 12px; color: var(--muted); margin-top: 2px; }
.chip.type.red { background: rgba(255,77,109,.16); color: #ff8da1; }
.chip.type.amber { background: rgba(245,197,66,.14); color: #f7d27a; }
.chip.type.green { background: rgba(52,224,161,.12); color: var(--good); }
.proof > summary { cursor: pointer; list-style: none; }
.proof .tree { margin: 10px 0 0; padding: 12px 14px; border: 1px solid var(--line); border-radius: 12px; }
.narr { margin: 0; font-size: 14px; line-height: 1.7; }
.ref { font-family: var(--mono); font-size: 11px; font-weight: 700; color: var(--indigo); background: none; border: 0; padding: 0 2px; cursor: pointer; vertical-align: super; }
.ref:hover { color: #fff; }
.cols { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.col { padding: 14px; border-radius: 12px; display: flex; flex-direction: column; gap: 12px; min-width: 0; }
.col.for { border: 1px solid rgba(255,77,109,.3); }
.col.against { border: 1px dashed var(--faint); }
.colh { font-size: 13px; font-weight: 700; }
.for .colh { color: #ff8da1; }
.against .colh { color: var(--txt); }
.ev { display: flex; flex-direction: column; gap: 5px; }
.ev .t { font-size: 13px; line-height: 1.5; }
.n { font-family: var(--mono); color: var(--muted); }
.src { align-self: flex-start; font-family: var(--mono); font-size: 11px; padding: 2px 8px; border-radius: 6px; background: rgba(255,255,255,.06); color: var(--muted); }
.empty { margin: 0; font-size: 12.5px; color: var(--faint); }
.nf { margin-top: 12px; padding: 12px 14px; border-radius: 12px; border: 1px solid var(--line); }
.nf .colh { color: var(--muted); }
.probe { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; font-size: 13px; }
.probe li { padding-left: 14px; position: relative; }
.probe li::before { content: ''; position: absolute; left: 0; top: .55em; width: 6px; height: 6px; border-radius: 50%; background: var(--faint); }
.probe li.bad::before { background: #ff4d6d; }
.probe li.warn::before { background: #f5c542; }
.probe li.ok::before { background: #3cc896; }
.nfnote { margin: 4px 0 8px; font-size: 12px; color: var(--faint); }
.shot { display: block; width: 100%; max-height: 360px; object-fit: contain; object-position: top; border-radius: 10px; border: 1px solid var(--line2); background: rgba(255,255,255,.03); margin-bottom: 10px; }
.compare { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px; }
.compare figure { margin: 0; }
.compare .shot { margin-bottom: 4px; }
.compare figcaption { font-family: var(--mono); font-size: 11px; color: var(--muted); }
@media (max-width: 560px) { .compare { grid-template-columns: 1fr; } }
.rtext { margin-top: 8px; font-size: 12.5px; color: var(--muted); }
.rtext summary { cursor: pointer; }
.rtext p { margin: 6px 0 0; white-space: pre-wrap; word-break: break-word; max-height: 180px; overflow: auto; }
.nf ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
.nf li { display: flex; justify-content: space-between; gap: 12px; font-size: 13px; color: var(--muted); }
.nf li em { font-style: normal; font-family: var(--mono); font-size: 11px; color: var(--faint); white-space: nowrap; }
.rows { border: 1px solid var(--line); border-radius: 12px; overflow: hidden; }
.r { display: grid; grid-template-columns: 130px 1fr; gap: 12px; padding: 10px 14px; border-bottom: 1px solid var(--line); font-size: 13px; }
.r:last-child { border-bottom: 0; }
.k { font-family: var(--mono); font-size: 12px; color: var(--muted); }
.good { color: var(--good); }
.camp { color: var(--indigo); font-weight: 600; text-decoration: none; }
.rel { margin: 0 0 8px; font-size: 13px; line-height: 1.55; }
.sibs { display: flex; gap: 8px; flex-wrap: wrap; }
.sib { font-size: 12px; padding: 5px 10px; border-radius: 8px; background: rgba(255,255,255,.06); }
.mono { font-family: var(--mono); }
.ladder { list-style: none; margin: 0 0 10px; padding: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; }
.ladder li { display: grid; grid-template-columns: 10px 1fr; column-gap: 8px; align-items: center; opacity: .5; }
.ladder li.on { opacity: 1; }
.ladder i { width: 9px; height: 9px; border-radius: 50%; border: 1.5px solid var(--faint); grid-row: span 2; }
.ladder li.on i { background: var(--muted); border-color: var(--muted); }
.ladder li.cur i { background: var(--bad); border-color: var(--bad); }
.ladder b { font-size: 12.5px; font-weight: 600; }
.ladder small, .events small { color: var(--faint); font-size: 11.5px; }
.events { margin: 0; padding-left: 18px; font-size: 12.5px; line-height: 1.7; }
.events small { display: block; }
.err { color: var(--bad); font-size: 13px; }
@media (max-width: 760px) {
  .cols { grid-template-columns: 1fr; }
  .drawer { width: 100%; overflow-y: auto; }
  .body { overflow: visible; flex: none; }
  .r { grid-template-columns: 1fr; gap: 2px; }
  .dom { font-size: 17px; }
}
</style>
