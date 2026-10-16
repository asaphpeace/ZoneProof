<script setup lang="ts">
import { ref, watch } from 'vue'
import { api } from '@/api/client'

// Who can remove this look-alike, a draft complaint to each, and a record of what happened. ZoneProof never sends anything: a person
// reviews and approves the text, sends it themselves (mail link, copy, or the provider's form), then records that it was sent.
const props = defineProps<{ candidateId: string }>()
const emit = defineEmits<{ changed: [] }>()

const routes = ref<any[]>([])
const takedowns = ref<any[]>([])
const finding = ref(false)
const busy = ref('')
const error = ref('')
const edits = ref<Record<string, { subject: string; body: string }>>({})
const notes = ref<Record<string, string>>({})

const STATUS_LABEL: Record<string, string> = { draft: 'Draft', approved: 'Approved, not yet sent', sent: 'Sent', acknowledged: 'Acknowledged', removed: 'Removed', rejected: 'Rejected' }
const MOVE_LABEL: Record<string, string> = { approved: 'Approve this text', draft: 'Back to draft', sent: 'I sent it', acknowledged: 'They acknowledged', removed: 'It was taken down', rejected: 'They declined' }

async function loadTakedowns() {
  try {
    takedowns.value = await api.brandTakedowns(props.candidateId)
    for (const t of takedowns.value) if (!edits.value[t.id]) edits.value[t.id] = { subject: t.subject, body: t.body }
  } catch (e: any) { error.value = e.message }
}
watch(() => props.candidateId, () => { routes.value = []; takedowns.value = []; edits.value = {}; error.value = ''; loadTakedowns() }, { immediate: true })

async function findRoutes() {
  finding.value = true
  error.value = ''
  try { routes.value = (await api.brandTakedownRoutes(props.candidateId)).routes } catch (e: any) { error.value = e.message || 'Could not look up contacts' } finally { finding.value = false }
}
async function draft(route: any) {
  busy.value = route.kind
  try { await api.brandTakedownCreate(props.candidateId, route); await loadTakedowns(); emit('changed') } catch (e: any) { error.value = e.message } finally { busy.value = '' }
}
async function save(t: any) {
  busy.value = t.id
  try { await api.brandTakedownEdit(t.id, edits.value[t.id].subject, edits.value[t.id].body); await loadTakedowns() } catch (e: any) { error.value = e.message } finally { busy.value = '' }
}
async function move(t: any, status: string) {
  busy.value = t.id
  try { await api.brandTakedownMove(t.id, status, notes.value[t.id] || undefined); await loadTakedowns(); emit('changed') } catch (e: any) { error.value = e.message } finally { busy.value = '' }
}
async function copy(t: any) {
  try { await navigator.clipboard.writeText(`${t.subject}\n\n${t.body}`) } catch { error.value = 'Could not copy. Select the text and copy it by hand.' }
}
</script>

<template>
  <div class="tk">
    <p class="lead">ZoneProof drafts the complaint; you review it, send it yourself, and record what happens. Nothing is sent from here.</p>
    <p v-if="error" class="err" role="alert">{{ error }}</p>

    <button v-if="!routes.length" type="button" class="btn" :disabled="finding" @click="findRoutes">{{ finding ? 'Looking up contacts…' : 'Find who can remove it' }}</button>
    <ul v-else class="routes">
      <li v-for="r in routes" :key="r.kind + r.target">
        <div class="rh"><b>{{ r.label }}</b>
          <span class="cert" :class="r.certainty" :title="r.certainty === 'discovered' ? 'Read from a public record just now' : 'A well-known route we cannot verify from here: confirm the current contact before relying on it'">{{ r.certainty === 'discovered' ? 'Found' : 'Suggested: confirm first' }}</span></div>
        <div v-if="r.target" class="tg">{{ r.how === 'form' ? 'Report form' : 'Email' }}: <a v-if="r.how === 'form'" :href="r.target" target="_blank" rel="noopener noreferrer">{{ r.target }}</a><span v-else class="mono">{{ r.target }}</span></div>
        <p class="nt">{{ r.note }}</p>
        <button type="button" class="btn sm" :disabled="busy === r.kind" @click="draft(r)">Draft a complaint</button>
      </li>
    </ul>

    <div v-for="t in takedowns" :key="t.id" class="td">
      <div class="th"><b>{{ t.route_label }}</b><span class="st" :class="t.status">{{ STATUS_LABEL[t.status] }}</span></div>
      <p v-if="t.status === 'draft' && t.evidence_level === 'name_only'" class="basis warn">
        Based on the domain name only. No page content has been captured, so the complaint says so. Most providers act on page content or a blocklist listing.
      </p>
      <p v-else-if="t.status === 'draft' && t.evidence_level === 'page_evidence'" class="basis">
        Based on what was captured from the page or a public listing. Private reports and cluster inferences are never included.
      </p>
      <template v-if="t.status === 'draft'">
        <label class="sr" :for="`s-${t.id}`">Subject</label>
        <input :id="`s-${t.id}`" v-model="edits[t.id].subject" class="in" />
        <label class="sr" :for="`b-${t.id}`">Message</label>
        <textarea :id="`b-${t.id}`" v-model="edits[t.id].body" class="in" rows="12" />
        <button type="button" class="btn sm" :disabled="busy === t.id" @click="save(t)">Save changes</button>
      </template>
      <template v-else>
        <div class="sub">{{ t.subject }}</div>
        <pre class="body">{{ t.body }}</pre>
        <div class="acts">
          <a v-if="t.mailto" class="btn sm" :href="t.mailto">Open in your mail app</a>
          <button type="button" class="btn sm" @click="copy(t)">Copy text</button>
          <a v-if="t.how === 'form'" class="btn sm" :href="t.target" target="_blank" rel="noopener noreferrer">Open the form</a>
        </div>
      </template>
      <div v-if="t.sent_at" class="meta">Marked sent {{ t.sent_at.slice(0, 10) }}.</div>
      <div v-if="t.outcome_note" class="meta">Note: {{ t.outcome_note }}</div>
      <div v-if="t.allowed_next.length" class="mv">
        <input v-model="notes[t.id]" class="in note" placeholder="Optional note (what they said)" :aria-label="`Note for ${t.route_label}`" />
        <button v-for="n in t.allowed_next" :key="n" type="button" class="btn sm" :class="{ primary: n === 'approved' }" :disabled="busy === t.id" @click="move(t, n)">{{ MOVE_LABEL[n] }}</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.lead { margin: 0 0 10px; font-size: 12.5px; color: var(--muted); }
.err { color: #ff8da1; font-size: 12.5px; }
.btn { background: rgba(255,255,255,.04); color: var(--txt); border: 1px solid var(--line2); border-radius: 8px; padding: 6px 12px; font: 600 12px var(--mono); cursor: pointer; text-decoration: none; display: inline-block; }
.btn.sm { padding: 4px 10px; font-size: 11px; }
.btn.primary { background: linear-gradient(90deg, #5b5cf0, #4b4ce0); border-color: transparent; color: #fff; }
.btn:disabled { opacity: .5; cursor: default; }
.routes { list-style: none; padding: 0; margin: 0 0 14px; display: grid; gap: 10px; }
.routes li, .td { border: 1px solid var(--line2); border-radius: 12px; padding: 12px; background: rgba(255,255,255,.02); }
.td { margin-top: 12px; }
.rh, .th { display: flex; justify-content: space-between; gap: 8px; align-items: center; flex-wrap: wrap; }
.cert { font: 700 10.5px var(--mono); padding: 2px 8px; border-radius: 999px; cursor: help; }
.basis { margin: 6px 0 8px; font-size: 12px; color: var(--muted); }
.basis.warn { color: #f3c969; }
.cert.discovered { background: rgba(60,200,150,.14); color: #6fe0b8; }
.cert.suggested { background: rgba(245,197,66,.14); color: #f7d27a; }
.tg { font-size: 12.5px; margin-top: 4px; }
.mono { font-family: var(--mono); }
.nt { margin: 6px 0 8px; font-size: 12px; color: var(--faint); }
.st { font: 700 10.5px var(--mono); padding: 2px 9px; border-radius: 999px; background: rgba(91,92,240,.16); color: #b9c0ff; }
.st.removed { background: rgba(60,200,150,.14); color: #6fe0b8; }
.st.rejected { background: rgba(255,77,109,.16); color: #ff8da1; }
.in { width: 100%; box-sizing: border-box; margin: 6px 0; background: rgba(255,255,255,.04); border: 1px solid var(--line2); border-radius: 8px; color: var(--txt); padding: 8px 10px; font: 13px var(--body); }
textarea.in { font-family: var(--mono); font-size: 12px; resize: vertical; }
.body { white-space: pre-wrap; font: 12px/1.5 var(--mono); background: rgba(255,255,255,.03); padding: 10px; border-radius: 8px; margin: 6px 0; }
.sub { font-weight: 700; font-size: 13px; margin-top: 6px; }
.acts, .mv { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-top: 8px; }
.mv .note { flex: 1 1 200px; margin: 0; }
.meta { font-size: 12px; color: var(--muted); margin-top: 6px; }
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
</style>
