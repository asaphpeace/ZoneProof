<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useDomainsStore } from '@/stores/domains'

const emit = defineEmits<{ next: [domains: string[]] }>()

const domains     = useDomainsStore()
const raw         = ref('')
const queued      = ref<string[]>([])
const error       = ref('')

onMounted(() => { if (!domains.list.length) domains.fetch() })

const existingSet = computed(() => new Set(domains.list.map(d => d.domain)))

function parseDomains(v: string) {
  return v.split(/[\s,;\n]+/).map(d => d.trim().toLowerCase()).filter(Boolean)
}

function addTag(e: KeyboardEvent) {
  if (e.key === 'Enter' || e.key === ',') {
    e.preventDefault()
    const val = (e.target as HTMLInputElement).value.trim()
    if (!val) return
    const parsed = parseDomains(val)
    for (const d of parsed) {
      if (!queued.value.includes(d)) queued.value.push(d)
    }
    raw.value = ''
  }
}

function removeTag(i: number) { queued.value.splice(i, 1) }

function pasteHandler(e: ClipboardEvent) {
  e.preventDefault()
  const text = e.clipboardData?.getData('text') ?? ''
  const parsed = parseDomains(text)
  for (const d of parsed) {
    if (!queued.value.includes(d)) queued.value.push(d)
  }
}

// Bulk CSV/text file import — for MSPs onboarding many client domains at
// once. Accepts any plain-text or .csv file: one domain per line, or a
// comma-separated row (e.g. exported from a spreadsheet). A header row like
// "domain" or "name" is dropped automatically rather than queued as a
// (invalid) domain. Everything downstream — DMARC check, TLS info, confirm —
// is unchanged; this just populates the same `queued` list manual entry does.
const fileInput = ref<HTMLInputElement | null>(null)
const fileError  = ref('')

function triggerFileUpload() { fileInput.value?.click() }

function onFileSelected(e: Event) {
  fileError.value = ''
  const file = (e.target as HTMLInputElement).files?.[0]
  if (!file) return
  const reader = new FileReader()
  reader.onload = () => {
    const text = String(reader.result || '')
    const candidates = parseDomains(text).filter(
      d => !['domain', 'domains', 'name', 'names', 'hostname'].includes(d)
    )
    const valid = candidates.filter(d => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d))
    const skipped = candidates.length - valid.length
    let added = 0
    for (const d of valid) {
      if (!queued.value.includes(d)) { queued.value.push(d); added++ }
    }
    if (skipped > 0) fileError.value = `Imported ${added} domain${added !== 1 ? 's' : ''} — skipped ${skipped} unrecognised line${skipped !== 1 ? 's' : ''}`
  }
  reader.onerror = () => { fileError.value = 'Could not read that file' }
  reader.readAsText(file)
  ;(e.target as HTMLInputElement).value = ''  // allow re-selecting the same file
}

function next() {
  if (!queued.value.length) { error.value = 'Add at least one domain'; return }
  const invalid = queued.value.filter(d => !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d))
  if (invalid.length) { error.value = `Invalid format: ${invalid.join(', ')}`; return }
  error.value = ''
  emit('next', [...queued.value])
}

const newCount      = computed(() => queued.value.filter(d => !existingSet.value.has(d)).length)
const existingCount = computed(() => queued.value.filter(d => existingSet.value.has(d)).length)
</script>

<template>
  <div>
    <div class="sh">Add domains</div>
    <p class="hint">Enter one or more domains. Press Enter or comma to add each one. Paste a list and we'll split it automatically.</p>

    <div class="tag-input" :class="{ focused: true }">
      <span v-for="(d, i) in queued" :key="d" class="tag" :class="existingSet.has(d) ? 'tag-existing' : ''">
        <span v-if="existingSet.has(d)" class="tag-badge">monitored</span>
        {{ d }}
        <button @click="removeTag(i)">×</button>
      </span>
      <input
        v-model="raw"
        type="text"
        placeholder="example.com, another.org…"
        @keydown="addTag"
        @paste="pasteHandler"
      />
    </div>

    <div v-if="queued.length" class="summary">
      <span v-if="newCount">
        <b class="hi">{{ newCount }}</b> new domain{{ newCount !== 1 ? 's' : '' }}
      </span>
      <span v-if="newCount && existingCount"> · </span>
      <span v-if="existingCount">
        <b class="warn">{{ existingCount }}</b> already monitored — wizard will let you skip or re-onboard
      </span>
    </div>

    <div v-if="error" class="err">{{ error }}</div>

    <div class="bulk-import">
      <input ref="fileInput" type="file" accept=".csv,.txt" class="file-input-hidden" @change="onFileSelected"/>
      <button type="button" class="bulk-btn" @click="triggerFileUpload">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
        Import from CSV or text file
      </button>
      <span v-if="fileError" class="file-note">{{ fileError }}</span>
    </div>

    <div class="actions">
      <button class="btn" :disabled="!queued.length" @click="next">
        Next <span v-if="queued.length > 1">({{ queued.length }} domains)</span> →
      </button>
    </div>
  </div>
</template>

<style scoped>
.sh { font-family: var(--disp); font-weight: 800; font-size: 18px; margin-bottom: 8px; }
.hint { color: var(--muted); font-size: 13px; line-height: 1.6; margin-bottom: 18px; }
.tag-input { display: flex; flex-wrap: wrap; gap: 8px; padding: 12px 14px; background: rgba(255,255,255,.04); border: 1px solid var(--line2); border-radius: 14px; min-height: 56px; align-items: center; }
.tag { display: flex; align-items: center; gap: 6px; font-family: var(--mono); font-size: 11.5px; padding: 4px 10px; background: rgba(91,92,240,.2); border: 1px solid rgba(91,92,240,.4); border-radius: 20px; color: #9aa6ff; }
.tag-existing { background: rgba(255,190,0,.12); border-color: rgba(255,190,0,.35); color: var(--amber); }
.tag-badge { font-size: 9px; text-transform: uppercase; letter-spacing: .6px; background: rgba(255,190,0,.2); border-radius: 6px; padding: 1px 5px; }
.tag button { background: none; border: none; color: inherit; cursor: pointer; padding: 0; font-size: 14px; line-height: 1; opacity: .7; }
.tag button:hover { opacity: 1; }
.tag-input input { flex: 1; min-width: 180px; background: none; border: none; outline: none; color: var(--txt); font-family: var(--body); font-size: 13px; padding: 4px 0; }
.summary { margin-top: 10px; font-size: 12.5px; color: var(--muted); }
.hi { color: var(--teal); }
.warn { color: var(--amber); }
.err { color: var(--bad); font-size: 12px; margin-top: 8px; }

.bulk-import { display: flex; align-items: center; gap: 10px; margin-top: 14px; }
.file-input-hidden { display: none; }
.bulk-btn {
  display: flex; align-items: center; gap: 7px; padding: 8px 14px; border-radius: 10px;
  background: rgba(255,255,255,.04); border: 1px dashed var(--line2); color: var(--muted);
  font-family: var(--body); font-size: 12px; cursor: pointer; transition: .15s;
}
.bulk-btn:hover { background: rgba(255,255,255,.07); color: var(--txt); border-color: var(--indigo); }
.bulk-btn svg { width: 14px; height: 14px; }
.file-note { font-size: 11.5px; color: var(--amber); }

.actions { margin-top: 24px; display: flex; justify-content: flex-end; }
.btn { background: linear-gradient(90deg,#5b5cf0,#4b4ce0); color:#fff; border:none; border-radius:12px; padding:11px 24px; font-family:var(--disp); font-weight:700; font-size:13px; cursor:pointer; }
.btn:disabled { opacity:.5; cursor:not-allowed; }
</style>
