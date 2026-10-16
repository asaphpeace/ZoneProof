<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '@/api/client'
import { useDomainsStore } from '@/stores/domains'
import { useUiStore } from '@/stores/ui'
import PlatformSetupModal from '@/components/domain/PlatformSetupModal.vue'

// Runs after WizardStep4Confirm activates the domains — proactive
// declaration before any DMARC data exists, but with real domain IDs
// available (the declare endpoint needs an activated Domain row).
// See PAIN_POINT_RESOLUTION_PLAN.md Pain 1.
const props = defineProps<{ domainNames: string[] }>()
const emit  = defineEmits<{ done: [] }>()

const domainsStore = useDomainsStore()
const ui = useUiStore()

const catalog = ref<any[]>([])
const selected = ref<Set<string>>(new Set())
const mimecastChoiceOpen = ref(false)
const customOpen = ref(false)
const customName = ref('')
const loading = ref(true)
const saving = ref(false)
const detecting = ref(false)
const detectResult = ref<string | null>(null)
const setupModalKey = ref<string | null>(null)
const domainIds = ref<string[]>([])

onMounted(async () => {
  try {
    const [cat] = await Promise.all([api.platformCatalog(), domainsStore.fetch()])
    catalog.value = cat
    domainIds.value = domainsStore.list
      .filter((d: any) => props.domainNames.includes(d.domain))
      .map((d: any) => d.id)
  } finally {
    loading.value = false
  }
})

function toggleTile(key: string) {
  if (key === 'mimecast') {
    mimecastChoiceOpen.value = true
    return
  }
  const next = new Set(selected.value)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  selected.value = next
}

function chooseMimecastBranch(branch: 'direct' | 'relay') {
  const next = new Set(selected.value)
  next.delete('mimecast_direct')
  next.delete('mimecast_relay')
  next.add(`mimecast_${branch}`)
  selected.value = next
  mimecastChoiceOpen.value = false
}

function previewSetup(key: string) {
  setupModalKey.value = key
}

async function finish() {
  saving.value = true
  try {
    for (const domainId of domainIds.value) {
      for (const key of selected.value) {
        await api.declarePlatform(domainId, key)
      }
      if (customName.value.trim()) {
        await api.declarePlatform(domainId, 'other', customName.value.trim())
      }
    }
    if (selected.value.size || customName.value.trim()) {
      ui.toast('Sending platforms declared — setup cards are ready on each domain')
    }
  } catch (e: any) {
    ui.toast(e.message || 'Failed to declare platforms')
  } finally {
    saving.value = false
    emit('done')
  }
}

function skip() {
  emit('done')
}

async function detectFromDns() {
  if (!props.domainNames.length) return
  detecting.value = true
  detectResult.value = null
  try {
    const domain = props.domainNames[0]
    const { detected, mimecast_detected } = await api.wizardDetectPlatforms(domain)

    const next = new Set(selected.value)
    let added = 0

    for (const key of detected) {
      if (!next.has(key)) { next.add(key); added++ }
    }
    if (mimecast_detected) {
      // Surface the Mimecast branch choice — just open the picker
      mimecastChoiceOpen.value = true
    }

    selected.value = next

    if (added === 0 && !mimecast_detected) {
      detectResult.value = 'No known platforms detected in DNS — select manually or skip.'
    } else {
      const parts: string[] = []
      if (added) parts.push(`${added} platform${added > 1 ? 's' : ''} detected`)
      if (mimecast_detected) parts.push('Mimecast detected — choose your deployment mode below')
      detectResult.value = parts.join('. ')
    }
  } catch {
    detectResult.value = 'DNS probe failed — select platforms manually.'
  } finally {
    detecting.value = false
  }
}
</script>

<template>
  <div>
    <div class="sh">Which platforms send mail for {{ domainNames.length > 1 ? 'these domains' : domainNames[0] }}?</div>
    <p class="hint">
      Declaring a platform now generates its exact SPF/DKIM setup before any DMARC data
      even exists — no waiting for a real report to reveal a problem days later.
    </p>

    <div v-if="loading" class="loading-state">Loading platforms…</div>
    <template v-else>
      <div class="tile-grid">
        <button
          v-for="p in catalog" :key="p.key"
          class="tile"
          :class="{ active: selected.has(p.key) || (p.key === 'mimecast' && (selected.has('mimecast_direct') || selected.has('mimecast_relay'))) }"
          @click="toggleTile(p.key)"
        >
          {{ p.name }}
          <span v-if="p.key === 'mimecast' && selected.has('mimecast_direct')" class="tile-branch">direct</span>
          <span v-if="p.key === 'mimecast' && selected.has('mimecast_relay')" class="tile-branch">relay</span>
        </button>
        <button class="tile other" :class="{ active: customOpen }" @click="customOpen = !customOpen">+ Other</button>
      </div>

      <div v-if="customOpen" class="custom-row">
        <input v-model="customName" type="text" placeholder="Platform name" class="custom-input" />
        <span class="custom-hint">We don't have a setup guide for this yet — flagging it helps us prioritize which to add next.</span>
      </div>

      <!-- Mimecast deployment-mode choice — it has no single profile -->
      <div v-if="mimecastChoiceOpen" class="mimecast-choice">
        <div class="mc-title">How is Mimecast deployed for this domain?</div>
        <button class="mc-option" @click="chooseMimecastBranch('direct')">
          <b>Sending directly through Mimecast</b>
          <span>Mimecast is the platform itself — like SendGrid or Mailchimp</span>
        </button>
        <button class="mc-option" @click="chooseMimecastBranch('relay')">
          <b>Mimecast relaying for our own mail server</b>
          <span>Exchange/Postfix/etc. behind a Mimecast gateway — DKIM signing usually stays on your server</span>
        </button>
      </div>

      <!-- Quick preview of a selected platform's setup card -->
      <div v-if="selected.size" class="selected-list">
        <span class="selected-label">Selected:</span>
        <button v-for="key in selected" :key="key" class="selected-chip" @click="previewSetup(key)">
          {{ key.replace('_', ' ') }} — preview setup
        </button>
      </div>
    </template>

    <div v-if="detectResult" class="detect-result" :class="{ warn: detectResult.startsWith('No') || detectResult.startsWith('DNS') }">
      {{ detectResult }}
    </div>

    <div class="actions">
      <div class="actions-left">
        <button class="btn ghost detect-btn" :disabled="detecting" @click="detectFromDns">
          <span v-if="detecting" class="spinner" />
          {{ detecting ? 'Scanning DNS…' : 'Detect from DNS' }}
        </button>
        <button class="btn ghost" @click="skip">Skip</button>
      </div>
      <button class="btn" :disabled="saving" @click="finish">
        {{ saving ? 'Saving…' : 'Finish' }}
      </button>
    </div>

    <PlatformSetupModal
      v-if="setupModalKey && domainIds.length"
      :domain-id="domainIds[0]"
      :platform-key="setupModalKey"
      @close="setupModalKey = null"
      @done="setupModalKey = null"
    />
  </div>
</template>

<style scoped>
.sh { font-family: var(--disp); font-weight: 800; font-size: 16px; margin-bottom: 6px; }
.hint { font-size: 12.5px; color: var(--muted); line-height: 1.55; margin-bottom: 18px; }
.loading-state { padding: 30px; text-align: center; color: var(--muted); font-family: var(--mono); font-size: 12px; }

.tile-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 14px; }
@media (max-width: 560px) { .tile-grid { grid-template-columns: repeat(2, 1fr); } }
.tile {
  background: rgba(255,255,255,.03); border: 1px solid var(--line2); border-radius: 12px;
  padding: 12px 10px; font-size: 12px; color: var(--muted); cursor: pointer; transition: .15s;
  text-align: center; position: relative;
}
.tile:hover { border-color: var(--indigo); color: var(--txt); }
.tile.active { background: rgba(91,92,240,.14); border-color: var(--indigo); color: #9aa6ff; font-weight: 600; }
.tile.other { border-style: dashed; }
.tile-branch { display: block; font-family: var(--mono); font-size: 9px; color: var(--teal); margin-top: 3px; }

.custom-row { margin-bottom: 14px; }
.custom-input { width: 100%; background: rgba(255,255,255,.04); border: 1px solid var(--line2); border-radius: 9px; padding: 9px 12px; font-size: 12.5px; color: var(--txt); outline: none; margin-bottom: 6px; }
.custom-input:focus { border-color: var(--indigo); }
.custom-hint { font-size: 10.5px; color: var(--faint); }

.mimecast-choice { background: rgba(91,92,240,.06); border: 1px solid rgba(91,92,240,.2); border-radius: 12px; padding: 14px; margin-bottom: 14px; }
.mc-title { font-size: 12.5px; font-weight: 600; color: var(--txt); margin-bottom: 10px; }
.mc-option {
  display: flex; flex-direction: column; gap: 2px; width: 100%; text-align: left;
  background: rgba(255,255,255,.03); border: 1px solid var(--line); border-radius: 10px;
  padding: 10px 12px; margin-bottom: 8px; cursor: pointer; color: var(--txt); font-size: 12px;
}
.mc-option:hover { border-color: var(--indigo); }
.mc-option span { font-size: 11px; color: var(--faint); font-weight: 400; }

.selected-list { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; margin-bottom: 14px; }
.selected-label { font-family: var(--mono); font-size: 9px; text-transform: uppercase; letter-spacing: .5px; color: var(--faint); }
.selected-chip { font-family: var(--mono); font-size: 10.5px; background: rgba(46,230,197,.1); color: var(--teal); border: 1px solid rgba(46,230,197,.25); border-radius: 8px; padding: 4px 10px; cursor: pointer; }

.detect-result { font-size: 11.5px; color: var(--teal); background: rgba(46,230,197,.08); border: 1px solid rgba(46,230,197,.2); border-radius: 9px; padding: 8px 12px; margin-bottom: 10px; }
.detect-result.warn { color: var(--muted); background: rgba(255,255,255,.03); border-color: var(--line2); }
.actions { display: flex; justify-content: space-between; align-items: center; gap: 10px; margin-top: 18px; }
.actions-left { display: flex; gap: 8px; }
.detect-btn { display: flex; align-items: center; gap: 6px; }
.spinner { width: 11px; height: 11px; border: 1.5px solid rgba(255,255,255,.2); border-top-color: var(--teal); border-radius: 50%; animation: spin .7s linear infinite; flex-shrink: 0; }
@keyframes spin { to { transform: rotate(360deg); } }
.btn { background: linear-gradient(90deg,#5b5cf0,#4b4ce0); color: #fff; border: none; border-radius: 12px; padding: 11px 18px; font-family: var(--disp); font-weight: 700; font-size: 13px; cursor: pointer; }
.btn.ghost { background: rgba(255,255,255,.04); border: 1px solid var(--line2); color: var(--txt); box-shadow: none; }
.btn:disabled { opacity: .6; cursor: not-allowed; }
</style>
