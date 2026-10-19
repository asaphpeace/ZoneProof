<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '@/api/client'
import { useUiStore } from '@/stores/ui'

// The retroactive entry point — without this, only brand-new domains going
// through the wizard ever get the proactive platform-declaration flow.
// PAIN_POINT_RESOLUTION_PLAN.md flagged this gap explicitly: every
// already-onboarded domain was otherwise stuck on passive detection only.
const props = defineProps<{ domainId: string }>()
const emit = defineEmits<{ close: []; added: [] }>()
const ui = useUiStore()

const catalog = ref<any[]>([])
const loading = ref(true)
const mimecastChoiceOpen = ref(false)
const customName = ref('')
const adding = ref<string | null>(null)

onMounted(async () => {
  try {
    catalog.value = await api.platformCatalog()
  } finally {
    loading.value = false
  }
})

async function add(key: string) {
  if (key === 'mimecast') {
    mimecastChoiceOpen.value = true
    return
  }
  adding.value = key
  try {
    await api.declarePlatform(props.domainId, key)
    ui.toast('Platform declared — setup card ready')
    emit('added')
  } finally {
    adding.value = null
  }
}

async function addMimecast(branch: 'direct' | 'relay') {
  mimecastChoiceOpen.value = false
  adding.value = `mimecast_${branch}`
  try {
    await api.declarePlatform(props.domainId, `mimecast_${branch}`)
    ui.toast('Mimecast declared — setup card ready')
    emit('added')
  } finally {
    adding.value = null
  }
}

async function addCustom() {
  if (!customName.value.trim()) return
  adding.value = 'other'
  try {
    await api.declarePlatform(props.domainId, 'other', customName.value.trim())
    ui.toast('Flagged — we don\'t have a setup guide for this one yet')
    emit('added')
  } finally {
    adding.value = null
    customName.value = ''
  }
}
</script>

<template>
  <Teleport to="body">
    <div class="overlay" @click.self="emit('close')">
      <div class="panel">
        <div class="mh">
          <span>Add a sending platform</span>
          <button class="mx" @click="emit('close')">✕</button>
        </div>

        <div v-if="loading" class="loading">Loading…</div>
        <template v-else>
          <div class="tile-grid">
            <button
              v-for="p in catalog" :key="p.key" class="tile"
              :disabled="adding === p.key" @click="add(p.key)"
            >
              {{ adding === p.key ? 'Adding…' : p.name }}
            </button>
          </div>

          <div v-if="mimecastChoiceOpen" class="mimecast-choice">
            <div class="mc-title">How is Mimecast deployed for this domain?</div>
            <button class="mc-option" @click="addMimecast('direct')">
              <b>Sending directly through Mimecast</b>
              <span>Mimecast is the platform itself</span>
            </button>
            <button class="mc-option" @click="addMimecast('relay')">
              <b>Relaying for our own mail server</b>
              <span>DKIM signing usually stays on your server in this mode</span>
            </button>
          </div>

          <div class="custom-row">
            <input v-model="customName" type="text" placeholder="Other platform name" class="custom-input" />
            <button class="btn small" :disabled="!customName.trim() || adding === 'other'" @click="addCustom">Flag it</button>
          </div>
        </template>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.overlay { position: fixed; inset: 0; background: rgba(0,0,0,.6); backdrop-filter: blur(4px); z-index: 300; display: grid; place-items: center; padding: 20px; }
.panel { width: 520px; max-width: 94vw; max-height: 85vh; overflow-y: auto; background: var(--surface-raised); border: 1px solid var(--line2); border-radius: 18px; padding: 22px; box-shadow: 0 30px 80px rgba(0,0,0,.7); }
.mh { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
.mh span { font-family: var(--disp); font-weight: 800; font-size: 15px; }
.mx { background: none; border: 1px solid var(--line); border-radius: 8px; color: var(--muted); width: 26px; height: 26px; cursor: pointer; font-size: 13px; }
.loading { padding: 30px; text-align: center; color: var(--muted); font-family: var(--mono); font-size: 12px; }

.tile-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 9px; margin-bottom: 14px; }
.tile { background: rgba(255,255,255,.03); border: 1px solid var(--line2); border-radius: 11px; padding: 10px; font-size: 12px; color: var(--muted); cursor: pointer; transition: .15s; }
.tile:hover:not(:disabled) { border-color: var(--indigo); color: var(--txt); }
.tile:disabled { opacity: .6; cursor: not-allowed; }

.mimecast-choice { background: rgba(91,92,240,.06); border: 1px solid rgba(91,92,240,.2); border-radius: 12px; padding: 14px; margin-bottom: 14px; }
.mc-title { font-size: 12px; font-weight: 600; color: var(--txt); margin-bottom: 10px; }
.mc-option { display: flex; flex-direction: column; gap: 2px; width: 100%; text-align: left; background: rgba(255,255,255,.03); border: 1px solid var(--line); border-radius: 10px; padding: 9px 11px; margin-bottom: 7px; cursor: pointer; color: var(--txt); font-size: 11.5px; }
.mc-option span { font-size: 10.5px; color: var(--faint); font-weight: 400; }

.custom-row { display: flex; gap: 8px; }
.custom-input { flex: 1; background: rgba(255,255,255,.04); border: 1px solid var(--line2); border-radius: 9px; padding: 8px 12px; font-size: 12px; color: var(--txt); outline: none; }
.custom-input:focus { border-color: var(--indigo); }
.btn.small { background: rgba(91,92,240,.16); border: 1px solid rgba(91,92,240,.35); color: #9aa6ff; border-radius: 9px; padding: 8px 14px; font-size: 11.5px; font-weight: 700; cursor: pointer; }
.btn.small:disabled { opacity: .5; cursor: not-allowed; }
</style>
