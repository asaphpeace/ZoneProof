<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '@/api/client'
import { useUiStore } from '@/stores/ui'
import PlatformSetupModal from './PlatformSetupModal.vue'
import AddPlatformModal from './AddPlatformModal.vue'

const props = defineProps<{ domainId: string }>()
const ui = useUiStore()

const rows = ref<any[]>([])
const loading = ref(true)
const setupModalKey = ref<string | null>(null)
const showAddModal = ref(false)
const removing = ref<string | null>(null)

async function load() {
  loading.value = true
  try {
    rows.value = await api.platformStatus(props.domainId)
  } finally {
    loading.value = false
  }
}

onMounted(load)

function onAdded() {
  showAddModal.value = false
  load()
}

async function remove(key: string) {
  if (!confirm('Remove this platform? It will drop out of your combined SPF record on the next setup view.')) return
  removing.value = key
  try {
    await api.removePlatform(props.domainId, key)
    ui.toast('Platform removed')
    await load()
  } finally {
    removing.value = null
  }
}

const STATUS_COLOR: Record<string, string> = {
  included: 'var(--good)', configured: 'var(--good)', aligned: 'var(--good)',
  missing: 'var(--bad)', not_configured: 'var(--bad)', unaligned: 'var(--bad)',
  unknown: 'var(--faint)',
}
</script>

<template>
  <div class="matrix-card">
    <div class="mc-header">
      <div class="mc-title">Sending platforms</div>
      <button class="add-btn" @click="showAddModal = true">+ Add a sending platform</button>
    </div>

    <div v-if="loading" class="empty">Loading…</div>
    <div v-else-if="!rows.length" class="empty">
      No sending platforms declared or detected yet. Add one, or wait for real DMARC reports to reveal them automatically.
    </div>
    <template v-else>
      <div class="thead">
        <span>Platform</span>
        <span>SPF</span>
        <span>DKIM</span>
        <span>Alignment</span>
        <span></span>
      </div>
      <div v-for="r in rows" :key="r.key" class="row">
        <div class="cell-name">
          {{ r.name }}
          <span v-if="r.declared" class="tag declared">declared</span>
          <span v-if="r.detected" class="tag detected">detected</span>
        </div>
        <span class="cell-status" :style="`color:${STATUS_COLOR[r.spf_status]}`">{{ r.spf_status.replace('_', ' ') }}</span>
        <span class="cell-status" :style="`color:${STATUS_COLOR[r.dkim_status]}`">{{ r.dkim_status.replace('_', ' ') }}</span>
        <span class="cell-status" :style="`color:${STATUS_COLOR[r.alignment_status]}`">{{ r.alignment_status.replace('_', ' ') }}</span>
        <div class="cell-actions">
          <button class="fix-btn" @click="setupModalKey = r.key">View setup</button>
          <button v-if="r.declared" class="remove-btn" :disabled="removing === r.key" @click="remove(r.key)">
            {{ removing === r.key ? '…' : 'Remove' }}
          </button>
        </div>
      </div>
    </template>

    <PlatformSetupModal
      v-if="setupModalKey"
      :domain-id="domainId"
      :platform-key="setupModalKey"
      @close="setupModalKey = null"
      @done="setupModalKey = null; load()"
    />
    <AddPlatformModal
      v-if="showAddModal"
      :domain-id="domainId"
      @close="showAddModal = false"
      @added="onAdded"
    />
  </div>
</template>

<style scoped>
.matrix-card {
  background: var(--glass); border: 1px solid var(--line2); border-radius: 16px;
  padding: 18px 20px; margin-bottom: 20px;
}
.mc-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
.mc-title { font-family: var(--disp); font-weight: 700; font-size: 14px; }
.add-btn {
  background: rgba(91,92,240,.12); border: 1px solid rgba(91,92,240,.3); color: #9aa6ff;
  border-radius: 10px; padding: 7px 14px; font-family: var(--disp); font-weight: 700; font-size: 12px; cursor: pointer;
}
.add-btn:hover { background: rgba(91,92,240,.2); }
.empty { font-size: 12.5px; color: var(--muted); padding: 14px 0; }

.thead {
  display: grid; grid-template-columns: 1.6fr .8fr .8fr .8fr 1.4fr;
  gap: 10px; font-family: var(--mono); font-size: 9px; letter-spacing: .8px; text-transform: uppercase;
  color: var(--faint); padding: 0 4px 9px; border-bottom: 1px solid var(--line);
}
.row {
  display: grid; grid-template-columns: 1.6fr .8fr .8fr .8fr 1.4fr;
  gap: 10px; align-items: center; padding: 11px 4px; border-bottom: 1px solid rgba(255,255,255,.04);
}
.cell-name { font-size: 12.5px; color: var(--txt); display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.tag { font-family: var(--mono); font-size: 8px; font-weight: 700; padding: 2px 6px; border-radius: 6px; }
.tag.declared { background: rgba(91,92,240,.16); color: #9aa6ff; }
.tag.detected { background: rgba(46,230,197,.14); color: var(--teal); }
.cell-status { font-family: var(--mono); font-size: 11px; text-transform: capitalize; }
.cell-actions { display: flex; gap: 6px; justify-content: flex-end; }
.fix-btn {
  background: none; border: 1px solid var(--line2); border-radius: 8px; color: var(--muted);
  padding: 5px 10px; font-size: 11px; cursor: pointer;
}
.fix-btn:hover { border-color: var(--indigo); color: var(--txt); }
.remove-btn {
  background: none; border: 1px solid rgba(255,77,109,.25); border-radius: 8px; color: var(--bad);
  padding: 5px 10px; font-size: 11px; cursor: pointer;
}
.remove-btn:disabled { opacity: .6; cursor: not-allowed; }
</style>
