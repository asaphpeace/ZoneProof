<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { api } from '@/api/client'

const emit = defineEmits<{ close: [] }>()
const concepts = ref<any[]>([])
const loading = ref(true)
const search = ref('')

onMounted(async () => {
  try {
    concepts.value = await api.conceptsAll()
  } finally {
    loading.value = false
  }
})

const filtered = computed(() => {
  const q = search.value.trim().toLowerCase()
  if (!q) return concepts.value
  return concepts.value.filter(c => c.term.toLowerCase().includes(q) || c.text.toLowerCase().includes(q))
})
</script>

<template>
  <Teleport to="body">
    <div class="overlay" @click.self="emit('close')">
      <div class="panel">
        <div class="mh">
          <span>Glossary</span>
          <button class="mx" @click="emit('close')">✕</button>
        </div>
        <input v-model="search" type="text" placeholder="Search terms…" class="search-input" />
        <div v-if="loading" class="loading">Loading…</div>
        <div v-else class="entries">
          <div v-for="c in filtered" :key="c.id" class="entry">
            <div class="entry-term">{{ c.term }} <span v-if="c.seen" class="seen-tag">seen</span></div>
            <p class="entry-text">{{ c.text }}</p>
          </div>
          <div v-if="!filtered.length" class="empty">No terms match "{{ search }}"</div>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.overlay { position: fixed; inset: 0; background: rgba(0,0,0,.6); backdrop-filter: blur(4px); z-index: 400; display: grid; place-items: center; padding: 20px; }
.panel { width: 520px; max-width: 94vw; max-height: 80vh; overflow-y: auto; background: var(--surface-raised); border: 1px solid var(--line2); border-radius: 18px; padding: 22px; box-shadow: 0 30px 80px rgba(0,0,0,.7); }
.mh { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; }
.mh span { font-family: var(--disp); font-weight: 800; font-size: 16px; }
.mx { background: none; border: 1px solid var(--line); border-radius: 8px; color: var(--muted); width: 28px; height: 28px; cursor: pointer; font-size: 14px; }
.search-input { width: 100%; background: rgba(255,255,255,.04); border: 1px solid var(--line2); border-radius: 10px; padding: 9px 13px; font-size: 12.5px; color: var(--txt); outline: none; margin-bottom: 14px; }
.search-input:focus { border-color: var(--indigo); }
.loading, .empty { padding: 20px; text-align: center; color: var(--muted); font-family: var(--mono); font-size: 12px; }
.entries { display: flex; flex-direction: column; gap: 12px; }
.entry { padding-bottom: 12px; border-bottom: 1px solid var(--line); }
.entry:last-child { border-bottom: none; }
.entry-term { font-family: var(--disp); font-weight: 700; font-size: 13px; color: #9aa6ff; margin-bottom: 4px; display: flex; align-items: center; gap: 8px; }
.seen-tag { font-family: var(--mono); font-size: 8.5px; color: var(--good); background: rgba(52,224,161,.12); padding: 1px 6px; border-radius: 6px; }
.entry-text { font-size: 12.5px; color: var(--muted); line-height: 1.55; margin: 0; }
</style>
