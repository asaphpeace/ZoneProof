<script setup lang="ts">
import { computed, ref } from 'vue'
import { timeAgo } from './brandLabels'

const props = defineProps<{ sources: any[] }>()
const open = ref(false)

const problems = computed(() => props.sources.filter(s => s.status === 'degraded' || s.status === 'down'))
const allHealthy = computed(() => props.sources.length > 0 && problems.value.length === 0)
const dot = (s: any) => ({ healthy: 'var(--good)', degraded: 'var(--warn)', down: 'var(--bad)', unknown: 'var(--faint)' } as Record<string, string>)[s.status] ?? 'var(--faint)'

function text(s: any) {
  if (s.status === 'unknown') return 'Not checked yet'
  if (s.status === 'healthy') return `Healthy · checked ${timeAgo(s.last_success_at)}`
  const why = s.last_error ? ` (${s.last_error})` : ''
  if (s.status === 'degraded') return `Retrying${why}`
  const next = s.retry_after ? `, next attempt ${new Date(s.retry_after).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}` : ''
  return `Unavailable${why}${next}`
}
</script>

<template>
  <section v-if="sources.length" class="strip" aria-label="Source health">
    <button v-if="allHealthy" type="button" class="ok" :aria-expanded="open" @click="open = !open">
      <i class="d" style="background: var(--good)" /> All {{ sources.length }} sources healthy
      <span class="more">{{ open ? 'Hide' : 'Details' }}</span>
    </button>
    <div v-if="!allHealthy || open" class="list">
      <span v-for="s in sources" :key="s.source" class="src" :class="{ bad: s.status === 'degraded' || s.status === 'down' }"
        :title="s.status === 'healthy' ? '' : 'Results from this source are delayed or missing until it recovers. Other discovery continues normally.'">
        <i class="d" :style="{ background: dot(s) }" /><b>{{ s.label }}</b><span>{{ text(s) }}</span>
      </span>
    </div>
  </section>
</template>

<style scoped>
.strip { display: flex; flex-direction: column; gap: 8px; }
.ok { align-self: flex-start; display: inline-flex; align-items: center; gap: 8px; border: 1px solid var(--line2); background: transparent; color: var(--muted); border-radius: 999px; padding: 5px 12px; font-family: var(--mono); font-size: 11px; cursor: pointer; }
.ok:hover { color: var(--txt); border-color: var(--indigo); }
.more { color: var(--indigo); }
.list { display: flex; gap: 8px; flex-wrap: wrap; }
.src { display: inline-flex; align-items: center; gap: 8px; padding: 6px 12px; border-radius: 10px; border: 1px solid var(--line); font-size: 12px; color: var(--muted); }
.src b { color: var(--txt); font-weight: 600; }
.src.bad { border-color: rgba(245,197,66,.35); background: rgba(245,197,66,.07); color: #f7d27a; }
.d { width: 8px; height: 8px; border-radius: 50%; flex: none; display: inline-block; }
</style>
