<script setup lang="ts">
import { computed } from 'vue'
import { rungsFor, RUNGS } from './brandLabels'

const props = defineProps<{ stage: string; tone?: string; showLabel?: boolean }>()
const rungs = computed(() => rungsFor(props.stage))
const label = computed(() => RUNGS.find(r => r.key === props.stage)?.label ?? 'Not registered')
const reached = computed(() => rungs.value.filter(r => r.on).length)
const color = computed(() => ({ red: 'var(--bad)', amber: 'var(--warn)', green: 'var(--good)', slate: 'var(--muted)' } as Record<string, string>)[props.tone ?? 'slate'] ?? 'var(--muted)')
</script>

<template>
  <span class="life">
    <span class="dots" role="img" :aria-label="`Lifecycle: reached ${label}, stage ${reached} of ${RUNGS.length}`">
      <i v-for="r in rungs" :key="r.key" :class="{ on: r.on }" :style="r.on ? { background: color, borderColor: color } : undefined" />
    </span>
    <span v-if="showLabel !== false" class="lab">{{ label }}</span>
  </span>
</template>

<style scoped>
.life { display: inline-flex; flex-direction: column; gap: 5px; align-items: flex-end; }
.dots { display: inline-flex; gap: 5px; }
.dots i { width: 9px; height: 9px; border-radius: 50%; border: 1.5px solid var(--faint); box-sizing: border-box; }
.lab { font-family: var(--mono); font-size: 11px; color: var(--muted); }
</style>
