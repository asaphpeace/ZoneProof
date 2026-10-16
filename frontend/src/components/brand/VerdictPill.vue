<script setup lang="ts">
import { computed } from 'vue'
import { TONE } from './brandLabels'

const props = defineProps<{ verdict: { label: string; tone: string }; size?: 'sm' | 'md' }>()
const t = computed(() => TONE[props.verdict?.tone] ?? TONE.slate)
</script>

<template>
  <span class="pill" :class="size" :style="{ color: t.fg, background: t.bg, borderColor: t.bd, borderStyle: t.dashed ? 'dashed' : 'solid' }">
    {{ verdict.label }}
  </span>
</template>

<style scoped>
.pill { display: inline-flex; align-items: center; padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; border-width: 1px; white-space: nowrap; }
.pill.md { padding: 4px 12px; font-size: 13px; }
</style>
