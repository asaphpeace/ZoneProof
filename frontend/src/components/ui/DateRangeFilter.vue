<script setup lang="ts">
const props = defineProps<{ modelValue: number | null }>()
const emit  = defineEmits<{ 'update:modelValue': [days: number | null] }>()

const PRESETS: { label: string; days: number | null }[] = [
  { label: 'All',  days: null },
  { label: '7d',   days: 7 },
  { label: '30d',  days: 30 },
  { label: '90d',  days: 90 },
  { label: '6m',   days: 180 },
  { label: '1y',   days: 365 },
]
</script>

<template>
  <div class="drf">
    <span class="drf-label">Period</span>
    <div class="drf-pills">
      <button
        v-for="p in PRESETS"
        :key="String(p.days)"
        class="pill"
        :class="{ active: modelValue === p.days }"
        @click="emit('update:modelValue', p.days)"
      >{{ p.label }}</button>
    </div>
  </div>
</template>

<style scoped>
.drf { display: flex; align-items: center; gap: 10px; }
.drf-label { font-family: var(--mono); font-size: 10px; text-transform: uppercase; letter-spacing: .6px; color: var(--faint); white-space: nowrap; }
.drf-pills { display: flex; gap: 4px; }
.pill {
  font-family: var(--mono); font-size: 11px; padding: 4px 10px;
  background: rgba(255,255,255,.04); border: 1px solid var(--line2);
  border-radius: 20px; color: var(--muted); cursor: pointer; transition: .12s;
}
.pill:hover { border-color: var(--indigo); color: var(--txt); }
.pill.active { background: rgba(91,92,240,.18); border-color: var(--indigo); color: #9aa6ff; font-weight: 600; }
</style>
