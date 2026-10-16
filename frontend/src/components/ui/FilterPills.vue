<script setup lang="ts">
defineProps<{ options: Array<{ value: string; label: string }>; modelValue: string }>()
const emit = defineEmits<{ 'update:modelValue': [v: string] }>()
</script>

<template>
  <div class="filters">
    <div
      v-for="opt in options" :key="opt.value"
      :class="['fpill', modelValue === opt.value ? 'active' : '']"
      @click="emit('update:modelValue', opt.value)"
    >{{ opt.label }}</div>
  </div>
</template>

<style scoped>
.filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
.fpill {
  font-family: var(--mono); font-size: 11.5px; padding: 8px 14px; border-radius: 20px;
  border: 1px solid var(--line2); color: var(--muted); cursor: pointer; transition: .15s;
  background: rgba(255,255,255,.02);
}
.fpill:hover { color: var(--txt); border-color: var(--indigo); }
.fpill.active { background: linear-gradient(90deg, #5b5cf0, #4b4ce0); color: #fff; border-color: transparent; }
</style>
