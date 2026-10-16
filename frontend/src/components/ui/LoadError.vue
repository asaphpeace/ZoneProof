<script setup lang="ts">
// A failed load is not an empty page. Shown by the data views when their
// primary request fails, so the user can tell "could not ask" from "no data".
const props = defineProps<{ message: string; title?: string }>()
const sentence = () => props.message.replace(/[.!?\s]*$/, '.')
defineEmits<{ (e: 'retry'): void }>()
</script>

<template>
  <div class="load-error" role="alert">
    <div class="le-text">
      <strong>{{ title || 'This page could not be loaded.' }}</strong>
      <span>{{ sentence() }} This is not the same as having no data.</span>
    </div>
    <button type="button" class="le-retry" @click="$emit('retry')">Try again</button>
  </div>
</template>

<style scoped>
.load-error {
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
  margin: 0 0 16px; padding: 12px 16px; border-radius: 10px;
  background: rgba(240, 90, 90, 0.10); border: 1px solid rgba(240, 90, 90, 0.35);
  color: var(--text, #e8e9f2); font-size: 13px;
}
.le-text { display: flex; flex-direction: column; gap: 2px; }
.le-text span { color: var(--muted, #9aa0b4); }
.le-retry {
  flex: none; padding: 7px 14px; border-radius: 8px; cursor: pointer; font-weight: 600;
  background: transparent; border: 1px solid rgba(240, 90, 90, 0.6); color: inherit;
}
.le-retry:hover { background: rgba(240, 90, 90, 0.15); }
</style>
