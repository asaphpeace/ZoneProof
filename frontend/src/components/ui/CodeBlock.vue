<script setup lang="ts">
defineProps<{ code: string }>()
</script>

<template>
  <pre class="code" tabindex="0" aria-label="Code example">{{ code }}</pre>
</template>

<style scoped>
.code {
  background: rgba(0,0,0,.45); border: 1px solid var(--line2); border-radius: 11px;
  padding: 13px; font-family: var(--mono); font-size: 11.5px; color: #a8ecdf;
  overflow-x: auto; white-space: pre-wrap; word-break: break-word;
}
</style>
